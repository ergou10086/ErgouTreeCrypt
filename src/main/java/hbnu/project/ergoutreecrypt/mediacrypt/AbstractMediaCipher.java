package hbnu.project.ergoutreecrypt.mediacrypt;

import hbnu.project.ergoutreecrypt.crypto.RandomBytes;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.List;

/**
 * 媒体加解密模板，实现各格式共享的通用流程，子类只需提供格式相关的"解析 + 元数据读写"。
 *
 * <p><b>加密流程</b>（{@link #encrypt}）：
 * <ol>
 *   <li>子类 {@link #planEncrypt} 解析源文件，产出"待加密 payload 区间"；</li>
 *   <li>生成随机 salt / hkdfSalt / nonce，派生 enc/mac 子密钥；</li>
 *   <li>把源文件原样拷贝到输出（保留全部容器结构）；</li>
 *   <li>在输出文件上对 payload 区间做等长 XOR（可选同时算原文 MAC）；</li>
 *   <li>子类 {@link #writeMetadata} 把元数据写入输出文件的格式专属载体。</li>
 * </ol>
 *
 * <p><b>解密流程</b>（{@link #decrypt}）：
 * <ol>
 *   <li>子类 {@link #readMetadata} 从源读取元数据，并产出还原所需的"待解密区间"与"去元数据后的输出"；</li>
 *   <li>派生子密钥，对输出文件上的区间做等长 XOR 还原（可选重算明文 MAC）；</li>
 *   <li>若元数据含完整性 MAC，则常量时间比较，失败抛出 {@link MediaCryptException}（密码错误/损坏）。</li>
 * </ol>
 *
 * <p>注意：元数据载体的"写入/剥离"会改变文件结构，由各格式子类全权负责（因为 WAV/MP3/MP4 载体不同）。
 * 模板只负责"拷贝 + 在指定区间做加解密 + MAC 校验"这些与格式无关的部分。
 *
 * @author ErgouTree
 */
public abstract class AbstractMediaCipher implements MediaCipher {

    @Override
    public final void encrypt(Path input, Path output, byte[] password, MediaCryptOptions options,
                              MediaProgress progress) throws MediaCryptException, IOException {
        if (options == null) {
            options = MediaCryptOptions.defaults();
        }
        if (progress == null) {
            progress = MediaProgress.NONE;
        }
        MediaCryptProfile profile = options.resolveProfile(format());

        // 1. 子类解析源文件，得到加密计划（payload 区间 + 元数据载体写入所需的上下文）。
        EncryptPlan plan = planEncrypt(input, profile);

        // 2. 生成随机材料。
        byte[] salt = RandomBytes.generate(MediaMetadata.SALT_LEN);
        byte[] hkdfSalt = RandomBytes.generate(MediaMetadata.HKDF_SALT_LEN);
        byte[] nonce = RandomBytes.generate(MediaMetadata.NONCE_LEN);

        // 3. 源文件原样拷贝到输出（保留所有容器结构；后续在副本上原地加密）。
        Files.copy(input, output, StandardCopyOption.REPLACE_EXISTING);

        byte[] plainMac = null;
        try (MediaKeySchedule keys = MediaKeySchedule.derive(password, salt, hkdfSalt, options.paranoid());
             FileChannel ch = FileChannel.open(output, StandardOpenOption.READ, StandardOpenOption.WRITE)) {

            // 4. 可选：先算原文 payload MAC（在 XOR 之前）。
            if (options.storeIntegrity()) {
                plainMac = PayloadCrypter.computePlaintextMac(ch, plan.payloadRanges(),
                        keys.macKey(), options.paranoid());
            }

            // 5. 在输出副本上对 payload 区间做等长 XOR。
            PayloadCrypter.process(ch, plan.payloadRanges(), keys.encKey(), nonce,
                    true, null, progress);
        } catch (MediaCryptCancelledException e) {
            Files.deleteIfExists(output);
            throw e;
        }

        // 6. 写入元数据载体（追加 chunk / PRIV 帧 / uuid box）。
        MediaMetadata metadata = new MediaMetadata(format(), profile, options.paranoid(),
                salt, hkdfSalt, nonce, plainMac);
        writeMetadata(output, metadata, plan);
    }

    @Override
    public final void decrypt(Path input, Path output, byte[] password, MediaProgress progress)
            throws MediaCryptException, IOException {
        if (progress == null) {
            progress = MediaProgress.NONE;
        }
        // 1. 子类读取元数据并准备输出（剥离元数据载体后的原始容器拷贝）+ 待解密区间。
        DecryptPlan plan = readMetadata(input, output);
        MediaMetadata metadata = plan.metadata();

        if (metadata.format() != format()) {
            throw new MediaCryptException("元数据格式 " + metadata.format()
                    + " 与解密器 " + format() + " 不匹配");
        }

        byte[] recomputedMac = null;
        try (MediaKeySchedule keys = MediaKeySchedule.derive(password, metadata.salt(),
                metadata.hkdfSalt(), metadata.paranoid());
             FileChannel ch = FileChannel.open(output, StandardOpenOption.READ, StandardOpenOption.WRITE)) {

            hbnu.project.ergoutreecrypt.crypto.Mac mac = metadata.hasIntegrity()
                    ? hbnu.project.ergoutreecrypt.crypto.MacFactory.create(keys.macKey(), metadata.paranoid())
                    : null;
            try {
                PayloadCrypter.process(ch, plan.payloadRanges(), keys.encKey(), metadata.nonce(),
                        false, mac, progress);
                if (mac != null) {
                    recomputedMac = mac.doFinal();
                }
            } finally {
                if (mac != null) {
                    mac.close();
                }
            }
        } catch (MediaCryptCancelledException e) {
            Files.deleteIfExists(output);
            throw e;
        }

        // 2. 完整性校验：常量时间比较还原后明文 MAC 与元数据中存的原文 MAC。
        if (metadata.hasIntegrity()) {
            byte[] expected = metadata.plainMac();
            if (!MessageDigest.isEqual(expected, recomputedMac)) {
                // 删除可能错误的输出，避免残留半成品。
                Files.deleteIfExists(output);
                throw new MediaCryptException("完整性校验失败：密码错误或文件已损坏/被篡改");
            }
        }
    }

    @Override
    public boolean verifyIntegrity(Path input, byte[] password, MediaProgress progress)
            throws MediaCryptException, IOException {
        if (progress == null) {
            progress = MediaProgress.NONE;
        }
        Path tempOutput = null;
        try {
            // 1. 创建临时文件作为解密目标（仅用于给 PayloadCrypter 提供可写通道）
            tempOutput = Files.createTempFile("ergou-av-verify-", ".tmp");

            // 2. 读取元数据并剥离到临时文件
            DecryptPlan plan = readMetadata(input, tempOutput);
            MediaMetadata metadata = plan.metadata();

            if (metadata.format() != format()) {
                throw new MediaCryptException("元数据格式 " + metadata.format()
                        + " 与解密器 " + format() + " 不匹配");
            }

            // 3. 若未存储完整性 MAC，直接返回 false
            if (!metadata.hasIntegrity()) {
                return false;
            }

            // 4. 派生密钥
            byte[] recomputedMac = null;
            try (MediaKeySchedule keys = MediaKeySchedule.derive(password, metadata.salt(),
                    metadata.hkdfSalt(), metadata.paranoid());
                 FileChannel ch = FileChannel.open(tempOutput,
                         StandardOpenOption.READ, StandardOpenOption.WRITE)) {

                hbnu.project.ergoutreecrypt.crypto.Mac mac =
                        hbnu.project.ergoutreecrypt.crypto.MacFactory.create(
                                keys.macKey(), metadata.paranoid());
                try {
                    // 5. XOR 还原明文并累加 MAC
                    PayloadCrypter.process(ch, plan.payloadRanges(), keys.encKey(),
                            metadata.nonce(), false, mac, progress);
                    recomputedMac = mac.doFinal();
                } finally {
                    mac.close();
                }
            } catch (MediaCryptCancelledException e) {
                throw e;
            }

            // 6. 常量时间比对
            byte[] expected = metadata.plainMac();
            if (!MessageDigest.isEqual(expected, recomputedMac)) {
                throw new MediaCryptException("完整性校验失败：密码错误或文件已损坏/被篡改");
            }
            return true;
        } finally {
            // 7. 无论成功与否，删除临时文件
            if (tempOutput != null) {
                try {
                    Files.deleteIfExists(tempOutput);
                } catch (IOException ignored) {
                }
            }
        }
    }

    // ---- 子类需实现的格式相关钩子 ----

    /**
     * 解析源媒体文件，产出加密计划。
     *
     * @param input   源媒体文件
     * @param profile 实际生效的档位
     * @return 加密计划（payload 区间等）
     */
    protected abstract EncryptPlan planEncrypt(Path input, MediaCryptProfile profile)
            throws MediaCryptException, IOException;

    /**
     * 把元数据写入<b>已完成 payload 加密</b>的输出文件（格式专属载体）。
     *
     * <p>实现时若插入元数据改变了文件中 payload 的偏移，需自行保证一致性
     * （推荐：把元数据追加在 payload 区间之后，或写入不影响 payload 偏移的位置）。
     */
    protected abstract void writeMetadata(Path output, MediaMetadata metadata, EncryptPlan plan)
            throws MediaCryptException, IOException;

    /**
     * 从加密文件读取元数据，剥离元数据载体后将原始容器写到 {@code output}，并给出待解密区间。
     *
     * @param input  加密后的媒体文件
     * @param output 还原目标（实现需先写入"去元数据后的容器"，模板随后在其上原地解密）
     * @return 解密计划（元数据 + 待解密区间）
     */
    protected abstract DecryptPlan readMetadata(Path input, Path output)
            throws MediaCryptException, IOException;

    // ---- 计划对象 ----

    /**
     * 加密计划：待加密 payload 区间，以及子类写元数据可能需要的附加信息。
     */
    public static class EncryptPlan {
        private final List<ByteRange> payloadRanges;

        public EncryptPlan(List<ByteRange> payloadRanges) {
            this.payloadRanges = List.copyOf(payloadRanges);
        }

        public List<ByteRange> payloadRanges() {
            return payloadRanges;
        }
    }

    /**
     * 解密计划：解析出的元数据与待解密区间（针对已写入 {@code output} 的去元数据容器）。
     */
    public static class DecryptPlan {
        private final MediaMetadata metadata;
        private final List<ByteRange> payloadRanges;

        public DecryptPlan(MediaMetadata metadata, List<ByteRange> payloadRanges) {
            this.metadata = metadata;
            this.payloadRanges = List.copyOf(payloadRanges);
        }

        public MediaMetadata metadata() {
            return metadata;
        }

        public List<ByteRange> payloadRanges() {
            return payloadRanges;
        }
    }
}
