package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.*;
import hbnu.project.ergoutreecrypt.encoding.Padding;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.header.Flags;
import hbnu.project.ergoutreecrypt.header.HeaderAuth;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer;
import hbnu.project.ergoutreecrypt.password.Passwordless;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;

/**
 * 双卷可否认加密：一个容器，两个密码，两份内容。
 *
 * <h3>文件格式</h3>
 * <pre>
 * ┌──────────────────────────────────────────────┐
 * │ Magic: "EGTD" (4 bytes)                      │
 * │ Version: 0x01 (1 byte)                       │
 * │ HeaderSize: uint32 LE (4 bytes)              │
 * ├──────────────────────────────────────────────┤
 * │ MetaBlock-1 (decoy slot): 552 bytes          │
 * │   salt[16] + nonce[24]                       │
 * │   + XChaCha20_encrypt(plaintext_meta_1)      │
 * ├──────────────────────────────────────────────┤
 * │ MetaBlock-2 (hidden slot): 552 bytes         │
 * │   无隐藏卷时填充 SecureRandom 字节             │
 * ├──────────────────────────────────────────────┤
 * │ Decoy Data Region                            │
 * ├──────────────────────────────────────────────┤
 * │ Hidden Data Region                           │
 * └──────────────────────────────────────────────┘
 * </pre>
 *
 * <h3>安全属性</h3>
 * <ul>
 *   <li>两个 MetaBlock 尺寸固定（各 552 字节），无隐藏卷时 MetaBlock-2 为随机字节，
 *       与有效加密块密码学上不可区分</li>
 *   <li>每个密码独立派生 Argon2id 密钥，salt 各不相同</li>
 *   <li>MetaBlock 内嵌 keyHash（HMAC-SHA3-512），无需触碰数据区即可验证密码</li>
 *   <li>解密时优先尝试 MetaBlock-1（钓鱼槽位），匹配则仅解密钓鱼数据，隐藏区完全不可见</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class DualDeniability {

    /**
     * 文件魔数："EGTD"，区别于普通 .ergou 的 header。
     */
    static final byte[] MAGIC = {'E', 'G', 'T', 'D'};

    /**
     * 当前格式版本。
     */
    static final byte CURRENT_VERSION = 0x01;

    /**
     * MetaBlock 明文载荷大小（加密前）。
     */
    static final int METABLOCK_PLAIN_SIZE = 512;

    /**
     * MetaBlock salt 长度（16 字节）。
     */
    static final int METABLOCK_SALT_SIZE = 16;

    /**
     * MetaBlock nonce 长度（24 字节）。
     */
    static final int METABLOCK_NONCE_SIZE = 24;

    /**
     * 单个 MetaBlock 文件尺寸：salt(16) + nonce(24) + encrypted(512) = 552。
     */
    static final int METABLOCK_ENC_SIZE = METABLOCK_SALT_SIZE + METABLOCK_NONCE_SIZE + METABLOCK_PLAIN_SIZE;

    /**
     * 完整 header 尺寸：magic(4) + version(1) + hdrSize(4) + metablock1(552) + metablock2(552) = 1113。
     */
    static final int TOTAL_HEADER_SIZE = 4 + 1 + 4 + METABLOCK_ENC_SIZE * 2;

    /**
     * keyHash 在 MetaBlock 明文中的偏移与尺寸。
     */
    private static final int KEYHASH_OFFSET = 0;
    private static final int KEYHASH_SIZE = 64;

    /**
     * salt 在 MetaBlock 明文中的偏移与尺寸。
     */
    private static final int SALT_OFFSET = 64;
    private static final int SALT_SIZE = 16;

    /**
     * hkdfSalt 在 MetaBlock 明文中的偏移与尺寸。
     */
    private static final int HKDFSALT_OFFSET = 80;
    private static final int HKDFSALT_SIZE = 32;

    /**
     * serpentIV 在 MetaBlock 明文中的偏移与尺寸。
     */
    private static final int SERPENTIV_OFFSET = 112;
    private static final int SERPENTIV_SIZE = 16;

    /**
     * nonce 在 MetaBlock 明文中的偏移与尺寸。
     */
    private static final int NONCE_OFFSET = 128;
    private static final int NONCE_SIZE = 24;

    /**
     * authTag 在 MetaBlock 明文中的偏移与尺寸。
     */
    private static final int AUTHTAG_OFFSET = 152;
    private static final int AUTHTAG_SIZE = 64;

    /**
     * dataOffset（uint64 LE）在 MetaBlock 明文中的偏移。
     */
    private static final int DATAOFFSET_OFFSET = 216;

    /**
     * dataLength（uint64 LE）在 MetaBlock 明文中的偏移。
     */
    private static final int DATALENGTH_OFFSET = 224;

    /**
     * origNameLen（uint16 LE）在 MetaBlock 明文中的偏移。
     */
    private static final int ORIGNAMELEN_OFFSET = 232;

    /**
     * origName 在 MetaBlock 明文中的起始偏移。
     */
    private static final int ORIGNAME_OFFSET = 234;

    /**
     * 最大原始文件名长度（UTF-8 字节），保证 flags(6) + padding 能填满 512 字节。
     */
    static final int MAX_FILENAME_BYTES = METABLOCK_PLAIN_SIZE - ORIGNAME_OFFSET - 6;

    /**
     * canary 令牌在 MetaBlock 明文中的偏移（固定在填充区内，距末尾 16 字节）。
     */
    private static final int CANARY_OFFSET = METABLOCK_PLAIN_SIZE - 16;

    /**
     * Argon2 密钥长度。
     */
    private static final int KEY_SIZE = 32;

    private DualDeniability() {
    }

    // ==================== 公开 API ====================

    /**
     * 双卷可否认加密主入口。
     *
     * <p>直接读取真实文件与钓鱼文件，生成 EGTD 容器。
     * 完成后按需执行分卷与归档，与普通加密流程一致。
     *
     * @param req 加密请求（含 real 文件、real 密码、decoy 文件、fake 密码）
     * @throws Exception 密码学或 I/O 错误
     */
    public static void encrypt(EncryptRequest req) throws Exception {
        ProgressReporter reporter = req.getReporter();
        String realFile = req.getInputFile();
        String decoyFile = req.getDecoyFilePath();
        String realPassword = Passwordless.effectivePassword(req.getPassword());
        String fakePassword = Passwordless.effectivePassword(req.getFakePassword());
        boolean paranoid = req.isParanoid();
        boolean reedSolomon = req.isReedSolomon();
        RsCodecs rs = req.getRsCodecs();

        // 预处理：多文件合并 / 压缩
        String realInput = realFile;
        String decoyInput = decoyFile;
        String tempReal = null;
        String tempDecoy = null;
        List<String> files = req.getInputFiles();
        if (files != null && !files.isEmpty()) {
            if (reporter != null) {
                reporter.setStatus(Messages.get("status.compressing.real.multi"), ProgressPhase.ARCHIVE);
            }
            Path tmp = Files.createTempFile("ergou_real", ".tmp");
            try (OutputStream out = Files.newOutputStream(tmp)) {
                for (String f : files) {
                    Files.copy(Path.of(f), out);
                }
            }
            tempReal = tmp.toString();
            realInput = tempReal;
        } else if (req.isCompress()) {
            if (reporter != null) {
                reporter.setStatus(Messages.get("status.compressing.real"), ProgressPhase.ARCHIVE);
            }
            Path tmp = Files.createTempFile("ergou_real", ".tmp");
            Files.copy(Path.of(realFile), tmp);
            tempReal = tmp.toString();
            realInput = tempReal;
        }

        try {
            long realSize = Files.size(Path.of(realInput));
            long decoySize = Files.size(Path.of(decoyInput));

            // 生成 MetaBlock 密码学参数（不含 authTag，稍后填入）
            MetaBlockParams decoyParams = MetaBlockParams.generate(decoySize, paranoid, reedSolomon,
                    Path.of(decoyFile).getFileName().toString());
            MetaBlockParams realParams = MetaBlockParams.generate(realSize, paranoid, reedSolomon,
                    Path.of(realFile).getFileName().toString());

            // 第一步：先加密数据区域到临时文件，获取 authTag
            if (reporter != null) {
                reporter.setStatus(Messages.get("status.encrypting.decoy"));
            }
            Path decoyTempEnc = Files.createTempFile("ergou_decoy_enc", ".tmp");
            DataRegion.encryptToFile(decoyInput, decoyTempEnc, decoyParams, fakePassword, paranoid,
                    reedSolomon, rs, reporter, 0f, 0.5f, realSize + decoySize);

            if (reporter != null) {
                reporter.setStatus(Messages.get("status.encrypting.hidden"));
            }
            Path realTempEnc = Files.createTempFile("ergou_real_enc", ".tmp");
            DataRegion.encryptToFile(realInput, realTempEnc, realParams, realPassword, paranoid,
                    reedSolomon, rs, reporter, 0.5f, 1.0f, realSize + decoySize);

            // 第二步：计算偏移，authTag 已在 encryptToFile 中填入 params
            long decoyEncSize = Files.size(decoyTempEnc);
            long realEncSize = Files.size(realTempEnc);
            long decoyDataOffset = TOTAL_HEADER_SIZE;
            long realDataOffset = TOTAL_HEADER_SIZE + decoyEncSize;
            decoyParams.dataOffset = decoyDataOffset;
            realParams.dataOffset = realDataOffset;

            // 第三步：写入 EGTD 文件（MetaBlock 此时含正确的 authTag 和 keyHash）
            String outputPath = req.getOutputFile();
            String incomplete = outputPath + ".incomplete";

            try (OutputStream fout = Files.newOutputStream(Path.of(incomplete))) {
                // 写入 header：magic + version + hdrSize
                fout.write(MAGIC);
                fout.write(CURRENT_VERSION);
                byte[] hdrSizeBuf = new byte[4];
                ByteBuffer.wrap(hdrSizeBuf).order(ByteOrder.LITTLE_ENDIAN).putInt(TOTAL_HEADER_SIZE);
                fout.write(hdrSizeBuf);

                // 写入 MetaBlock-1（decoy）—— 此时 authTag 已知
                byte[] decoyPwBytes = PasswordNormalizer.encodeForKdf(fakePassword);
                MetaBlock.writeEncrypted(fout, decoyParams, decoyPwBytes);
                SecureZero.zero(decoyPwBytes);

                // 写入 MetaBlock-2（hidden）
                byte[] realPwBytes = PasswordNormalizer.encodeForKdf(realPassword);
                MetaBlock.writeEncrypted(fout, realParams, realPwBytes);
                SecureZero.zero(realPwBytes);

                // 复制已加密的 Decoy Data Region
                Files.copy(decoyTempEnc, fout);

                // 复制已加密的 Hidden Data Region
                Files.copy(realTempEnc, fout);

                fout.flush();
            }

            // 清理加密临时文件
            Files.deleteIfExists(decoyTempEnc);
            Files.deleteIfExists(realTempEnc);

            // 原子重命名
            Files.move(Path.of(incomplete), Path.of(outputPath),
                    StandardCopyOption.REPLACE_EXISTING);

            // 可选：分卷
            boolean split = req.isSplit() && req.getChunkSize() > 0;
            Path chunkDir = null;
            if (split) {
                if (reporter != null) {
                    reporter.setStatus(Messages.get("status.splitting"));
                }
                long chunkBytes = (long) req.getChunkSize() * CryptoConstants.MIB;
                chunkDir = splitOutput(Path.of(outputPath), chunkBytes);
                req.setOutputFile(chunkDir.resolve(Path.of(outputPath).getFileName()).toString());
            }

            // 可选：归档压缩
            String archiveFormat = req.getArchiveFormat();
            boolean archive = archiveFormat != null && !archiveFormat.isEmpty();
            if (archive) {
                if (reporter != null) {
                    reporter.setStatus(Messages.get("status.archiving"), ProgressPhase.ARCHIVE);
                }
                ArchivePacker.Format fmt = ArchivePacker.parseFormat(archiveFormat);
                Path outPath = Path.of(req.getOutputFile());
                Path parent = outPath.getParent() != null ? outPath.getParent() : Path.of(".");

                if (split) {
                    // GZ 多条目时 packEntries 会自动提升为 TAR.GZ，扩展名也需同步调整
                    ArchivePacker.Format extFmt = (fmt == ArchivePacker.Format.GZ)
                            ? ArchivePacker.Format.TAR_GZ : fmt;
                    List<Path> chunks = Splitter.listChunks(outPath);
                    Path archiveParent = parent.getParent() != null ? parent.getParent() : Path.of(".");
                    String archiveName = parent.getFileName().toString() + ArchivePacker.extOf(extFmt);
                    Path archivePath = archiveParent.resolve(archiveName);
                    ArchivePacker.packEntries(archivePath, parent, chunks, fmt,
                            ArchivePacker.resolveArchivePassword(
                                    req.getArchivePassword(), req.getPassword(), fmt), reporter);
                    for (Path c : chunks) {
                        Files.deleteIfExists(c);
                    }
                    try {
                        Files.deleteIfExists(parent);
                    } catch (IOException ignored) {
                    }
                    req.setOutputFile(archivePath.toString());
                } else {
                    Path archivePath = Path.of(req.getOutputFile() + ArchivePacker.extOf(fmt));
                    ArchivePacker.pack(archivePath, outPath, fmt,
                            ArchivePacker.resolveArchivePassword(
                                    req.getArchivePassword(), req.getPassword(), fmt), reporter);
                    Files.deleteIfExists(outPath);
                    req.setOutputFile(archivePath.toString());
                }
                if (reporter != null) {
                    reporter.setProgress(1f, "", ProgressPhase.ARCHIVE);
                }
            }

            if (reporter != null) {
                reporter.setProgress(1.0f, "");
            }
        } finally {
            // 清理临时文件
            if (tempReal != null) {
                Files.deleteIfExists(Path.of(tempReal));
            }
            if (tempDecoy != null) {
                Files.deleteIfExists(Path.of(tempDecoy));
            }
            try {
                Files.deleteIfExists(Path.of(req.getOutputFile() + ".incomplete"));
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * 双卷可否认解密主入口。
     *
     * <p>自动检测 EGTD 格式，依次尝试 MetaBlock-1（钓鱼）和 MetaBlock-2（隐藏），
     * 解密匹配的数据区域并写入输出文件。
     *
     * @param req 解密请求（含密码）
     * @throws Exception 密码错误或 I/O 错误
     */
    public static void decrypt(DecryptRequest req) throws Exception {
        String inputFile = req.getInputFile();
        String password = Passwordless.effectivePassword(req.getPassword());
        ProgressReporter reporter = req.getReporter();
        RsCodecs rs = req.getRsCodecs();

        // 暴力破解防护
        hbnu.project.ergoutreecrypt.crypto.BruteForceGuard guard =
                hbnu.project.ergoutreecrypt.crypto.BruteForceGuard.getInstance();
        if (!req.isForceDecrypt() && !guard.allowAttempt(inputFile)) {
            throw new IOException(String.format(
                    "too many failed attempts (%d), file temporarily locked",
                    guard.getMaxAttempts()));
        }

        if (reporter != null) {
            reporter.setStatus(Messages.get("status.detecting.dual"));
        }

        // 解析 header
        try (InputStream fin = Files.newInputStream(Path.of(inputFile))) {
            byte[] magic = new byte[4];
            readExact(fin, magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IOException("not a dual-deniability volume");
            }
            int version = fin.read();
            if (version < 0) {
                throw new IOException("unexpected EOF reading version");
            }
            byte[] hdrSizeBuf = new byte[4];
            readExact(fin, hdrSizeBuf);
            int hdrSize = ByteBuffer.wrap(hdrSizeBuf).order(ByteOrder.LITTLE_ENDIAN).getInt();

            // 读取两个 MetaBlock
            byte[] mb1Enc = new byte[METABLOCK_ENC_SIZE];
            byte[] mb2Enc = new byte[METABLOCK_ENC_SIZE];
            readExact(fin, mb1Enc);
            readExact(fin, mb2Enc);

            // 依次尝试密码候选
            List<byte[]> candidates = PasswordNormalizer.candidates(password);
            if (req.isForceDecrypt()) {
                candidates = List.of(password.getBytes(StandardCharsets.UTF_8));
            }

            // 先尝试 MetaBlock-1（钓鱼槽位）
            // MetaBlock 密钥派生使用非偏执模式（偏执由数据区独立控制）
            for (byte[] cand : candidates) {
                MetaBlockParams params = MetaBlock.tryDecryptAndVerify(mb1Enc, cand, false);
                if (params != null) {
                    boolean paranoid = params.flags.isParanoid();
                    if (reporter != null) {
                        reporter.setStatus(Messages.get("status.decrypting.decoy"));
                    }
                    DataRegion.decryptFrom(inputFile, params, cand, paranoid,
                            req.isForceDecrypt(), rs, reporter, req.getOutputFile());
                    return;
                }
            }

            // 再尝试 MetaBlock-2（隐藏槽位）
            for (byte[] cand : candidates) {
                MetaBlockParams params = MetaBlock.tryDecryptAndVerify(mb2Enc, cand, false);
                if (params != null) {
                    boolean paranoid = params.flags.isParanoid();
                    if (reporter != null) {
                        reporter.setStatus(Messages.get("status.decrypting.hidden"));
                    }
                    DataRegion.decryptFrom(inputFile, params, cand, paranoid,
                            req.isForceDecrypt(), rs, reporter, req.getOutputFile());
                    return;
                }
            }

            // 所有密码候选均失败
            guard.recordFailure(inputFile);
            throw new IOException("password is incorrect or the file is not a valid dual-deniability volume");
        }
        // 解密成功，重置计数器（在 DataRegion.decryptFrom 中已完成）
        // 注意：recordSuccess 在返回前由 Decryptor 统一调用，此处不重复
    }

    /**
     * 检测文件是否为双卷可否认加密容器（EGTD 格式）。
     *
     * @param filePath 文件路径
     * @return 若文件以 "EGTD" 魔数开头则返回 true
     */
    public static boolean isDualDeniable(String filePath) {
        try {
            if (Files.size(Path.of(filePath)) < TOTAL_HEADER_SIZE) {
                return false;
            }
            try (InputStream in = Files.newInputStream(Path.of(filePath))) {
                byte[] magic = new byte[4];
                int n = in.read(magic);
                return n == 4 && Arrays.equals(magic, MAGIC);
            }
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== MetaBlock 参数容器 ====================

    /**
     * RS128 编码：将明文按 128 字节块分割，逐块编码为 136 字节。
     */
    private static byte[] encodeWithRS(byte[] data, int len, RsCodecs rs) {
        boolean isFullBlock = len == CryptoConstants.MIB;

        if (isFullBlock) {
            int fullChunks = len / Padding.BLOCK_SIZE;
            byte[] result = new byte[fullChunks * 136];
            byte[] chunk = new byte[Padding.BLOCK_SIZE];
            byte[] enc = new byte[136];
            int pos = 0;
            for (int i = 0; i < fullChunks; i++) {
                System.arraycopy(data, i * Padding.BLOCK_SIZE, chunk, 0, Padding.BLOCK_SIZE);
                ReedSolomon.encodeInto(enc, rs.rs128, chunk);
                System.arraycopy(enc, 0, result, pos, 136);
                pos += 136;
            }
            return result;
        }

        int fullChunks = len / Padding.BLOCK_SIZE;
        int remaining = len - fullChunks * Padding.BLOCK_SIZE;
        int chunkCount = fullChunks + 1;

        byte[] result = new byte[chunkCount * 136];
        byte[] chunk = new byte[Padding.BLOCK_SIZE];
        byte[] enc = new byte[136];
        int pos = 0;
        for (int i = 0; i < fullChunks; i++) {
            System.arraycopy(data, i * Padding.BLOCK_SIZE, chunk, 0, Padding.BLOCK_SIZE);
            ReedSolomon.encodeInto(enc, rs.rs128, chunk);
            System.arraycopy(enc, 0, result, pos, 136);
            pos += 136;
        }

        byte[] last = new byte[remaining];
        System.arraycopy(data, fullChunks * Padding.BLOCK_SIZE, last, 0, remaining);
        byte[] padded = Padding.pad(last);
        ReedSolomon.encodeInto(enc, rs.rs128, padded);
        System.arraycopy(enc, 0, result, pos, 136);

        return result;
    }

    // ==================== MetaBlock 加密/解密 ====================

    /**
     * RS128 快速解码：将编码数据按 136 字节块分割，逐块解码为 128 字节。
     */
    private static byte[] decodeWithRSFast(byte[] data, int len, RsCodecs rs,
                                           boolean isLast, boolean padded,
                                           boolean forceDecode, boolean fastDecode) {
        int fullEncodedSize = CryptoConstants.MIB / Padding.BLOCK_SIZE * 136;

        if (len >= fullEncodedSize) {
            int chunkCount = len / 136;
            byte[] result = new byte[chunkCount * Padding.BLOCK_SIZE];
            byte[] chunk = new byte[136];
            for (int i = 0; i < chunkCount; i++) {
                System.arraycopy(data, i * 136, chunk, 0, 136);
                ReedSolomon.DecodeResult dr = ReedSolomon.decode(rs.rs128, chunk, fastDecode);
                byte[] decoded = dr.data;
                if (isLast && i == chunkCount - 1 && padded) {
                    decoded = Padding.unpad(decoded);
                }
                System.arraycopy(decoded, 0, result, i * Padding.BLOCK_SIZE, decoded.length);
                if (isLast && i == chunkCount - 1 && padded) {
                    return Arrays.copyOf(result,
                            (chunkCount - 1) * Padding.BLOCK_SIZE + decoded.length);
                }
            }
            return result;
        } else {
            int chunkCount = len / 136;
            byte[] result = new byte[chunkCount * Padding.BLOCK_SIZE];
            byte[] chunk = new byte[136];
            for (int i = 0; i < chunkCount; i++) {
                System.arraycopy(data, i * 136, chunk, 0, 136);
                ReedSolomon.DecodeResult dr = ReedSolomon.decode(rs.rs128, chunk, fastDecode);
                byte[] decoded = dr.data;
                if (i == chunkCount - 1) {
                    decoded = Padding.unpad(decoded);
                }
                System.arraycopy(decoded, 0, result, i * Padding.BLOCK_SIZE, decoded.length);
                if (i == chunkCount - 1) {
                    return Arrays.copyOf(result,
                            (chunkCount - 1) * Padding.BLOCK_SIZE + decoded.length);
                }
            }
            return result;
        }
    }

    // ==================== 数据区加密/解密 ====================

    /**
     * XChaCha20 XOR 操作：对固定长度数据执行 keystream XOR。
     */
    private static void xChaCha20Xor(byte[] key, byte[] nonce24, byte[] dst, byte[] src, int len) {
        ChaChaState state = new ChaChaState(key, nonce24);
        state.xor(dst, src, len);
    }

    // ==================== 内部密码学适配 ====================

    /**
     * 从输入流精确读取指定字节数。
     */
    private static void readExact(InputStream in, byte[] buf) throws IOException {
        int offset = 0;
        while (offset < buf.length) {
            int n = in.read(buf, offset, buf.length - offset);
            if (n < 0) {
                throw new java.io.EOFException("unexpected EOF");
            }
            offset += n;
        }
    }

    /**
     * 从输入流尽量读满缓冲区（最多 maxLen 字节）。
     */
    private static int readFull(InputStream in, byte[] buf, int maxLen) throws IOException {
        int total = 0;
        while (total < maxLen) {
            int n = in.read(buf, total, maxLen - total);
            if (n < 0) {
                break;
            }
            total += n;
        }
        return total;
    }

    // ==================== RS 编码辅助 ====================

    /**
     * 从输入流尽量读满整个缓冲区。
     */
    private static int readFull(InputStream in, byte[] buf) throws IOException {
        return readFull(in, buf, buf.length);
    }

    /**
     * 分卷输出：将文件切分为固定大小的碎片。
     *
     * @param filePath   待切分的文件
     * @param chunkBytes 每卷字节数
     * @return 分卷文件夹路径
     * @throws IOException I/O 错误
     */
    private static Path splitOutput(Path filePath, long chunkBytes) throws IOException {
        String outName = filePath.getFileName().toString();
        String folderName = outName;
        if (folderName.toLowerCase().endsWith(".ergou")) {
            folderName = folderName.substring(0, folderName.length() - ".ergou".length());
        } else if (folderName.toLowerCase().endsWith(".pcv")) {
            folderName = folderName.substring(0, folderName.length() - ".pcv".length());
        }
        Path parent = filePath.getParent() != null ? filePath.getParent() : Path.of(".");
        Path chunkDir = parent.resolve(folderName);

        if (Files.exists(chunkDir) && !Files.isDirectory(chunkDir)) {
            folderName = folderName + "_ergou_split";
            chunkDir = parent.resolve(folderName);
        }
        Files.createDirectories(chunkDir);
        Path movedFile = chunkDir.resolve(outName);
        Files.move(filePath, movedFile, StandardCopyOption.REPLACE_EXISTING);
        Splitter.split(movedFile, chunkBytes);
        Files.deleteIfExists(movedFile);
        return chunkDir;
    }

    // ==================== I/O 辅助 ====================

    /**
     * 单个数据区域的密码学参数集合，序列化后写入 MetaBlock 明文载荷。
     */
    static final class MetaBlockParams {
        /**
         * HMAC-SHA3-512 密钥验证哈希（64 字节）。
         */
        byte[] keyHash;
        /**
         * Argon2id salt（16 字节）。
         */
        byte[] salt;
        /**
         * HKDF salt（32 字节）。
         */
        byte[] hkdfSalt;
        /**
         * Serpent IV（16 字节）。
         */
        byte[] serpentIV;
        /**
         * XChaCha20 nonce（24 字节）。
         */
        byte[] nonce;
        /**
         * 载荷 MAC 认证标签（64 字节），加密后回填。
         */
        byte[] authTag;
        /**
         * 加密数据在文件中的绝对偏移（uint64）。
         */
        long dataOffset;
        /**
         * 明文载荷长度（uint64）。
         */
        long dataLength;
        /**
         * 原始文件名（UTF-8）。
         */
        String origName;
        /**
         * 选项标志位。
         */
        Flags flags;
        /**
         * 金丝雀令牌（16 字节），由 MetaBlock 的 salt 派生，用于篡改检测。
         */
        byte[] canary;

        /**
         * 生成随机密码学参数。
         *
         * @param dataLen     明文数据长度
         * @param paranoid    偏执模式
         * @param reedSolomon RS 纠错
         * @param origName    原始文件名
         * @return 填充了随机值的参数实例
         */
        static MetaBlockParams generate(long dataLen, boolean paranoid, boolean reedSolomon,
                                        String origName) {
            MetaBlockParams p = new MetaBlockParams();
            p.keyHash = new byte[KEYHASH_SIZE];
            p.salt = RandomBytes.generate(SALT_SIZE);
            p.hkdfSalt = RandomBytes.generate(HKDFSALT_SIZE);
            p.serpentIV = RandomBytes.generate(SERPENTIV_SIZE);
            p.nonce = RandomBytes.generate(NONCE_SIZE);
            p.authTag = new byte[AUTHTAG_SIZE];
            p.dataLength = dataLen;
            p.origName = origName;
            p.flags = new Flags(paranoid, false, false, reedSolomon, false);
            return p;
        }

        /**
         * 从 MetaBlock 明文（512 字节）反序列化。
         *
         * @param plain 解密后的 MetaBlock 明文
         * @return 解析出的参数实例
         */
        static MetaBlockParams deserialize(byte[] plain) {
            MetaBlockParams p = new MetaBlockParams();
            p.keyHash = Arrays.copyOfRange(plain, KEYHASH_OFFSET, KEYHASH_OFFSET + KEYHASH_SIZE);
            p.salt = Arrays.copyOfRange(plain, SALT_OFFSET, SALT_OFFSET + SALT_SIZE);
            p.hkdfSalt = Arrays.copyOfRange(plain, HKDFSALT_OFFSET, HKDFSALT_OFFSET + HKDFSALT_SIZE);
            p.serpentIV = Arrays.copyOfRange(plain, SERPENTIV_OFFSET, SERPENTIV_OFFSET + SERPENTIV_SIZE);
            p.nonce = Arrays.copyOfRange(plain, NONCE_OFFSET, NONCE_OFFSET + NONCE_SIZE);
            p.authTag = Arrays.copyOfRange(plain, AUTHTAG_OFFSET, AUTHTAG_OFFSET + AUTHTAG_SIZE);
            p.dataOffset = ByteBuffer.wrap(plain, DATAOFFSET_OFFSET, 8)
                    .order(ByteOrder.LITTLE_ENDIAN).getLong();
            p.dataLength = ByteBuffer.wrap(plain, DATALENGTH_OFFSET, 8)
                    .order(ByteOrder.LITTLE_ENDIAN).getLong();
            int nameLen = ByteBuffer.wrap(plain, ORIGNAMELEN_OFFSET, 2)
                    .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
            if (nameLen > MAX_FILENAME_BYTES) {
                nameLen = MAX_FILENAME_BYTES;
            }
            p.origName = new String(plain, ORIGNAME_OFFSET, nameLen, StandardCharsets.UTF_8);
            int flagsOff = ORIGNAME_OFFSET + nameLen;
            byte[] flagBytes = Arrays.copyOfRange(plain, flagsOff, flagsOff + 6);
            p.flags = Flags.fromBytes(flagBytes);
            // 读取 canary 令牌（固定在距末尾 16 字节处）
            p.canary = Arrays.copyOfRange(plain, CANARY_OFFSET, CANARY_OFFSET + 16);
            return p;
        }

        /**
         * 计算编码后的数据区域大小（含 RS 编码膨胀）。
         *
         * @param reedSolomon 是否启用 RS 编码
         * @return 文件占用的字节数
         */
        long encodedSize(boolean reedSolomon) {
            if (!reedSolomon || dataLength == 0) {
                return dataLength;
            }
            // 与 encodeWithRS 行为一致：
            // 每 1 MiB 完整块 → 8192 × 136 字节（无填充）
            // 最后不足 1 MiB 的剩余 → (fullBlocks + 1) × 136（始终追加一个填充块）
            long fullMiB = dataLength / CryptoConstants.MIB;
            long fullEncoded = fullMiB * (CryptoConstants.MIB / Padding.BLOCK_SIZE * 136);
            long remaining = dataLength - fullMiB * CryptoConstants.MIB;
            if (remaining > 0 || dataLength < CryptoConstants.MIB) {
                long remainingFullBlocks = remaining / Padding.BLOCK_SIZE;
                long remainingEncoded = (remainingFullBlocks + 1) * 136;
                return fullEncoded + remainingEncoded;
            }
            return fullEncoded;
        }

        /**
         * 序列化为 MetaBlock 明文（512 字节）。
         * keyHash 位置写入全零占位，authTag 位置写入全零占位。
         */
        byte[] serialize() {
            byte[] plain = new byte[METABLOCK_PLAIN_SIZE];
            // keyHash（由 writeEncrypted 在序列化后覆盖写入）
            System.arraycopy(keyHash, 0, plain, KEYHASH_OFFSET, KEYHASH_SIZE);
            // salt
            System.arraycopy(salt, 0, plain, SALT_OFFSET, SALT_SIZE);
            // hkdfSalt
            System.arraycopy(hkdfSalt, 0, plain, HKDFSALT_OFFSET, HKDFSALT_SIZE);
            // serpentIV
            System.arraycopy(serpentIV, 0, plain, SERPENTIV_OFFSET, SERPENTIV_SIZE);
            // nonce
            System.arraycopy(nonce, 0, plain, NONCE_OFFSET, NONCE_SIZE);
            // authTag（由 encryptToFile 在序列化前填入）
            System.arraycopy(authTag, 0, plain, AUTHTAG_OFFSET, AUTHTAG_SIZE);
            // dataOffset (8 bytes LE)
            ByteBuffer.wrap(plain, DATAOFFSET_OFFSET, 8).order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(dataOffset);
            // dataLength (8 bytes LE)
            ByteBuffer.wrap(plain, DATALENGTH_OFFSET, 8).order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(dataLength);
            // origNameLen (2 bytes LE)
            byte[] nameBytes = origName.getBytes(StandardCharsets.UTF_8);
            int nameLen = Math.min(nameBytes.length, MAX_FILENAME_BYTES);
            ByteBuffer.wrap(plain, ORIGNAMELEN_OFFSET, 2).order(ByteOrder.LITTLE_ENDIAN)
                    .putShort((short) nameLen);
            // origName
            System.arraycopy(nameBytes, 0, plain, ORIGNAME_OFFSET, nameLen);
            // flags (6 bytes，含 dualDeniable)
            int flagsOff = ORIGNAME_OFFSET + nameLen;
            byte[] flagBytes = flags.toBytesExtended();
            System.arraycopy(flagBytes, 0, plain, flagsOff, flagBytes.length);
            // 其余为随机填充（跳过 canary 位置）
            int padStart = flagsOff + flagBytes.length;
            if (padStart < CANARY_OFFSET) {
                byte[] pad = RandomBytes.generate(CANARY_OFFSET - padStart);
                System.arraycopy(pad, 0, plain, padStart, pad.length);
            }
            // canary 令牌（16 字节，固定在距末尾 16 字节处）
            if (canary != null && canary.length == 16) {
                System.arraycopy(canary, 0, plain, CANARY_OFFSET, 16);
            }
            return plain;
        }
    }

    /**
     * MetaBlock 的加解密与验证逻辑。
     */
    static final class MetaBlock {

        private MetaBlock() {
        }

        /**
         * 加密参数并写入输出流。
         *
         * @param out      输出流（定位在 MetaBlock 起始位置）
         * @param params   密码学参数
         * @param pwBytes  密码 UTF-8 字节
         * @param paranoid 偏执模式
         * @throws Exception 密码学错误
         */
        static void writeEncrypted(OutputStream out, MetaBlockParams params,
                                   byte[] pwBytes) throws Exception {
            // 生成 MetaBlock 的 salt + nonce
            byte[] mbSalt = RandomBytes.generate(METABLOCK_SALT_SIZE);
            byte[] mbNonce = RandomBytes.generate(METABLOCK_NONCE_SIZE);

            // 生成金丝雀令牌（由 mbSalt 派生，每个 MetaBlock 不同）
            params.canary = hbnu.project.ergoutreecrypt.crypto.CanaryToken.generate(mbSalt);

            // 派生 MetaBlock 加密密钥（独立于数据区密钥）
            byte[] mbKey = Argon2Kdf.deriveKey(pwBytes, mbSalt, false);
            try {
                // 序列化明文（keyHash 和 authTag 为零占位，canary 已设置）
                byte[] plain = params.serialize();

                // 计算并写入 keyHash（HMAC-SHA3-512 覆盖 canary 在内的所有字段）
                byte[] computedKeyHash = computeKeyHash(mbKey, params);
                System.arraycopy(computedKeyHash, 0, plain, KEYHASH_OFFSET, KEYHASH_SIZE);
                params.keyHash = computedKeyHash;

                // XChaCha20 加密
                byte[] ciphertext = new byte[METABLOCK_PLAIN_SIZE];
                xChaCha20Xor(mbKey, mbNonce, ciphertext, plain, METABLOCK_PLAIN_SIZE);

                // 写入：salt + nonce + ciphertext
                out.write(mbSalt);
                out.write(mbNonce);
                out.write(ciphertext);
            } finally {
                SecureZero.zero(mbKey);
            }
        }

        /**
         * 尝试用密码解密 MetaBlock 并验证 keyHash。
         *
         * @param encrypted 完整的 MetaBlock 密文（552 字节）
         * @param pwBytes   密码 UTF-8 字节
         * @param paranoid  偏执模式（用于验证 flags 中的 paranoid 标志匹配）
         * @return 解密并验证通过则返回 MetaBlockParams，否则返回 null
         */
        static MetaBlockParams tryDecryptAndVerify(byte[] encrypted, byte[] pwBytes,
                                                   boolean paranoid) {
            // 解析：salt(16) + nonce(24) + ciphertext(512)
            byte[] mbSalt = Arrays.copyOfRange(encrypted, 0, METABLOCK_SALT_SIZE);
            byte[] mbNonce = Arrays.copyOfRange(encrypted, METABLOCK_SALT_SIZE,
                    METABLOCK_SALT_SIZE + METABLOCK_NONCE_SIZE);
            byte[] ciphertext = Arrays.copyOfRange(encrypted,
                    METABLOCK_SALT_SIZE + METABLOCK_NONCE_SIZE, encrypted.length);

            byte[] mbKey = Argon2Kdf.deriveKey(pwBytes, mbSalt, false);
            try {
                // XChaCha20 解密
                byte[] plain = new byte[METABLOCK_PLAIN_SIZE];
                xChaCha20Xor(mbKey, mbNonce, plain, ciphertext, METABLOCK_PLAIN_SIZE);

                // 反序列化
                MetaBlockParams params = MetaBlockParams.deserialize(plain);

                // 验证 keyHash
                byte[] computed = computeKeyHash(mbKey, params);
                if (!HeaderAuth.constantTimeEqual(computed, params.keyHash)) {
                    return null;
                }
                return params;
            } finally {
                SecureZero.zero(mbKey);
            }
        }

        /**
         * 计算 MetaBlock 的 keyHash。
         *
         * <p>HMAC-SHA3-512(mbKey, salt || hkdfSalt || serpentIV || nonce || authTag ||
         * dataOffset || dataLength || origNameLen || origName || flags)
         *
         * @param mbKey  MetaBlock 加密密钥（32 字节）
         * @param params 密码学参数（keyHash 字段被忽略）
         * @return 64 字节 HMAC-SHA3-512
         */
        static byte[] computeKeyHash(byte[] mbKey, MetaBlockParams params) {
            HMac hmac = new HMac(new SHA3Digest(512));
            hmac.init(new KeyParameter(mbKey));

            hmac.update(params.salt, 0, params.salt.length);
            hmac.update(params.hkdfSalt, 0, params.hkdfSalt.length);
            hmac.update(params.serpentIV, 0, params.serpentIV.length);
            hmac.update(params.nonce, 0, params.nonce.length);
            hmac.update(params.authTag, 0, params.authTag.length);

            byte[] tmp8 = new byte[8];
            ByteBuffer.wrap(tmp8).order(ByteOrder.LITTLE_ENDIAN).putLong(params.dataOffset);
            hmac.update(tmp8, 0, 8);
            ByteBuffer.wrap(tmp8).order(ByteOrder.LITTLE_ENDIAN).putLong(params.dataLength);
            hmac.update(tmp8, 0, 8);

            byte[] nameBytes = params.origName.getBytes(StandardCharsets.UTF_8);
            int nameLen = Math.min(nameBytes.length, MAX_FILENAME_BYTES);
            byte[] tmp2 = new byte[2];
            ByteBuffer.wrap(tmp2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) nameLen);
            hmac.update(tmp2, 0, 2);
            if (nameLen > 0) {
                hmac.update(nameBytes, 0, nameLen);
            }

            byte[] flagBytes = params.flags.toBytesExtended();
            hmac.update(flagBytes, 0, flagBytes.length);

            // 金丝雀令牌（16 字节）
            if (params.canary != null && params.canary.length == 16) {
                hmac.update(params.canary, 0, 16);
            }

            byte[] out = new byte[hmac.getMacSize()];
            hmac.doFinal(out, 0);
            return out;
        }
    }

    /**
     * 单个数据区域的加密与解密逻辑。
     *
     * <p>复用标准流水线：XChaCha20(+Serpent) + MAC + 可选 RS 编码。
     */
    static final class DataRegion {

        private DataRegion() {
        }

        /**
         * 加密文件并写入临时文件，同时将 authTag 填入 params。
         *
         * @param inputFile     输入文件路径
         * @param outputFile    加密后的输出文件路径（临时文件）
         * @param params        密码学参数（authTag 在加密后填入）
         * @param password      密码
         * @param paranoid      偏执模式
         * @param reedSolomon   RS 纠错
         * @param rs            RS 编解码器
         * @param reporter      进度回调（可为 null）
         * @param progressStart 进度起始比例 [0, 1]
         * @param progressEnd   进度结束比例 [0, 1]
         * @param totalPayload  两区明文总大小（用于进度计算）
         * @throws Exception 密码学或 I/O 错误
         */
        static void encryptToFile(String inputFile, Path outputFile, MetaBlockParams params,
                                  String password, boolean paranoid, boolean reedSolomon,
                                  RsCodecs rs, ProgressReporter reporter,
                                  float progressStart, float progressEnd, long totalPayload)
                throws Exception {
            byte[] pwBytes = PasswordNormalizer.encodeForKdf(password);
            byte[] key = Argon2Kdf.deriveKey(pwBytes, params.salt, paranoid);
            SecureZero.zero(pwBytes);

            try {
                HkdfStream hkdf = new HkdfStream(key, params.hkdfSalt);
                SubkeyReader subkeyReader = new SubkeyReader(hkdf);
                byte[] headerSk = subkeyReader.headerSubkey();
                byte[] macSubkey = subkeyReader.macSubkey();
                byte[] serpentKey = subkeyReader.serpentKey();

                Mac mac = MacFactory.create(macSubkey, paranoid);
                CipherSuiteAdapter cs = new CipherSuiteAdapter(key, params.nonce,
                        serpentKey, params.serpentIV, mac, hkdf, paranoid);

                try (InputStream fin = Files.newInputStream(Path.of(inputFile));
                     OutputStream fout = Files.newOutputStream(outputFile)) {
                    byte[] src = new byte[CryptoConstants.MIB];
                    byte[] dst = new byte[CryptoConstants.MIB];
                    long done = 0;
                    long counter = 0;

                    while (true) {
                        int n = readFull(fin, src);
                        if (n <= 0) {
                            break;
                        }

                        cs.encrypt(dst, src, n);

                        if (reedSolomon) {
                            byte[] encoded = encodeWithRS(dst, n, rs);
                            fout.write(encoded);
                        } else {
                            fout.write(dst, 0, n);
                        }

                        done += n;
                        counter += CryptoConstants.MIB;

                        if (reporter != null && totalPayload > 0) {
                            float frac = (float) done / totalPayload;
                            float progress = progressStart + frac * (progressEnd - progressStart);
                            reporter.setProgress(Math.min(progress, progressEnd), "");
                        }

                        if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                            cs.rekey();
                            counter = 0;
                        }
                    }
                }

                // 现在 authTag 已知，填入 params
                byte[] authTag = cs.sum();
                System.arraycopy(authTag, 0, params.authTag, 0, AUTHTAG_SIZE);

                SecureZero.zero(macSubkey);
                SecureZero.zero(serpentKey);
                SecureZero.zero(headerSk);
                cs.close();
            } finally {
                SecureZero.zero(key);
            }
        }

        /**
         * 从文件中解密数据区域并写入输出文件。
         *
         * @param inputFile     EGTD 容器文件路径
         * @param params        密码学参数
         * @param passwordBytes 密码 UTF-8 字节
         * @param paranoid      偏执模式
         * @param forceDecrypt  强制解密（忽略 MAC 失败）
         * @param rs            RS 编解码器
         * @param reporter      进度回调
         * @param outputFile    输出文件路径
         * @throws Exception 密码学或 I/O 错误
         */
        static void decryptFrom(String inputFile, MetaBlockParams params, byte[] passwordBytes,
                                boolean paranoid, boolean forceDecrypt, RsCodecs rs,
                                ProgressReporter reporter, String outputFile) throws Exception {
            boolean reedSolomon = params.flags.isReedSolomon();
            byte[] key = Argon2Kdf.deriveKey(passwordBytes, params.salt, paranoid);

            try {
                HkdfStream hkdf = new HkdfStream(key, params.hkdfSalt);
                SubkeyReader subkeyReader = new SubkeyReader(hkdf);
                byte[] headerSk = subkeyReader.headerSubkey();
                byte[] macSubkey = subkeyReader.macSubkey();
                byte[] serpentKey = subkeyReader.serpentKey();

                Mac mac = MacFactory.create(macSubkey, paranoid);
                CipherSuiteAdapter cs = new CipherSuiteAdapter(key, params.nonce,
                        serpentKey, params.serpentIV, mac, hkdf, paranoid);

                long dataOffset = params.dataOffset;
                long encodedLen = params.encodedSize(reedSolomon);

                String incomplete = outputFile + ".incomplete";
                try (FileChannel ch = FileChannel.open(Path.of(inputFile), StandardOpenOption.READ);
                     OutputStream fout = Files.newOutputStream(Path.of(incomplete))) {

                    ch.position(dataOffset);

                    int bufSize = reedSolomon
                            ? CryptoConstants.MIB / Padding.BLOCK_SIZE * 136
                            : CryptoConstants.MIB;
                    byte[] src = new byte[bufSize];
                    byte[] dst = new byte[CryptoConstants.MIB];
                    long done = 0;
                    long counter = 0;

                    InputStream chIn = java.nio.channels.Channels.newInputStream(ch);

                    while (done < encodedLen) {
                        int maxRead = (int) Math.min(bufSize, encodedLen - done);
                        int n = readFull(chIn, src, maxRead);
                        if (n <= 0) {
                            break;
                        }

                        if (reedSolomon) {
                            boolean isLast = done + n >= encodedLen;
                            byte[] decoded = decodeWithRSFast(src, n, rs, isLast,
                                    params.flags.isPadded(), forceDecrypt, true);
                            cs.decrypt(dst, decoded, decoded.length);
                            fout.write(dst, 0, decoded.length);
                        } else {
                            cs.decrypt(dst, src, n);
                            fout.write(dst, 0, n);
                        }

                        done += n;
                        counter += CryptoConstants.MIB;

                        if (reporter != null && params.dataLength > 0) {
                            reporter.setProgress((float) done / encodedLen, "");
                        }

                        if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                            cs.rekey();
                            counter = 0;
                        }
                    }
                }

                // MAC 校验
                byte[] computedMac = cs.sum();
                boolean macOk = HeaderAuth.constantTimeEqual(computedMac, params.authTag);

                if (!macOk && !forceDecrypt) {
                    Files.deleteIfExists(Path.of(incomplete));
                    cs.close();
                    SecureZero.zero(key);
                    SecureZero.zero(macSubkey);
                    SecureZero.zero(serpentKey);
                    SecureZero.zero(headerSk);
                    throw new IOException("MAC verification failed — file may be corrupted or tampered");
                }

                cs.close();
                SecureZero.zero(macSubkey);
                SecureZero.zero(serpentKey);
                SecureZero.zero(headerSk);

                // 原子重命名
                Files.move(Path.of(incomplete), Path.of(outputFile),
                        StandardCopyOption.REPLACE_EXISTING);
            } finally {
                SecureZero.zero(key);
            }
        }
    }

    /**
     * 简化版 CipherSuite，用于 MetaBlock/DataRegion 的 XChaCha20(+Serpent) 加密。
     *
     * <p>不依赖完整的 CipherSuite 类，保持 MetaBlock 逻辑自包含。
     * 处理顺序：加密 [Serpent] → XChaCha20 → MAC；解密 MAC → XChaCha20 → [Serpent]。
     */
    private static final class CipherSuiteAdapter {

        /**
         * 载荷 MAC。
         */
        private final Mac mac;

        /**
         * HKDF 字节流，rekey 时读取新 nonce/IV。
         */
        private final HkdfStream hkdf;

        /**
         * 是否启用 Serpent 叠加层。
         */
        private final boolean paranoid;

        /**
         * XChaCha20 主密钥。
         */
        private final byte[] key;

        /**
         * Serpent 密钥。
         */
        private final byte[] serpentKey;

        /**
         * 当前 XChaCha20 流密码。
         */
        private ChaChaState chacha;

        /**
         * 当前 Serpent-CTR 流密码。
         */
        private hbnu.project.ergoutreecrypt.crypto.SerpentCtr serpent;

        /**
         * 临时缓冲区。
         */
        private byte[] scratch;

        /**
         * 初始化适配器。
         */
        CipherSuiteAdapter(byte[] key, byte[] nonce, byte[] serpentKey, byte[] serpentIV,
                           Mac mac, HkdfStream hkdf, boolean paranoid) {
            this.key = key.clone();
            this.serpentKey = serpentKey != null ? serpentKey.clone() : null;
            this.mac = mac;
            this.hkdf = hkdf;
            this.paranoid = paranoid;

            this.chacha = new ChaChaState(key, nonce);
            if (paranoid) {
                this.serpent = new hbnu.project.ergoutreecrypt.crypto.SerpentCtr(
                        this.serpentKey, serpentIV);
                this.scratch = new byte[CryptoConstants.MIB];
            }
        }

        /**
         * 加密一块数据：[Serpent] → XChaCha20 → MAC(密文)。
         */
        void encrypt(byte[] dst, byte[] src, int len) {
            if (paranoid) {
                serpent.process(dst, src, len);
                System.arraycopy(dst, 0, scratch, 0, len);
                chacha.xor(dst, scratch, len);
            } else {
                chacha.xor(dst, src, len);
            }
            mac.update(dst, len);
        }

        /**
         * 解密一块数据：MAC(密文) → XChaCha20 → [Serpent]。
         */
        void decrypt(byte[] dst, byte[] src, int len) {
            mac.update(src, len);
            chacha.xor(dst, src, len);
            if (paranoid) {
                System.arraycopy(dst, 0, scratch, 0, len);
                serpent.process(dst, scratch, len);
            }
        }

        /**
         * Rekey：从 HKDF 流读取新 nonce（24B），偏执模式下还读取新 IV（16B）。
         */
        void rekey() {
            byte[] newNonce = hkdf.read(CryptoConstants.REKEY_NONCE_SIZE);
            chacha = new ChaChaState(key, newNonce);
            if (paranoid) {
                byte[] newIv = hkdf.read(CryptoConstants.REKEY_IV_SIZE);
                serpent = new hbnu.project.ergoutreecrypt.crypto.SerpentCtr(serpentKey, newIv);
            }
        }

        /**
         * 产出最终 MAC 认证标签。
         */
        byte[] sum() {
            return mac.doFinal();
        }

        /**
         * 安全清零。
         */
        void close() {
            SecureZero.zero(key);
            SecureZero.zero(serpentKey);
            SecureZero.zero(scratch);
            if (mac != null) {
                mac.close();
            }
            chacha = null;
            serpent = null;
        }
    }

    /**
     * ChaCha20-IETF（RFC 7539）keystream 包装器。
     *
     * <p>使用 XChaCha20 的 HChaCha20 子密钥派生，支持 24 字节 nonce。
     */
    private static final class ChaChaState {

        /**
         * 底层 ChaCha20(RFC 7539) 引擎。
         */
        private final ChaCha7539Engine engine;

        /**
         * @param key     32 字节密钥
         * @param nonce24 24 字节 nonce
         */
        ChaChaState(byte[] key, byte[] nonce24) {
            byte[] subKey = XChaCha20.hChaCha20(key, nonce24);
            this.engine = new ChaCha7539Engine();
            byte[] nonce12 = new byte[12];
            System.arraycopy(nonce24, 16, nonce12, 4, 8);
            this.engine.init(true, new ParametersWithIV(new KeyParameter(subKey), nonce12));
        }

        /**
         * XOR keystream 到目标数组。
         */
        void xor(byte[] dst, byte[] src, int len) {
            engine.processBytes(src, 0, len, dst, 0);
        }
    }
}
