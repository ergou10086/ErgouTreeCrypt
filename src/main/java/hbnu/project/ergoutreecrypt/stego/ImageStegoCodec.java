package hbnu.project.ergoutreecrypt.stego;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.XChaCha20;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * LSB 图像隐写统一入口（容量限制型）。
 *
 * <p>集成"先加密后嵌入"的完整流程：
 * 文件内容 → Argon2id → HKDF 派生 encKey/macKey → XChaCha20 流加密 → LSB 嵌入 PNG 像素。
 * 提取为逆过程。复用 {@code crypto} 层原语，零新密码学依赖。
 *
 * <p><b>容量限制</b>：可隐藏的数据量受限于图像像素数 × 通道数 × LSB 深度。
 * 大文件需要足够大的图像或更高的 LSB 深度。
 * 未来计划实现<b>无限制型隐写</b>（不依赖像素容量的方案），本类将作为"容量限制型"保留。
 *
 * @author ErgouTree
 */
public final class ImageStegoCodec {

    /**
     * 加密子密钥长度（XChaCha20 key = 32 字节）。
     */
    private static final int ENC_KEY_LEN = 32;

    /**
     * MAC 子密钥长度（BLAKE2b-512 key = 32 字节）。
     */
    private static final int MAC_KEY_LEN = 32;

    /**
     * 默认的提取试探头大小（103 基础 + 256 文件名 + 64 MAC = 423）。
     */
    private static final int DEFAULT_EXTRACT_HEADER_ESTIMATE = 103 + 256 + 64;

    /**
     * 无密码时使用的固定密码短语。
     */
    private static final byte[] DEFAULT_PASSWORD =
            "ErgouTree-stego-default-passphrase".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    /**
     * 将文件隐藏嵌入到 PNG 图像中。
     *
     * @param imageFile  原始 PNG 图像
     * @param secretFile 待隐藏的任意文件
     * @param output     输出隐写 PNG 文件
     * @param password   密码 UTF-8 字节（可为空，表示无密码模式）
     * @param options    隐写选项
     * @throws IOException         文件读写失败
     * @throws ImageStegoException 格式不支持或容量不足
     */
    public void hide(final Path imageFile, final Path secretFile, final Path output,
                      final byte[] password, final StegoOptions options)
            throws IOException, ImageStegoException {
        byte[] plaintext = Files.readAllBytes(secretFile);
        String fileName = secretFile.getFileName().toString();

        // 生成随机值
        byte[] salt = RandomBytes.generate(16);
        byte[] hkdfSalt = RandomBytes.generate(32);
        byte[] nonce = RandomBytes.generate(24);

        // 密钥派生
        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;
        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, salt, options.isParanoid());
        byte[] ciphertext;
        byte[] payloadMac = null;

        HkdfStream hkdf = null;
        try {
            hkdf = new HkdfStream(masterKey, hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);

            // 加密
            ciphertext = encrypt(encKey, nonce, plaintext);

            // 可选：原文 MAC
            if (options.isStoreMac()) {
                payloadMac = computePayloadMac(macKey, plaintext);
            }

            SecureZero.zeroAll(encKey, macKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        // 构建元数据头
        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(options.lsbDepth())
                .hasMac(options.isStoreMac())
                .paranoid(options.isParanoid())
                .channels(3)
                .payloadSize(plaintext.length)
                .fileName(fileName)
                .salt(salt)
                .hkdfSalt(hkdfSalt)
                .nonce(nonce)
                .payloadMac(payloadMac)
                .build();
        byte[] header = meta.toBytes();

        try {
            // 嵌入
            PngLsbStego.embed(imageFile, output, header, ciphertext, options.lsbDepth());
        } finally {
            SecureZero.zero(ciphertext);
        }
    }

    /**
     * 从隐写 PNG 图像中提取隐藏的文件。
     *
     * @param stegoImage 隐写 PNG 文件
     * @param outputDir  提取文件的输出目录
     * @param password   密码 UTF-8 字节
     * @return 提取出的文件路径
     * @throws IOException         文件读写失败
     * @throws ImageStegoException 未检测到隐写数据或密码错误
     */
    public Path extract(final Path stegoImage, final Path outputDir,
                         final byte[] password) throws IOException, ImageStegoException {
        // 因为不知道 lsbDepth（需要从 header 中读取），而 header 本身也是按 unknown lsbDepth 嵌入的，
        // 我们需要尝试所有可能的 lsbDepth 值，直到解析出合法魔数。
        PngLsbStego.ExtractResult extracted = null;
        StegoMetadata meta = null;
        int foundLsbDepth = 1;
        ImageStegoException lastError = null;
        for (int tryDepth = 1; tryDepth <= 4; tryDepth++) {
            try {
                extracted = PngLsbStego.extract(
                        stegoImage, DEFAULT_EXTRACT_HEADER_ESTIMATE, tryDepth);
                meta = extracted.metadata();
                foundLsbDepth = tryDepth;
                lastError = null;
                break;
            } catch (ImageStegoException e) {
                lastError = e;
            }
        }
        if (lastError != null) {
            throw lastError;
        }
        int lsbDepth = meta.lsbDepth();

        // 用实际的头大小重新提取（第一次提取时的预期头大小只是近似值）
        int exactHeaderSize = StegoMetadata.headerSize(meta.fileName(), meta.hasMac());
        extracted = PngLsbStego.extract(stegoImage, exactHeaderSize, lsbDepth);
        meta = extracted.metadata();

        // 密钥派生
        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;
        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, meta.salt(), meta.isParanoid());
        byte[] plaintext;

        HkdfStream hkdf = null;
        try {
            hkdf = new HkdfStream(masterKey, meta.hkdfSalt());
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);

            // 解密
            plaintext = decrypt(encKey, meta.nonce(), extracted.encryptedPayload());

            // 可选：验证 MAC
            if (meta.hasMac() && meta.payloadMac() != null) {
                byte[] computedMac = computePayloadMac(macKey, plaintext);
                if (!constantTimeEquals(computedMac, meta.payloadMac())) {
                    SecureZero.zero(plaintext);
                    throw new ImageStegoException("完整性校验失败——密码错误或数据被篡改");
                }
            }

            SecureZero.zeroAll(encKey, macKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        // 写出文件
        Path outputFile = outputDir.resolve(meta.fileName());
        Files.write(outputFile, plaintext);
        return outputFile;
    }

    /**
     * 检测图像是否含有本工具的隐写数据。
     *
     * @param imageFile 图像文件路径
     * @return true 若检测到本工具的隐写魔数
     */
    public boolean isStegoImage(final Path imageFile) {
        try {
            PngLsbStego.extract(imageFile, StegoMetadata.MAGIC.length, 1);
            return true;
        } catch (Exception e) {
            // 对调色板 PNG 的异常（不是隐写图像的正常情况）
            if (e.getMessage() != null && e.getMessage().contains("调色板")) {
                return false;
            }
            return false;
        }
    }

    /**
     * 计算给定图像和选项下可隐藏的最大文件字节数。
     *
     * @param imageFile PNG 图像文件
     * @param options   隐写选项
     * @param fileName  待隐藏的文件名
     * @return 可用容量（字节）
     */
    public long availableCapacity(final Path imageFile, final StegoOptions options,
                                   final String fileName) throws IOException, ImageStegoException {
        java.awt.image.BufferedImage img = javax.imageio.ImageIO.read(imageFile.toFile());
        if (img == null) {
            throw new ImageStegoException("无法读取图像");
        }
        int channels = 3;
        int hs = StegoMetadata.headerSize(fileName, options.isStoreMac());
        return StegoCapacity.availableBytes(img.getWidth(), img.getHeight(),
                channels, options.lsbDepth(), hs);
    }

    // ---- Chunk 结构隐写（无容量限制）----

    /**
     * Chunk 结构隐写：将加密后的文件追加到 PNG 的 IEND 块之后。
     *
     * <p>与 LSB 像素隐写不同，此方法不修改任何像素数据——图片显示与原图完全一致，
     * 且可嵌入的数据量不受像素尺寸限制。
     */
    public void hideChunk(final Path imageFile, final Path secretFile, final Path output,
                           final byte[] password, final StegoOptions options)
            throws IOException, ImageStegoException {
        byte[] plaintext = Files.readAllBytes(secretFile);
        String fileName = secretFile.getFileName().toString();

        byte[] salt = RandomBytes.generate(16);
        byte[] hkdfSalt = RandomBytes.generate(32);
        byte[] nonce = RandomBytes.generate(24);

        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;
        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, salt, options.isParanoid());
        byte[] ciphertext;
        byte[] payloadMac = null;

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);

            ciphertext = encrypt(encKey, nonce, plaintext);

            if (options.isStoreMac()) {
                payloadMac = computePayloadMac(macKey, plaintext);
            }
            SecureZero.zeroAll(encKey, macKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        byte flags = 0;
        if (options.isParanoid()) flags |= 1;
        if (options.isStoreMac()) flags |= 2;

        ChunkTrailer trailer = new ChunkTrailer(
                ciphertext.length, fileName, salt, hkdfSalt, nonce, flags, payloadMac);

        try {
            PngChunkStego.embed(imageFile, output, ciphertext, trailer);
        } finally {
            SecureZero.zero(ciphertext);
        }
    }

    /**
     * Chunk 结构提取：从 PNG 文件末尾提取隐藏的文件。
     */
    public Path extractChunk(final Path stegoImage, final Path outputDir,
                              final byte[] password) throws IOException, ImageStegoException {
        PngChunkStego.ChunkExtractResult result = PngChunkStego.extract(stegoImage);
        ChunkTrailer trailer = result.trailer();

        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;
        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, trailer.salt, trailer.isParanoid());
        byte[] plaintext;

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, trailer.hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);

            plaintext = decrypt(encKey, trailer.nonce, result.encryptedPayload());

            if (trailer.hasMac() && trailer.payloadMac != null) {
                byte[] computedMac = computePayloadMac(macKey, plaintext);
                if (!constantTimeEquals(computedMac, trailer.payloadMac)) {
                    SecureZero.zero(plaintext);
                    throw new ImageStegoException("完整性校验失败——密码错误或数据被篡改");
                }
            }
            SecureZero.zeroAll(encKey, macKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        Path outputFile = outputDir.resolve(trailer.fileName);
        Files.write(outputFile, plaintext);
        return outputFile;
    }

    /**
     * 检测图像是否含有 Chunk 隐写数据。
     */
    public boolean isChunkStegoImage(final Path imageFile) throws IOException {
        return PngChunkStego.isChunkStego(imageFile);
    }

    // ---- 内部工具方法 ----

    /**
     * 流加密（XChaCha20 XOR）。
     */
    private static byte[] encrypt(final byte[] key, final byte[] nonce, final byte[] plaintext) {
        XChaCha20 cipher = new XChaCha20(key, nonce);
        byte[] out = new byte[plaintext.length];
        cipher.process(out, plaintext, plaintext.length);
        return out;
    }

    /**
     * 流解密（XChaCha20 XOR 自反）。
     */
    private static byte[] decrypt(final byte[] key, final byte[] nonce, final byte[] ciphertext) {
        return encrypt(key, nonce, ciphertext);
    }

    /**
     * 计算原文 BLAKE2b-512 MAC。
     */
    private static byte[] computePayloadMac(final byte[] macKey, final byte[] data) {
        Mac mac = MacFactory.create(macKey, false);
        mac.update(data, data.length);
        byte[] tag = mac.doFinal();
        return tag;
    }

    /**
     * 常量时间比较两个字节数组。
     */
    private static boolean constantTimeEquals(final byte[] a, final byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
