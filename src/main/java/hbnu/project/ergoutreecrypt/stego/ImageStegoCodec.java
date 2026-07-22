package hbnu.project.ergoutreecrypt.stego;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.SerpentCtr;
import hbnu.project.ergoutreecrypt.crypto.XChaCha20;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

/**
 * 图像隐写统一入口（LSB 像素 + Chunk 结构）。
 *
 * <p>集成"先加密后嵌入"的完整流程，支持：
 * <ul>
 *   <li>Paranoid 模式：Serpent-CTR → XChaCha20 双层加密</li>
 *   <li>隐蔽模式：HMAC 派生魔数，避免固定魔数字符串检测</li>
 *   <li>文件大小混淆：追加随机填充到用户指定大小</li>
 *   <li>防暴力破解：BruteForceGuard 限速提取尝试</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class ImageStegoCodec {

    private static final int ENC_KEY_LEN = 32;
    private static final int MAC_KEY_LEN = 32;
    private static final int SERPENT_KEY_LEN = 32;
    private static final int SERPENT_IV_LEN = 16;

    private static final int DEFAULT_EXTRACT_HEADER_ESTIMATE = 103 + 256 + 64 + 32;

    private static final byte[] DEFAULT_PASSWORD =
            "ErgouTree-stego-default-passphrase".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // ---- LSB 隐藏 ----

    /**
     * 将文件隐藏嵌入到 PNG 图像中（LSB 像素域）。
     */
    public void hide(final Path imageFile, final Path secretFile, final Path output,
                      final byte[] password, final StegoOptions options)
            throws IOException, ImageStegoException {
        byte[] plaintext = Files.readAllBytes(secretFile);
        String fileName = secretFile.getFileName().toString();

        byte[] salt = RandomBytes.generate(16);
        byte[] hkdfSalt = RandomBytes.generate(32);
        byte[] nonce = RandomBytes.generate(24);
        byte[] serpentIv = options.isParanoid() ? RandomBytes.generate(SERPENT_IV_LEN) : null;
        byte[] stealthSalt = options.isStealth() ? RandomBytes.generate(StegoMetadata.STEALTH_SALT_LEN) : null;

        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;
        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, salt, options.isParanoid());
        byte[] ciphertext;
        byte[] payloadMac = null;

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);
            byte[] serpentKey = options.isParanoid() ? hkdf.read(SERPENT_KEY_LEN) : null;

            ciphertext = encryptPayload(encKey, nonce, serpentKey, serpentIv, plaintext);

            if (options.isStoreMac()) {
                payloadMac = computePayloadMac(macKey, plaintext);
            }
            SecureZero.zeroAll(encKey, macKey, serpentKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(options.lsbDepth())
                .hasMac(options.isStoreMac())
                .paranoid(options.isParanoid())
                .stealth(options.isStealth())
                .channels(3)
                .payloadSize(plaintext.length)
                .fileName(fileName)
                .salt(salt)
                .hkdfSalt(hkdfSalt)
                .nonce(nonce)
                .serpentIv(serpentIv)
                .payloadMac(payloadMac)
                .build();

        byte[] stealthMagic = null;
        if (options.isStealth()) {
            stealthMagic = StegoMetadata.deriveStealthMagic(stealthSalt, effectivePwd);
        }
        byte[] header = meta.toBytes(stealthSalt, stealthMagic);

        try {
            PngLsbStego.embed(imageFile, output, header, ciphertext, options.lsbDepth());
        } finally {
            SecureZero.zero(ciphertext);
        }

        // 文件大小混淆
        if (options.isObfuscateSize() && options.targetSizeBytes() > 0) {
            padToSize(output, options.targetSizeBytes());
        }
    }

    // ---- LSB 提取 ----

    /**
     * 从隐写 PNG 图像中提取隐藏的文件（LSB 像素域）。
     */
    public Path extract(final Path stegoImage, final Path outputDir,
                         final byte[] password) throws IOException, ImageStegoException {
        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;

        // BruteForceGuard 检查
        BruteForceGuard guard = BruteForceGuard.getInstance();
        String filePath = stegoImage.toAbsolutePath().toString();
        if (!guard.allowAttempt(filePath)) {
            throw new ImageStegoException(
                    "解密尝试次数过多（" + guard.getMaxAttempts()
                    + " 次），请稍后再试或确认密码是否正确");
        }

        // 尝试所有 LSB 深度
        PngLsbStego.ExtractResult extracted = null;
        StegoMetadata meta = null;
        int foundLsbDepth = 1;
        ImageStegoException lastError = null;
        for (int tryDepth = 1; tryDepth <= 4; tryDepth++) {
            try {
                extracted = PngLsbStego.extract(
                        stegoImage, DEFAULT_EXTRACT_HEADER_ESTIMATE, tryDepth, effectivePwd);
                meta = extracted.metadata();
                foundLsbDepth = tryDepth;
                lastError = null;
                break;
            } catch (ImageStegoException e) {
                lastError = e;
            }
        }
        if (lastError != null) {
            guard.recordFailure(filePath);
            throw lastError;
        }

        int lsbDepth = meta.lsbDepth();
        int exactHeaderSize = StegoMetadata.headerSize(
                meta.fileName(), meta.hasMac(), meta.isParanoid(), meta.isStealth());
        extracted = PngLsbStego.extract(stegoImage, exactHeaderSize, lsbDepth, effectivePwd);
        meta = extracted.metadata();

        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, meta.salt(), meta.isParanoid());
        byte[] plaintext;

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, meta.hkdfSalt());
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);
            byte[] serpentKey = meta.isParanoid() ? hkdf.read(SERPENT_KEY_LEN) : null;

            plaintext = decryptPayload(encKey, meta.nonce(), serpentKey, meta.serpentIv(),
                    extracted.encryptedPayload());

            if (meta.hasMac() && meta.payloadMac() != null) {
                byte[] computedMac = computePayloadMac(macKey, plaintext);
                if (!constantTimeEquals(computedMac, meta.payloadMac())) {
                    SecureZero.zero(plaintext);
                    guard.recordFailure(filePath);
                    throw new ImageStegoException("完整性校验失败——密码错误或数据被篡改");
                }
            }
            SecureZero.zeroAll(encKey, macKey, serpentKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        guard.recordSuccess(filePath);
        Path outputFile = outputDir.resolve(meta.fileName());
        Files.write(outputFile, plaintext);
        return outputFile;
    }

    // ---- Chunk 隐藏 ----

    /**
     * Chunk 结构隐写：将加密后的文件追加到 PNG 的 IEND 块之后。
     */
    public void hideChunk(final Path imageFile, final Path secretFile, final Path output,
                           final byte[] password, final StegoOptions options)
            throws IOException, ImageStegoException {
        byte[] plaintext = Files.readAllBytes(secretFile);
        String fileName = secretFile.getFileName().toString();

        byte[] salt = RandomBytes.generate(16);
        byte[] hkdfSalt = RandomBytes.generate(32);
        byte[] nonce = RandomBytes.generate(24);
        byte[] serpentIv = options.isParanoid() ? RandomBytes.generate(SERPENT_IV_LEN) : null;
        byte[] stealthSalt = options.isStealth() ? RandomBytes.generate(ChunkTrailer.STEALTH_SALT_LEN) : null;

        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;
        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, salt, options.isParanoid());
        byte[] ciphertext;
        byte[] payloadMac = null;

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);
            byte[] serpentKey = options.isParanoid() ? hkdf.read(SERPENT_KEY_LEN) : null;

            ciphertext = encryptPayload(encKey, nonce, serpentKey, serpentIv, plaintext);

            if (options.isStoreMac()) {
                payloadMac = computePayloadMac(macKey, plaintext);
            }
            SecureZero.zeroAll(encKey, macKey, serpentKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        byte flags = 0;
        if (options.isParanoid()) flags |= 1;
        if (options.isStoreMac()) flags |= 2;
        if (options.isStealth()) flags |= 4;

        ChunkTrailer trailer = new ChunkTrailer(
                ciphertext.length, fileName, salt, hkdfSalt, nonce,
                serpentIv, flags, payloadMac, options.isStealth());

        byte[] stealthMagic = null;
        if (options.isStealth()) {
            stealthMagic = ChunkTrailer.deriveStealthMagic(stealthSalt, effectivePwd);
        }

        try {
            PngChunkStego.embed(imageFile, output, ciphertext, trailer, stealthSalt, stealthMagic);
        } finally {
            SecureZero.zero(ciphertext);
        }

        if (options.isObfuscateSize() && options.targetSizeBytes() > 0) {
            padToSize(output, options.targetSizeBytes());
        }
    }

    // ---- Chunk 提取 ----

    /**
     * Chunk 结构提取：从 PNG 文件末尾提取隐藏的文件。
     */
    public Path extractChunk(final Path stegoImage, final Path outputDir,
                              final byte[] password) throws IOException, ImageStegoException {
        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;

        BruteForceGuard guard = BruteForceGuard.getInstance();
        String filePath = stegoImage.toAbsolutePath().toString();
        if (!guard.allowAttempt(filePath)) {
            throw new ImageStegoException(
                    "解密尝试次数过多（" + guard.getMaxAttempts()
                    + " 次），请稍后再试或确认密码是否正确");
        }

        PngChunkStego.ChunkExtractResult result;
        try {
            result = PngChunkStego.extract(stegoImage, effectivePwd);
        } catch (ImageStegoException e) {
            guard.recordFailure(filePath);
            throw e;
        }
        ChunkTrailer trailer = result.trailer();

        byte[] masterKey = Argon2Kdf.deriveKey(effectivePwd, trailer.salt, trailer.isParanoid());
        byte[] plaintext;

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, trailer.hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);
            byte[] serpentKey = trailer.isParanoid() ? hkdf.read(SERPENT_KEY_LEN) : null;

            plaintext = decryptPayload(encKey, trailer.nonce, serpentKey, trailer.serpentIv,
                    result.encryptedPayload());

            if (trailer.hasMac() && trailer.payloadMac != null) {
                byte[] computedMac = computePayloadMac(macKey, plaintext);
                if (!constantTimeEquals(computedMac, trailer.payloadMac)) {
                    SecureZero.zero(plaintext);
                    guard.recordFailure(filePath);
                    throw new ImageStegoException("完整性校验失败——密码错误或数据被篡改");
                }
            }
            SecureZero.zeroAll(encKey, macKey, serpentKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        guard.recordSuccess(filePath);
        Path outputFile = outputDir.resolve(trailer.fileName);
        Files.write(outputFile, plaintext);
        return outputFile;
    }

    // ---- 检测 ----

    public boolean isStegoImage(final Path imageFile) {
        try {
            PngLsbStego.extract(imageFile, StegoMetadata.MAGIC.length, 1, null);
            return true;
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("调色板")) {
                return false;
            }
            return false;
        }
    }

    public boolean isChunkStegoImage(final Path imageFile) throws IOException {
        return PngChunkStego.isChunkStego(imageFile);
    }

    // ---- 容量 ----

    public long availableCapacity(final Path imageFile, final StegoOptions options,
                                   final String fileName) throws IOException, ImageStegoException {
        java.awt.image.BufferedImage img = javax.imageio.ImageIO.read(imageFile.toFile());
        if (img == null) {
            throw new ImageStegoException("无法读取图像");
        }
        int channels = 3;
        int hs = StegoMetadata.headerSize(fileName, options.isStoreMac(),
                options.isParanoid(), options.isStealth());
        return StegoCapacity.availableBytes(img.getWidth(), img.getHeight(),
                channels, options.lsbDepth(), hs);
    }

    // ---- 内部加密/解密 ----

    private static byte[] encryptPayload(final byte[] encKey, final byte[] nonce,
                                          final byte[] serpentKey, final byte[] serpentIv,
                                          final byte[] plaintext) {
        byte[] work = plaintext;
        if (serpentKey != null && serpentIv != null) {
            SerpentCtr sc = new SerpentCtr(serpentKey, serpentIv);
            work = new byte[plaintext.length];
            sc.process(work, plaintext, plaintext.length);
        }
        XChaCha20 chacha = new XChaCha20(encKey, nonce);
        byte[] out = new byte[work.length];
        chacha.process(out, work, work.length);
        return out;
    }

    private static byte[] decryptPayload(final byte[] encKey, final byte[] nonce,
                                          final byte[] serpentKey, final byte[] serpentIv,
                                          final byte[] ciphertext) {
        XChaCha20 chacha = new XChaCha20(encKey, nonce);
        byte[] work = new byte[ciphertext.length];
        chacha.process(work, ciphertext, ciphertext.length);
        if (serpentKey != null && serpentIv != null) {
            SerpentCtr sc = new SerpentCtr(serpentKey, serpentIv);
            byte[] out = new byte[work.length];
            sc.process(out, work, work.length);
            return out;
        }
        return work;
    }

    private static byte[] computePayloadMac(final byte[] macKey, final byte[] data) {
        Mac mac = MacFactory.create(macKey, false);
        mac.update(data, data.length);
        return mac.doFinal();
    }

    private static boolean constantTimeEquals(final byte[] a, final byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    // ---- 文件大小混淆 ----

    /**
     * 在文件末尾追加密码学随机字节，直到达到目标大小。
     *
     * @throws ImageStegoException 若目标大小小于当前文件大小
     */
    private static void padToSize(final Path file, final long targetBytes)
            throws IOException, ImageStegoException {
        long current = Files.size(file);
        if (current >= targetBytes) {
            throw new ImageStegoException(String.format(
                    "目标大小(%s)小于或等于实际隐写文件大小(%s)，无法混淆。请增大目标大小。",
                    formatSize(current), formatSize(targetBytes)));
        }
        long toAdd = targetBytes - current;
        SecureRandom sr = new SecureRandom();
        byte[] buf = new byte[8192];
        try (java.io.OutputStream out = Files.newOutputStream(file,
                StandardOpenOption.APPEND)) {
            long remaining = toAdd;
            while (remaining > 0) {
                int chunk = (int) Math.min(remaining, buf.length);
                sr.nextBytes(buf);
                out.write(buf, 0, chunk);
                remaining -= chunk;
            }
        }
    }

    private static String formatSize(final long bytes) {
        if (bytes < 1024) return bytes + " B";
        else if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }
}
