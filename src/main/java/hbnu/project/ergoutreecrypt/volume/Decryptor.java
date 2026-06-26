package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.CipherSuite;
import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.SubkeyReader;
import hbnu.project.ergoutreecrypt.crypto.XChaCha20;
import hbnu.project.ergoutreecrypt.encoding.Padding;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.header.HeaderAuth;
import hbnu.project.ergoutreecrypt.header.HeaderLayout;
import hbnu.project.ergoutreecrypt.header.HeaderReader;
import hbnu.project.ergoutreecrypt.header.ReadResult;
import hbnu.project.ergoutreecrypt.keyfile.KeyfileProcessor;
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer;
import hbnu.project.ergoutreecrypt.password.Passwordless;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;

/**
 * 解密编排器（8 阶段流水线）。
 *
 * <p>支持 v1/v2 协议、普通/偏执模式、有/无 keyfile、有/无 RS 纠错、可否认加密等全部场景。
 *
 * <p>流水线：
 * <ol>
 *   <li>preprocess — 合并分卷 + 去可否认加密层</li>
 *   <li>readHeader — RS 解码 header 各字段</li>
 *   <li>deriveKeys → processKeyfiles → verifyAuth（三态密码候选尝试）</li>
 *   <li>decryptPayload — fastDecode → XChaCha20 → Serpent</li>
 *   <li>finalize — MAC 校验 + 全 RS 重试 + 原子重命名</li>
 * </ol>
 *
 * @author ErgouTree
 */
public final class Decryptor {

    private Decryptor() {
    }

    /**
     * 主入口：执行完整解密流程。
     *
     * @param req 解密请求参数
     * @throws Exception 密码错误、MAC 验证失败或 I/O 错误
     */
    public static void decrypt(DecryptRequest req) throws Exception {
        OperationContext ctx = new OperationContext();
        ctx.outputFile = req.getOutputFile();
        ctx.reporter = req.getReporter();
        try {
            decryptPreprocess(ctx, req);
            decryptReadHeader(ctx, req);
            decryptDeriveProcessVerify(ctx, req);
            decryptPayload(ctx, req, true);
            decryptFinalize(ctx, req);
        } catch (Exception e) {
            cleanupDecrypt(ctx, req);
            throw e;
        } finally {
            ctx.close();
        }
    }

    // ==================== Phase 1: Preprocess ====================

    /**
     * 解密预处理：合并分卷碎片、检测并剥离可否认加密外层。
     */
    static void decryptPreprocess(OperationContext ctx, DecryptRequest req) throws Exception {
        String inputFile = req.getInputFile();

        // 合并分卷碎片
        if (req.isRecombine()) {
            ctx.setStatus("Recombining chunks...");
            String base = Splitter.splitChunkBase(inputFile);
            if (base == null) {
                base = inputFile;
            }
            Path outputPath = Path.of(base);
            Splitter.recombine(outputPath, base);
            ctx.tempFile = outputPath.toString();
            inputFile = outputPath.toString();
        }

        // 可否认加密自动检测：未显式指定时通过探测文件头判断
        boolean deniability = req.isDeniability();
        if (!deniability) {
            deniability = Deniability.isDeniable(inputFile, req.getRsCodecs());
        }

        // 剥离可否认加密外层（在读取内层 volume header 之前）
        if (deniability) {
            String decrypted = Deniability.removeDeniability(inputFile,
                    Passwordless.effectivePassword(req.getPassword()),
                    ctx.reporter, req.getRsCodecs());
            ctx.tempFile = decrypted;
            inputFile = decrypted;
        }

        ctx.inputFile = inputFile;
    }

    // ==================== Phase 2: Read header ====================

    /**
     * 读取并 RS 解码卷头各字段。
     */
    static void decryptReadHeader(OperationContext ctx, DecryptRequest req) throws IOException {
        ctx.setStatus("Reading header...");

        try (InputStream in = Files.newInputStream(Path.of(ctx.inputFile))) {
            HeaderReader reader = new HeaderReader(in, req.getRsCodecs());
            ReadResult result = reader.readHeader();
            ctx.header = result.getHeader();
            int commentByteLen = ctx.header.getComments()
                    .getBytes(StandardCharsets.UTF_8).length;
            ctx.total = Files.size(Path.of(ctx.inputFile))
                    - HeaderLayout.headerSize(commentByteLen);
        }

        ctx.isLegacyV1 = ctx.header.isLegacyV1();
        ctx.useKeyfiles = ctx.header.getFlags().isUseKeyfiles();
    }

    // ==================== Phase 3-5: Derive + Keyfile + Verify ====================

    /**
     * 依次尝试密码候选形态进行密钥派生、keyfile 处理与 header 认证。
     * 无密码时使用公开默认密码，保证"无密码"文件人人可解密。
     */
    static void decryptDeriveProcessVerify(OperationContext ctx, DecryptRequest req) throws Exception {
        String effectivePw = Passwordless.effectivePassword(req.getPassword());
        List<byte[]> candidates = PasswordNormalizer.candidates(effectivePw);
        if (req.isForceDecrypt()) {
            candidates = List.of(effectivePw.getBytes(StandardCharsets.UTF_8));
        }

        Exception lastErr = null;
        for (int i = 0; i < candidates.size(); i++) {
            byte[] cand = candidates.get(i);
            ctx.setPasswordBytes(cand);
            try {
                decryptDeriveKeys(ctx, req);
                decryptProcessKeyfiles(ctx, req);
                decryptVerifyAuth(ctx, req);
                return;
            } catch (Exception e) {
                if (!HeaderAuth.AuthException.isPasswordError(e) || i == candidates.size() - 1) {
                    throw e;
                }
                lastErr = e;
            }
        }
        if (lastErr != null) {
            throw lastErr;
        }
    }

    /**
     * Argon2id 密钥派生。
     */
    private static void decryptDeriveKeys(OperationContext ctx, DecryptRequest req) {
        ctx.setStatus("Deriving key...");
        boolean paranoid = ctx.header.getFlags().isParanoid();
        byte[] key = Argon2Kdf.deriveKey(ctx.passwordBytes, ctx.header.getSalt(), paranoid);
        ctx.setKey(key);
    }

    /**
     * Keyfile 处理：计算哈希并与密码密钥合并。
     */
    private static void decryptProcessKeyfiles(OperationContext ctx, DecryptRequest req) throws IOException {
        if (!ctx.useKeyfiles) {
            ctx.keyfileHash = new byte[32];
            return;
        }
        List<String> kfPaths = req.getKeyfiles();
        if (kfPaths == null || kfPaths.isEmpty()) {
            throw new IOException("keyfiles required but none provided");
        }
        ctx.setStatus("Processing keyfiles...");
        List<Path> paths = kfPaths.stream().map(Path::of).toList();
        KeyfileProcessor kf = KeyfileProcessor.process(paths,
                ctx.header.getFlags().isKeyfileOrdered(), null);
        ctx.setKeyfileKey(kf.key());
        ctx.keyfileHash = kf.hash();

        // 纯 keyfile 模式（无密码）：keyfile 密钥即为主密钥
        String password = req.getPassword();
        if ((password == null || password.isEmpty()) && ctx.keyfileKey != null) {
            ctx.setKey(ctx.keyfileKey.clone());
        }
    }

    /**
     * Header 认证验证（v1 SHA3-512 / v2 HMAC-SHA3-512）。
     */
    private static void decryptVerifyAuth(OperationContext ctx, DecryptRequest req) {
        ctx.setStatus("Verifying authentication...");

        if (ctx.isLegacyV1) {
            // v1: SHA3-512(key) 验证，keyfile XOR 在 HKDF 之前
            HeaderAuth.AuthResult ar = HeaderAuth.verifyV1Header(ctx.key, ctx.header);
            if (!ar.isValid() && !req.isForceDecrypt()) {
                throw HeaderAuth.AuthException.passwordError();
            }
            byte[] combinedKey = ctx.key;
            if (ctx.useKeyfiles && ctx.keyfileKey != null) {
                combinedKey = KeyfileProcessor.xorWithKey(ctx.key, ctx.keyfileKey);
            }
            HkdfStream hkdf = new HkdfStream(combinedKey, ctx.header.getHkdfSalt());
            ctx.subkeyReader = new SubkeyReader(hkdf);
            ctx.setKey(combinedKey);
        } else {
            // v2: HKDF 在 keyfile XOR 之前
            HkdfStream hkdf = new HkdfStream(ctx.key, ctx.header.getHkdfSalt());
            ctx.subkeyReader = new SubkeyReader(hkdf);

            byte[] subkeyHeader = ctx.subkeyReader.headerSubkey();
            HeaderAuth.AuthResult ar = HeaderAuth.verifyV2Header(subkeyHeader, ctx.header, ctx.keyfileHash);
            if (!ar.isValid() && !req.isForceDecrypt()) {
                throw HeaderAuth.AuthException.v2PasswordOrTamperError();
            }

            // 校验 keyfile hash
            if (ctx.useKeyfiles) {
                if (!HeaderAuth.verifyKeyfileHash(ctx.keyfileHash, ctx.header.getKeyfileHash())) {
                    if (!req.isForceDecrypt()) {
                        throw HeaderAuth.AuthException.keyfileError(
                                ctx.header.getFlags().isKeyfileOrdered());
                    }
                }
                // v2: keyfile XOR 在 HKDF 之后（仅当有密码时）
                boolean keyfileOnly = (req.getPassword() == null || req.getPassword().isEmpty())
                        && ctx.useKeyfiles;
                if (ctx.keyfileKey != null && !keyfileOnly) {
                    if (KeyfileProcessor.isDuplicateKeyfileKey(ctx.keyfileKey)) {
                        throw new IllegalStateException("duplicate keyfiles detected");
                    }
                    ctx.setKey(KeyfileProcessor.xorWithKey(ctx.key, ctx.keyfileKey));
                }
            }
        }
    }

    // ==================== Phase 6: Decrypt payload ====================

    /**
     * 解密载荷：RS 解码 → XChaCha20(+Serpent) 解密，每 60 GiB rekey 一次。
     */
    private static void decryptPayload(OperationContext ctx, DecryptRequest req, boolean fastDecode) throws Exception {
        byte[] macSubkey = ctx.subkeyReader.macSubkey();
        byte[] serpentKey = ctx.subkeyReader.serpentKey();

        Mac mac = MacFactory.create(macSubkey, ctx.header.getFlags().isParanoid());
        CipherSuite cs = new CipherSuite(ctx.key, ctx.header.getNonce(), serpentKey,
                ctx.header.getSerpentIV(), mac, ctx.subkeyReader.stream(),
                ctx.header.getFlags().isParanoid());
        if (ctx.cipherSuite != null) {
            ctx.cipherSuite.close();
        }
        ctx.cipherSuite = cs;

        boolean reedsolo = ctx.header.getFlags().isReedSolomon();
        boolean padded = ctx.header.getFlags().isPadded();
        int commentByteLen = ctx.header.getComments()
                .getBytes(StandardCharsets.UTF_8).length;
        long headerSize = HeaderLayout.headerSize(commentByteLen);

        try (InputStream fin = Files.newInputStream(Path.of(ctx.inputFile));
             OutputStream fout = Files.newOutputStream(
                     Path.of(req.getOutputFile() + ".incomplete"))) {

            // 跳过 header 部分
            fin.skipNBytes(headerSize);

            int bufSize = reedsolo ? CryptoConstants.MIB / 128 * 136 : CryptoConstants.MIB;
            byte[] src = new byte[bufSize];
            byte[] dst = new byte[CryptoConstants.MIB];
            long done = 0;
            long counter = 0;

            while (true) {
                if (ctx.isCancelled()) {
                    throw new InterruptedException("cancelled");
                }

                int n = readFull(fin, src);
                if (n <= 0) {
                    break;
                }

                // RS 解码（若启用）
                byte[] data;
                if (reedsolo) {
                    boolean isLast = done + n >= ctx.total;
                    data = decodeWithRSFast(src, n, req.getRsCodecs(),
                            isLast, padded, req.isForceDecrypt(), fastDecode);
                } else {
                    data = new byte[n];
                    System.arraycopy(src, 0, data, 0, n);
                }

                // XChaCha20(+Serpent) 解密
                byte[] decrypted = new byte[data.length];
                cs.decrypt(decrypted, data, data.length);
                fout.write(decrypted);

                if (reedsolo) {
                    done += CryptoConstants.MIB / 128 * 136;
                } else {
                    done += n;
                }
                counter += CryptoConstants.MIB;

                if (ctx.total > 0) {
                    float progress = (float) done / ctx.total;
                    ctx.updateProgress(progress, "");
                }

                // 每 60 GiB rekey 一次
                if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                    cs.rekey();
                    counter = 0;
                }
            }
        }

        SecureZero.zero(macSubkey);
        SecureZero.zero(serpentKey);
    }

    // ==================== Phase 7: Finalize ====================

    /**
     * 最终化：MAC 校验，必要时全 RS 重试，原子重命名为最终输出。
     */
    private static void decryptFinalize(OperationContext ctx, DecryptRequest req) throws Exception {
        ctx.setStatus("Verifying MAC...");

        byte[] computedMac = ctx.cipherSuite.sum();
        boolean macOk = HeaderAuth.constantTimeEqual(computedMac, ctx.header.getAuthTag());

        // RS 模式下首次 fast-decode MAC 失败时，用完全 RS 解码重试一次
        if (!macOk && ctx.header.getFlags().isReedSolomon() && !ctx.triedFullRSDecode) {
            ctx.triedFullRSDecode = true;
            Files.deleteIfExists(Path.of(req.getOutputFile() + ".incomplete"));

            // 重新派生密钥（需要全新的 HKDF 流）
            ctx.setPasswordBytes(PasswordNormalizer.encodeForKdf(
                    Passwordless.effectivePassword(req.getPassword())));
            decryptDeriveKeys(ctx, req);
            decryptProcessKeyfiles(ctx, req);
            decryptVerifyAuth(ctx, req);

            decryptPayload(ctx, req, false);
            decryptFinalize(ctx, req);
            return;
        }

        if (!macOk) {
            if (req.isForceDecrypt()) {
                // 强制解密模式：即使 MAC 不匹配也继续
            } else {
                Files.deleteIfExists(Path.of(req.getOutputFile() + ".incomplete"));
                throw new IOException("MAC verification failed — file may be corrupted");
            }
        }

        // 原子重命名 .incomplete → 最终输出
        Files.move(Path.of(req.getOutputFile() + ".incomplete"), Path.of(req.getOutputFile()),
                StandardCopyOption.REPLACE_EXISTING);

        // 清理临时文件
        if (ctx.tempFile != null) {
            Files.deleteIfExists(Path.of(ctx.tempFile));
        }
    }

    /**
     * 解密失败时清理临时文件与不完整输出。
     */
    private static void cleanupDecrypt(OperationContext ctx, DecryptRequest req) {
        if (ctx.tempFile != null) {
            try {
                Files.deleteIfExists(Path.of(ctx.tempFile));
            } catch (IOException ignored) {
            }
        }
        try {
            Files.deleteIfExists(Path.of(req.getOutputFile() + ".incomplete"));
        } catch (IOException ignored) {
        }
    }

    // ==================== RS 快速解码辅助 ====================

    /**
     * RS128 快速解码：将编码数据按 136 字节块分割，逐块 RS 解码为 128 字节。
     * 末块若有 PKCS#7 填充则去除。
     */
    static byte[] decodeWithRSFast(byte[] data, int len, RsCodecs rs,
                                   boolean isLast, boolean padded,
                                   boolean forceDecode, boolean fastDecode) {
        int fullEncodedSize = CryptoConstants.MIB / Padding.BLOCK_SIZE * 136;

        if (len >= fullEncodedSize) {
            // 整块：8192 个 136 字节 RS 块
            int chunkCount = len / 136;
            byte[] result = new byte[chunkCount * Padding.BLOCK_SIZE];
            for (int i = 0; i < chunkCount; i++) {
                byte[] chunk = new byte[136];
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
            // 部分块：逐块解码，末块总是 unpad
            int chunkCount = len / 136;
            byte[] result = new byte[chunkCount * Padding.BLOCK_SIZE];
            for (int i = 0; i < chunkCount; i++) {
                byte[] chunk = new byte[136];
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

    /**
     * 从输入流中尽量读满缓冲区，返回实际读取的字节数。
     */
    static int readFull(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) {
                break;
            }
            total += n;
        }
        return total;
    }
}
