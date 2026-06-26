package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.*;
import hbnu.project.ergoutreecrypt.encoding.Padding;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

/**
 * 8 阶段解密编排，对应 Go {@code internal/volume/decrypt.go}。
 *
 * <p>能解密 Go Picocrypt 生成的 .pcv 卷。支持 v1/v2、普通/偏执、有/无 keyfile、有/无 RS、deniability。
 *
 * <p>流水线：
 * <ol>
 *   <li>preprocess — recombine + 去 deniability</li>
 *   <li>readHeader — RS 解码 header 字段</li>
 *   <li>deriveKeys → processKeyfiles → verifyAuth（三态密码尝试）</li>
 *   <li>decryptPayload — fastDecode → XChaCha20 → Serpent</li>
 *   <li>finalize — MAC 校验 + 全 RS 重试 + rename</li>
 * </ol>
 *
 * @author ErgouTree
 */
public final class Decryptor {

    private Decryptor() {
    }

    /**
     * 主入口，对应 Go Decrypt()。
     */
    public static void decrypt(DecryptRequest req) throws Exception {
        OperationContext ctx = new OperationContext();
        ctx.outputFile = req.getOutputFile();
        ctx.reporter = req.getReporter();
        try {
            decryptPreprocess(ctx, req);
            decryptReadHeader(ctx, req);
            decryptDeriveProcessVerify(ctx, req);
            decryptPayload(ctx, req, true); // fast decode first
            decryptFinalize(ctx, req);
        } catch (Exception e) {
            cleanupDecrypt(ctx, req);
            throw e;
        } finally {
            ctx.close();
        }
    }

    // ================================================================
    // Phase 1: Preprocess
    // ================================================================
    static void decryptPreprocess(OperationContext ctx, DecryptRequest req) throws Exception {
        String inputFile = req.getInputFile();

        // Recombine split chunks
        if (req.isRecombine()) {
            ctx.setStatus("Recombining chunks...");
            String base = hbnu.project.ergoutreecrypt.fileops.Splitter.splitChunkBase(inputFile);
            if (base == null) {
                base = inputFile;
            }
            Path outputPath = Path.of(base);
            hbnu.project.ergoutreecrypt.fileops.Splitter.recombine(outputPath, base);
            ctx.tempFile = outputPath.toString();
            inputFile = outputPath.toString();
        }

        // Deniability detection: if the user didn't explicitly request it,
        // auto-detect by probing the file header (matches Go GUI behavior
        // where previewHeader catches ErrInvalidVersion and sets Deniability).
        boolean deniability = req.isDeniability();
        if (!deniability) {
            deniability = Deniability.isDeniable(inputFile, req.getRsCodecs());
        }

        // Remove deniability wrapper (before reading the inner volume header)
        if (deniability) {
            String decrypted = Deniability.removeDeniability(inputFile,
                    Passwordless.effectivePassword(req.getPassword()),
                    ctx.reporter, req.getRsCodecs());
            ctx.tempFile = decrypted;
            inputFile = decrypted;
        }

        ctx.inputFile = inputFile;
    }

    // ================================================================
    // Phase 2: Read header
    // ================================================================
    static void decryptReadHeader(OperationContext ctx, DecryptRequest req) throws IOException {
        ctx.setStatus("Reading header...");

        try (InputStream in = Files.newInputStream(Path.of(ctx.inputFile))) {
            HeaderReader reader = new HeaderReader(in, req.getRsCodecs());
            ReadResult result = reader.readHeader();
            ctx.header = result.getHeader();
            // 注释长度 = UTF-8 字节数（非 Java char count），与 header 中存储的一致
            int commentByteLen = ctx.header.getComments()
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            ctx.total = Files.size(Path.of(ctx.inputFile))
                    - HeaderLayout.headerSize(commentByteLen);
        }

        ctx.isLegacyV1 = ctx.header.isLegacyV1();
        ctx.useKeyfiles = ctx.header.getFlags().isUseKeyfiles();
    }

    // ================================================================
    // Phase 3-5: Derive + Keyfile + Verify (with password candidates)
    // ================================================================
    static void decryptDeriveProcessVerify(OperationContext ctx, DecryptRequest req) throws Exception {
        // 无密码时使用公开默认密码，保证"无密码"文件人人可解密
        String effectivePw = Passwordless.effectivePassword(req.getPassword());
        List<byte[]> candidates = PasswordNormalizer.candidates(effectivePw);
        if (req.isForceDecrypt()) {
            candidates = List.of(effectivePw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        Exception lastErr = null;
        for (int i = 0; i < candidates.size(); i++) {
            byte[] cand = candidates.get(i);
            ctx.setPasswordBytes(cand);
            try {
                decryptDeriveKeys(ctx, req);
                decryptProcessKeyfiles(ctx, req);
                decryptVerifyAuth(ctx, req);
                return; // success
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

    // ================================================================
    // Key derivation
    // ================================================================
    private static void decryptDeriveKeys(OperationContext ctx, DecryptRequest req) {
        ctx.setStatus("Deriving key...");

        // 无密码时 passwordBytes 已是 DEFAULT_PASSWORD 的字节，直接 Argon2 派生
        boolean paranoid = ctx.header.getFlags().isParanoid();
        byte[] key = Argon2Kdf.deriveKey(ctx.passwordBytes, ctx.header.getSalt(), paranoid);
        ctx.setKey(key);
    }

    // ================================================================
    // Keyfile processing
    // ================================================================
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

    // ================================================================
    // Auth verification (v1 vs v2)
    // ================================================================
    private static void decryptVerifyAuth(OperationContext ctx, DecryptRequest req) {
        ctx.setStatus("Verifying authentication...");

        if (ctx.isLegacyV1) {
            // v1: SHA3-512(key) verification first
            HeaderAuth.AuthResult ar = HeaderAuth.verifyV1Header(ctx.key, ctx.header);
            if (!ar.isValid() && !req.isForceDecrypt()) {
                throw HeaderAuth.AuthException.passwordError();
            }
            // v1: XOR keyfile BEFORE HKDF
            byte[] combinedKey = ctx.key;
            if (ctx.useKeyfiles && ctx.keyfileKey != null) {
                combinedKey = KeyfileProcessor.xorWithKey(ctx.key, ctx.keyfileKey);
            }
            HkdfStream hkdf = new HkdfStream(combinedKey, ctx.header.getHkdfSalt());
            ctx.subkeyReader = new SubkeyReader(hkdf);
            ctx.setKey(combinedKey);
        } else {
            // v2: HKDF BEFORE keyfile XOR
            HkdfStream hkdf = new HkdfStream(ctx.key, ctx.header.getHkdfSalt());
            ctx.subkeyReader = new SubkeyReader(hkdf);

            byte[] subkeyHeader = ctx.subkeyReader.headerSubkey();
            HeaderAuth.AuthResult ar = HeaderAuth.verifyV2Header(subkeyHeader, ctx.header, ctx.keyfileHash);
            if (!ar.isValid() && !req.isForceDecrypt()) {
                throw HeaderAuth.AuthException.v2PasswordOrTamperError();
            }
            // Verify keyfiles
            if (ctx.useKeyfiles) {
                if (!HeaderAuth.verifyKeyfileHash(ctx.keyfileHash, ctx.header.getKeyfileHash())) {
                    if (!req.isForceDecrypt()) {
                        throw HeaderAuth.AuthException.keyfileError(
                                ctx.header.getFlags().isKeyfileOrdered());
                    }
                }
                // XOR keyfile AFTER HKDF (v2) — only if password is present
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

    // ================================================================
    // Phase 6: Decrypt payload
    // ================================================================
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
                .getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        long headerSize = HeaderLayout.headerSize(commentByteLen);

        try (InputStream fin = Files.newInputStream(Path.of(ctx.inputFile));
             OutputStream fout = Files.newOutputStream(
                     Path.of(req.getOutputFile() + ".incomplete"))) {

            // Skip past header
            fin.skipNBytes(headerSize);

            int bufSize = reedsolo ? CryptoConstants.MIB / 128 * 136 : CryptoConstants.MIB;
            byte[] src = new byte[bufSize];
            byte[] dst = new byte[CryptoConstants.MIB];
            long done = 0;
            long counter = 0;
            long startMs = System.currentTimeMillis();

            while (true) {
                if (ctx.isCancelled()) {
                    throw new InterruptedException("cancelled");
                }

                int n = readFull(fin, src);
                if (n <= 0) {
                    break;
                }

                byte[] data;
                if (reedsolo) {
                    boolean isLast = done + n >= ctx.total;
                    data = decodeWithRSFast(src, n, req.getRsCodecs(),
                            isLast, padded, req.isForceDecrypt(), fastDecode);
                } else {
                    data = new byte[n];
                    System.arraycopy(src, 0, data, 0, n);
                }

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

                // Rekey every 60 GiB
                if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                    cs.rekey();
                    counter = 0;
                }
            }
        }

        SecureZero.zero(macSubkey);
        SecureZero.zero(serpentKey);
    }

    // ================================================================
    // Phase 7: Finalize
    // ================================================================
    private static void decryptFinalize(OperationContext ctx, DecryptRequest req) throws Exception {
        ctx.setStatus("Verifying MAC...");

        byte[] computedMac = ctx.cipherSuite.sum();
        boolean macOk = HeaderAuth.constantTimeEqual(computedMac, ctx.header.getAuthTag());

        if (!macOk && ctx.header.getFlags().isReedSolomon() && !ctx.triedFullRSDecode) {
            // Full RS retry
            ctx.triedFullRSDecode = true;
            Files.deleteIfExists(Path.of(req.getOutputFile() + ".incomplete"));

            // Re-derive keys for fresh HKDF stream
            if (ctx.isLegacyV1) {
                // v1 re-derive
                ctx.setPasswordBytes(PasswordNormalizer.encodeForKdf(
                        Passwordless.effectivePassword(req.getPassword())));
                decryptDeriveKeys(ctx, req);
                decryptProcessKeyfiles(ctx, req);
                decryptVerifyAuth(ctx, req);
            } else {
                ctx.setPasswordBytes(PasswordNormalizer.encodeForKdf(
                        Passwordless.effectivePassword(req.getPassword())));
                decryptDeriveKeys(ctx, req);
                decryptProcessKeyfiles(ctx, req);
                decryptVerifyAuth(ctx, req);
            }

            decryptPayload(ctx, req, false); // full RS decode
            decryptFinalize(ctx, req);       // verify MAC again
            return;
        }

        if (!macOk) {
            if (req.isForceDecrypt()) {
                // continue
            } else {
                Files.deleteIfExists(Path.of(req.getOutputFile() + ".incomplete"));
                throw new IOException("MAC verification failed — file may be corrupted");
            }
        }

        // Rename .incomplete → final
        Files.move(Path.of(req.getOutputFile() + ".incomplete"), Path.of(req.getOutputFile()),
                StandardCopyOption.REPLACE_EXISTING);

        // Cleanup temp
        if (ctx.tempFile != null) {
            Files.deleteIfExists(Path.of(ctx.tempFile));
        }
    }

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

    // ================================================================
    // RS fast decode
    // ================================================================
    static byte[] decodeWithRSFast(byte[] data, int len, RsCodecs rs,
                                   boolean isLast, boolean padded,
                                   boolean forceDecode, boolean fastDecode) {
        int fullEncodedSize = CryptoConstants.MIB / Padding.BLOCK_SIZE * 136;

        if (len >= fullEncodedSize) {
            // Full block: process each 136-byte RS128 chunk
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
                    // Resize for unpadded last chunk
                    return java.util.Arrays.copyOf(result,
                            (chunkCount - 1) * Padding.BLOCK_SIZE + decoded.length);
                }
            }
            return result;
        } else {
            // Partial block
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
                    return java.util.Arrays.copyOf(result,
                            (chunkCount - 1) * Padding.BLOCK_SIZE + decoded.length);
                }
            }
            return result;
        }
    }

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
