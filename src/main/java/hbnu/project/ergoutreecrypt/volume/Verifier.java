package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.encoding.Padding;
import hbnu.project.ergoutreecrypt.header.HeaderAuth;
import hbnu.project.ergoutreecrypt.header.HeaderLayout;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 文件完整性校验编排器。
 *
 * <p>对加密文件（.ergou / .pcv）执行只读的完整性校验：读取 volume header、
 * 验证 header 认证标签（v1 / v2）、扫描密文载荷并比对 MAC，全程不产生明文输出。
 *
 * <p>校验流水线（5 阶段）：
 * <ol>
 *   <li>preprocess — 合成分卷 + 去 deniability（复用 {@link Decryptor#decryptPreprocess}）</li>
 *   <li>readHeader — RS 解码 header（复用 {@link Decryptor#decryptReadHeader}）</li>
 *   <li>deriveProcessVerify — 派生密钥 + keyfile + header auth（复用 {@link Decryptor#decryptDeriveProcessVerify}）</li>
 *   <li>macScan — 仅计算密文 MAC（不解密），支持 RS fast/full decode</li>
 *   <li>compare — 常量时间比对 MAC，RS 模式下首次失败会 full-decode 重试一次</li>
 * </ol>
 *
 * <p>因为项目采用 encrypt-then-MAC，载荷 MAC 覆盖的是密文，因此校验阶段
 * 不需要执行 XChaCha20 / Serpent 解密，只需把密文原样（RS 解码后）喂给 MAC 累加器。
 *
 * @author ErgouTree
 */
public final class Verifier {

    private Verifier() {
    }

    /**
     * 主入口：对加密文件执行完整性校验。
     *
     * @param req 校验请求参数
     * @return true 表示校验通过，文件完好
     * @throws Exception 校验失败（密码错误、header 被篡改、载荷损坏/被篡改）或 I/O 错误
     */
    public static boolean verify(VerifyRequest req) throws Exception {
        OperationContext ctx = new OperationContext();
        ctx.reporter = req.getReporter();
        try {
            Decryptor.decryptPreprocess(ctx, toDecryptRequest(req));
            Decryptor.decryptReadHeader(ctx, toDecryptRequest(req));
            Decryptor.decryptDeriveProcessVerify(ctx, toDecryptRequest(req));
            verifyMacScan(ctx, req, true);
            verifyCompare(ctx, req);
            return true;
        } finally {
            cleanupVerify(ctx);
            ctx.close();
        }
    }

    // ================================================================
    // Phase 4: MAC-only scan (不解密，只累加密文 MAC)
    // ================================================================

    /**
     * 读取密文载荷并累加 MAC，不解密。
     *
     * <p>与 {@link Decryptor#decryptPayload} 的关键区别：不创建 CipherSuite，
     * 不执行 XChaCha20 / Serpent 解密。密文（经 RS 解码后）直接喂给 MAC。
     *
     * @param fastDecode true 为快速 RS 解码，false 为完全 RS 解码（重试时使用）
     */
    private static void verifyMacScan(OperationContext ctx, VerifyRequest req,
                                       boolean fastDecode) throws Exception {
        ctx.setStatus("Scanning file for MAC verification...");

        byte[] macSubkey = ctx.subkeyReader.macSubkey();
        Mac mac = MacFactory.create(macSubkey, ctx.header.getFlags().isParanoid());
        ctx.cipherSuite = null; // 不使用 CipherSuite，直接用 Mac

        boolean reedsolo = ctx.header.getFlags().isReedSolomon();
        boolean padded = ctx.header.getFlags().isPadded();
        int commentByteLen = ctx.header.getComments()
                .getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        long headerSize = HeaderLayout.headerSize(commentByteLen);

        try (InputStream fin = Files.newInputStream(Path.of(ctx.inputFile))) {
            // 跳过 header
            fin.skipNBytes(headerSize);

            int bufSize = reedsolo ? CryptoConstants.MIB / 128 * 136 : CryptoConstants.MIB;
            byte[] src = new byte[bufSize];
            long done = 0;

            while (true) {
                if (ctx.isCancelled()) {
                    throw new InterruptedException("cancelled");
                }

                int n = Decryptor.readFull(fin, src);
                if (n <= 0) {
                    break;
                }

                byte[] data;
                if (reedsolo) {
                    boolean isLast = done + n >= ctx.total;
                    data = Decryptor.decodeWithRSFast(src, n, req.getRsCodecs(),
                            isLast, padded, req.isForceDecrypt(), fastDecode);
                } else {
                    data = new byte[n];
                    System.arraycopy(src, 0, data, 0, n);
                }

                // 只累加 MAC，不解密
                mac.update(data, data.length);

                if (reedsolo) {
                    done += CryptoConstants.MIB / 128 * 136;
                } else {
                    done += n;
                }

                if (ctx.total > 0) {
                    float progress = (float) done / ctx.total;
                    ctx.updateProgress(progress, "");
                }
            }
        }

        // 暂存 MAC 结果到上下文中，供 compare 阶段使用
        ctx.keyfileHash = mac.doFinal(); // 复用 keyfileHash 字段存储 computedMac
        mac.close();
        SecureZero.zero(macSubkey);
    }

    // ================================================================
    // Phase 5: MAC 比对 + RS 完全解码重试
    // ================================================================

    /**
     * 常量时间比对载荷 MAC。
     *
     * <p>若开启了 Reed-Solomon 且首次 fast-decode MAC 比对失败，则用
     * {@code fastDecode=false} 重试一次（完全 RS 解码）。
     */
    private static void verifyCompare(OperationContext ctx, VerifyRequest req) throws Exception {
        ctx.setStatus("Verifying MAC...");

        byte[] computedMac = ctx.keyfileHash; // 由 verifyMacScan 暂存
        boolean macOk = HeaderAuth.constantTimeEqual(computedMac, ctx.header.getAuthTag());

        if (!macOk && ctx.header.getFlags().isReedSolomon() && !ctx.triedFullRSDecode) {
            // 用完全 RS 解码重试一次
            ctx.triedFullRSDecode = true;
            SecureZero.zero(computedMac);
            verifyMacScan(ctx, req, false);
            verifyCompare(ctx, req);
            return;
        }

        if (!macOk) {
            if (req.isForceDecrypt()) {
                return;
            }
            throw new IOException("MAC verification failed — file may be corrupted");
        }

        SecureZero.zero(computedMac);
    }

    // ================================================================
    // 辅助方法
    // ================================================================

    /**
     * 从 VerifyRequest 构建临时 DecryptRequest，用于复用 Decryptor 的前三个阶段。
     */
    private static DecryptRequest toDecryptRequest(VerifyRequest req) {
        DecryptRequest dr = new DecryptRequest();
        dr.setInputFile(req.getInputFile());
        dr.setPassword(req.getPassword());
        dr.setKeyfiles(req.getKeyfiles());
        dr.setForceDecrypt(req.isForceDecrypt());
        dr.setRecombine(req.isRecombine());
        dr.setDeniability(req.isDeniability());
        dr.setReporter(req.getReporter());
        dr.setRsCodecs(req.getRsCodecs());
        return dr;
    }

    /**
     * 清理校验过程中产生的临时文件（recombine 合并结果、deniability 剥离结果）。
     */
    private static void cleanupVerify(OperationContext ctx) {
        if (ctx.tempFile != null) {
            try {
                Files.deleteIfExists(Path.of(ctx.tempFile));
            } catch (IOException ignored) {
            }
        }
    }
}
