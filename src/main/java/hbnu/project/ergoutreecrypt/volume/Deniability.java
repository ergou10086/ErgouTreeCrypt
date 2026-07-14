package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.XChaCha20;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.header.HeaderLayout;
import hbnu.project.ergoutreecrypt.header.HeaderReader;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

/**
 * 可否认加密：在已完成的卷外层包裹 XChaCha20 加密。
 *
 * <p>文件布局：{@code salt(16) + nonce(24) + XChaCha20(inner_volume)}，使文件看似随机数据。
 *
 * <ul>
 *   <li>使用独立 Argon2id（Normal 参数：4 passes / 1 GiB / 4 threads）</li>
 *   <li>Rekey 使用 SHA3-256(nonce)[:24] 而非 HKDF</li>
 *   <li>无 MAC——通过探测内层 RS5 编码的 version 字段验证密码正确性</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class Deniability {

    /**
     * 可否认加密 salt 长度（16 字节）。
     */
    static final int SALT_SIZE = 16;

    /**
     * 可否认加密 nonce 长度（24 字节）。
     */
    static final int NONCE_SIZE = 24;

    /**
     * 可否认加密密钥长度（32 字节）。
     */
    static final int KEY_SIZE = 32;

    /**
     * 最小可否认文件大小：salt(16) + nonce(24) + baseHeader(789) = 829 字节。
     */
    private static final int MIN_DENIABLE_SIZE = SALT_SIZE + NONCE_SIZE + HeaderLayout.BASE_HEADER_SIZE;

    private Deniability() {
    }

    /**
     * 在加密卷外添加可否认加密外层。
     *
     * @param volumePath 已完成的卷文件路径
     * @param password   密码
     * @param reporter   进度回调
     * @throws Exception 加密或 I/O 错误
     */
    public static void addDeniability(String volumePath, String password,
                                      ProgressReporter reporter) throws Exception {
        if (reporter != null) {
            reporter.setStatus(Messages.get("status.deniability.add"));
        }

        long total = Files.size(Path.of(volumePath));
        String tmpPath = volumePath + ".tmp";
        String incomplete = volumePath + ".incomplete";

        Files.move(Path.of(volumePath), Path.of(tmpPath), StandardCopyOption.REPLACE_EXISTING);

        try (OutputStream fout = Files.newOutputStream(Path.of(incomplete));
             InputStream fin = Files.newInputStream(Path.of(tmpPath))) {

            byte[] salt = RandomBytes.generate(SALT_SIZE);
            byte[] nonce = RandomBytes.generate(NONCE_SIZE);
            fout.write(salt);
            fout.write(nonce);

            byte[] pwBytes = PasswordNormalizer.encodeForKdf(password);
            byte[] key = Argon2Kdf.deriveKey(pwBytes, salt, false);
            SecureZero.zero(pwBytes);

            try {
                byte[] buf = new byte[CryptoConstants.MIB];
                byte[] dst = new byte[CryptoConstants.MIB];
                long done = 0;
                long counter = 0;
                ChaChaState state = new ChaChaState(key, nonce);

                while (true) {
                    int n = readFull(fin, buf);
                    if (n <= 0) {
                        break;
                    }

                    state.xor(dst, buf, n);
                    fout.write(dst, 0, n);
                    done += n;
                    counter += CryptoConstants.MIB;

                    if (reporter != null && total > 0) {
                        reporter.setProgress((float) done / total, "");
                    }

                    if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                        nonce = deniabilityRekey(nonce);
                        state = new ChaChaState(key, nonce);
                        counter = 0;
                    }
                }
            } finally {
                SecureZero.zero(key);
            }
        } catch (Exception e) {
            Files.deleteIfExists(Path.of(incomplete));
            Files.move(Path.of(tmpPath), Path.of(volumePath), StandardCopyOption.REPLACE_EXISTING);
            throw e;
        }

        Files.delete(Path.of(tmpPath));
        Files.move(Path.of(incomplete), Path.of(volumePath), StandardCopyOption.REPLACE_EXISTING);

        if (reporter != null) {
            reporter.setProgress(1.0f, "");
        }
    }

    /**
     * 剥离可否认加密外层，还原内层卷。
     *
     * @param volumePath 可否认加密文件路径
     * @param password   密码
     * @param reporter   进度回调
     * @param rs         RS 编解码器
     * @return 剥离后的临时文件路径（调用方负责清理）
     * @throws Exception 密码错误或文件不是卷
     */
    public static String removeDeniability(String volumePath, String password,
                                            ProgressReporter reporter, RsCodecs rs) throws Exception {
        if (reporter != null) {
            reporter.setStatus(Messages.get("status.deniability.remove"));
        }

        long total = Files.size(Path.of(volumePath));
        long payloadLen = total - SALT_SIZE - NONCE_SIZE;

        String outputPath = volumePath;
        while (outputPath.endsWith(".tmp")) {
            outputPath = outputPath.substring(0, outputPath.length() - 4);
        }
        outputPath += ".tmp";

        // 读取 salt + nonce + probe + 剩余 payload
        byte[] salt = new byte[SALT_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];
        byte[] probe = new byte[HeaderLayout.VERSION_ENC_SIZE];
        byte[] payload;

        try (InputStream fin = Files.newInputStream(Path.of(volumePath))) {
            readFullExact(fin, salt);
            readFullExact(fin, nonce);
            readFullExact(fin, probe);
            payload = new byte[(int) payloadLen - probe.length];
            readFullExactAll(fin, payload);
        }

        // 通过探测 version 字段选择正确密钥
        byte[] key = selectDeniabilityKey(password, salt, nonce, probe, rs);

        try (OutputStream fout = Files.newOutputStream(Path.of(outputPath))) {
            byte[] buf = new byte[CryptoConstants.MIB];
            long done = 0;
            long counter = 0;
            ChaChaState state = new ChaChaState(key, nonce);

            // keystream 从位置 0 开始（salt+nonce 直接写入，不经 XOR）
            byte[] allData = new byte[probe.length + payload.length];
            System.arraycopy(probe, 0, allData, 0, probe.length);
            System.arraycopy(payload, 0, allData, probe.length, payload.length);

            int offset = 0;
            while (offset < allData.length) {
                int chunk = Math.min(buf.length, allData.length - offset);
                state.xor(buf, allData, offset, chunk);
                fout.write(buf, 0, chunk);
                offset += chunk;
                done += chunk;
                counter += chunk;

                if (reporter != null && payloadLen > 0) {
                    reporter.setProgress((float) done / payloadLen, "");
                }
                if (counter >= CryptoConstants.REKEY_THRESHOLD) {
                    nonce = deniabilityRekey(nonce);
                    state = new ChaChaState(key, nonce);
                    counter = 0;
                }
            }
        } catch (Exception e) {
            SecureZero.zero(key);
            Files.deleteIfExists(Path.of(outputPath));
            throw e;
        }
        SecureZero.zero(key);

        // 验证解密后的文件含有效的 version 字段
        try (InputStream verifyIn = Files.newInputStream(Path.of(outputPath))) {
            byte[] versionEnc = new byte[HeaderLayout.VERSION_ENC_SIZE];
            readFullExact(verifyIn, versionEnc);
            ReedSolomon.DecodeResult vd = ReedSolomon.decode(rs.rs5, versionEnc, false);
            if (vd.corrupted || !HeaderReader.matchVersion(vd.data)) {
                Files.deleteIfExists(Path.of(outputPath));
                throw new IOException("password is incorrect or the file is not a volume");
            }
        }

        return outputPath;
    }

    /**
     * 通过探测内层 RS5 编码的 version 字段来选择正确的可否认加密密钥。
     */
    static byte[] selectDeniabilityKey(String password, byte[] salt, byte[] nonce,
                                        byte[] probe, RsCodecs rs) throws Exception {
        List<byte[]> candidates = PasswordNormalizer.candidates(password);
        for (byte[] cand : candidates) {
            byte[] key = Argon2Kdf.deriveKey(cand, salt, false);
            boolean matched = false;
            try {
                ChaChaState state = new ChaChaState(key, nonce);
                byte[] dec = new byte[probe.length];
                state.xor(dec, probe, probe.length);
                ReedSolomon.DecodeResult vd = ReedSolomon.decode(rs.rs5, dec, false);
                if (!vd.corrupted && HeaderReader.matchVersion(vd.data)) {
                    matched = true;
                    return key;
                }
            } finally {
                if (!matched) {
                    SecureZero.zero(key);
                }
            }
        }
        throw new IOException("password is incorrect or the file is not a volume");
    }

    /**
     * 检测文件是否为可否认加密卷。
     *
     * @param volumePath 文件路径
     * @param rs         RS 编解码器
     * @return 若开头不是合法 version（但后续结构似 header）则返回 true
     */
    public static boolean isDeniable(String volumePath, RsCodecs rs) {
        try {
            long size = Files.size(Path.of(volumePath));
            if (size < MIN_DENIABLE_SIZE) {
                return false;
            }

            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(volumePath, "r")) {
                byte[] versionEnc = new byte[HeaderLayout.VERSION_ENC_SIZE];
                raf.readFully(versionEnc);

                ReedSolomon.DecodeResult vd = ReedSolomon.decode(rs.rs5, versionEnc, false);
                if (!vd.corrupted && HeaderReader.matchVersion(vd.data)) {
                    return false;
                }

                return !looksLikeRegularHeaderAfterDamagedVersion(raf, rs);
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 试探 version 编码损坏后余下的 comment length + flags 是否仍像合法 header。
     */
    private static boolean looksLikeRegularHeaderAfterDamagedVersion(
            java.io.RandomAccessFile raf, RsCodecs rs) throws IOException {
        byte[] commentLenEnc = new byte[HeaderLayout.COMMENT_LEN_ENC_SIZE];
        raf.seek(HeaderLayout.VERSION_ENC_SIZE);
        raf.readFully(commentLenEnc);

        ReedSolomon.DecodeResult cld = ReedSolomon.decode(rs.rs5, commentLenEnc, false);
        if (cld.corrupted) {
            return false;
        }

        String commentLenStr = new String(cld.data);
        int commentsLen;
        try {
            commentsLen = Integer.parseInt(commentLenStr);
        } catch (NumberFormatException e) {
            return false;
        }
        if (commentsLen < 0 || commentsLen > 99999) {
            return false;
        }

        long flagsOffset = HeaderLayout.VERSION_ENC_SIZE + HeaderLayout.COMMENT_LEN_ENC_SIZE
                + (long) commentsLen * 3;
        byte[] flagsEnc = new byte[HeaderLayout.FLAGS_ENC_SIZE];
        raf.seek(flagsOffset);
        raf.readFully(flagsEnc);

        ReedSolomon.DecodeResult fd = ReedSolomon.decode(rs.rs5, flagsEnc, false);
        if (fd.corrupted) {
            return false;
        }
        for (byte b : fd.data) {
            if (b != 0 && b != 1) {
                return false;
            }
        }
        return true;
    }

    /**
     * 可否认加密的 rekey：SHA3-256(oldNonce)[:24] → 新 nonce。
     */
    static byte[] deniabilityRekey(byte[] oldNonce) {
        SHA3Digest sha3 = new SHA3Digest(256);
        sha3.update(oldNonce, 0, oldNonce.length);
        byte[] sum = new byte[32];
        sha3.doFinal(sum, 0);
        byte[] newNonce = new byte[NONCE_SIZE];
        System.arraycopy(sum, 0, newNonce, 0, NONCE_SIZE);
        return newNonce;
    }

    /**
     * 简易 XChaCha20 / ChaCha20-IETF keystream 包装（用于可否认加密，无认证）。
     */
    private static final class ChaChaState {

        /**
         * 底层 ChaCha20(RFC 7539) 引擎。
         */
        private final ChaCha7539Engine engine;

        /**
         * @param key     32 字节密钥
         * @param nonce24 24 字节 nonce（XChaCha20 派生子密钥 + 子 nonce）
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

        /**
         * XOR keystream 到目标数组（带源偏移）。
         */
        void xor(byte[] dst, byte[] src, int srcOff, int len) {
            engine.processBytes(src, srcOff, len, dst, 0);
        }
    }

    /**
     * 从输入流中尽量读满缓冲区。
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

    /**
     * 从输入流中精确读取指定字节数（不足时抛 EOFException）。
     */
    static void readFullExact(InputStream in, byte[] buf) throws IOException {
        int offset = 0;
        while (offset < buf.length) {
            int n = in.read(buf, offset, buf.length - offset);
            if (n < 0) {
                throw new EOFException("unexpected EOF");
            }
            offset += n;
        }
    }

    /**
     * 从输入流中精确读取全部字节（委托 {@link #readFullExact}）。
     */
    static void readFullExactAll(InputStream in, byte[] buf) throws IOException {
        readFullExact(in, buf);
    }
}
