package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.*;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.header.HeaderLayout;
import hbnu.project.ergoutreecrypt.header.HeaderReader;
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

/**
 * Deniability（可否认加密）外层 XChaCha20 包装
 *
 * <p>在已完成的 .pcv/.ergou 卷外再包一层 XChaCha20 加密，使文件看似随机数据。
 * 文件布局：{@code salt(16) + nonce(24) + XChaCha20(inner_volume)}。
 *
 * <ul>
 *   <li>使用独立 Argon2id（Normal 参数：4 passes / 1 GiB / 4 threads）</li>
 *   <li>Rekey 使用 SHA3-256(nonce)[:24] 而非 HKDF</li>
 *   <li>无 MAC——通过探测内层 RS5 编码 version 字段验证密码正确性</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class Deniability {

    private Deniability() {}

    static final int SALT_SIZE = 16;
    static final int NONCE_SIZE = 24;
    static final int KEY_SIZE = 32;

    /** 最小可否认文件大小：salt(16) + nonce(24) + baseHeader(789) = 829 */
    private static final int MIN_DENIABLE_SIZE = SALT_SIZE + NONCE_SIZE + HeaderLayout.BASE_HEADER_SIZE;

    // ================================================================
    // AddDeniability
    // ================================================================
    public static void addDeniability(String volumePath, String password,
                                      ProgressReporter reporter) throws Exception {
        if (reporter != null) reporter.setStatus("Adding deniability...");

        long total = Files.size(Path.of(volumePath));
        String tmpPath = volumePath + ".tmp";
        String incomplete = volumePath + ".incomplete";

        // Rename original → .tmp
        Files.move(Path.of(volumePath), Path.of(tmpPath), StandardCopyOption.REPLACE_EXISTING);

        try (OutputStream fout = Files.newOutputStream(Path.of(incomplete));
             InputStream fin = Files.newInputStream(Path.of(tmpPath))) {

            byte[] salt = RandomBytes.generate(SALT_SIZE);
            byte[] nonce = RandomBytes.generate(NONCE_SIZE);
            fout.write(salt);
            fout.write(nonce);

            byte[] pwBytes = PasswordNormalizer.encodeForKdf(password);
            byte[] key = Argon2Kdf.deriveKey(pwBytes, salt, false); // Normal mode
            SecureZero.zero(pwBytes);

            try {
                byte[] buf = new byte[CryptoConstants.MIB];
                byte[] dst = new byte[CryptoConstants.MIB];
                long done = 0;
                long counter = 0;
                ChaChaState state = new ChaChaState(key, nonce);

                while (true) {
                    int n = readFull(fin, buf);
                    if (n <= 0) break;

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
            // Restore original
            Files.deleteIfExists(Path.of(incomplete));
            Files.move(Path.of(tmpPath), Path.of(volumePath), StandardCopyOption.REPLACE_EXISTING);
            throw e;
        }

        Files.delete(Path.of(tmpPath));
        Files.move(Path.of(incomplete), Path.of(volumePath), StandardCopyOption.REPLACE_EXISTING);

        if (reporter != null) reporter.setProgress(1.0f, "");
    }

    // ================================================================
    // RemoveDeniability
    // ================================================================
    public static String removeDeniability(String volumePath, String password,
                                            ProgressReporter reporter, RsCodecs rs) throws Exception {
        if (reporter != null) reporter.setStatus("Removing deniability...");

        long total = Files.size(Path.of(volumePath));
        long payloadLen = total - SALT_SIZE - NONCE_SIZE;

        // Output path: strip .tmp suffixes, append .tmp
        String outputPath = volumePath;
        while (outputPath.endsWith(".tmp")) {
            outputPath = outputPath.substring(0, outputPath.length() - 4);
        }
        outputPath += ".tmp";

        // Read salt+nonce+probe from input, select key, then decrypt all payload in one pass
        byte[] salt = new byte[SALT_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];
        byte[] probe = new byte[HeaderLayout.VERSION_ENC_SIZE];
        byte[] payload;

        try (InputStream fin = Files.newInputStream(Path.of(volumePath))) {
            readFullExact(fin, salt);
            readFullExact(fin, nonce);
            readFullExact(fin, probe);
            // Read remaining payload
            payload = new byte[(int) payloadLen - probe.length];
            readFullExactAll(fin, payload);
        }

        // Select key by probing version field
        byte[] key = selectDeniabilityKey(password, salt, nonce, probe, rs);

        try (OutputStream fout = Files.newOutputStream(Path.of(outputPath))) {
            byte[] buf = new byte[CryptoConstants.MIB];
            long done = 0;
            long counter = 0;
            ChaChaState state = new ChaChaState(key, nonce);
            // NOTE: keystream starts at position 0, which corresponds to file position 40
            // (the salt+nonce are written directly, NOT XORed with keystream).
            // So NO burn is needed — keystream[0] decrypts the first byte of the volume.

            // Decrypt probe + payload as one continuous stream
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

        // Verify decrypted file has valid version
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

    // ================================================================
    // Key selection (probe-based)
    // ================================================================
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
                    return key; // caller must zero; do NOT zero here
                }
            } finally {
                // Only zero on the failure path. Zeroing a matched key here would
                // wipe the very array we just returned (finally runs after the
                // return value is captured but before the caller receives it).
                if (!matched) {
                    SecureZero.zero(key);
                }
            }
        }
        throw new IOException("password is incorrect or the file is not a volume");
    }

    // ================================================================
    // IsDeniable detection
    // ================================================================
    public static boolean isDeniable(String volumePath, RsCodecs rs) {
        try {
            long size = Files.size(Path.of(volumePath));
            if (size < MIN_DENIABLE_SIZE) return false;

            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(volumePath, "r")) {
                byte[] versionEnc = new byte[HeaderLayout.VERSION_ENC_SIZE];
                raf.readFully(versionEnc);

                ReedSolomon.DecodeResult vd = ReedSolomon.decode(rs.rs5, versionEnc, false);
                if (!vd.corrupted && HeaderReader.matchVersion(vd.data)) {
                    return false; // valid version → regular volume
                }

                return !looksLikeRegularHeaderAfterDamagedVersion(raf, rs);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean looksLikeRegularHeaderAfterDamagedVersion(
            java.io.RandomAccessFile raf, RsCodecs rs) throws IOException {
        // Try comment length at offset VersionEncSize
        byte[] commentLenEnc = new byte[HeaderLayout.COMMENT_LEN_ENC_SIZE];
        raf.seek(HeaderLayout.VERSION_ENC_SIZE);
        raf.readFully(commentLenEnc);

        ReedSolomon.DecodeResult cld = ReedSolomon.decode(rs.rs5, commentLenEnc, false);
        if (cld.corrupted) return false;

        String commentLenStr = new String(cld.data);
        int commentsLen;
        try {
            commentsLen = Integer.parseInt(commentLenStr);
        } catch (NumberFormatException e) {
            return false;
        }
        if (commentsLen < 0 || commentsLen > 99999) return false;

        // Try flags at calculated offset
        long flagsOffset = HeaderLayout.VERSION_ENC_SIZE + HeaderLayout.COMMENT_LEN_ENC_SIZE
                + (long) commentsLen * 3;
        byte[] flagsEnc = new byte[HeaderLayout.FLAGS_ENC_SIZE];
        raf.seek(flagsOffset);
        raf.readFully(flagsEnc);

        ReedSolomon.DecodeResult fd = ReedSolomon.decode(rs.rs5, flagsEnc, false);
        if (fd.corrupted) return false;

        // Flags must be 0 or 1
        for (byte b : fd.data) {
            if (b != 0 && b != 1) return false;
        }
        return true;
    }

    // ================================================================
    // XChaCha20 wrapper (unauth, for deniability)
    // ================================================================
    static byte[] deniabilityRekey(byte[] oldNonce) {
        SHA3Digest sha3 = new SHA3Digest(256);
        sha3.update(oldNonce, 0, oldNonce.length);
        byte[] sum = new byte[32];
        sha3.doFinal(sum, 0);
        byte[] newNonce = new byte[NONCE_SIZE];
        System.arraycopy(sum, 0, newNonce, 0, NONCE_SIZE);
        return newNonce;
    }

    /** Simple XChaCha20 (24-byte nonce)/ChaCha20-IETF keystream wrapper. */
    private static final class ChaChaState {
        private final ChaCha7539Engine engine;

        ChaChaState(byte[] key, byte[] nonce24) {
            // XChaCha20: HChaCha20(key, nonce24[0:16]) → subKey
            // ChaCha20-IETF: 12-byte nonce = counter(4B=0) + nonce24[16:24](8B)
            byte[] subKey = XChaCha20.hChaCha20(key, nonce24);
            this.engine = new ChaCha7539Engine();
            byte[] nonce12 = new byte[12];
            System.arraycopy(nonce24, 16, nonce12, 4, 8); // last 8 bytes → nonce12[4:12]
            this.engine.init(true, new ParametersWithIV(new KeyParameter(subKey), nonce12));
        }

        void xor(byte[] dst, byte[] src, int len) {
            engine.processBytes(src, 0, len, dst, 0);
        }
        void xor(byte[] dst, byte[] src, int srcOff, int len) {
            engine.processBytes(src, srcOff, len, dst, 0);
        }
    }

    // ================================================================
    // I/O helpers
    // ================================================================
    static int readFull(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) break;
            total += n;
        }
        return total;
    }

    static void readFullExact(InputStream in, byte[] buf) throws IOException {
        int offset = 0;
        while (offset < buf.length) {
            int n = in.read(buf, offset, buf.length - offset);
            if (n < 0) throw new EOFException("unexpected EOF");
            offset += n;
        }
    }

    static void readFullExactAll(InputStream in, byte[] buf) throws IOException {
        readFullExact(in, buf);
    }
}
