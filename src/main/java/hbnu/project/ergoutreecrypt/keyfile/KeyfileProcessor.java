package hbnu.project.ergoutreecrypt.keyfile;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Keyfile 处理器
 *
 * <ul>
 *   <li><b>Ordered</b>：SHA3-256(file1 || file2 || …)，顺序敏感。</li>
 *   <li><b>Unordered</b>：SHA3-256(file1) ⊕ SHA3-256(file2) ⊕ …，XOR 交换律使顺序无关。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class KeyfileProcessor implements AutoCloseable {

    private byte[] key;
    private byte[] hash;
    private boolean closed;

    KeyfileProcessor(byte[] key, byte[] hash) {
        this.key = key;
        this.hash = hash;
    }

    /**
     * 处理 keyfile 列表。对应 Go {@code Process}。
     *
     * @param paths    keyfile 路径列表
     * @param ordered  true=顺序拼接哈希、false=XOR（顺序无关）
     * @param progress 可选进度回调（0.0~1.0），可为 null
     * @return 含 key + hash 的处理器（用完须 close）
     * @throws IOException 文件 I/O 错误
     */
    public static KeyfileProcessor process(List<Path> paths, boolean ordered,
                                           ProgressCallback progress) throws IOException {
        if (paths == null || paths.isEmpty()) {
            return new KeyfileProcessor(new byte[32], new byte[32]);
        }

        // 计算总大小用于进度
        long totalSize = 0;
        for (Path p : paths) {
            totalSize += Files.size(p);
        }

        byte[] key;
        if (ordered) {
            key = processOrdered(paths, totalSize, progress);
        } else {
            key = processUnordered(paths, totalSize, progress);
        }

        // SHA3-256(key) → hash for header
        byte[] hash = sha3256(key);

        return new KeyfileProcessor(key, hash);
    }

    private static byte[] processOrdered(List<Path> paths, long totalSize,
                                         ProgressCallback progress) throws IOException {
        SHA3Digest hasher = new SHA3Digest(256);
        byte[] buf = new byte[CryptoConstants.MIB];
        long done = 0;

        for (Path p : paths) {
            try (InputStream in = Files.newInputStream(p)) {
                int n;
                while ((n = in.read(buf)) != -1) {
                    hasher.update(buf, 0, n);
                    done += n;
                    if (progress != null && totalSize > 0) {
                        progress.onProgress((float) done / (float) totalSize);
                    }
                }
            }
        }

        byte[] out = new byte[hasher.getDigestSize()];
        hasher.doFinal(out, 0);
        return out;
    }

    private static byte[] processUnordered(List<Path> paths, long totalSize,
                                           ProgressCallback progress) throws IOException {
        byte[] combined = null;
        byte[] buf = new byte[CryptoConstants.MIB];
        long done = 0;

        for (Path p : paths) {
            SHA3Digest hasher = new SHA3Digest(256);
            try (InputStream in = Files.newInputStream(p)) {
                int n;
                while ((n = in.read(buf)) != -1) {
                    hasher.update(buf, 0, n);
                    done += n;
                    if (progress != null && totalSize > 0) {
                        progress.onProgress((float) done / (float) totalSize);
                    }
                }
            }

            byte[] fileHash = new byte[hasher.getDigestSize()];
            hasher.doFinal(fileHash, 0);

            if (combined == null) {
                combined = fileHash;
            } else {
                for (int i = 0; i < combined.length; i++) {
                    combined[i] ^= fileHash[i];
                }
            }
        }

        return combined;
    }

    // ---- 工厂方法 ----

    /**
     * 检查 keyfile key 是否全零（偶数个相同文件 XOR 抵消）。对应 Go {@code IsDuplicateKeyfileKey}。
     */
    public static boolean isDuplicateKeyfileKey(byte[] key) {
        if (key == null || key.length != 32) return false;
        for (byte b : key) {
            if (b != 0) return false;
        }
        return true;
    }

    // ---- 内部处理 ----

    /**
     * 将 password key 与 keyfile key XOR。对应 Go {@code XORWithKey}。
     * 两者均为 32 字节。
     */
    public static byte[] xorWithKey(byte[] passwordKey, byte[] keyfileKey) {
        if (passwordKey.length != 32 || keyfileKey.length != 32) {
            throw new IllegalArgumentException(
                    "XORWithKey: expected 32-byte keys, got "
                            + passwordKey.length + " and " + keyfileKey.length);
        }
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++) {
            result[i] = (byte) (passwordKey[i] ^ keyfileKey[i]);
        }
        return result;
    }

    private static byte[] sha3256(byte[] data) {
        SHA3Digest digest = new SHA3Digest(256);
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    // ---- 工具方法 ----

    /**
     * 32 字节 keyfile key，用于与密码密钥 XOR。
     */
    public byte[] key() {
        return key;
    }

    /**
     * 32 字节 SHA3-256(key)，用于 header 存储/校验。
     */
    public byte[] hash() {
        return hash;
    }

    @Override
    public void close() {
        if (closed) return;
        SecureZero.zero(key);
        key = null;
        closed = true;
    }

    // ---- 进度回调 ----

    @FunctionalInterface
    public interface ProgressCallback {
        void onProgress(float fraction);
    }
}
