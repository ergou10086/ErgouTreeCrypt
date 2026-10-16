package hbnu.project.ergoutreecrypt.keyfile;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Keyfile 处理器。
 *
 * <p>支持两种 keyfile 合并模式：
 * <ul>
 *   <li><b>Ordered（有序）</b>：SHA3-256(file1 || file2 || …)，顺序敏感；</li>
 *   <li><b>Unordered（无序）</b>：SHA3-256(file1) ⊕ SHA3-256(file2) ⊕ …，XOR 交换律使顺序无关。</li>
 * </ul>
 *
 * <p>处理完成后 key 通过 XOR 与密码密钥合并，hash 存入 header 用于后续校验。
 * 使用完毕后须调用 {@link #close()} 安全清零 key。
 *
 * @author ErgouTree
 */
public final class KeyfileProcessor implements AutoCloseable {

    /**
     * 32 字节 keyfile 派生密钥（与密码密钥 XOR 后使用）。
     */
    private byte[] key;

    /**
     * 32 字节 SHA3-256(key) 哈希（存入 header 供校验）。
     */
    private byte[] hash;

    /**
     * 是否已关闭（安全清零）。
     */
    private boolean closed;

    /**
     * 创建已派生的密钥材料容器。
     * @param key  32 字节 keyfile 派生密钥
     * @param hash 32 字节 SHA3-256(key) 哈希
     */
    KeyfileProcessor(byte[] key, byte[] hash) {
        this.key = key;
        this.hash = hash;
    }

    /**
     * 处理 keyfile 列表。
     *
     * @param paths    keyfile 文件路径列表
     * @param ordered  true=顺序拼接哈希，false=XOR（顺序无关）
     * @param progress 可选进度回调（0.0~1.0），可为 null
     * @return 含 key + hash 的处理器实例（用完须 close）
     * @throws IOException 文件 I/O 错误
     */
    public static KeyfileProcessor process(List<Path> paths, boolean ordered,
                                           ProgressCallback progress) throws IOException {
        return process(paths, ordered, progress, false);
    }

    /**
     * 处理新加密任务的密钥文件，拒绝无序模式中任何重复内容。
     * 读取旧卷仍使用 {@link #process(List, boolean, ProgressCallback)}，保持既有派生结果。
     *
     * @param paths 密钥文件路径
     * @param ordered 是否按顺序拼接
     * @param progress 可选进度回调
     * @return 派生密钥与哈希
     * @throws IOException 读取失败或重复文件会导致密钥抵消
     */
    public static KeyfileProcessor processForEncryption(List<Path> paths, boolean ordered,
                                                        ProgressCallback progress) throws IOException {
        return process(paths, ordered, progress, true);
    }

    /**
     * 读取与新加密共享派生算法，仅新加密启用重复内容校验。
     * @param paths 密钥文件路径
     * @param ordered 是否有序
     * @param progress 可选进度回调
     * @param rejectDuplicates 是否拒绝无序重复内容
     * @return 派生结果
     * @throws IOException 读取失败或重复内容
     */
    private static KeyfileProcessor process(List<Path> paths, boolean ordered,
                                            ProgressCallback progress, boolean rejectDuplicates) throws IOException {
        if (paths == null || paths.isEmpty()) {
            // 无 keyfile 时返回全零 key 和对应 hash
            return new KeyfileProcessor(new byte[32], new byte[32]);
        }

        // 计算总文件大小用于进度回调
        long totalSize = 0;
        for (Path p : paths) {
            totalSize += Files.size(p);
        }

        byte[] key;
        if (ordered) {
            key = processOrdered(paths, totalSize, progress);
        } else {
            key = processUnordered(paths, totalSize, progress, rejectDuplicates);
        }

        // SHA3-256(key) → hash 存入 header
        byte[] hash = sha3256(key);

        return new KeyfileProcessor(key, hash);
    }

    /**
     * 有序模式：将所有 keyfile 内容顺序拼接后做 SHA3-256。
     * @param paths 密钥文件路径
     * @param totalSize 总字节数
     * @param progress 可选进度回调
     * @return 拼接内容的 SHA3-256
     * @throws IOException 文件读取失败
     */
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

    /**
     * 无序模式：每个 keyfile 单独做 SHA3-256 后 XOR 合并（交换律保证顺序无关）。
     * @param paths 文件路径
     * @param totalSize 总字节数
     * @param progress 进度回调
     * @param rejectDuplicates 是否拒绝任意重复内容
     * @return 合并密钥
     * @throws IOException 读取失败或发现重复内容
     */
    private static byte[] processUnordered(List<Path> paths, long totalSize,
                                           ProgressCallback progress, boolean rejectDuplicates) throws IOException {
        byte[] combined = null;
        Set<ByteBuffer> seen = rejectDuplicates ? new HashSet<>() : null;
        byte[] buf = new byte[CryptoConstants.MIB];
        long done = 0;
        boolean complete = false;
        try {
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

                if (seen != null) {
                    ByteBuffer fingerprint = ByteBuffer.wrap(fileHash.clone());
                    if (!seen.add(fingerprint)) {
                        SecureZero.zero(fingerprint.array());
                        SecureZero.zero(fileHash);
                        throw new IOException("无序密钥文件包含重复内容，会相互抵消；请移除重复文件或使用有序模式");
                    }
                }

                // XOR 合并各文件哈希
                if (combined == null) {
                    combined = fileHash;
                } else {
                    for (int i = 0; i < combined.length; i++) {
                        combined[i] ^= fileHash[i];
                    }
                    SecureZero.zero(fileHash);
                }
            }

            complete = true;
            return combined;
        } finally {
            SecureZero.zero(buf);
            if (seen != null) {
                for (ByteBuffer fingerprint : seen) SecureZero.zero(fingerprint.array());
            }
            if (!complete) SecureZero.zero(combined);
        }
    }

    /**
     * 检查 keyfile key 是否全零（偶数个相同文件 XOR 抵消的哨兵值）。
     *
     * @param key 32 字节 keyfile 密钥
     * @return 若全为零则返回 true
     */
    public static boolean isDuplicateKeyfileKey(byte[] key) {
        if (key == null || key.length != 32) return false;
        for (byte b : key) {
            if (b != 0) return false;
        }
        return true;
    }

    /**
     * 将密码密钥与 keyfile 密钥做按位 XOR 得到最终加密密钥。
     * 两者均须为 32 字节。
     *
     * @param passwordKey Argon2 派生密钥（32 字节）
     * @param keyfileKey  keyfile 派生密钥（32 字节）
     * @return XOR 后的 32 字节密钥
     * @throws IllegalArgumentException 若任一输入长度不是 32 字节
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

    /**
     * 计算 SHA3-256 哈希。
     * @param data 待哈希字节
     * @return 32 字节哈希
     */
    private static byte[] sha3256(byte[] data) {
        SHA3Digest digest = new SHA3Digest(256);
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    /**
     * 返回 32 字节 keyfile 派生密钥（用于与密码密钥 XOR）。
     * @return 密钥，关闭后为 null
     */
    public byte[] key() {
        return key;
    }

    /**
     * 返回 32 字节 SHA3-256(key) 哈希（用于 header 存储/校验）。
     * @return 密钥哈希
     */
    public byte[] hash() {
        return hash;
    }

    /** 安全清零派生密钥，保留可公开的哈希；允许重复关闭。 */
    @Override
    public void close() {
        if (closed) return;
        SecureZero.zero(key);
        key = null;
        closed = true;
    }

    // ==================== 进度回调 ====================

    /**
     * 进度回调函数式接口。
     */
    @FunctionalInterface
    public interface ProgressCallback {

        /**
         * 进度更新回调。
         *
         * @param fraction 完成比例（0.0~1.0）
         */
        void onProgress(float fraction);
    }
}
