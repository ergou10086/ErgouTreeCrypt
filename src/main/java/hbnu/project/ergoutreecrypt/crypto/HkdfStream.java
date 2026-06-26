package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * HKDF-SHA3-256 扩展字节流。
 *
 * <p>封装 BouncyCastle 的 {@link HKDFBytesGenerator}，提供可连续读取的 expand 阶段字节流。
 * 连续多次调用 {@link #read(int)} 会从同一条 expand 流上顺序取字节。
 * info 参数为空（null），哈希函数为 SHA3-256。
 *
 * @author ErgouTree
 * @since 2026/6/16
 */
public final class HkdfStream {

    /**
     * BouncyCastle HKDF expand 字节生成器。
     */
    private final HKDFBytesGenerator generator;

    /**
     * 初始化 HKDF 流。
     *
     * @param key  IKM（输入密钥材料）：Argon2 派生密钥（v1 为 XOR 后密钥）
     * @param salt HKDF salt（32 字节，来自 header）
     */
    public HkdfStream(byte[] key, byte[] salt) {
        generator = new HKDFBytesGenerator(new SHA3Digest(256));
        generator.init(new HKDFParameters(key, salt, null));
    }

    /**
     * 从 HKDF expand 流顺序读取 n 字节。
     * 连续调用会在同一条流上继续推进，每次返回新分配的数组。
     *
     * @param n 需要读取的字节数
     * @return 新分配的 n 字节数组
     */
    public byte[] read(int n) {
        byte[] out = new byte[n];
        generator.generateBytes(out, 0, n);
        return out;
    }
}
