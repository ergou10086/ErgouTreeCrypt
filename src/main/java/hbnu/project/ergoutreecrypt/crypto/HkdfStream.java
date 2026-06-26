package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * HKDF-SHA3-256 字节流
 * <p>
 * HKDF 返回一个 {@code io.Reader}，按需连续产出 expand 阶段的密钥流。本类用 BouncyCastle 的 {@link HKDFBytesGenerator} 实现可连续读取多次 {@link #read(int)} 会从同一条 expand 流上顺序取字节。
 * <p>
 * info 为空（null），与 Go 的 {@code nil} 一致；hash 为 SHA3-256。
 *
 * @author ErgouTree
 * @since 2026/6/16
 */
public final class HkdfStream {

    private final HKDFBytesGenerator generator;

    /**
     * @param key  IKM（输入密钥材料）：Argon2 派生密钥（v1 为 XOR 后的密钥）
     * @param salt HKDF salt（32 字节，来自 header）
     */
    public HkdfStream(byte[] key, byte[] salt) {
        generator = new HKDFBytesGenerator(new SHA3Digest(256));
        generator.init(new HKDFParameters(key, salt, null));
    }

    /**
     * 从 HKDF expand 流顺序读取 {@code n} 字节。连续调用会在同一条流上继续推进，
     * 等价于 Go 对 {@code io.Reader} 的 {@code io.ReadFull}。
     */
    public byte[] read(int n) {
        byte[] out = new byte[n];
        generator.generateBytes(out, 0, n);
        return out;
    }
}
