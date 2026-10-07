package hbnu.project.ergoutreecrypt.header;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** 已完成结构校验的 FAST-v1 头；结构有效不表示密码或载荷认证已经通过。 */
public final class FastHeader {
    private final byte[] encoded;

    /**
     * 保存经读取器验证的头副本。
     * @param encoded 完整 160 字节头
     */
    FastHeader(byte[] encoded) { this.encoded = encoded.clone(); }

    /** @return 完整头的防御性副本 */
    public byte[] bytes() { return encoded.clone(); }

    /** @return 参与头认证的前 128 字节副本 */
    public byte[] authenticatedBytes() { return Arrays.copyOf(encoded, 128); }

    /** @return 16 字节 Argon2 盐值副本 */
    public byte[] argonSalt() { return Arrays.copyOfRange(encoded, 40, 56); }

    /** @return 32 字节 HKDF 盐值副本 */
    public byte[] hkdfSalt() { return Arrays.copyOfRange(encoded, 56, 88); }

    /** @return 32 字节头认证标签副本 */
    public byte[] mac() { return Arrays.copyOfRange(encoded, 128, 160); }

    /** @return 经结构校验的明文长度，仍须通过头和载荷认证 */
    public long plaintextLength() { return ByteBuffer.wrap(encoded).getLong(88); }
}
