package hbnu.project.ergoutreecrypt.header;

import hbnu.project.ergoutreecrypt.crypto.fast.FastKdfPolicy;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** FAST-v1 冻结的固定头编码；所有整数采用大端序，未知字段一律拒绝。 */
public final class FastHeaderReaderWriter {
    /** 完整固定头长度。 */
    public static final int HEADER_LENGTH = 160;
    /** 参与头 HMAC 的字节数。 */
    public static final int AUTHENTICATED_LENGTH = 128;
    /** 本版本唯一支持的套件标识。 */
    public static final int SUITE_AES256_GCM_HKDF_1MB = 2;
    /** Tink 密文分段长度。 */
    public static final int SEGMENT_SIZE = 1 << 20;
    /** 单容器明文上限为 1 TiB。 */
    public static final long MAX_PLAINTEXT_LENGTH = 1L << 40;
    /** 头认证子密钥的 HKDF 域。 */
    public static final String HEADER_KEY_INFO = "EGTC-FAST-v1/header-key";
    /** 流加密子密钥的 HKDF 域。 */
    public static final String STREAM_KEY_INFO = "EGTC-FAST-v1/stream-key";
    /** 头 HMAC 输入的协议域。 */
    public static final String HEADER_DOMAIN = "EGTC-FAST-v1/header";
    /** 流 AAD 的协议域。 */
    public static final String PAYLOAD_DOMAIN = "EGTC-FAST-v1/payload";
    private static final byte[] MAGIC = "EGTCFAST".getBytes(StandardCharsets.US_ASCII);
    private FastHeaderReaderWriter() { }

    /**
     * 判断完整的外层魔数，版本和其他字段由读取器继续验证。
     * @param prefix 恰好八字节的输入
     * @return 是否为 FAST 标识
     */
    public static boolean hasMagic(byte[] prefix) { return Arrays.equals(MAGIC, prefix); }

    /**
     * 生成待认证的固定 128 字节头，不含任何扩展和高级选项标志。
     * @param length 明文长度
     * @param argonSalt 16 字节随机盐值
     * @param hkdfSalt 32 字节随机盐值
     * @return 待计算 HMAC 的头
     * @throws CryptoException 长度或盐值非法
     */
    public static byte[] unsignedHeader(long length, byte[] argonSalt, byte[] hkdfSalt) throws CryptoException {
        if (length < 0 || length > MAX_PLAINTEXT_LENGTH || argonSalt == null || argonSalt.length != 16
                || hkdfSalt == null || hkdfSalt.length != 32) {
            throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 长度或盐值尺寸非法");
        }
        ByteBuffer buffer = ByteBuffer.allocate(AUTHENTICATED_LENGTH);
        buffer.put(MAGIC).putShort((short) 1).putShort((short) 0)
                .putShort((short) SUITE_AES256_GCM_HKDF_1MB).putShort((short) 1)
                .putInt(HEADER_LENGTH).putInt(0).putInt(FastKdfPolicy.MEMORY_KIB)
                .putInt(FastKdfPolicy.PASSES).putInt(FastKdfPolicy.LANES)
                .put((byte) FastKdfPolicy.ARGON_VERSION).put((byte) FastKdfPolicy.PASSWORD_ENCODING)
                .putShort((short) 0).put(argonSalt).put(hkdfSalt).putLong(length);
        return buffer.array();
    }

    /**
     * 组合已计算标签和待认证头，并再次验证结构。
     * @param unsigned 前 128 字节
     * @param mac 32 字节 HMAC
     * @return 不可变的结构有效头
     * @throws CryptoException 结构非法
     */
    public static FastHeader withMac(byte[] unsigned, byte[] mac) throws CryptoException {
        if (unsigned == null || unsigned.length != AUTHENTICATED_LENGTH || mac == null || mac.length != 32) {
            throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 头或标签尺寸非法");
        }
        return parse(ByteBuffer.allocate(HEADER_LENGTH).put(unsigned).put(mac).array());
    }

    /**
     * 从输入流读取恰好一个头，不探测或消费后续载荷。
     * @param input 密文输入流
     * @return 结构有效的头
     * @throws IOException 读取失败
     * @throws CryptoException 截断或字段不受支持
     */
    public static FastHeader read(InputStream input) throws IOException, CryptoException {
        return parse(input.readNBytes(HEADER_LENGTH));
    }

    /**
     * 验证全部字段和保留区，不执行 KDF、不分配与密文参数成比例的内存。
     * @param bytes 完整头
     * @return 结构有效的头
     * @throws CryptoException 格式不合法或不受支持
     */
    public static FastHeader parse(byte[] bytes) throws CryptoException {
        if (bytes == null || bytes.length != HEADER_LENGTH || !hasMagic(Arrays.copyOf(bytes, 8))) {
            throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 头截断或魔数错误");
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        if (buffer.getShort(8) != 1 || buffer.getShort(10) != 0) {
            throw new CryptoException(ErrorKind.UNSUPPORTED_VERSION, "不支持的 FAST 版本");
        }
        if (buffer.getShort(12) != SUITE_AES256_GCM_HKDF_1MB || buffer.getShort(14) != 1
                || buffer.getInt(20) != 0) {
            throw new CryptoException(ErrorKind.UNSUPPORTED_FORMAT, "不支持的 FAST 套件、KDF 或标志");
        }
        if (buffer.getInt(16) != HEADER_LENGTH) throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 头长度错误");
        FastKdfPolicy.validate(buffer.getInt(24), buffer.getInt(28), buffer.getInt(32),
                bytes[36] & 255, bytes[37] & 255);
        if (bytes[38] != 0 || bytes[39] != 0) throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 保留字段非零");
        for (int i = 96; i < 128; i++) {
            if (bytes[i] != 0) throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 保留区非零");
        }
        long length = buffer.getLong(88);
        if (length < 0 || length > MAX_PLAINTEXT_LENGTH) throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 明文长度越界");
        return new FastHeader(bytes);
    }

    /**
     * 计算 RAW AES256 完整容器的唯一合法字节数，包含空文件最终段。
     * @param plaintextLength 明文长度
     * @return 160 字节外头、40 字节内头、明文和全部标签的总长度
     * @throws CryptoException 长度越界
     */
    public static long containerLength(long plaintextLength) throws CryptoException {
        if (plaintextLength < 0 || plaintextLength > MAX_PLAINTEXT_LENGTH) {
            throw new CryptoException(ErrorKind.INVALID_HEADER, "FAST 明文长度越界");
        }
        long first = SEGMENT_SIZE - 40L - 16;
        long following = SEGMENT_SIZE - 16L;
        long segments = plaintextLength <= first ? 1 : 1 + (plaintextLength - first + following - 1) / following;
        return HEADER_LENGTH + 40L + plaintextLength + segments * 16;
    }
}
