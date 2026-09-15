package hbnu.project.ergoutreecrypt.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * {@link HkdfStream} 的 info 重载回归测试。
 *
 * <p>为图片协议新增三参构造器后，旧的两参构造器必须逐字节保持原有输出，否则卷、媒体与
 * 隐写的既有文件将无法解密。本测试用"等价形态比较 + 冻结向量"两道防线守住这一点。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class HkdfStreamInfoTest {

    /**
     * 测试用 IKM。
     */
    private static final byte[] IKM = "input key material for hkdf".getBytes(StandardCharsets.US_ASCII);

    /**
     * 测试用 salt。
     */
    private static final byte[] SALT = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    /**
     * 历史两参构造器在固定输入下的输出，冻结以防回归。
     *
     * <p>该值来自本次改造<b>之前</b>的实现语义（info 为空），任何变化都意味着旧文件失配。
     */
    private static final String LEGACY_VECTOR_HEX = "2e5d471e2a73a3d99faca36ba6521abf";

    /**
     * 两参构造器必须等价于显式传入 null 或空 info。
     */
    @Test
    void twoArgumentConstructorKeepsEmptyInfoSemantics() {
        byte[] legacy = new HkdfStream(IKM, SALT).read(16);
        byte[] explicitNull = new HkdfStream(IKM, SALT, null).read(16);
        byte[] emptyInfo = new HkdfStream(IKM, SALT, new byte[0]).read(16);

        assertArrayEquals(legacy, explicitNull);
        assertArrayEquals(legacy, emptyInfo);
    }

    /**
     * 非空 info 必须改变派生结果，这就是域分离的意义所在。
     */
    @Test
    void nonEmptyInfoChangesTheDerivedStream() {
        byte[] legacy = new HkdfStream(IKM, SALT).read(32);
        byte[] contextual = new HkdfStream(IKM, SALT,
                "ErgouTreeCrypt/EGTC-IMG/v1".getBytes(StandardCharsets.US_ASCII)).read(32);
        assertFalse(Arrays.equals(legacy, contextual));
    }

    /**
     * 连续读取必须等价于一次读取全部，保证流式语义未被破坏。
     */
    @Test
    void sequentialReadsMatchASingleRead() {
        byte[] chunked = new byte[80];
        HkdfStream stream = new HkdfStream(IKM, SALT, null);
        byte[] first = stream.read(32);
        byte[] second = stream.read(48);
        System.arraycopy(first, 0, chunked, 0, 32);
        System.arraycopy(second, 0, chunked, 32, 48);
        assertArrayEquals(new HkdfStream(IKM, SALT, null).read(80), chunked);
    }

    /**
     * 冻结向量：确认本次改造没有悄悄改变旧路径的派生结果。
     */
    @Test
    void legacyVectorIsStable() {
        String actual = toHex(new HkdfStream(IKM, SALT).read(16));
        assertEquals(LEGACY_VECTOR_HEX, actual,
                "两参 HkdfStream 的输出发生变化，旧卷/媒体/隐写文件会解密失败");
    }

    /**
     * 渲染为小写十六进制。
     *
     * @param data 字节数组
     * @return 十六进制文本
     */
    private static String toHex(final byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte b : data) {
            builder.append(Character.forDigit((b >> 4) & 0xf, 16));
            builder.append(Character.forDigit(b & 0xf, 16));
        }
        return builder.toString();
    }
}
