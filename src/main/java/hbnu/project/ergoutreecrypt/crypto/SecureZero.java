package hbnu.project.ergoutreecrypt.crypto;

import java.util.Arrays;

/**
 * 安全清零工具。
 *
 * <p>在密钥材料使用完毕后将其从内存中覆写为零，缩小敏感数据可被恢复的时间窗口。
 *
 * <p><b>注意：</b>JVM 的 JIT/GC 可能复制或重定位数组，且 {@link String} 不可在原地清零，
 * 因此本工具为"尽力而为"防护，仅保证对传入的 {@code byte[]} 与 {@code char[]} 进行覆写。
 *
 * @author ErgouTree
 */
public final class SecureZero {

    private SecureZero() {
    }

    /**
     * 将字节数组全填充为 0。{@code null} 安全。
     *
     * @param b 需要清零的字节数组，可为 null
     */
    public static void zero(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }

    /**
     * 将字符数组全填充为 null 字符。{@code null} 安全。
     *
     * @param c 需要清零的字符数组，可为 null
     */
    public static void zero(char[] c) {
        if (c != null) {
            Arrays.fill(c, '\0');
        }
    }

    /**
     * 批量清零多个字节数组，便于一次性释放一组密钥材料。
     *
     * @param arrays 需要清零的字节数组（可变参数），可为 null
     */
    public static void zeroAll(byte[]... arrays) {
        if (arrays == null) {
            return;
        }
        for (byte[] a : arrays) {
            zero(a);
        }
    }
}
