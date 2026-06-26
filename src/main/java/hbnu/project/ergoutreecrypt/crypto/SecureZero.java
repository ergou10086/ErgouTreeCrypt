package hbnu.project.ergoutreecrypt.crypto;

import java.util.Arrays;

/**
 * 安全清零工具
 * <p>
 * 用于在密钥材料使用完毕后尽快将其从内存中抹除，缩小敏感数据可被恢复的时间窗口。
 * <p>
 * 但是，JVM 的 JIT/GC 可能复制或重定位数组，且 {@link String} 不可在原地清零。
 * 因此本工具是"尽力而为"的，仅保证对传入的 {@code byte[]/char[]} 进行覆写。密码以 {@code String} 形式存在时无法保证清零，
 *
 * @author ErgouTree
 */
public final class SecureZero {

    private SecureZero() {
    }

    /**
     * 将字节数组填充为 0。{@code null} 安全。
     */
    public static void zero(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }

    /**
     * 将字符数组填充为 0。{@code null} 安全。
     */
    public static void zero(char[] c) {
        if (c != null) {
            Arrays.fill(c, '\0');
        }
    }

    /**
     * 清零多个字节数组，便于一次性释放一组密钥材料。
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
