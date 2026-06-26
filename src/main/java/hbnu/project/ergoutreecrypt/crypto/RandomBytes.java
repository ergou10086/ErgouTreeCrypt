package hbnu.project.ergoutreecrypt.crypto;

import java.security.SecureRandom;

/**
 * 密码学安全随机字节生成器。
 *
 * <p>使用 {@link SecureRandom} 生成 salt、nonce、IV 等密码学随机数，并附带非全零的健全性检查。
 *
 * @author ErgouTree
 */
public final class RandomBytes {

    /**
     * 共享的密码学安全随机数生成器实例。
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    private RandomBytes() {
    }

    /**
     * 生成 n 个密码学安全的随机字节。
     *
     * @param n 字节数
     * @return n 字节随机数组
     * @throws IllegalStateException 若生成结果为全零（极小概率，视为 RNG 故障）
     */
    public static byte[] generate(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);

        // 全零健全性检查
        boolean allZero = true;
        for (byte v : b) {
            if (v != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            throw new IllegalStateException("fatal SecureRandom error: produced zero bytes");
        }
        return b;
    }
}
