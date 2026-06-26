package hbnu.project.ergoutreecrypt.crypto;

import java.security.SecureRandom;

/**
 * 安全随机字节生成
 * <p>
 * 生成密码学安全的随机字节，并附带非全零的健全性检查，用于生成 salt、nonce、IV 等。
 *
 * @author ErgouTree
 */
public final class RandomBytes {

    private static final SecureRandom RANDOM = new SecureRandom();

    private RandomBytes() {
    }

    /**
     * 生成 {@code n} 个密码学安全随机字节。
     *
     * @throws IllegalStateException 若生成结果为全零，极小概率，视为 RNG 故障
     */
    public static byte[] generate(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);

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
