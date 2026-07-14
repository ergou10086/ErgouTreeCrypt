package hbnu.project.ergoutreecrypt.crypto;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * 金丝雀令牌（Canary Token）：篡改哨兵，嵌入加密载荷中用于检测文件篡改。
 *
 * <h3>设计原理</h3>
 * <p>在加密数据中嵌入一个由 salt 派生的 16 字节已知令牌。解密后校验金丝雀是否完好。
 * 密码错误会导致解密输出为伪随机数据，金丝雀损坏的概率为 1 - 2⁻¹²⁸ ≈ 99.999...%。
 * 若金丝雀完好但 keyHash/MAC 不匹配，则极可能是人为构造的篡改攻击（概率上不可能自然发生）。
 *
 * <h3>使用方式</h3>
 * <ol>
 *   <li>加密时：调用 {@link #generate(byte[])} 用 salt 生成金丝雀，写入加密后的载荷中</li>
 *   <li>解密后：调用 {@link #verify(byte[], byte[])} 比对提取的金丝雀和期望值</li>
 * </ol>
 *
 * <h3>安全属性</h3>
 * <ul>
 *   <li>每个文件的金丝雀不同（依赖文件独特的 salt）</li>
 *   <li>攻击者无法预知目标文件的金丝雀值</li>
 *   <li>16 字节 = 128 位熵，暴力碰撞不可行</li>
 *   <li>使用 HMAC-SHA3-256 派生，非简单固定值</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class CanaryToken {

    /** 金丝雀令牌长度（16 字节 = 128 位）。 */
    public static final int CANARY_SIZE = 16;

    /** HMAC-SHA3-256 的密钥材料（固定上下文标签，非秘密）。 */
    private static final byte[] CANARY_CONTEXT = {
            'E', 'G', 'T', 'C', '-', 'c', 'a', 'n', 'a', 'r', 'y', '-', 'v', '1'
    };

    private CanaryToken() {
    }

    /**
     * 从 salt 派生金丝雀令牌。
     *
     * <p>使用 HMAC-SHA3-256(CANARY_CONTEXT, salt)，取前 16 字节。
     * 每个文件的 salt 不同，因此金丝雀也不同。
     *
     * @param salt 加密时使用的盐值（至少 16 字节）
     * @return 16 字节金丝雀令牌
     */
    public static byte[] generate(byte[] salt) {
        org.bouncycastle.crypto.digests.SHA3Digest digest =
                new org.bouncycastle.crypto.digests.SHA3Digest(256);
        org.bouncycastle.crypto.macs.HMac hmac =
                new org.bouncycastle.crypto.macs.HMac(digest);
        hmac.init(new org.bouncycastle.crypto.params.KeyParameter(CANARY_CONTEXT));
        hmac.update(salt, 0, salt.length);
        byte[] full = new byte[32];
        hmac.doFinal(full, 0);
        return Arrays.copyOf(full, CANARY_SIZE);
    }

    /**
     * 生成金丝雀令牌并写入目标数组指定偏移处。
     *
     * @param salt 加密时使用的盐值
     * @param dst  目标数组
     * @param off  写入偏移
     */
    public static void generateInto(byte[] salt, byte[] dst, int off) {
        byte[] canary = generate(salt);
        System.arraycopy(canary, 0, dst, off, CANARY_SIZE);
    }

    /**
     * 验证金丝雀令牌是否匹配。
     *
     * @param salt   加密时使用的盐值（用于重新派生期望的金丝雀）
     * @param stored 从解密数据中提取的金丝雀字节（16 字节）
     * @return 若金丝雀完整无损则返回 true
     */
    public static boolean verify(byte[] salt, byte[] stored) {
        if (stored == null || stored.length != CANARY_SIZE) {
            return false;
        }
        byte[] expected = generate(salt);
        return MessageDigest.isEqual(expected, stored);
    }

    /**
     * 验证金丝雀是否损坏。
     * 若损坏，检查是否为全零（可能指示密码错误导致的随机输出，而非篡改）。
     *
     * @param salt   盐值
     * @param stored 提取的金丝雀
     * @return CanaryResult 包含验证结果和诊断信息
     */
    public static CanaryResult verifyWithDetail(byte[] salt, byte[] stored) {
        boolean intact = verify(salt, stored);
        if (intact) {
            return CanaryResult.INTACT;
        }
        // 检查是否为全零（密码错误时的典型输出）
        boolean allZero = true;
        if (stored != null) {
            for (byte b : stored) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }
        }
        return allZero ? CanaryResult.DAMAGED_LIKELY_WRONG_PASSWORD
                : CanaryResult.DAMAGED_POSSIBLE_TAMPER;
    }

    /**
     * 金丝雀验证结果枚举。
     */
    public enum CanaryResult {
        /** 金丝雀完好 —— 数据完整，密码正确。 */
        INTACT,
        /** 金丝雀损坏（全零） —— 很可能是密码错误导致的随机解密输出。 */
        DAMAGED_LIKELY_WRONG_PASSWORD,
        /** 金丝雀损坏（非全零） —— 可能是文件被篡改或部分损坏。 */
        DAMAGED_POSSIBLE_TAMPER
    }
}
