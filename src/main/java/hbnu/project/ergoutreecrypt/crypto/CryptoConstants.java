package hbnu.project.ergoutreecrypt.crypto;

/**
 * 密码学常量
 *
 * @author ErgouTree
 */
public final class CryptoConstants {

    /**
     * 普通模式迭代次数。
     */
    public static final int ARGON2_NORMAL_PASSES = 4;

    // ---- Argon2id 参数（kdf.go）----
    /**
     * 普通模式内存（KiB），1<<20 KiB = 1 GiB。
     */
    public static final int ARGON2_NORMAL_MEMORY_KIB = 1 << 20;

    /**
     * 普通模式并行度。
     */
    public static final int ARGON2_NORMAL_THREADS = 4;

    /**
     * 偏执模式迭代次数。
     */
    public static final int ARGON2_PARANOID_PASSES = 8;

    /**
     * 偏执模式内存（KiB），与普通模式相同 1 GiB。
     */
    public static final int ARGON2_PARANOID_MEMORY_KIB = 1 << 20;

    /**
     * 偏执模式并行度。
     */
    public static final int ARGON2_PARANOID_THREADS = 8;

    /**
     * Argon2 输出密钥长度（字节）。
     */
    public static final int ARGON2_KEY_SIZE = 32;

    /**
     * v2 header HMAC 子密钥长度。
     */
    public static final int SUBKEY_HEADER_SIZE = 64;

    // ---- HKDF 子密钥尺寸（kdf.go）----
    /**
     * 载荷 MAC 子密钥长度。
     */
    public static final int SUBKEY_MAC_SIZE = 32;
    /**
     * Serpent 密钥长度。
     */
    public static final int SUBKEY_SERPENT_SIZE = 32;
    /**
     * rekey 时 XChaCha20 nonce 长度。
     */
    public static final int REKEY_NONCE_SIZE = 24;
    /**
     * rekey 时 Serpent IV 长度。
     */
    public static final int REKEY_IV_SIZE = 16;
    /**
     * 载荷 MAC 输出长度
     * BLAKE2b-512 与 HMAC-SHA3-512 均为 64 字节
     */
    public static final int MAC_SIZE = 64;

    // ---- MAC ----
    /**
     * 1 MiB，载荷分块大小。
     */
    public static final int MIB = 1 << 20;

    // ---- 数据分块 / rekey 阈值 ----
    /**
     * rekey 阈值：每 60 GiB 重新派生 nonce/IV。
     */
    public static final long REKEY_THRESHOLD = 60L * (1 << 30);

    private CryptoConstants() {
    }
}
