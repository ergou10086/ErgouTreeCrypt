package hbnu.project.ergoutreecrypt.settings;

/**
 * 桌面端 Argon2 KDF 档位枚举（Phase B2）。
 *
 * <p>桌面端此前固定使用 1 GiB 内存参数派生密钥，导致其加密的文件在移动端解密时
 * 需在受限堆内跑满 1 GiB 派生，缓慢甚至闪退。本枚举把 KDF 强度从「硬编码常量」
 * 变为「用户可选的档位」，默认 {@link #BALANCED}（256 MiB），使新文件在移动端
 * 可堆内秒级解密；需要更高抗暴力破解强度、且仅在桌面解密的用户可选
 * {@link #STRONG}（1 GiB）或 {@link #PARANOID}（1 GiB / 8 轮）。
 *
 * <p>安全基线对照（RFC 9106 / OWASP）：Argon2id 内存受限档推荐 64 MiB / 3 轮、
 * OWASP 推荐 46 MiB；本枚举最低档 256 MiB / 3 轮仍远高于上述推荐值，故默认
 * {@link #BALANCED} 并非「退到不安全」，而是从「桌面专属偏执级」退到「仍很强、
 * 且移动端可用」的档位。
 *
 * <p>档位仅控制 KDF 的 {@code memory/passes/threads} 三元组；是否启用 Serpent
 * 双重加密与 HMAC-SHA3 仍由加密请求的偏执（paranoid）标志决定，二者正交。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
public enum Argon2DesktopMode {

    /** 均衡 256 MiB：3 轮 / 4 线程，移动端堆内秒级解密（默认档）。 */
    BALANCED("BALANCED", 256 << 10, 3, 4),

    /** 强 1 GiB：4 轮 / 4 线程，与旧版桌面端普通模式一致，移动端需走 native 派生。 */
    STRONG("STRONG", 1 << 20, 4, 4),

    /** 偏执 1 GiB：8 轮 / 8 线程，最高抗暴力破解强度，移动端需走 native 派生。 */
    PARANOID("PARANOID", 1 << 20, 8, 8);

    /** 持久化到设置（{@link SettingsManager}）的档位键值。 */
    private final String key;

    /** Argon2id 内存参数（KiB）。 */
    private final int memoryKiB;

    /** Argon2id 迭代次数。 */
    private final int passes;

    /** Argon2id 并行线程数。 */
    private final int threads;

    /**
     * 构造档位枚举常量。
     *
     * @param key      持久化键值
     * @param memoryKiB 内存参数（KiB）
     * @param passes    迭代次数
     * @param threads   并行线程数
     */
    Argon2DesktopMode(String key, int memoryKiB, int passes, int threads) {
        this.key = key;
        this.memoryKiB = memoryKiB;
        this.passes = passes;
        this.threads = threads;
    }

    /**
     * 返回持久化键值。
     *
     * @return 档位键值（如 {@code "BALANCED"}）
     */
    public String getKey() {
        return key;
    }

    /**
     * 返回 Argon2id 内存参数。
     *
     * @return 内存参数（KiB）
     */
    public int getMemoryKib() {
        return memoryKiB;
    }

    /**
     * 返回 Argon2id 迭代次数。
     *
     * @return 迭代次数
     */
    public int getPasses() {
        return passes;
    }

    /**
     * 返回 Argon2id 并行线程数。
     *
     * @return 并行线程数
     */
    public int getThreads() {
        return threads;
    }

    /**
     * 返回档位显示名称对应的国际化文案键（{@code kdfTier.<key>}）。
     *
     * @return 国际化文案键
     */
    public String getLabelKey() {
        return "kdfTier." + key;
    }

    /**
     * 从持久化键值解析档位，未知值回退到 {@link #BALANCED}。
     *
     * @param key 档位键值
     * @return 对应的档位枚举
     */
    public static Argon2DesktopMode fromKey(String key) {
        for (Argon2DesktopMode mode : values()) {
            if (mode.key.equals(key)) {
                return mode;
            }
        }
        return BALANCED;
    }
}
