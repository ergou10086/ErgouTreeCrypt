package hbnu.project.ergoutreecrypt.android.platform

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params

/**
 * Argon2 移动模式档位——从全局设置映射为 KDF 覆写参数。
 *
 * <p>移动端应用堆受限（largeHeap 通常 256~512 MiB），无法像桌面端一样默认使用
 * 1 GiB 内存参数。档位作为设置存储在 DataStore（{@code mobile.argon2.mode}），
 * 文件加密与隐写共用；隐写侧会把档位参数持久化进载体元数据（见
 * {@link hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata}）。
 *
 * <p>为消除"离堆 Argon2 派生慢 / 原生内存不足闪退 / 卡在 0%"等移动端适配问题，
 * 本枚举自 2026/8/28 起<b>移除 1 GiB 的 STANDARD 档</b>，并新增 {@link #AUTO}：
 * 运行时按设备当前可用堆自动选取能<b>在堆内完成</b>（秒级）的最大档位，
 * 使移动端加解密默认不再进入离堆路径。
 *
 * @property key       DataStore 中存储的档位键值
 * @property label     档位显示名称
 * @author ErgouTree
 * @since 2026/8/14
 */
enum class Argon2MobileMode(
    val key: String,
    val label: String
) {
    /** 自动：按设备当前可用堆，从高到低选取首个能堆内派生的档位。 */
    AUTO("AUTO", "自动"),

    /** 均衡 256 MiB：3 passes / 4 threads。 */
    BALANCED("BALANCED", "均衡 256 MiB"),

    /** 省电 64 MiB：2 passes / 2 threads。 */
    LIGHT("LIGHT", "省电 64 MiB");

    /**
     * 该档位的固定 KDF 参数；{@link #AUTO} 返回 null（需运行时解析）。
     *
     * @return 固定档位参数，AUTO 为 null
     */
    val tier: Tier? get() = FIXED_TIER[this]

    /**
     * 转换为隐写层使用的 Argon2 参数覆写（AUTO 会按设备堆解析后返回）。
     *
     * @return Argon2 参数覆写记录
     */
    fun toArgon2Params(): Argon2Params = resolve().toArgon2Params()

    /**
     * 解析出在给定可用堆字节数下实际生效的档位。
     *
     * <p>{@link #AUTO} 按可用堆从 {@link #AUTO_TIERS} 从高到低选取首个
     * 能堆内派生的档位；若都不满足则回退到最低档（32 MiB），保证总能完成派生。
     * 固定档位直接返回自身参数。
     *
     * @param availableHeapBytes 当前应用可用堆字节数
     * @return 实际生效的 KDF 参数
     */
    fun resolve(availableHeapBytes: Long = DeviceMemory.availableHeapBytes()): Tier {
        if (this != AUTO) {
            return FIXED_TIER.getValue(this)
        }
        return AUTO_TIERS.firstOrNull { it.fitsInHeap(availableHeapBytes) }
            ?: AUTO_TIERS.last()
    }

    /**
     * 估算该档位（AUTO 则按设备堆解析后）密钥派生所需的堆字节数。
     *
     * <p>复用共享核心 {@code Argon2Kdf.estimateRequiredHeapBytes} 的估算
     * 公式（内存参数 × 1.25 安全系数）。
     *
     * @return 估算所需堆字节数
     */
    fun estimateRequiredHeapBytes(): Long = resolve().estimateRequiredHeapBytes()

    companion object {

        /** AUTO 候选档位（从大到小，取第一个堆内可行者）。 */
        private val AUTO_TIERS = listOf(
            Tier(256 shl 10, 3, 4),
            Tier(64 shl 10, 2, 2),
            Tier(32 shl 10, 2, 2)
        )

        /** 固定档位 → 参数映射。 */
        private val FIXED_TIER = mapOf(
            BALANCED to Tier(256 shl 10, 3, 4),
            LIGHT to Tier(64 shl 10, 2, 2)
        )

        /** 档位堆内可行性判断的固定余量（32 MiB）。 */
        private const val FEASIBILITY_MARGIN_BYTES = 32L shl 20

        /**
         * 从 DataStore 存储的档位键值解析枚举，未知值回退到 {@link #AUTO}。
         *
         * @param key 档位键值
         * @return 对应的档位枚举
         */
        fun fromKey(key: String?): Argon2MobileMode =
            entries.firstOrNull { it.key == key } ?: AUTO

        /**
         * 判断某档位是否能在给定可用堆内派生（无需离堆回退）。
         *
         * <p>除 Argon2 内存本身外预留 32 MiB 固定余量（与共享核心预检一致）。
         * 注意：返回 false 不代表该档位不可用——共享核心的
         * {@code Argon2Kdf.deriveKey} 会自动回退到离堆（native 内存）实现完成
         * 派生，只是速度较慢。UI 可据此提示"将使用离堆内存"。
         *
         * @param mode 待判断的档位
         * @param availableHeapBytes 当前应用可用堆字节数（默认取实时值）
         * @return true 表示可在应用堆内派生
         */
        fun isFeasible(
            mode: Argon2MobileMode,
            availableHeapBytes: Long = DeviceMemory.availableHeapBytes()
        ): Boolean = mode.resolve(availableHeapBytes).fitsInHeap(availableHeapBytes)
    }
}

/**
 * Argon2 KDF 参数三元组（内存 KiB / 迭代次数 / 并行线程数）。
 *
 * @property memoryKiB 内存参数（KiB）
 * @property passes    迭代次数
 * @property threads   并行线程数
 */
data class Tier(
    val memoryKiB: Int,
    val passes: Int,
    val threads: Int
) {

    /**
     * 转换为隐写层使用的 Argon2 参数覆写。
     *
     * @return Argon2 参数覆写记录
     */
    fun toArgon2Params(): Argon2Params = Argon2Params(memoryKiB, passes, threads)

    /**
     * 估算该档位密钥派生所需的堆字节数（内存参数 × 1.25 安全系数）。
     *
     * @return 估算所需堆字节数
     */
    fun estimateRequiredHeapBytes(): Long =
        hbnu.project.ergoutreecrypt.crypto.Argon2Kdf.estimateRequiredHeapBytes(memoryKiB)

    /**
     * 判断该档位是否能在给定可用堆内派生（需求 + 32 MiB 余量 ≤ 可用堆）。
     *
     * @param availableHeapBytes 当前应用可用堆字节数
     * @return true 表示可堆内派生
     */
    fun fitsInHeap(availableHeapBytes: Long): Boolean =
        estimateRequiredHeapBytes() + FEASIBILITY_MARGIN_BYTES <= availableHeapBytes

    companion object {
        /** 档位堆内可行性判断的固定余量（32 MiB）。 */
        private const val FEASIBILITY_MARGIN_BYTES = 32L shl 20
    }
}
