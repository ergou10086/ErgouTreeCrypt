package hbnu.project.ergoutreecrypt.android.platform

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params

/**
 * Argon2 移动模式档位——从全局设置映射为 KDF 覆写参数。
 *
 * <p>桌面端默认使用 1 GiB 内存参数，移动端受堆内存限制（largeHeap 通常
 * 256~512 MB），使用更低的内存档位。档位作为设置存储在 DataStore
 * （{@code mobile.argon2.mode}），文件加密与隐写共用；
 * 隐写侧会把档位参数持久化进载体元数据（见
 * {@link hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata}）。
 *
 * @property key       DataStore 中存储的档位键值
 * @property label     档位显示名称
 * @property memoryKiB 内存参数（KiB）
 * @property passes    迭代次数
 * @property threads   并行线程数
 * @author ErgouTree
 * @since 2026/8/14
 */
enum class Argon2MobileMode(
    val key: String,
    val label: String,
    val memoryKiB: Int,
    val passes: Int,
    val threads: Int
) {
    STANDARD("STANDARD", "标准 1 GiB", 1 shl 20, 4, 4),
    BALANCED("BALANCED", "均衡 256 MiB", 256 shl 10, 3, 4),
    LIGHT("LIGHT", "省电 64 MiB", 64 shl 10, 2, 2);

    /**
     * 转换为隐写层使用的 Argon2 参数覆写。
     *
     * @return Argon2 参数覆写记录
     */
    fun toArgon2Params(): Argon2Params = Argon2Params(memoryKiB, passes, threads)

    /**
     * 估算该档位密钥派生所需的堆字节数。
     *
     * <p>复用共享核心 {@code Argon2Kdf.estimateRequiredHeapBytes} 的估算
     * 公式（内存参数 × 1.25 安全系数）。
     *
     * @return 估算所需堆字节数
     */
    fun estimateRequiredHeapBytes(): Long =
        hbnu.project.ergoutreecrypt.crypto.Argon2Kdf.estimateRequiredHeapBytes(memoryKiB)

    companion object {

        /**
         * 从 DataStore 存储的档位键值解析枚举，未知值回退到 STANDARD。
         *
         * @param key 档位键值
         * @return 对应的档位枚举
         */
        fun fromKey(key: String?): Argon2MobileMode =
            entries.firstOrNull { it.key == key } ?: STANDARD

        /**
         * 判断某档位是否能在设备当前应用堆内派生（无需离堆回退）。
         *
         * <p>除 Argon2 内存本身外预留 32 MiB 固定余量（与共享核心预检一致）。
         * 注意：返回 false 不代表该档位不可用——共享核心的
         * {@code Argon2Kdf.deriveKey} 会自动回退到离堆（native 内存）实现完成
         * 派生，只是速度较慢。UI 可据此提示"将使用离堆内存"。
         *
         * @param mode 待判断的档位
         * @return true 表示可在应用堆内派生
         */
        fun isFeasible(mode: Argon2MobileMode): Boolean {
            val required = mode.estimateRequiredHeapBytes() + FEASIBILITY_MARGIN_BYTES
            return required <= DeviceMemory.availableHeapBytes()
        }

        /** 档位堆内可行性判断的固定余量（32 MiB） */
        private const val FEASIBILITY_MARGIN_BYTES = 32L shl 20
    }
}
