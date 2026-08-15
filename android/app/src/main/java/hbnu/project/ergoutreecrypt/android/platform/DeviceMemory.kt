package hbnu.project.ergoutreecrypt.android.platform

import android.app.ActivityManager
import android.content.Context

/**
 * 设备内存探测工具——统一提供应用堆与系统内存的实时信息。
 *
 * <p>共享核心的 Argon2 预检（{@code Argon2Kdf.assertMemoryAvailable}）基于
 * {@code Runtime} 的堆上限判断，本类补充 Android 特有的系统内存查询
 * （{@link ActivityManager.MemoryInfo}），供内存指示器与移动端护栏阈值使用。
 *
 * <p>注意：物理内存大不等于应用可用堆大。Android 应用堆受
 * {@code android:largeHeap} 与系统 {dalvik.vm.heapsize} 限制（16 GB 内存设备
 * 通常也仅约 512 MiB），因此所有内存可行性判断都以堆上限为基准。
 *
 * @author ErgouTree
 * @since 2026/8/15
 */
object DeviceMemory {

    /** 护栏阈值下限（16 MiB）：低于此值的设备不常见，避免阈值过小失去保护意义 */
    private const val MIN_THRESHOLD_BYTES = 16L shl 20

    /** 护栏阈值上限（512 MiB）：避免大堆设备上非流式适配器一次性读入过多数据 */
    private const val MAX_THRESHOLD_BYTES = 512L shl 20

    /**
     * 当前应用可用的堆字节数。
     *
     * <p>计算方式与共享核心 {@code Argon2Kdf.availableHeapBytes()} 一致：
     * 堆上限减去已占用部分。Android 上堆上限受 largeHeap 影响。
     *
     * @return 可用堆字节数
     */
    fun availableHeapBytes(): Long {
        val rt = Runtime.getRuntime()
        return rt.maxMemory() - (rt.totalMemory() - rt.freeMemory())
    }

    /**
     * 应用堆上限字节数。
     *
     * @return 堆上限字节数
     */
    fun maxHeapBytes(): Long = Runtime.getRuntime().maxMemory()

    /**
     * 查询系统内存信息。
     *
     * @param context 上下文（用于获取 ActivityManager）
     * @return 系统内存信息快照，含 totalMem（总量）与 availMem（当前空闲）
     */
    fun systemMemoryInfo(context: Context): MemorySnapshot {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)
        return MemorySnapshot(mi.totalMem, mi.availMem)
    }

    /**
     * 计算低内存模式大文件护栏阈值（字节）。
     *
     * <p>非流式适配器的回退路径会把载体与载荷一次性读入内存（峰值约为
     * 文件大小的数倍），因此阈值取当前可用堆的四分之一，并夹在
     * {@link #MIN_THRESHOLD_BYTES}~{@link #MAX_THRESHOLD_BYTES} 之间，
     * 使护栏与设备实际能力匹配，而非固定 64 MiB。
     *
     * @return 护栏阈值字节数
     */
    fun lowMemoryThresholdBytes(): Long {
        val quarter = availableHeapBytes() / 4
        return quarter.coerceIn(MIN_THRESHOLD_BYTES, MAX_THRESHOLD_BYTES)
    }

    /**
     * 系统内存信息快照。
     *
     * @param totalBytes 系统内存总量（字节）
     * @param freeBytes  系统当前空闲内存（字节）
     */
    data class MemorySnapshot(
        val totalBytes: Long,
        val freeBytes: Long
    )
}
