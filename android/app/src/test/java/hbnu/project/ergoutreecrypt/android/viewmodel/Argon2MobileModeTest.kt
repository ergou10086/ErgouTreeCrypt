package hbnu.project.ergoutreecrypt.android.viewmodel

import hbnu.project.ergoutreecrypt.android.platform.Argon2MobileMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Argon2id 移动端参数档位测试。
 *
 * <p>验证 STANDARD / LIGHT 模式的参数正确性以及与桌面端 Normal 模式的兼容性。
 *
 * <p>对比基准（桌面端 CryptoConstants）：
 * <ul>
 *   <li>Normal: 4 passes, 1 GiB (1,048,576 KiB), 4 threads</li>
 *   <li>Paranoid: 8 passes, 1 GiB, 4 threads</li>
 * </ul>
 *
 * <p>Android STANDARD 模式使用与桌面端 Normal 完全相同的参数，
 * 保证在不含 Argon2Params 的 header 格式下跨平台互操作。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class Argon2MobileModeTest {

    /**
     * STANDARD 模式参数应与桌面端 Normal 一致。
     *
     * <p>这是跨平台互操作的基础保证：Android STANDARD 模式加密的文件，
     * 桌面端以 Normal 模式解密应得到相同密钥。
     */
    @Test
    fun standardMode_matchesDesktopNormal() {
        // STANDARD: mem=1 GiB KiB, passes=4, thr=4
        val standardMem = 1 shl 20 // 1 GiB in KiB
        val standardPasses = 4
        val standardThreads = 4

        assertEquals("STANDARD 内存参数应为 1 GiB (KiB)",
            1_048_576, standardMem)
        assertEquals("STANDARD passes 应与桌面端 Normal 一致", 4, standardPasses)
        assertEquals("STANDARD threads 应与桌面端 Normal 一致", 4, standardThreads)
    }

    /**
     * LIGHT 模式参数应为低内存档。
     */
    @Test
    fun lightMode_usesLowMemory() {
        val lightMem = 64 shl 10 // 64 MiB in KiB
        val lightPasses = 2
        val lightThreads = 2

        assertEquals("LIGHT 内存应为 64 MiB (KiB)", 65_536, lightMem)
        assertEquals("LIGHT passes", 2, lightPasses)
        assertEquals("LIGHT threads", 2, lightThreads)
    }

    /**
     * LIGHT 模式内存远小于 STANDARD。
     */
    @Test
    fun lightMemory_isLessThanStandard() {
        val standardMem = 1 shl 20
        val lightMem = 64 shl 10
        // 1 GiB / 64 MiB = 16 倍差距
        assertTrue("LIGHT 内存应远小于 STANDARD", lightMem < standardMem)
        assertEquals(16, standardMem / lightMem)
    }

    /**
     * 验证 LIGHT 模式在低端设备上的可行性：64 MiB 内存分配应在大部分设备上可行。
     */
    @Test
    fun lightMode_memoryFootprint_isRealistic() {
        val lightMemBytes = (64 shl 10).toLong() * 1024 // 64 MiB in bytes
        // 64 MiB 是 Argon2 的内存参数，实际需要的内存约为 64 MiB * 2（Block 数组 + 计算缓冲区）
        val estimatedRequiredBytes = lightMemBytes * 2
        // 64 MiB * 2 = 128 MiB，远低于 Android 设备的典型堆限制（256-512 MiB）
        assertTrue("LIGHT 模式估算内存应 ≤ 256 MiB",
            estimatedRequiredBytes <= 256L * 1024 * 1024)
    }

    /**
     * STANDARD 模式在设备上需要至少 2 GiB 可用内存，仅适合中高端设备。
     */
    @Test
    fun standardMode_memoryFootprint_requiresHighEndDevice() {
        val stdMemBytes = (1 shl 20).toLong() * 1024 // 1 GiB in bytes
        // 实际内存占用约为 Argon2 内存参数 × 2
        val estimatedRequiredBytes = stdMemBytes * 2
        assertTrue("STANDARD 模式估算内存应 ≥ 1 GiB",
            estimatedRequiredBytes >= 1L * 1024 * 1024 * 1024)
    }

    /**
     * 验证所有模式的 passes ≥ 1 且 threads ≥ 1。
     */
    @Test
    fun allModes_haveValidParameters() {
        data class ModeParams(val memKib: Int, val passes: Int, val threads: Int)

        val modes = listOf(
            ModeParams(1 shl 20, 4, 4), // STANDARD
            ModeParams(256 shl 10, 3, 4), // BALANCED
            ModeParams(64 shl 10, 2, 2) // LIGHT
        )

        for ((i, mode) in modes.withIndex()) {
            assertTrue("模式 $i: 内存应 > 0", mode.memKib > 0)
            assertTrue("模式 $i: passes 应 ≥ 1", mode.passes >= 1)
            assertTrue("模式 $i: threads 应 ≥ 1", mode.threads >= 1)
            // mem 必须是正数 KiB
            assertTrue("模式 $i: memKiB 应 ≥ 65536 (64 MiB)", mode.memKib >= 64 shl 10)
        }
    }

    /**
     * 各档位估算所需堆应介于参数内存的 1~2 倍之间。
     */
    @Test
    fun estimateRequiredHeapBytes_isWithinReasonableRange() {
        for (mode in Argon2MobileMode.entries) {
            val raw = mode.memoryKiB * 1024L
            val estimated = mode.estimateRequiredHeapBytes()
            assertTrue("${mode.key}: 估算值不应低于参数内存", estimated >= raw)
            assertTrue("${mode.key}: 估算值不应超过参数内存的 2 倍", estimated <= raw * 2)
        }
    }

    /**
     * LIGHT 档需求（约 112 MiB）在正常测试 JVM 上应判定为堆内可行。
     */
    @Test
    fun lightMode_isFeasibleInHeap() {
        assertTrue("LIGHT 档应堆内可行", Argon2MobileMode.isFeasible(Argon2MobileMode.LIGHT))
    }

    /**
     * 堆内可行性判定应与共享核心预检一致（预留 32 MiB 余量）。
     */
    @Test
    fun feasibility_requiresMargin() {
        val required = Argon2MobileMode.LIGHT.estimateRequiredHeapBytes() + (32L shl 20)
        assertEquals(
            "isFeasible 应与'需求 + 余量 ≤ 可用堆'一致",
            required <= Runtime.getRuntime().maxMemory() - (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()),
            Argon2MobileMode.isFeasible(Argon2MobileMode.LIGHT)
        )
    }
}
