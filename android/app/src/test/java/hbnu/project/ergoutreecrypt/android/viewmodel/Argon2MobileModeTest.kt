package hbnu.project.ergoutreecrypt.android.viewmodel

import hbnu.project.ergoutreecrypt.android.platform.Argon2MobileMode
import hbnu.project.ergoutreecrypt.android.platform.Tier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Argon2id 移动端参数档位测试。
 *
 * <p>验证 AUTO / BALANCED / LIGHT 档位的参数正确性、AUTO 按堆自动降档、
 * 未知键回退 AUTO 等行为。自 2026/8/28 起移除 1 GiB 的 STANDARD 档，
 * 移动端默认使用 AUTO（保证堆内派生）。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class Argon2MobileModeTest {

    /**
     * BALANCED 档位参数应为 256 MiB / 3 passes / 4 threads。
     */
    @Test
    fun balancedMode_usesExpectedParams() {
        val tier = Argon2MobileMode.BALANCED.tier!!
        assertEquals("BALANCED 内存应为 256 MiB (KiB)", 256 shl 10, tier.memoryKiB)
        assertEquals("BALANCED passes", 3, tier.passes)
        assertEquals("BALANCED threads", 4, tier.threads)
    }

    /**
     * LIGHT 档位参数应为 64 MiB / 2 passes / 2 threads。
     */
    @Test
    fun lightMode_usesExpectedParams() {
        val tier = Argon2MobileMode.LIGHT.tier!!
        assertEquals("LIGHT 内存应为 64 MiB (KiB)", 64 shl 10, tier.memoryKiB)
        assertEquals("LIGHT passes", 2, tier.passes)
        assertEquals("LIGHT threads", 2, tier.threads)
    }

    /**
     * AUTO 档没有固定参数，须运行时解析。
     */
    @Test
    fun autoMode_hasNoFixedTier() {
        assertEquals("AUTO 档不应有固定参数", null, Argon2MobileMode.AUTO.tier)
    }

    /**
     * AUTO 在可用堆充足时应解析为最大档（256 MiB）。
     */
    @Test
    fun autoMode_resolvesToLargestWhenHeapIsLarge() {
        val hugeHeap = 4L * 1024 * 1024 * 1024
        val tier = Argon2MobileMode.AUTO.resolve(hugeHeap)
        assertEquals("堆充足时 AUTO 应选 256 MiB", 256 shl 10, tier.memoryKiB)
    }

    /**
     * AUTO 在可用堆偏小时应降档为 64 MiB。
     */
    @Test
    fun autoMode_resolvesToLightWhenHeapIsTight() {
        // 200 MiB 堆：装不下 256 MiB（需 352 MiB），应降到 64 MiB
        val tightHeap = 200L * 1024 * 1024
        val tier = Argon2MobileMode.AUTO.resolve(tightHeap)
        assertEquals("200 MiB 堆应降档为 64 MiB", 64 shl 10, tier.memoryKiB)
    }

    /**
     * AUTO 在堆极小时应回退到最低档（32 MiB），保证总能完成派生。
     */
    @Test
    fun autoMode_fallsBackToMinimumTier() {
        val tinyHeap = 48L * 1024 * 1024
        val tier = Argon2MobileMode.AUTO.resolve(tinyHeap)
        assertEquals("极小堆应回退到 32 MiB", 32 shl 10, tier.memoryKiB)
    }

    /**
     * 固定档位 resolve 应始终返回自身参数，不受堆影响。
     */
    @Test
    fun fixedMode_ignoresHeap() {
        val lightTier = Argon2MobileMode.LIGHT.resolve(0)
        assertEquals("LIGHT 不受堆影响", 64 shl 10, lightTier.memoryKiB)
    }

    /**
     * 未知键应回退到 AUTO。
     */
    @Test
    fun fromKey_unknownFallsBackToAuto() {
        assertEquals(Argon2MobileMode.AUTO, Argon2MobileMode.fromKey("NON_EXISTENT"))
        assertEquals(Argon2MobileMode.AUTO, Argon2MobileMode.fromKey(null))
        assertEquals(Argon2MobileMode.BALANCED, Argon2MobileMode.fromKey("BALANCED"))
        assertEquals(Argon2MobileMode.LIGHT, Argon2MobileMode.fromKey("LIGHT"))
    }

    /**
     * 所有固定档位的估算堆应介于参数内存的 1~2 倍之间。
     */
    @Test
    fun estimateRequiredHeapBytes_isWithinReasonableRange() {
        for (tier in listOf(
            Tier(256 shl 10, 3, 4),
            Tier(64 shl 10, 2, 2),
            Tier(32 shl 10, 2, 2)
        )) {
            val raw = tier.memoryKiB * 1024L
            val estimated = tier.estimateRequiredHeapBytes()
            assertTrue("${tier.memoryKiB}: 估算值不应低于参数内存", estimated >= raw)
            assertTrue("${tier.memoryKiB}: 估算值不应超过参数内存的 2 倍", estimated <= raw * 2)
        }
    }

    /**
     * LIGHT 档在正常测试 JVM 上应判定为堆内可行。
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
        val available = Runtime.getRuntime().maxMemory() -
                (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())
        assertEquals(
            "isFeasible 应与'需求 + 余量 ≤ 可用堆'一致",
            required <= available,
            Argon2MobileMode.isFeasible(Argon2MobileMode.LIGHT)
        )
    }
}
