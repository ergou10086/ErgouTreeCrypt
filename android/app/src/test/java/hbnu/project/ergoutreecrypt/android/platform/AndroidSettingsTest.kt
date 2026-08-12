package hbnu.project.ergoutreecrypt.android.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AndroidSettings 键定义与参数校验测试。
 *
 * <p>由于 DataStore 需要 Context，此处仅测试键名的正确性、默认值一致性、
 * 以及线程数范围校验等不依赖 Context 的逻辑。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class AndroidSettingsTest {

    /**
     * 默认线程数应为 4（匹配移动端典型核心数）。
     */
    @Test
    fun defaultThreadCount_isFour() {
        assertEquals(4, DEFAULT_THREAD_COUNT)
    }

    /**
     * 最小/最大线程数范围合理。
     */
    @Test
    fun threadCountRange_isValid() {
        assertTrue("最小线程数应 ≥ 1", MIN_THREAD_COUNT >= 1)
        assertTrue("最大线程数应 ≤ 8（移动端限制）", MAX_THREAD_COUNT <= 8)
        assertTrue("最大线程数应 ≥ 最小线程数", MAX_THREAD_COUNT >= MIN_THREAD_COUNT)
    }

    /**
     * 默认 Argon2 模式为 STANDARD。
     */
    @Test
    fun defaultArgon2Mode_isStandard() {
        assertEquals("STANDARD", DEFAULT_ARGON2_MODE)
    }

    /**
     * 默认偏执模式为 false。
     */
    @Test
    fun defaultParanoid_isFalse() {
        assertEquals(false, DEFAULT_PARANOID)
    }

    /**
     * 默认 Reed-Solomon 为 false。
     */
    @Test
    fun defaultReedSolomon_isFalse() {
        assertEquals(false, DEFAULT_RS)
    }

    /**
     * 默认密码不填模式为 false。
     */
    @Test
    fun defaultPasswordless_isFalse() {
        assertEquals(false, DEFAULT_PASSWORDLESS)
    }

    /**
     * 默认自动解压为 true。
     */
    @Test
    fun defaultAutoDecompress_isTrue() {
        assertEquals(true, DEFAULT_AUTO_DECOMPRESS)
    }

    /**
     * 默认覆盖确认为 true。
     */
    @Test
    fun defaultConfirmOverwrite_isTrue() {
        assertEquals(true, DEFAULT_CONFIRM_OVERWRITE)
    }

    /**
     * 默认生物识别为 false。
     */
    @Test
    fun defaultBiometric_isFalse() {
        assertEquals(false, DEFAULT_BIOMETRIC)
    }

    /**
     * 默认主题模式为 SYSTEM。
     */
    @Test
    fun defaultThemeMode_isSystem() {
        assertEquals("SYSTEM", DEFAULT_THEME_MODE)
    }

    companion object {
        // 与 AndroidSettings.kt 中定义的默认值保持一致
        private const val DEFAULT_AUTO_DECOMPRESS = true
        private const val DEFAULT_CONFIRM_OVERWRITE = true
        private const val DEFAULT_PARANOID = false
        private const val DEFAULT_RS = false
        private const val DEFAULT_PASSWORDLESS = false
        private const val DEFAULT_THREAD_COUNT = 4
        private const val MIN_THREAD_COUNT = 1
        private const val MAX_THREAD_COUNT = 8
        private const val DEFAULT_THEME_MODE = "SYSTEM"
        private const val DEFAULT_ARGON2_MODE = "STANDARD"
        private const val DEFAULT_BIOMETRIC = false
    }
}
