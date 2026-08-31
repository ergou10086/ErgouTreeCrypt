package hbnu.project.ergoutreecrypt.android.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 文件名安全化测试。
 *
 * <p>验证 {@link FileNameSanitizer} 在过滤跨平台危险字符（{@code / |} 等）的同时，
 * 完整保留中文、日文、emoji 等合法 Unicode 字符，不产生乱码。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
class FileNameSanitizerTest {

    /**
     * 中文文件名应原样保留。
     */
    @Test
    fun sanitize_preservesChinese() {
        assertEquals("工作报告.docx", FileNameSanitizer.sanitize("工作报告.docx"))
    }

    /**
     * 日文文件名应原样保留。
     */
    @Test
    fun sanitize_preservesJapanese() {
        assertEquals("秘密のファイル.txt", FileNameSanitizer.sanitize("秘密のファイル.txt"))
    }

    /**
     * emoji（含代理对）应原样保留，不被拆成乱码。
     */
    @Test
    fun sanitize_preservesEmoji() {
        assertEquals("🎉测试😀.mp4", FileNameSanitizer.sanitize("🎉测试😀.mp4"))
    }

    /**
     * 中英日 emoji 混合文件名应整体保留。
     */
    @Test
    fun sanitize_preservesMixedUnicode() {
        assertEquals(
            "报告レポート🎉report.txt",
            FileNameSanitizer.sanitize("报告レポート🎉report.txt")
        )
    }

    /**
     * 路径分隔符与跨平台非法字符应被替换为下划线。
     */
    @Test
    fun sanitize_replacesIllegalCharacters() {
        assertEquals("a_b_c_d.txt", FileNameSanitizer.sanitize("a/b\\c:d.txt"))
        assertEquals("x_y_z", FileNameSanitizer.sanitize("x|y*z"))
        assertEquals("p_q_r", FileNameSanitizer.sanitize("p?q\"r"))
        assertEquals("m_n_o", FileNameSanitizer.sanitize("m<n>o"))
    }

    /**
     * 控制字符应被替换为下划线。
     */
    @Test
    fun sanitize_replacesControlCharacters() {
        assertEquals("a_b", FileNameSanitizer.sanitize("a\u0000b"))
        assertEquals("a_b", FileNameSanitizer.sanitize("a\u001Fb"))
        assertEquals("a_b", FileNameSanitizer.sanitize("a\u007Fb"))
    }

    /**
     * 首尾空格与点应被去除（避免 Windows 静默裁剪导致名字与预期不符）。
     */
    @Test
    fun sanitize_trimsLeadingAndTrailingSpacesAndDots() {
        assertEquals("report.txt", FileNameSanitizer.sanitize("  report.txt  "))
        assertEquals("report.txt", FileNameSanitizer.sanitize("...report.txt..."))
    }

    /**
     * 空名或纯点应回退为 "file"。
     */
    @Test
    fun sanitize_fallsBackForEmptyOrDotsOnly() {
        assertEquals("file", FileNameSanitizer.sanitize(""))
        assertEquals("file", FileNameSanitizer.sanitize("..."))
        assertEquals("file", FileNameSanitizer.sanitize("   "))
    }

    /**
     * Windows 保留设备名应加下划线前缀规避。
     */
    @Test
    fun sanitize_escapesReservedDeviceNames() {
        assertEquals("_CON", FileNameSanitizer.sanitize("CON"))
        assertEquals("_con.txt", FileNameSanitizer.sanitize("con.txt"))
        assertEquals("_LPT1", FileNameSanitizer.sanitize("LPT1"))
    }

    /**
     * 超长文件名应按 UTF-8 字节数截断到 255 以内，且不拆分代理对。
     */
    @Test
    fun sanitize_truncatesLongNameByUtf8Bytes() {
        val long = "あ".repeat(200)
        val result = FileNameSanitizer.sanitize(long)
        assertTrue("截断后 UTF-8 字节数不应超过 255", result.toByteArray(Charsets.UTF_8).size <= 255)
        assertFalse("截断结果不应包含未配对代理项", result.any { it.isSurrogate() })
    }

    /**
     * 相对路径应逐段清洗并保留段间分隔符。
     */
    @Test
    fun sanitizePathSegments_sanitizesEachSegment() {
        assertEquals(
            "sub_dir/报告.docx",
            FileNameSanitizer.sanitizePathSegments("sub:dir/报告.docx")
        )
        assertEquals("报告レポート🎉.mp4", FileNameSanitizer.sanitizePathSegments("报告レポート🎉.mp4"))
    }

    /**
     * 安全化函数应幂等：对已安全化的名字再次调用结果不变。
     */
    @Test
    fun sanitize_isIdempotent() {
        val once = FileNameSanitizer.sanitize("报告/🎉.docx")
        val twice = FileNameSanitizer.sanitize(once)
        assertEquals(once, twice)
    }
}
