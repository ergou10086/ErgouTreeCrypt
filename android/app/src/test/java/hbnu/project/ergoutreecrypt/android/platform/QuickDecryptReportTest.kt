package hbnu.project.ergoutreecrypt.android.platform

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 快速解密报告格式测试。
 */
class QuickDecryptReportTest {

    /**
     * 报告应完整展示各分类计数与失败文件名。
     */
    @Test
    fun summary_containsAllOutcomeCategories() {
        val report = QuickDecryptReport(
            scanned = 100,
            decrypted = 3,
            deleted = 2,
            passwordProtected = 4,
            unrelated = 92,
            failed = 1,
            deleteFailed = 1,
            failureNames = listOf("broken.egimg.png")
        )

        val summary = report.summary()
        assertTrue(summary.contains("扫描图片：100 张"))
        assertTrue(summary.contains("忽略密码保护：4 张"))
        assertTrue(summary.contains("源图删除失败：1 张"))
        assertTrue(summary.contains("broken.egimg.png"))
    }
}
