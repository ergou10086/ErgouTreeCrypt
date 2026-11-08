package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.SplitDownloadSupport
import org.junit.Assert.*
import org.junit.Test
import org.junit.Rule
import org.junit.runner.RunWith
import java.io.File

/** 下载兼容专项：真实 ART 读取桌面产物，并导出手机实际生成的产物。 */
@RunWith(AndroidJUnit4::class)
class SplitDownloadTest {
    /** 保持测试应用在前台，避免真机系统冻结后台 instrumentation。 */
    @get:Rule val foreground = ActivityScenarioRule(MainActivity::class.java)

    /** 同一批字节在电脑 → 手机、手机 → 手机分别认证与解密。 */
    @Test fun desktopOnArtAndArtOnArt() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.filesDir, "split-downloads")
        val desktop = File(root, "desktop")
        assertEquals(36, SplitDownloadSupport.verify(desktop.toPath(), File(root, "desktop-on-android").toPath()))
        val android = File(root, "android")
        SplitDownloadSupport.generate(android.toPath(), File(desktop, "source.bin").toPath())
        assertEquals(36, SplitDownloadSupport.verify(android.toPath(), File(root, "android-self").toPath()))
    }

    /** 只在传入样本参数时读取用户指定的大分卷，不记录密码。 */
    @Test fun realDownloadOnArt() {
        val args = InstrumentationRegistry.getArguments()
        org.junit.Assume.assumeTrue(args.getString("splitRealSample") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.filesDir, "split-downloads-real")
        val input = File(root, "input").listFiles()!!.first { it.name.endsWith(".0") }
        val secret = File(root, "password")
        val password = secret.readText()
        secret.delete()
        val output = File(root, "plain")
        output.parentFile!!.mkdirs()
        try {
            val report = SplitDownloadSupport.sample(input.toPath(), output.toPath(), password)
            File(root, "report").writeText(report)
            println("REAL DOWNLOAD PASS $report")
        } finally {
            output.delete()
        }
    }
}
