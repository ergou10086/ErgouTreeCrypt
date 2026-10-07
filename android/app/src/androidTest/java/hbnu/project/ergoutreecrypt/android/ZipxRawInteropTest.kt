package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.ZipxInteropSupport
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 互通修复后仅复验受影响的原始编解码用例，不重复无变化的卷处理。 */
@RunWith(AndroidJUnit4::class)
class ZipxRawInteropTest {
    /** 读取更新后的桌面产物，再重新生成并自校验 Android 原始产物。 */
    @Test fun desktopToAndroidAndAndroidToAndroidThenExport() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.filesDir, "zipx-interop")
        ZipxInteropSupport.verifyRawArchives(File(root, "desktop").toPath(), File(root, "desktop-raw-on-android").toPath())
        ZipxInteropSupport.refreshXzArchives(File(root, "android").toPath(), true)
    }
}
