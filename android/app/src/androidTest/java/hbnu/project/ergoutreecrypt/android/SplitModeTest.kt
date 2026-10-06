package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport
import hbnu.project.ergoutreecrypt.settings.SettingsManager
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 两种分卷格式的桌面 → ART 和 ART → ART 认证与解密。 */
@RunWith(AndroidJUnit4::class)
class SplitModeTest {
    /** @throws Exception 两种格式的互操作或设置快照失败 */
    @Test fun desktopOnArtAndArtOnArt() {
        val root = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "split-mode")
        val desktop = File(root, "desktop")
        val saved = SettingsManager.getSplitMetadataMode()
        try {
            SettingsManager.setSplitMetadataMode(SplitMetadataMode.MANIFEST)
            assertEquals(14, SplitInteropSupport.verifyModes(desktop.toPath(), File(root, "desktop-on-android").toPath()))
            val android = File(root, "android")
            assertEquals(14, SplitInteropSupport.generateModes(android.toPath(), File(desktop, "sample.bin").toPath(), true))
            SettingsManager.setSplitMetadataMode(SplitMetadataMode.EMBEDDED)
            assertEquals(14, SplitInteropSupport.verifyModes(android.toPath(), File(root, "android-self").toPath()))
        } finally { SettingsManager.setSplitMetadataMode(saved) }
    }
}
