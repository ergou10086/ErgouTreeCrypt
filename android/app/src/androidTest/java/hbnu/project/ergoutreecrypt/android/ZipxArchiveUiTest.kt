package hbnu.project.ergoutreecrypt.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.ui.screen.EncryptScreen
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** 在真实 Compose 页面验证 ZIPX 可选且保留原生密码控件。 */
@RunWith(AndroidJUnit4::class)
class ZipxArchiveUiTest {
    @get:Rule val compose = createComposeRule()

    /** 关闭自定义归档加密时，仍可使用 ZIPX 原生 AES。 */
    @Test fun nativeZipxPasswordControl() {
        val settings = AndroidSettings(InstrumentationRegistry.getInstrumentation().targetContext)
        val saved = runBlocking { settings.isArchiveCustomEncryption.first() }
        try {
            runBlocking { settings.setArchiveCustomEncryption(false) }
            compose.setContent { MaterialTheme { EncryptScreen() } }
            compose.onNodeWithText("高级选项").performScrollTo().performClick()
            compose.onNodeWithContentDescription("加密后压缩").performScrollTo().performClick()
            compose.onNodeWithText("ZIP").performScrollTo().performClick()
            compose.onNodeWithText("ZIPX").performClick()
            compose.onNodeWithText("压缩包密码（可选）").assertExists()
            compose.onNodeWithText("仅本工具可解", substring = true).assertDoesNotExist()
        } finally { runBlocking { settings.setArchiveCustomEncryption(saved) } }
    }
}
