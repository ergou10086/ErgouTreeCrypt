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

/** Exercises actual Compose controls and their DataStore-driven password visibility. */
@RunWith(AndroidJUnit4::class)
class Lz4ArchiveUiTest {
    @get:Rule val compose = createComposeRule()
    @Test fun formatsNoticeAndPasswordFollowSettings() {
        val settings = AndroidSettings(InstrumentationRegistry.getInstrumentation().targetContext)
        val saved = runBlocking { settings.isArchiveCustomEncryption.first() }
        val savedFallback = runBlocking { settings.isArchivePasswordFallback.first() }
        try {
            runBlocking { settings.setArchiveCustomEncryption(true); settings.setArchivePasswordFallback(false) }
            compose.setContent { MaterialTheme { EncryptScreen() } }
            compose.onNodeWithText("高级选项").performScrollTo().performClick()
            compose.onNodeWithContentDescription("加密后压缩")
                .performScrollTo().performClick()
            for (format in listOf("LZ4", "TAR.LZ4", "GZ", "TAR.GZ", "7Z")) {
                compose.onNodeWithText(if (format == "LZ4") "ZIP" else when(format) {
                    "TAR.LZ4" -> "LZ4"; "GZ" -> "TAR.LZ4"; "TAR.GZ" -> "GZ"; else -> "TAR.GZ"
                }).performScrollTo().performClick()
                compose.onNodeWithText(format).performClick()
                compose.onNodeWithText("仅本工具可解", substring = true).assertExists()
                compose.onNodeWithText("压缩包密码（可选）").assertExists()
            }
            compose.onNodeWithText("压缩包密码（可选）").performScrollTo().performTextInput("archive-测试")
            runBlocking { settings.setArchiveCustomEncryption(false) }
            compose.waitUntil(5000) { compose.onAllNodesWithText("压缩包密码（可选）").fetchSemanticsNodes().isEmpty() }
            compose.onNodeWithText("仅本工具可解", substring = true).assertExists()
        } finally {
            runBlocking { settings.setArchiveCustomEncryption(saved); settings.setArchivePasswordFallback(savedFallback) }
        }
    }
}
