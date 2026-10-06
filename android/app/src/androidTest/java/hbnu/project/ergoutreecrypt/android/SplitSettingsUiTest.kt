package hbnu.project.ergoutreecrypt.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.ui.screen.SettingsScreen
import hbnu.project.ergoutreecrypt.i18n.Messages
import hbnu.project.ergoutreecrypt.settings.SettingsManager
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode
import hbnu.project.ergoutreecrypt.volume.EncryptRequest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** 实际 Compose 设置页与 DataStore 冷启动同步验证。 */
@RunWith(AndroidJUnit4::class)
class SplitSettingsUiTest {
    @get:Rule val compose = createComposeRule()
    /** @throws Exception 设置切换、重新同步或版本不匹配 */
    @Test fun choicesPersistAndReachCore() {
        val settings = AndroidSettings(InstrumentationRegistry.getInstrumentation().targetContext.applicationContext)
        val saved = runBlocking { settings.splitMetadataMode.first() }
        try {
            compose.setContent { MaterialTheme { SettingsScreen() } }
            for (mode in SplitMetadataMode.values()) {
                compose.onNodeWithText(Messages.get(mode.labelKey)).performScrollTo().performClick()
                compose.waitUntil(10000) { SettingsManager.getSplitMetadataMode() == mode }
                compose.onNodeWithText(Messages.get(mode.labelKey)).assertIsSelected()
                runBlocking {
                    assertEquals(mode, AndroidSettings(InstrumentationRegistry.getInstrumentation().targetContext).splitMetadataMode.first())
                    SettingsManager.setSplitMetadataMode(if (mode == SplitMetadataMode.EMBEDDED) SplitMetadataMode.MANIFEST else SplitMetadataMode.EMBEDDED)
                    settings.syncToSettingsManager()
                }
                assertEquals(mode, SettingsManager.getSplitMetadataMode())
                assertEquals(mode, EncryptRequest().splitMetadataMode)
            }
            assertEquals(InstrumentationRegistry.getArguments().getString("expectedVersion"), BuildConfig.APP_VERSION_NAME)
            val parts = BuildConfig.APP_VERSION_NAME.split('.').map { it.toInt() }
            assertEquals(parts[0] * 10000 + parts[1] * 100 + parts[2], BuildConfig.VERSION_CODE)
        } finally { runBlocking { settings.setSplitMetadataMode(saved) } }
    }
}
