package hbnu.project.ergoutreecrypt.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.ui.navigation.ErgouNavGraph
import hbnu.project.ergoutreecrypt.android.ui.theme.ErgouTheme

/**
 * 主 Activity — 应用唯一入口。
 *
 * <p>使用 Jetpack Compose 渲染所有 UI，不依赖传统 XML 布局。
 * 在 setContent 中装配主题与导航。主题模式由设置中的 DataStore 驱动。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val settings = remember { AndroidSettings(applicationContext) }
            val themeMode by settings.themeMode.collectAsState(initial = "SYSTEM")

            val darkTheme = when (themeMode) {
                "LIGHT" -> false
                "DARK" -> true
                else -> isSystemInDarkTheme() // SYSTEM
            }

            ErgouTheme(darkTheme = darkTheme) {
                ErgouNavGraph()
            }
        }
    }
}
