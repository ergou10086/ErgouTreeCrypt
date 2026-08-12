package hbnu.project.ergoutreecrypt.android.ui.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * 媒体加密页面 — Phase 2 已集成到加密/解密页面的高级选项中。
 *
 * <p>在"文件加密"或"文件解密"页面选择支持格式（MP3/MP4/WAV）的文件后，
 * 展开高级选项并勾选"格式保持加密/解密"即可使用。
 *
 * <p>支持的格式：MP3 / MP4 / WAV — 加密后文件仍可被播放器打开，内容为噪声。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun MediaCryptScreen() {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            "音视频格式保持加密",
            style = MaterialTheme.typography.titleLarge
        )
        Text(
            "此功能已集成到 文件加密 / 文件解密 页面中。\n选择 MP3 / MP4 / WAV 文件后，在高级选项中勾选\"格式保持加密\"即可使用。",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 12.dp)
        )
    }
}
