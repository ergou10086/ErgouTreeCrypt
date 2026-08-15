package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import hbnu.project.ergoutreecrypt.android.platform.DeviceMemory
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

/** 指示器刷新间隔（毫秒） */
private const val REFRESH_INTERVAL_MS = 1500L

/**
 * 内存使用情况指示器——低调的单行小字。
 *
 * <p>展示系统当前空闲内存与应用堆占用（已用/上限），帮助用户在加解密操作
 * 前后判断内存是否紧张（例如提取大文件前预知堆余量）。视觉上使用
 * {@code labelSmall} 字号与低透明度颜色，置于页面内容顶部右对齐，
 * 不干扰主要操作流程。
 *
 * <p>展示与否由设置项 {@code ui.memory.indicator} 控制，由各页面在调用处
 * 判断，本组件自身不感知设置。
 *
 * <p>数据每 {@value #REFRESH_INTERVAL_MS} 毫秒刷新一次：
 * <ul>
 *   <li>系统空闲：{@link android.app.ActivityManager.MemoryInfo#availMem}</li>
 *   <li>应用堆：{@code Runtime} 的已用（total - free）与上限（max）</li>
 * </ul>
 *
 * @param modifier 布局修饰符（调用方可指定对齐方式）
 * @author ErgouTree
 * @since 2026/8/15
 */
@Composable
fun MemoryIndicator(modifier: Modifier = Modifier) {
    val context = LocalContext.current

    var systemFreeBytes by remember { mutableLongStateOf(0L) }
    var heapUsedBytes by remember { mutableLongStateOf(0L) }
    var heapMaxBytes by remember { mutableLongStateOf(0L) }

    LaunchedEffect(Unit) {
        while (isActive) {
            val rt = Runtime.getRuntime()
            heapUsedBytes = rt.totalMemory() - rt.freeMemory()
            heapMaxBytes = rt.maxMemory()
            systemFreeBytes = DeviceMemory.systemMemoryInfo(context).freeBytes
            delay(REFRESH_INTERVAL_MS)
        }
    }

    Text(
        text = "内存 空闲 ${formatFileSize(systemFreeBytes)} · 堆 ${formatFileSize(heapUsedBytes)} / ${formatFileSize(heapMaxBytes)}",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.55f),
        textAlign = TextAlign.End,
        modifier = modifier.fillMaxWidth()
    )
}
