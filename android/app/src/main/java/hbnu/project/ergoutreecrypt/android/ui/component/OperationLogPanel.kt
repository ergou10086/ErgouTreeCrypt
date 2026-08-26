package hbnu.project.ergoutreecrypt.android.ui.component

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Article
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import hbnu.project.ergoutreecrypt.i18n.Messages
import hbnu.project.ergoutreecrypt.log.LogEvent
import hbnu.project.ergoutreecrypt.log.LogLevel
import hbnu.project.ergoutreecrypt.log.LogListener
import hbnu.project.ergoutreecrypt.log.LogService

/**
 * 顶栏日志与操作历史按钮组。
 *
 * <p>日志图标位于历史图标左侧；当前页日志框展开时日志图标使用主色高亮。
 *
 * @param logVisible    当前页日志框是否可见
 * @param onToggleLog   切换当前页日志框
 * @param onOpenHistory 打开操作历史
 */
@Composable
fun LogHistoryActions(
    logVisible: Boolean,
    onToggleLog: () -> Unit,
    onOpenHistory: () -> Unit
) {
    IconButton(onClick = onToggleLog) {
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.Article,
            contentDescription = msg("logs.title", "日志"),
            tint = if (logVisible) {
                MaterialTheme.colorScheme.primary
            } else {
                LocalContentColor.current
            }
        )
    }
    IconButton(onClick = onOpenHistory) {
        Icon(
            imageVector = Icons.Outlined.History,
            contentDescription = "操作历史"
        )
    }
}

/**
 * 页内操作日志框：出现在高级选项下方，仅当前页可见，提供清空与复制。
 *
 * @param visible  是否展开显示
 * @param modifier 修饰符
 */
@Composable
fun OperationLogPanel(
    visible: Boolean,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val events = remember { mutableStateListOf<LogEvent>() }
    val listState = rememberLazyListState()
    val mainHandler = remember { Handler(Looper.getMainLooper()) }

    DisposableEffect(Unit) {
        events.clear()
        events.addAll(LogService.snapshot())
        var disposed = false
        val listener = object : LogListener {
            override fun onEvent(event: LogEvent) {
                mainHandler.post {
                    if (!disposed) {
                        events.add(event)
                    }
                }
            }

            override fun onCleared() {
                mainHandler.post {
                    if (!disposed) {
                        events.clear()
                    }
                }
            }
        }
        LogService.addListener(listener)
        onDispose {
            disposed = true
            LogService.removeListener(listener)
        }
    }

    LaunchedEffect(events.size, visible) {
        if (visible && events.isNotEmpty()) {
            listState.scrollToItem(events.lastIndex)
        }
    }

    AnimatedVisibility(
        visible = visible,
        enter = expandVertically(),
        exit = shrinkVertically(),
        modifier = modifier.fillMaxWidth()
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
            )
        ) {
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                Text(
                    text = msg("logs.title", "日志"),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Medium
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(220.dp)
                ) {
                    if (events.isEmpty()) {
                        Text(
                            text = msg("logs.empty", "暂无日志"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.align(Alignment.Center)
                        )
                    } else {
                        LazyColumn(state = listState, modifier = Modifier.fillMaxWidth()) {
                            itemsIndexed(events) { _, event ->
                                Text(
                                    text = event.formatLine(),
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    lineHeight = 15.sp,
                                    color = colorFor(event.level),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 1.dp)
                                )
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(onClick = { LogService.clear() }) {
                        Text(msg("logs.clear", "清空"))
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    FilledTonalButton(onClick = { copyLogs(context) }) {
                        Text(msg("logs.copy", "复制日志"))
                    }
                }
            }
        }
    }
}

/**
 * 按级别着色日志行。
 *
 * @param level 日志级别
 * @return 对应颜色
 */
@Composable
private fun colorFor(level: LogLevel) = when (level) {
    LogLevel.ERROR -> MaterialTheme.colorScheme.error
    LogLevel.WARN -> MaterialTheme.colorScheme.tertiary
    LogLevel.TRACE -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.75f)
    else -> MaterialTheme.colorScheme.onSurface
}

/**
 * 将内存日志复制到剪贴板。
 *
 * @param context 用于剪贴板与 Toast
 */
private fun copyLogs(context: Context) {
    val text = LogService.exportText()
    if (text.isBlank()) {
        Toast.makeText(context, msg("logs.copyEmpty", "暂无日志可复制"), Toast.LENGTH_SHORT).show()
        return
    }
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("ergou_log", text))
    Toast.makeText(context, msg("logs.copySuccess", "日志已复制"), Toast.LENGTH_SHORT).show()
}

/**
 * 读取 i18n 文案，缺失或尚未同步时使用回退文本。
 *
 * <p>{@link Messages#get} 找不到 key 时返回 {@code !key!} 而不抛异常，
 * 因此不能只靠 catch。
 *
 * @param key      资源键
 * @param fallback 回退文本
 * @return 文案
 */
private fun msg(key: String, fallback: String): String {
    val text = try {
        Messages.get(key)
    } catch (_: Exception) {
        return fallback
    }
    return if (text == "!$key!") fallback else text
}
