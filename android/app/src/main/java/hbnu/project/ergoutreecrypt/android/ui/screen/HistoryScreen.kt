package hbnu.project.ergoutreecrypt.android.ui.screen

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationRecord
import hbnu.project.ergoutreecrypt.history.OperationType
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** 历史列表时间展示格式。 */
private val TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")

/**
 * 根据操作类型返回图标。
 *
 * @param type 操作类型
 * @return 对应的 Material 图标
 */
private fun typeIcon(type: OperationType): ImageVector {
    return when (type) {
        OperationType.GENERIC_ENCRYPT, OperationType.FPE_ENCRYPT -> Icons.Filled.Lock
        OperationType.GENERIC_DECRYPT, OperationType.FPE_DECRYPT -> Icons.Filled.LockOpen
        OperationType.STEGO_ENCODE -> Icons.Filled.Visibility
        OperationType.STEGO_EXTRACT -> Icons.Filled.VisibilityOff
    }
}

/**
 * 操作历史列表页。
 *
 * <p>移动端历史界面：触控友好的卡片列表，每条记录展示文件名、
 * 操作类型与操作时间；点按记录打开其输出文件夹，文件夹不存在或
 * 无法打开时以 Toast 友好提示。右上角提供返回与清空按钮，
 * 清空前弹出确认对话框。
 *
 * @param onBack 返回上一页回调
 * @author ErgouTree
 * @since 2026/8/14
 */
@Composable
fun HistoryScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val fileOps = remember { AndroidFileOps(ctx.applicationContext) }
    // 每次进入重新组合时重新加载（HistoryScreen 为按需挂载的全屏覆盖页）
    var records by remember { mutableStateOf(HistoryService.list()) }
    var showClearConfirm by remember { mutableStateOf(false) }

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            title = { Text("清空历史") },
            text = { Text("确定要清空全部操作历史吗？此操作不可恢复。") },
            confirmButton = {
                TextButton(onClick = {
                    HistoryService.clear()
                    records = emptyList()
                    showClearConfirm = false
                }) { Text("清空") }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) { Text("取消") }
            }
        )
    }

    Scaffold(
        // 容器透明，避免遮住全局背景图层
        containerColor = Color.Transparent,
        topBar = {
            CompactTopBar(
                title = "操作历史",
                actions = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                    if (records.isNotEmpty()) {
                        IconButton(onClick = { showClearConfirm = true }) {
                            Icon(Icons.Outlined.Delete, contentDescription = "清空历史")
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        if (records.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "暂无操作记录",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f)
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(records, key = { "${it.timestampEpochMillis}-${it.fileName}" }) { record ->
                    HistoryCard(record = record, onClick = {
                        // 点按记录 → 打开输出文件夹；失败时给出友好提示
                        val opened = fileOps.openOutputFolder(record)
                        if (!opened) {
                            Toast.makeText(ctx, "输出文件夹不存在或已被删除", Toast.LENGTH_SHORT).show()
                        }
                    })
                }
            }
        }
    }
}

/**
 * 单条历史记录卡片。
 *
 * @param record  历史记录
 * @param onClick 点按回调（打开输出文件夹）
 */
@Composable
private fun HistoryCard(record: OperationRecord, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = typeIcon(record.type),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(22.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = record.fileName ?: "",
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.size(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // 操作类型标签
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.7f)
                    ) {
                        Text(
                            text = record.type.defaultLabel,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = formatTime(record),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

/**
 * 将记录时间戳格式化为本地时区的时间字符串。
 *
 * @param record 历史记录
 * @return 形如 {@code 2026-08-14 15:30} 的时间文本
 */
private fun formatTime(record: OperationRecord): String {
    return TIME_FORMAT.format(
        Instant.ofEpochMilli(record.timestampEpochMillis).atZone(ZoneId.systemDefault()))
}
