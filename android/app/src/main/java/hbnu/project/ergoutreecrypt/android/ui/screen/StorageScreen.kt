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
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.StorageUsage
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.viewmodel.OperationCoordinator
import hbnu.project.ergoutreecrypt.log.LogService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 存储空间页。
 *
 * <p>逐项列出本工具产生的缓存占用（类别 / 落盘位置 / 占用 / 文件数），顶部给出合计占用，
 * 底部提供「清理缓存」。清理前弹出确认框，清理后立即重新扫描并以 Toast 提示实际释放量。
 *
 * <p>清理只针对中间产物与可再生缓存，不会删除用户已生成的加密/解密结果文件。
 * 有加解密任务正在运行时禁用清理，避免删掉进行中的操作所依赖的临时文件。
 *
 * @param onBack 返回上一页回调
 * @author ErgouTree
 * @since 2026/9/20
 */
@Composable
fun StorageScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val storage = remember { StorageUsage(ctx.applicationContext) }
    val busy by OperationCoordinator.busy.collectAsState()

    var entries by remember { mutableStateOf<List<StorageUsage.Entry>>(emptyList()) }
    var scanning by remember { mutableStateOf(true) }
    var showClearConfirm by remember { mutableStateOf(false) }

    val totalBytes = entries.sumOf { it.bytes }

    // 每次进入重新扫描（本页为按需挂载的全屏覆盖页）
    LaunchedEffect(Unit) {
        scanning = true
        entries = withContext(Dispatchers.IO) { storage.scan() }
        scanning = false
    }

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            title = { Text("确认清理全部缓存？") },
            text = {
                Text(
                    "将删除以上全部缓存（合计 ${humanSize(totalBytes)}）。" +
                        "此操作不可恢复；已生成的加密/解密结果文件不受影响，" +
                        "已选中但尚未开始的任务需要重新选择文件。"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showClearConfirm = false
                    scope.launch {
                        scanning = true
                        val freed = withContext(Dispatchers.IO) { storage.clearAll() }
                        entries = withContext(Dispatchers.IO) { storage.scan() }
                        scanning = false
                        Toast.makeText(
                            ctx,
                            "已清理缓存，释放 ${humanSize(freed)}",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }) { Text("清理") }
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
                title = "存储空间",
                actions = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
        ) {
            Spacer(Modifier.height(8.dp))

            TotalCard(totalBytes = totalBytes, scanning = scanning)
            Spacer(Modifier.height(12.dp))

            if (!scanning && entries.all { it.bytes == 0L }) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "当前没有可清理的缓存",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f)
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(bottom = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(entries, key = { it.label }) { entry ->
                        EntryCard(entry = entry)
                    }
                }
            }

            Button(
                onClick = { showClearConfirm = true },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 12.dp),
                enabled = !busy && !scanning && totalBytes > 0L,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError
                )
            ) {
                Icon(Icons.Outlined.Delete, null, Modifier.size(16.dp))
                Text(" 清理缓存")
            }

            if (busy) {
                Text(
                    text = "有任务正在运行，暂不可清理",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
            }
        }
    }
}

/**
 * 合计占用卡片。
 *
 * @param totalBytes 合计占用字节数
 * @param scanning   是否正在扫描，为 true 时显示进度指示
 */
@Composable
private fun TotalCard(totalBytes: Long, scanning: Boolean) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
        )
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            Text(
                text = "合计占用",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = humanSize(totalBytes),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold
                )
                if (scanning) {
                    Spacer(Modifier.width(10.dp))
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                }
            }
        }
    }
}

/**
 * 单条缓存明细卡片。
 *
 * @param entry 缓存明细
 */
@Composable
private fun EntryCard(entry: StorageUsage.Entry) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.label,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = entry.path,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = humanSize(entry.bytes),
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "${entry.files} 个文件",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/**
 * 将字节数格式化为人类可读字符串。
 *
 * @param bytes 字节数
 * @return 形如 {@code 12.34 MiB} 的文本
 */
private fun humanSize(bytes: Long): String = LogService.humanSize(bytes.coerceAtLeast(0L))
