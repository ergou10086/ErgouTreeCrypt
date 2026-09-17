package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * 人类可读的文件大小文本。
 *
 * @param bytes 字节数
 * @return 形如 {@code 1.5 MiB} 的文本；非正数返回 {@code 0 B}
 */
private fun formatSize(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val units = arrayOf("B", "KiB", "MiB", "GiB")
    var s = bytes.toDouble()
    var i = 0
    while (s >= 1024.0 && i < units.size - 1) {
        s /= 1024.0
        i++
    }
    return if (i == 0) "$bytes B" else "%.1f %s".format(s, units[i])
}

/**
 * 多文件选择卡片。
 *
 * <p>文件数量多时用内嵌滚动列表展示，逐行给出文件名、大小与移除按钮，
 * 顶部提供总数、总大小以及「添加文件 / 清空」入口，避免长列表把页面撑爆。
 *
 * @param names      已选文件名列表（顺序与外部选中列表一致）
 * @param sizes      与 [names] 等长的字节大小；目录或大小未知时传 null
 * @param onRemove   移除第 index 项
 * @param onAdd      追加文件（打开多选文件选择器）
 * @param onClear    清空全部选择
 */
@Composable
fun MultiFilePickerCard(
    names: List<String>,
    sizes: List<Long?>,
    onRemove: (Int) -> Unit,
    onAdd: () -> Unit,
    onClear: () -> Unit
) {
    val totalBytes = sizes.sumOf { it ?: 0L }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
    ) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "已选择 ${names.size} 个文件",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = "总大小：${formatSize(totalBytes)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                TextButton(onClick = onAdd) { Text("添加文件") }
                TextButton(onClick = onClear) { Text("清空") }
            }
            Spacer(Modifier.height(6.dp))
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 180.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                itemsIndexed(names) { index, name ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = name,
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            val size = sizes.getOrNull(index)
                            if (size != null) {
                                Text(
                                    text = formatSize(size),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                        Spacer(Modifier.width(4.dp))
                        IconButton(onClick = { onRemove(index) }) {
                            Icon(
                                imageVector = Icons.Filled.Close,
                                contentDescription = "移除",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}
