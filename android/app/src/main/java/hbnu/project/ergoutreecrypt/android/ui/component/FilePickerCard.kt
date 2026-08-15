package hbnu.project.ergoutreecrypt.android.ui.component

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * 文件选择卡片组件。
 *
 * <p>显示已选文件的名称和大小，点击可触发文件选择。未选择文件时显示提示文案。
 * 文件处理中（{@code loading = true}）时显示旋转圆圈与提示，避免大文件期间界面看似无响应。
 *
 * @param fileName    已选文件名，null 表示未选择
 * @param fileSize    已选文件大小（字节），null 表示未知
 * @param onClick     点击回调，触发文件选择器
 * @param label       未选择文件时的提示文案
 * @param modifier    修饰符
 * @param loading     为 true 时显示处理中指示，替代文件名与大小
 * @param loadingText 处理中提示文本（loading 为 true 时显示）
 * @param loadingHint 处理中辅助提示，可为空（loading 为 true 时显示）
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun FilePickerCard(
    fileName: String?,
    fileSize: Long?,
    onClick: () -> Unit,
    label: String = "点击选择文件",
    modifier: Modifier = Modifier,
    loading: Boolean = false,
    loadingText: String = "",
    loadingHint: String = ""
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            // 半透明容器，避免遮挡全局背景图
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (loading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(40.dp),
                    strokeWidth = 3.dp,
                    color = MaterialTheme.colorScheme.primary
                )

                Spacer(modifier = Modifier.width(16.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = loadingText.ifEmpty { "…" },
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    if (loadingHint.isNotEmpty()) {
                        Text(
                            text = loadingHint,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            } else {
                Icon(
                    imageVector = if (fileName != null) {
                        Icons.AutoMirrored.Filled.InsertDriveFile
                    } else {
                        Icons.Default.AttachFile
                    },
                    contentDescription = null,
                    modifier = Modifier.size(40.dp),
                    tint = if (fileName != null) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )

                Spacer(modifier = Modifier.width(16.dp))

                Column(modifier = Modifier.weight(1f)) {
                    if (fileName != null) {
                        Text(
                            text = fileName,
                            style = MaterialTheme.typography.titleSmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (fileSize != null) {
                            Text(
                                text = formatFileSize(fileSize),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

/**
 * 格式化文件大小为可读字符串。
 *
 * @param bytes 文件字节数
 * @return 格式化后的大小字符串（如 "1.5 MiB"）
 */
fun formatFileSize(bytes: Long): String {
    if (bytes <= 0) {
        return "0 B"
    }
    val units = arrayOf("B", "KiB", "MiB", "GiB")
    var size = bytes.toDouble()
    var unitIndex = 0
    while (size >= 1024.0 && unitIndex < units.size - 1) {
        size /= 1024.0
        unitIndex++
    }
    return if (unitIndex == 0) {
        "${bytes} B"
    } else {
        "%.1f %s".format(size, units[unitIndex])
    }
}

/**
 * 从 Uri 中提取文件名。
 *
 * <p>优先通过 {@link OpenableColumns#DISPLAY_NAME} 查询真实显示名。
 * SAF 返回的 {@code content://} URI 的 {@code lastPathSegment} 通常是文档 ID，
 * 云盘等提供者可能不含扩展名，直接使用会导致后续的扩展名/格式判断失败；
 * 查询失败时回退到解析路径段。
 *
 * @param context 上下文，用于查询 ContentResolver
 * @param uri     文件 Uri
 * @return 文件名，若无法提取则返回 "未知文件"
 */
fun extractFileName(context: Context, uri: Uri): String {
    // 优先查询真实显示名（含扩展名）
    try {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) {
                    val name = cursor.getString(idx)
                    if (!name.isNullOrBlank()) {
                        return name
                    }
                }
            }
        }
    } catch (_: Exception) {
        // 查询失败时回退到路径段解析
    }
    val path = uri.lastPathSegment ?: return "未知文件"
    // 去除路径前缀，获取纯文件名
    val lastSlash = path.lastIndexOf('/')
    return if (lastSlash >= 0) path.substring(lastSlash + 1) else path
}
