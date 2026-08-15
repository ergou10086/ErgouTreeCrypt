package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * 文件操作按钮行组件。
 *
 * <p>在已选文件卡片下方展示"换文件"、"换文件夹"、"移除"操作按钮，以较小的尺寸均匀排列在一行中，
 * 避免按钮内容溢出换行。
 *
 * @param onPickFile    点击"换文件"按钮的回调
 * @param onRemove      点击"移除"按钮的回调
 * @param onPickFolder  点击"换文件夹"按钮的回调，为 null 时隐藏该按钮
 * @param pickFileLabel "换文件"按钮的文案，可自定义（如"换载体"）
 * @param modifier      修饰符
 * @author ErgouTree
 * @since 2026/8/13
 */
@Composable
fun FileActionRow(
    onPickFile: () -> Unit,
    onRemove: () -> Unit,
    onPickFolder: (() -> Unit)? = null,
    pickFileLabel: String = "换文件",
    modifier: Modifier = Modifier
) {
    Row(modifier = modifier.fillMaxWidth()) {
        FilledTonalButton(
            onClick = onPickFile,
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(horizontal = 8.dp)
        ) {
            Icon(Icons.Default.Add, null, Modifier.size(14.dp))
            Spacer(Modifier.width(4.dp))
            Text(pickFileLabel, style = MaterialTheme.typography.labelMedium)
        }
        if (onPickFolder != null) {
            Spacer(Modifier.width(4.dp))
            FilledTonalButton(
                onClick = onPickFolder,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 8.dp)
            ) {
                Icon(Icons.Default.FolderOpen, null, Modifier.size(14.dp))
                Spacer(Modifier.width(4.dp))
                Text("换文件夹", style = MaterialTheme.typography.labelMedium)
            }
        }
        Spacer(Modifier.width(4.dp))
        FilledTonalButton(
            onClick = onRemove,
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(horizontal = 8.dp)
        ) {
            Icon(Icons.Default.Delete, null, Modifier.size(14.dp))
            Spacer(Modifier.width(4.dp))
            Text("移除", style = MaterialTheme.typography.labelMedium)
        }
    }
}
