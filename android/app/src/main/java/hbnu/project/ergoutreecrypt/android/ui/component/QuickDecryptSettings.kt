package hbnu.project.ergoutreecrypt.android.ui.component

import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import kotlinx.coroutines.launch

/**
 * 快速解密的相册目录与扫描数量设置。
 */
@Composable
fun QuickDecryptSettings() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settings = remember { AndroidSettings(context.applicationContext) }
    val albumUri by settings.quickDecryptAlbumUri.collectAsState(initial = null)
    val scanLimit by settings.quickDecryptScanLimit.collectAsState(initial = 100)
    var limitText by remember { mutableStateOf("100") }

    LaunchedEffect(scanLimit) {
        limitText = scanLimit.toString()
    }

    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            scope.launch { settings.setQuickDecryptAlbumUri(uri.toString()) }
        }
    }

    ExpandableCard(title = "快速解密") {
        Text(
            "图片还原页可批量扫描相册，仅处理“公开恢复”图片；密码保护图片会被忽略。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(10.dp))
        Text("扫描目录", style = MaterialTheme.typography.labelMedium)
        Text(
            albumDisplayName(albumUri),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth()) {
            Button(
                onClick = { folderPicker.launch(null) },
                modifier = Modifier.weight(1f)
            ) {
                Text("选择相册文件夹")
            }
            if (albumUri != null) {
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = { scope.launch { settings.setQuickDecryptAlbumUri(null) } },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("恢复默认")
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
            value = limitText,
            onValueChange = { text ->
                val digits = text.filter(Char::isDigit).take(4)
                limitText = digits
                digits.toIntOrNull()?.takeIf { it in 1..1000 }?.let { value ->
                    scope.launch { settings.setQuickDecryptScanLimit(value) }
                }
            },
            label = { Text("扫描图片数量（1-1000）") },
            supportingText = { Text("默认扫描按时间排序的前 100 张图片") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            isError = (limitText.toIntOrNull() ?: 0) !in 1..1000,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

/**
 * 把相册 URI 转为适合设置页展示的文本。
 *
 * @param uri 相册目录 URI 字符串，可为 null
 * @return 默认相册说明或目录标识
 */
private fun albumDisplayName(uri: String?): String {
    if (uri == null) {
        return "系统相册（DCIM/Camera）"
    }
    return runCatching {
        DocumentsContract.getTreeDocumentId(Uri.parse(uri)).substringAfter(':')
    }.getOrNull()?.ifBlank { "已选择自定义相册" } ?: "已选择自定义相册"
}
