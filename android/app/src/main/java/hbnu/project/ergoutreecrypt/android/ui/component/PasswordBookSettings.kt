package hbnu.project.ergoutreecrypt.android.ui.component

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.passwordbook.PasswordBookCsv
import hbnu.project.ergoutreecrypt.passwordbook.PasswordBookEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets

/**
 * 设置页中的可折叠密码本编辑器。
 *
 * <p>名称与密码按两列编辑，支持 CSV 导入和导出。
 */
@Composable
fun PasswordBookSettings() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settings = remember { AndroidSettings(context.applicationContext) }
    val storedEntries by settings.passwordBookEntries.collectAsState(initial = emptyList())
    var entries by remember { mutableStateOf<List<PasswordBookEntry>>(emptyList()) }
    var editing by remember { mutableStateOf(false) }

    LaunchedEffect(storedEntries) {
        if (!editing) {
            entries = storedEntries
        }
    }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openInputStream(uri).use { input ->
                            requireNotNull(input) { "无法读取所选文件" }
                            PasswordBookCsv.read(
                                InputStreamReader(input, StandardCharsets.UTF_8)
                            )
                        }
                    }
                }.onSuccess { imported ->
                    editing = true
                    entries = imported
                    settings.setPasswordBookEntries(imported)
                    Toast.makeText(context, "已导入 ${imported.size} 条密码", Toast.LENGTH_SHORT).show()
                }.onFailure {
                    Toast.makeText(context, "导入失败：${it.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv")
    ) { uri ->
        if (uri != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri).use { output ->
                            requireNotNull(output) { "无法写入所选文件" }
                            OutputStreamWriter(output, StandardCharsets.UTF_8).use { writer ->
                                PasswordBookCsv.write(entries, writer)
                            }
                        }
                    }
                }.onSuccess {
                    Toast.makeText(context, "密码本已导出", Toast.LENGTH_SHORT).show()
                }.onFailure {
                    Toast.makeText(context, "导出失败：${it.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    ExpandableCard(title = "密码本") {
        Text(
            text = "保存常用密码。密码输入框右侧的下拉箭头可直接选择；确认密码框不显示该入口。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("名称", modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelMedium)
            Text("密码", modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.width(48.dp))
        }
        entries.forEachIndexed { index, entry ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = entry.name,
                    onValueChange = { value ->
                        editing = true
                        entries = entries.replace(index, PasswordBookEntry(value, entry.password))
                        scope.launch { settings.setPasswordBookEntries(entries) }
                    },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                OutlinedTextField(
                    value = entry.password,
                    onValueChange = { value ->
                        editing = true
                        entries = entries.replace(index, PasswordBookEntry(entry.name, value))
                        scope.launch { settings.setPasswordBookEntries(entries) }
                    },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                IconButton(onClick = {
                    editing = true
                    entries = entries.filterIndexed { row, _ -> row != index }
                    scope.launch { settings.setPasswordBookEntries(entries) }
                }) {
                    Icon(Icons.Default.Delete, contentDescription = "删除密码")
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = {
                editing = true
                entries = entries + PasswordBookEntry("", "")
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("添加密码")
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { importLauncher.launch(arrayOf("text/csv", "text/comma-separated-values")) },
                modifier = Modifier.weight(1f)
            ) {
                Text("导入 CSV")
            }
            OutlinedButton(
                onClick = { exportLauncher.launch("password-book.csv") },
                modifier = Modifier.weight(1f)
            ) {
                Text("导出 CSV")
            }
        }
    }
}

/**
 * 替换列表中的指定密码记录。
 *
 * @param index 目标索引
 * @param entry 新记录
 * @return 替换后的新列表
 */
private fun List<PasswordBookEntry>.replace(
    index: Int,
    entry: PasswordBookEntry
): List<PasswordBookEntry> = mapIndexed { row, current -> if (row == index) entry else current }
