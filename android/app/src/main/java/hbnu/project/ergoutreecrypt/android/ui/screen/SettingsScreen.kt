package hbnu.project.ergoutreecrypt.android.ui.screen

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Image
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.i18n.Messages
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.launch
import java.util.Locale

/**
 * 设置页面。
 *
 * <p>提供 Argon2 移动模式、默认加密选项、线程数、背景图片等设置。已作为底部导航栏独立 Tab。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settings = remember { AndroidSettings(context.applicationContext) }

    val argon2Mode by settings.argon2MobileMode.collectAsState(initial = "STANDARD")
    val themeMode by settings.themeMode.collectAsState(initial = "SYSTEM")
    val languageCode by settings.languageCode.collectAsState(initial = "zh_CN")
    val threadCount by settings.threadCount.collectAsState(initial = 4)
    val defaultParanoid by settings.isDefaultParanoid.collectAsState(initial = false)
    val defaultReedSolomon by settings.isDefaultReedSolomon.collectAsState(initial = false)

    // 背景图片设置
    val bgUri by settings.backgroundImageUri.collectAsState(initial = null)
    val bgOpacity by settings.backgroundOpacity.collectAsState(initial = 30)
    var bgFileName by remember { mutableStateOf<String?>(null) }

    // 图片选择器（支持常见图片格式）
    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            scope.launch {
                // 获取持久化权限
                try {
                    context.contentResolver.takePersistableUriPermission(
                        uri,
                        android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                } catch (_: SecurityException) {
                    // 某些 URI 不支持持久化权限，仍可临时使用
                }
                settings.setBackgroundImageUri(uri.toString())
                // 尝试提取文件名作为显示标签
                bgFileName = try {
                    val cursor = context.contentResolver.query(uri, null, null, null, null)
                    cursor?.use {
                        if (it.moveToFirst()) {
                            val idx = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                            if (idx >= 0) it.getString(idx) else "已选择图片"
                        } else "已选择图片"
                    } ?: "已选择图片"
                } catch (_: Exception) {
                    "已选择图片"
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("设置") }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            // === Argon2 移动模式 ===
            Text(
                text = "Argon2 移动模式",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "标准模式 (1 GiB) 与桌面端完全兼容。省电模式 (64 MiB) 适合低端设备，但文件可能无法在旧版桌面端解密。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row {
                FilterChip(
                    selected = argon2Mode == "STANDARD",
                    onClick = {
                        scope.launch { settings.setArgon2MobileMode("STANDARD") }
                    },
                    label = { Text("标准 1 GiB") }
                )
                Spacer(modifier = Modifier.padding(horizontal = 8.dp))
                FilterChip(
                    selected = argon2Mode != "STANDARD",
                    onClick = {
                        scope.launch { settings.setArgon2MobileMode("LIGHT") }
                    },
                    label = { Text("省电 64 MiB") }
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // === 主题模式 ===
            Text(
                text = "主题模式",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "切换浅色或深色外观。选择「跟随系统」时跟随 Android 系统设置自动切换。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row {
                FilterChip(
                    selected = themeMode == "SYSTEM",
                    onClick = { scope.launch { settings.setThemeMode("SYSTEM") } },
                    label = { Text("跟随系统") }
                )
                Spacer(modifier = Modifier.padding(horizontal = 6.dp))
                FilterChip(
                    selected = themeMode == "LIGHT",
                    onClick = { scope.launch { settings.setThemeMode("LIGHT") } },
                    label = { Text("浅色") }
                )
                Spacer(modifier = Modifier.padding(horizontal = 6.dp))
                FilterChip(
                    selected = themeMode == "DARK",
                    onClick = { scope.launch { settings.setThemeMode("DARK") } },
                    label = { Text("深色") }
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // === 界面语言 ===
            Text(
                text = "界面语言",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "切换后应用将自动重启以应用新语言。经典密码名称与描述随语言切换。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row {
                FilterChip(
                    selected = languageCode == "zh_CN",
                    onClick = {
                        scope.launch {
                            settings.setLanguageCode("zh_CN")
                            Messages.setLocale(Locale.SIMPLIFIED_CHINESE)
                            (context as? android.app.Activity)?.recreate()
                        }
                    },
                    label = { Text("中文") }
                )
                Spacer(modifier = Modifier.padding(horizontal = 6.dp))
                FilterChip(
                    selected = languageCode == "en",
                    onClick = {
                        scope.launch {
                            settings.setLanguageCode("en")
                            Messages.setLocale(Locale.ENGLISH)
                            (context as? android.app.Activity)?.recreate()
                        }
                    },
                    label = { Text("English") }
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // === 默认加密选项 ===
            SettingSwitch(
                title = "默认偏执模式",
                description = "新建加密任务时默认开启 Serpent+XChaCha20 双重加密",
                checked = defaultParanoid,
                onCheckedChange = { scope.launch { settings.setDefaultParanoid(it) } }
            )

            SettingSwitch(
                title = "默认纠错码",
                description = "新建加密任务时默认开启 Reed-Solomon 纠错，体积增加约 6%",
                checked = defaultReedSolomon,
                onCheckedChange = { scope.launch { settings.setDefaultReedSolomon(it) } }
            )

            Spacer(modifier = Modifier.height(24.dp))

            // === 线程数 ===
            var sliderValue by remember { mutableFloatStateOf(threadCount.toFloat()) }

            // DataStore 值变化时同步到滑块
            LaunchedEffect(threadCount) {
                sliderValue = threadCount.toFloat()
            }

            // 对滑块拖动进行 300ms 防抖后才写入 DataStore，避免拖动时频繁启动协程
            LaunchedEffect(Unit) {
                snapshotFlow { sliderValue }
                    .debounce(300L)
                    .collect { value ->
                        settings.setThreadCount(value.toInt())
                    }
            }

            Text(
                text = "并行线程数：${sliderValue.toInt()}",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "移动端建议 2-4 线程，更高会增加 CPU 占用",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            Slider(
                value = sliderValue,
                onValueChange = { sliderValue = it },
                valueRange = 1f..8f,
                steps = 6
            )

            Spacer(modifier = Modifier.height(24.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))

            // === 背景图片 ===
            Text(
                text = "背景图片",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "选择一张图片作为应用背景装饰。透明度越低，背景越淡。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(10.dp))

            // 当前状态与操作行
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Image,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = if (bgUri != null)
                        MaterialTheme.colorScheme.primary
                    else
                        MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (bgUri != null) {
                        bgFileName ?: "已设置背景 ($bgUri 长度: ${bgUri!!.length})"
                    } else {
                        "未设置背景图片"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (bgUri != null)
                        MaterialTheme.colorScheme.primary
                    else
                        MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // 选择 + 移除按钮行
            Row(modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = { imagePicker.launch("image/*") },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Default.Image, null, Modifier.size(16.dp))
                    Text(" 选择图片")
                }
                if (bgUri != null) {
                    Spacer(modifier = Modifier.width(8.dp))
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                settings.setBackgroundImageUri(null)
                                bgFileName = null
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Icon(Icons.Default.Delete, null, Modifier.size(16.dp))
                        Text(" 移除背景")
                    }
                }
            }

            // 透明度滑块（仅在有背景时完全可交互）
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "透明度：$bgOpacity%",
                style = MaterialTheme.typography.bodyMedium,
                color = if (bgUri != null)
                    MaterialTheme.colorScheme.onSurface
                else
                    MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
            )
            Slider(
                value = bgOpacity.toFloat(),
                onValueChange = {
                    scope.launch { settings.setBackgroundOpacity(it.toInt()) }
                },
                valueRange = 0f..100f,
                modifier = Modifier.fillMaxWidth(),
                enabled = bgUri != null
            )
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "完全透明",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    "完全显示",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(24.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))

            // === 关于信息 ===
            Text(
                text = "关于",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "ErgouTreeCrypt Android v1.4.7\n核心版本：v2.15（对应桌面版 v2.0.9）\n\n基于 Kotlin + Jetpack Compose\n加密核心与桌面版 100% 共享源码",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * 带标题和描述的 Switch 设置项。
 *
 * @param title         设置标题
 * @param description   设置描述
 * @param checked       当前开关状态
 * @param onCheckedChange 状态变更回调
 */
@Composable
private fun SettingSwitch(
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, style = MaterialTheme.typography.bodyLarge)
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
        Spacer(modifier = Modifier.height(12.dp))
    }
}
