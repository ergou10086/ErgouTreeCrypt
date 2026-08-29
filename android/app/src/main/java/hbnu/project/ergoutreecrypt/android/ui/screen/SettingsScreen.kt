package hbnu.project.ergoutreecrypt.android.ui.screen

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.WindowInsets
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
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.PermissionSection
import hbnu.project.ergoutreecrypt.android.ui.component.PickerLoadingIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.pickerLoadingText
import hbnu.project.ergoutreecrypt.i18n.Messages
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
fun SettingsScreen(onOpenHistory: () -> Unit = {}) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settings = remember { AndroidSettings(context.applicationContext) }

    val argon2Mode by settings.argon2MobileMode.collectAsState(initial = "BALANCED")
    val themeMode by settings.themeMode.collectAsState(initial = "SYSTEM")
    val languageCode by settings.languageCode.collectAsState(initial = "zh_CN")
    val threadCount by settings.threadCount.collectAsState(initial = 2)
    val defaultReedSolomon by settings.isDefaultReedSolomon.collectAsState(initial = false)

    // 背景图片设置
    val bgUri by settings.backgroundImageUri.collectAsState(initial = null)
    val bgOpacity by settings.backgroundOpacity.collectAsState(initial = 30)
    var bgFileName by remember { mutableStateOf<String?>(null) }

    // ---- 背景图片选择加载状态 ----
    var imageLoading by remember { mutableStateOf(false) }
    var imagePickJob by remember { mutableStateOf<Job?>(null) }

    // 内存指示器开关
    val showMemoryIndicator by settings.showMemoryIndicator.collectAsState(initial = true)
    val logLevel by settings.logLevel.collectAsState(initial = "INFO")
    val logClearOnNewOp by settings.isLogClearOnNewOp.collectAsState(initial = true)
    val logJvmDiagnostics by settings.isJvmDiagnostics.collectAsState(initial = false)

    // 图片选择器（OpenDocument 返回的 URI 支持持久化授权，重启后背景仍可加载）
    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理
        imagePickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        imageLoading = true
        imagePickJob = scope.launch {
            val myJob = coroutineContext[Job]
            try {
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
                // 尝试提取文件名作为显示标签（查询移入 IO 线程）
                bgFileName = withContext(Dispatchers.IO) {
                    try {
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
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (imagePickJob === myJob) {
                    imageLoading = false
                }
            }
        }
    }

    Scaffold(
        // 容器透明，避免遮住全局背景图层
        containerColor = Color.Transparent,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            CompactTopBar(
                title = "设置",
                actions = {
                    IconButton(onClick = onOpenHistory) {
                        Icon(Icons.Outlined.History, contentDescription = "操作历史")
                    }
                }
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
                text = "自动模式为推荐默认档，按设备当前可用内存自动选取能在堆内秒级派生的最大档位，避免离堆派生导致的卡顿与闪退。均衡 (256 MiB) 与省电 (64 MiB) 供手动指定。较低档位加密的文件仍可在桌面端解密（参数随文件存储）。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            // 三个档位平分整行宽度，小字号保证单行内放下
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                FilterChip(
                    selected = argon2Mode == "AUTO",
                    onClick = { scope.launch { settings.setArgon2MobileMode("AUTO") } },
                    label = { Text("自动", style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth()) },
                    modifier = Modifier.weight(1f)
                )
                FilterChip(
                    selected = argon2Mode == "BALANCED",
                    onClick = { scope.launch { settings.setArgon2MobileMode("BALANCED") } },
                    label = { Text("均衡 256 MiB", style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth()) },
                    modifier = Modifier.weight(1f)
                )
                FilterChip(
                    selected = argon2Mode == "LIGHT",
                    onClick = { scope.launch { settings.setArgon2MobileMode("LIGHT") } },
                    label = { Text("省电 64 MiB", style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth()) },
                    modifier = Modifier.weight(1f)
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
                title = "默认纠错码",
                description = "新建加密任务时默认开启 Reed-Solomon 纠错，体积增加约 6%",
                checked = defaultReedSolomon,
                onCheckedChange = { scope.launch { settings.setDefaultReedSolomon(it) } }
            )

            SettingSwitch(
                title = "内存指示器",
                description = "在加密、解密、隐写与提取页面顶部显示低调的内存占用信息（系统空闲内存与应用堆占用）",
                checked = showMemoryIndicator,
                onCheckedChange = { scope.launch { settings.setShowMemoryIndicator(it) } }
            )

            Spacer(modifier = Modifier.height(24.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "日志",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = try { Messages.get("settings.logLevel.tip") } catch (_: Exception) {
                    "标准（INFO）记录操作、阶段与错误；诊断（TRACE）额外记录耗时与参数。"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row {
                FilterChip(
                    selected = logLevel != "TRACE",
                    onClick = { scope.launch { settings.setLogLevel("INFO") } },
                    label = {
                        Text(try { Messages.get("settings.logLevel.info") } catch (_: Exception) { "标准（INFO）" })
                    }
                )
                Spacer(modifier = Modifier.padding(horizontal = 6.dp))
                FilterChip(
                    selected = logLevel == "TRACE",
                    onClick = { scope.launch { settings.setLogLevel("TRACE") } },
                    label = {
                        Text(try { Messages.get("settings.logLevel.trace") } catch (_: Exception) { "诊断（TRACE）" })
                    }
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = try { Messages.get("settings.logRefresh.tip") } catch (_: Exception) {
                    "每次新加密/解密等操作开始时清空当前日志，或一直留存显示。"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row {
                FilterChip(
                    selected = logClearOnNewOp,
                    onClick = { scope.launch { settings.setLogClearOnNewOp(true) } },
                    label = {
                        Text(try { Messages.get("settings.logRefresh.clear") } catch (_: Exception) { "每次新操作清空" })
                    }
                )
                Spacer(modifier = Modifier.padding(horizontal = 6.dp))
                FilterChip(
                    selected = !logClearOnNewOp,
                    onClick = { scope.launch { settings.setLogClearOnNewOp(false) } },
                    label = {
                        Text(try { Messages.get("settings.logRefresh.keep") } catch (_: Exception) { "不刷新，一直留存" })
                    }
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            SettingSwitch(
                title = try { Messages.get("settings.logJvm") } catch (_: Exception) { "JVM 底层日志" },
                description = try { Messages.get("settings.logJvm.tip") } catch (_: Exception) {
                    "默认关闭。开启后记录堆内存、GC 累计与完整异常堆栈，用于诊断内存不足等 JVM 问题。"
                },
                checked = logJvmDiagnostics,
                onCheckedChange = { scope.launch { settings.setJvmDiagnostics(it) } }
            )

            Spacer(modifier = Modifier.height(24.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))

            // === 权限管理 ===
            Text(
                text = "权限管理",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "为兼容澎湃OS/MIUI 等国产系统的存储限制，未授予所有文件访问权限时，输出会自动保存到 下载/ErgouTreeCrypt 目录。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(10.dp))
            PermissionSection()

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
                text = "移动端线程数限制在 1-4（默认 2）。文件夹加解密始终逐文件串行处理，避免内存峰值。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            Slider(
                value = sliderValue,
                onValueChange = { sliderValue = it },
                valueRange = 1f..4f,
                steps = 2
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
                    onClick = { imagePicker.launch(arrayOf("image/*")) },
                    modifier = Modifier.weight(1f),
                    enabled = !imageLoading
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

            // 背景图片处理中：显示旋转圆圈提示
            if (imageLoading) {
                Spacer(Modifier.height(8.dp))
                PickerLoadingIndicator(text = pickerLoadingText())
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
                text = "ErgouTreeCrypt Android v2.3.5\n核心版本：v2.15（对应桌面版 v2.3.5）\n\n基于 Kotlin + Jetpack Compose\n加密核心与桌面版 100% 共享源码",
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
