package hbnu.project.ergoutreecrypt.android.ui.screen

import android.graphics.BitmapFactory
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.ui.component.ExpandableCard
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.InfoTooltip
import hbnu.project.ergoutreecrypt.android.ui.component.PasswordStrengthMeter
import hbnu.project.ergoutreecrypt.android.ui.component.ProgressCard
import hbnu.project.ergoutreecrypt.android.ui.component.ResultDialog
import hbnu.project.ergoutreecrypt.android.ui.component.ResultType
import hbnu.project.ergoutreecrypt.android.ui.component.extractFileName
import hbnu.project.ergoutreecrypt.android.ui.component.formatFileSize
import hbnu.project.ergoutreecrypt.android.ui.component.generateRandomPassword
import hbnu.project.ergoutreecrypt.android.ui.component.mapErrorToChineseMessage
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.android.viewmodel.StegoViewModel
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// ==================== 载体类型常量 ====================

/** 支持的所有载体文件扩展名（含 "." 前缀，小写） */
private val SUPPORTED_CARRIER_EXTENSIONS = setOf(
    ".png", ".zip", ".pdf", ".wav", ".flac", ".mp4", ".m4a", ".m4v", ".mov"
)

/** 可显示图像预览的载体扩展名 */
private val IMAGE_CARRIER_EXTENSIONS = setOf(".png")

/** 提示文本 */
private val TIP_STEGO_PARANOID = "启用后数据先经 Serpent 加密再经 XChaCha20 加密，提供双重保护。"
private val TIP_STEGO_COMPRESS = "加密前先使用 Zstandard 压缩数据，可减小隐藏数据的体积。"
private val TIP_STEGO_INTEGRITY = "存储原文的完整性校验码（MAC），提取后自动验证文件是否被篡改。"
private val TIP_STEGO_STEALTH = "使用 HMAC 派生魔数替代固定魔数，避免通过魔数字符串检测隐写数据。"
private val TIP_STEGO_OBFUSCATE = "在输出文件末尾追加随机字节，使文件大小达到指定目标，增加检测难度。"
private val TIP_STEGO_PREFER_CHUNK = "对于 PNG 载体：优先使用 stEG 自定义块嵌入（更隐蔽）；关闭则在 IEND 后直接追加。"

/**
 * 检测文件扩展名是否为支持的载体类型。
 *
 * @param fileName 文件名
 * @return 若为支持的载体类型返回 true
 */
private fun isSupportedCarrier(fileName: String): Boolean {
    val lower = fileName.lowercase()
    return SUPPORTED_CARRIER_EXTENSIONS.any { lower.endsWith(it) }
}

/**
 * 检测文件扩展名是否可显示图像预览。
 *
 * @param fileName 文件名
 * @return 若为图像类型返回 true
 */
private fun isImageCarrier(fileName: String): Boolean {
    val lower = fileName.lowercase()
    return IMAGE_CARRIER_EXTENSIONS.any { lower.endsWith(it) }
}

// ============================================================
// StegoScreen — 统一隐写（隐藏）页面
// ============================================================

/**
 * 隐写页面（隐藏模式）。
 *
 * <p>用户选择待隐藏的文件和载体文件，设置密码与高级选项后，
 * 将文件加密嵌入到载体中。支持 PNG/ZIP/PDF/WAV/FLAC/MP4 等载体格式。
 * PNG 载体可显示图像预览。所有选项与桌面端 {@link FileStegoOptions} 对齐。
 *
 * <p>注意：移动端不使用 LSB 像素域隐写（依赖 java.awt），仅使用 Chunk/追加模式。
 *
 * @author ErgouTree
 * @since 2026/8/12
 */
@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun StegoScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val scroll = rememberScrollState()
    val fileOps = remember { AndroidFileOps(ctx.applicationContext) }
    val vm = remember { StegoViewModel(ctx.applicationContext) }
    val progress by vm.progress.collectAsState()
    val isRunning = progress.state == ProgressState.State.RUNNING

    // ---- 待隐藏文件 ----
    var secretUri by remember { mutableStateOf<Uri?>(null) }
    var secretPath by remember { mutableStateOf<String?>(null) }
    var secretName by remember { mutableStateOf<String?>(null) }
    var secretSize by remember { mutableStateOf<Long?>(null) }

    // ---- 载体文件 ----
    var carrierUri by remember { mutableStateOf<Uri?>(null) }
    var carrierPath by remember { mutableStateOf<String?>(null) }
    var carrierName by remember { mutableStateOf<String?>(null) }
    var carrierSize by remember { mutableStateOf<Long?>(null) }
    var carrierValid by remember { mutableStateOf(false) }
    // 图像预览
    var carrierBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }

    // ---- 密码 ----
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    // ---- 高级选项（与桌面端 FileStegoOptions 对齐） ----
    var paranoid by remember { mutableStateOf(false) }
    var compressed by remember { mutableStateOf(false) }
    var storeIntegrity by remember { mutableStateOf(true) }
    var stealth by remember { mutableStateOf(false) }
    var obfuscateSize by remember { mutableStateOf(false) }
    var targetSizeMB by remember { mutableStateOf(10) }
    var preferChunk by remember { mutableStateOf(true) }

    // ---- 输出 ----
    var outDir by remember { mutableStateOf<String?>(null) }
    var outName by remember { mutableStateOf<String?>(null) }

    // ---- 待隐藏文件选择器 ----
    val secretPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u != null) scope.launch {
            secretUri = u
            secretName = extractFileName(u)
            secretPath = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
            if (secretPath != null) {
                val f = File(secretPath!!)
                secretSize = if (f.exists()) f.length() else null
                if (outDir == null) {
                    outDir = f.parent ?: ctx.filesDir.absolutePath
                }
            }
        }
    }

    // ---- 载体文件选择器 ----
    val carrierPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u != null) scope.launch {
            val name = extractFileName(u)
            // UI 层校验：检查扩展名
            if (!isSupportedCarrier(name)) {
                val supported = SUPPORTED_CARRIER_EXTENSIONS.joinToString(", ")
                Toast.makeText(
                    ctx,
                    "不支持的载体格式：${name.substringAfterLast('.', "未知")}。" +
                            " 支持的格式：$supported",
                    Toast.LENGTH_LONG
                ).show()
                return@launch
            }
            carrierUri = u
            carrierName = name
            carrierPath = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
            carrierValid = carrierPath != null
            if (carrierPath != null) {
                val f = File(carrierPath!!)
                carrierSize = if (f.exists()) f.length() else null
                // 生成输出文件名
                val dotIdx = name.lastIndexOf('.')
                outName = if (dotIdx >= 0) {
                    "${name.substring(0, dotIdx)}_stego${name.substring(dotIdx)}"
                } else {
                    "${name}_stego"
                }
                if (outDir == null) {
                    outDir = f.parent ?: ctx.filesDir.absolutePath
                }
                // 回收旧预览图，防止 native 内存泄漏
                carrierBitmap?.recycle()
                // 加载图像预览（仅 PNG）
                carrierBitmap = if (isImageCarrier(name)) {
                    withContext(Dispatchers.IO) {
                        loadThumbnail(carrierPath!!, 360)
                    }
                } else {
                    null
                }
            }
        }
    }

    // ---- 输出目录选择器 ----
    val outDirPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { u ->
        if (u != null) scope.launch {
            val resolved = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
            if (resolved != null) {
                outDir = resolved
            }
        }
    }

    val hasSecret = secretPath != null
    val hasCarrier = carrierPath != null && carrierValid
    val canStart = hasSecret && hasCarrier && !isRunning

    // ---- 开始隐写 ----
    fun doHide() {
        val outFile = "${outDir ?: secretPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath}/${outName ?: "stego_output"}"
        val opts = FileStegoOptions.builder()
            .paranoid(paranoid)
            .compressed(compressed)
            .storeIntegrity(storeIntegrity)
            .stealth(stealth)
            .obfuscateSize(obfuscateSize)
            .targetSizeBytes(if (obfuscateSize) targetSizeMB * 1024L * 1024L else 0)
            .preferChunk(preferChunk)
            .build()
        vm.hide(carrierPath!!, secretPath!!, outFile, password, opts)
    }

    // ---- 结果弹窗状态 ----
    var showResultDialog by remember { mutableStateOf(false) }
    var resultTitle by remember { mutableStateOf("") }
    var resultMessage by remember { mutableStateOf("") }
    var resultDetail by remember { mutableStateOf<String?>(null) }
    var resultType by remember { mutableStateOf(ResultType.INFO) }

    LaunchedEffect(progress.state) {
        when (progress.state) {
            ProgressState.State.DONE -> {
                resultTitle = "隐写完成"
                resultMessage = "文件已成功隐藏到载体中。\n输出文件：${outName ?: ""}"
                resultDetail = null
                resultType = ResultType.SUCCESS
                showResultDialog = true
            }
            ProgressState.State.ERROR -> {
                resultTitle = "隐写失败"
                resultMessage = mapErrorToChineseMessage(progress.error)
                resultDetail = progress.error
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                resultTitle = "已取消"
                resultMessage = "隐写操作已被取消。"
                resultDetail = null
                resultType = ResultType.INFO
                showResultDialog = true
            }
            else -> { /* no-op */ }
        }
    }

    // 离开页面时取消正在进行的操作并回收 Bitmap，防止后台协程和 native 内存泄漏
    DisposableEffect(Unit) {
        onDispose {
            vm.cancel()
            carrierBitmap?.recycle()
        }
    }

    if (showResultDialog) {
        ResultDialog(
            title = resultTitle,
            message = resultMessage,
            detail = resultDetail,
            type = resultType,
            onDismiss = { showResultDialog = false },
            confirmLabel = "确定"
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("隐写") })
        },
        bottomBar = {
            if (isRunning) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    ProgressCard(progressState = progress, onCancel = { vm.cancel() })
                }
            } else {
                Box(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    Button(
                        onClick = { doHide() },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = canStart
                    ) {
                        Icon(Icons.Default.Visibility, null)
                        Text("  开始隐写")
                    }
                }
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(scroll)
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            // ============================================================
            // 一、待隐藏文件选择区
            // ============================================================
            Text(
                "待隐藏文件",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(6.dp))
            if (!hasSecret) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    onClick = { secretPicker.launch(arrayOf("*/*")) }
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.InsertDriveFile, null,
                            Modifier.size(40.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "点击选择待隐藏文件",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "任意类型文件均可作为隐藏内容",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                    }
                }
            } else {
                FilePickerCard(
                    fileName = secretName,
                    fileSize = secretSize,
                    onClick = { secretPicker.launch(arrayOf("*/*")) },
                    label = "点击更换待隐藏文件"
                )
                Row(modifier = Modifier.fillMaxWidth()) {
                    FilledTonalButton(
                        onClick = { secretPicker.launch(arrayOf("*/*")) },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Add, null, Modifier.size(16.dp)); Text("  换文件") }
                    Spacer(Modifier.width(6.dp))
                    FilledTonalButton(
                        onClick = {
                            secretUri = null; secretPath = null
                            secretName = null; secretSize = null
                        },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Delete, null, Modifier.size(16.dp)); Text("  移除") }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ============================================================
            // 二、载体文件选择区
            // ============================================================
            Text(
                "载体文件",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(6.dp))
            if (!hasCarrier) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    onClick = { carrierPicker.launch(arrayOf("*/*")) }
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            Icons.Default.Visibility, null,
                            Modifier.size(40.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "点击选择载体文件",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "支持格式：PNG / ZIP / PDF / WAV / FLAC / MP4",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                    }
                }
            } else {
                // 载体信息卡片
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.AutoMirrored.Filled.InsertDriveFile, null,
                                Modifier.size(40.dp),
                                tint = MaterialTheme.colorScheme.primary
                            )
                            Spacer(Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = carrierName ?: "",
                                    style = MaterialTheme.typography.titleSmall,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                if (carrierSize != null) {
                                    Text(
                                        text = formatFileSize(carrierSize!!),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }

                        // 图像预览（仅 PNG 载体）
                        if (carrierBitmap != null) {
                            Spacer(modifier = Modifier.height(12.dp))
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surface
                                ),
                                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                            ) {
                                Column(modifier = Modifier.padding(8.dp)) {
                                    Text(
                                        "载体预览",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Image(
                                        bitmap = carrierBitmap!!.asImageBitmap(),
                                        contentDescription = "载体图片预览",
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(200.dp),
                                        contentScale = ContentScale.Fit
                                    )
                                }
                            }
                        }
                    }
                }

                // 更换/移除按钮行
                Row(modifier = Modifier.fillMaxWidth()) {
                    FilledTonalButton(
                        onClick = { carrierPicker.launch(arrayOf("*/*")) },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Add, null, Modifier.size(16.dp)); Text("  换载体") }
                    Spacer(Modifier.width(6.dp))
                    FilledTonalButton(
                        onClick = {
                            carrierBitmap?.recycle()
                            carrierUri = null; carrierPath = null; carrierName = null
                            carrierSize = null; carrierValid = false; carrierBitmap = null
                        },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Delete, null, Modifier.size(16.dp)); Text("  移除") }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ============================================================
            // 三、输出目录
            // ============================================================
            val displayPath = when {
                outDir != null -> outDir!!
                else -> ""
            }
            val displayText = if (displayPath.isNotEmpty()) {
                if (displayPath.length > 44) "…${displayPath.takeLast(44)}" else displayPath
            } else {
                "默认输出至输入文件同级目录"
            }

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.small,
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)),
                onClick = { outDirPicker.launch(null) }
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "输出目录",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = displayText,
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Icon(Icons.Default.FolderOpen, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }

            // 输出文件名显示
            if (outName != null) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "输出文件名：${outName}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ============================================================
            // 四、密码区
            // ============================================================
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("密码") },
                placeholder = { Text("请输入密码（可留空使用无密码模式）") },
                enabled = !isRunning,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Password, imeAction = ImeAction.Done),
                trailingIcon = {
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(
                            imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = if (passwordVisible) "隐藏密码" else "显示密码"
                        )
                    }
                }
            )

            Spacer(modifier = Modifier.height(4.dp))
            if (password.isEmpty()) {
                Text(
                    "未输入密码 — 文件将使用系统默认约定密码进行无密码加密",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            } else {
                PasswordStrengthMeter(password = password, modifier = Modifier.fillMaxWidth())
            }

            // 密码操作按钮
            Spacer(modifier = Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = {
                        val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        if (password.isNotEmpty()) cm.setPrimaryClip(android.content.ClipData.newPlainText("pwd", password))
                    },
                    modifier = Modifier.weight(1f),
                    shape = MaterialTheme.shapes.small,
                    contentPadding = ButtonDefaults.ContentPadding
                ) {
                    Icon(Icons.Default.ContentCopy, null, Modifier.size(16.dp))
                    Text(" 复制密码", style = MaterialTheme.typography.labelMedium)
                }
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = { password = generateRandomPassword(20); passwordVisible = true },
                    modifier = Modifier.weight(1f),
                    shape = MaterialTheme.shapes.small,
                    contentPadding = ButtonDefaults.ContentPadding
                ) {
                    Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
                    Text(" 随机密码", style = MaterialTheme.typography.labelMedium)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ============================================================
            // 五、高级选项（与桌面端 FileStegoOptions 对齐）
            // ============================================================
            ExpandableCard(title = "高级选项") {

                // ---- 偏执模式 ----
                OptionRow("偏执模式（Serpent + XChaCha20 双重加密）", paranoid, { paranoid = it }, TIP_STEGO_PARANOID)
                Spacer(Modifier.height(6.dp))

                // ---- 加密前压缩 ----
                OptionRow("加密前压缩（Zstandard）", compressed, { compressed = it }, TIP_STEGO_COMPRESS)
                Spacer(Modifier.height(6.dp))

                // ---- 完整性校验 ----
                OptionRow("完整性校验（MAC）", storeIntegrity, { storeIntegrity = it }, TIP_STEGO_INTEGRITY)
                Spacer(Modifier.height(6.dp))

                // ---- 隐蔽模式 ----
                OptionRow("隐蔽模式（HMAC 派生魔数）", stealth, { stealth = it }, TIP_STEGO_STEALTH)

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- 文件大小混淆 ----
                OptionRow("文件大小混淆", obfuscateSize, { obfuscateSize = it }, TIP_STEGO_OBFUSCATE)
                if (obfuscateSize) {
                    Spacer(modifier = Modifier.height(4.dp))
                    OutlinedTextField(
                        value = targetSizeMB.toString(),
                        onValueChange = { v -> targetSizeMB = v.toIntOrNull() ?: 10 },
                        label = { Text("目标大小（MiB）") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(start = 36.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Number, imeAction = ImeAction.Next),
                        textStyle = MaterialTheme.typography.bodyMedium
                    )
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- Prefer Chunk（仅对 PNG 载体有意义） ----
                val isPngCarrier = carrierName?.lowercase()?.endsWith(".png") == true
                OptionRow(
                    "优先使用 Chunk 嵌入（PNG stEG 块）",
                    preferChunk,
                    { preferChunk = it },
                    TIP_STEGO_PREFER_CHUNK
                )
                if (!isPngCarrier && carrierName != null) {
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        "此选项仅对 PNG 载体有效，其他格式使用追加模式",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        modifier = Modifier.padding(start = 36.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(80.dp))
        }
    }
}

// ==================== 辅助函数 ====================

/**
 * 加载图像缩略图。
 *
 * @param filePath 图像文件路径
 * @param maxDim   最大宽/高（像素）
 * @return 缩放后的 Bitmap，失败返回 null
 */
private fun loadThumbnail(filePath: String, maxDim: Int): android.graphics.Bitmap? {
    return try {
        val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(filePath, opts)
        val scaleFactor = maxOf(
            (opts.outWidth + maxDim - 1) / maxDim,
            (opts.outHeight + maxDim - 1) / maxDim,
            1
        )
        val decodeOpts = BitmapFactory.Options().apply { inSampleSize = scaleFactor }
        BitmapFactory.decodeFile(filePath, decodeOpts)
    } catch (_: Exception) {
        null
    }
}

// ==================== 辅助组件 ====================

/**
 * 选项行：Checkbox + 标签 + ⓘ 提示。
 */
@Composable
private fun OptionRow(
    label: String,
    checked: Boolean,
    onToggle: (Boolean) -> Unit,
    tip: String,
    enabled: Boolean = true
) {
    val alpha = if (enabled) 1f else 0.38f
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onToggle, enabled = enabled)
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f).padding(start = 4.dp),
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = alpha)
        )
        InfoTooltip(tip)
    }
}
