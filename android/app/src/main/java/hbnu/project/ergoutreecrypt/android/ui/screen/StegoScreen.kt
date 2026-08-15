package hbnu.project.ergoutreecrypt.android.ui.screen

import android.content.Intent
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
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.platform.PendingSafOutput
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.ExpandableCard
import hbnu.project.ergoutreecrypt.android.ui.component.FileActionRow
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.InfoTooltip
import hbnu.project.ergoutreecrypt.android.ui.component.MemoryIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.PasswordStrengthMeter
import hbnu.project.ergoutreecrypt.android.ui.component.PickerLoadingIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.ProgressCard
import hbnu.project.ergoutreecrypt.android.ui.component.ResultDialog
import hbnu.project.ergoutreecrypt.android.ui.component.ResultType
import hbnu.project.ergoutreecrypt.android.ui.component.SUPPORTED_CARRIER_EXTENSIONS
import hbnu.project.ergoutreecrypt.android.ui.component.extractFileName
import hbnu.project.ergoutreecrypt.android.ui.component.formatFileSize
import hbnu.project.ergoutreecrypt.android.ui.component.generateRandomPassword
import hbnu.project.ergoutreecrypt.android.ui.component.isImageCarrier
import hbnu.project.ergoutreecrypt.android.ui.component.isSupportedCarrier
import hbnu.project.ergoutreecrypt.android.ui.component.mapErrorToChineseMessage
import hbnu.project.ergoutreecrypt.android.ui.component.pickerLoadingHint
import hbnu.project.ergoutreecrypt.android.ui.component.pickerLoadingText
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.platform.Argon2MobileMode
import hbnu.project.ergoutreecrypt.android.platform.DeviceMemory
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.android.viewmodel.StegoViewModel
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// ==================== 提示文本常量 ====================

/** 提示文本 */
private val TIP_STEGO_PARANOID = "启用后数据先经 Serpent 加密再经 XChaCha20 加密，提供双重保护。"
private val TIP_STEGO_COMPRESS = "加密前先使用 Zstandard 压缩数据，可减小隐藏数据的体积。"
private val TIP_STEGO_INTEGRITY = "存储原文的完整性校验码（MAC），提取后自动验证文件是否被篡改。"
private val TIP_STEGO_STEALTH = "使用 HMAC 派生魔数替代固定魔数，避免通过魔数字符串检测隐写数据。"
private val TIP_STEGO_OBFUSCATE = "在输出文件末尾追加随机字节，使文件大小达到指定目标，增加检测难度。"
private val TIP_STEGO_PREFER_CHUNK = "对于 PNG 载体：优先使用 stEG 自定义块嵌入（更隐蔽）；关闭则在 IEND 后直接追加。"

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
fun StegoScreen(onOpenHistory: () -> Unit = {}) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val scroll = rememberScrollState()
    val fileOps = remember { AndroidFileOps(ctx.applicationContext) }
    val settings = remember { AndroidSettings(ctx.applicationContext) }
    val vm = remember { StegoViewModel(ctx.applicationContext) }
    val progress by vm.progress.collectAsState()
    val isRunning = progress.state == ProgressState.State.RUNNING
    val showMemoryIndicator by settings.showMemoryIndicator.collectAsState(initial = true)

    // ---- 待隐藏文件 ----
    var secretUri by remember { mutableStateOf<Uri?>(null) }
    var secretPath by remember { mutableStateOf<String?>(null) }
    var secretName by remember { mutableStateOf<String?>(null) }
    var secretSize by remember { mutableStateOf<Long?>(null) }

    // ---- 待隐藏文件选择加载状态 ----
    var secretLoading by remember { mutableStateOf(false) }
    var secretPickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 载体文件 ----
    var carrierUri by remember { mutableStateOf<Uri?>(null) }
    var carrierPath by remember { mutableStateOf<String?>(null) }
    var carrierName by remember { mutableStateOf<String?>(null) }
    var carrierSize by remember { mutableStateOf<Long?>(null) }
    var carrierValid by remember { mutableStateOf(false) }
    // 图像预览
    var carrierBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }

    // ---- 载体文件选择加载状态 ----
    var carrierLoading by remember { mutableStateOf(false) }
    var carrierPickJob by remember { mutableStateOf<Job?>(null) }

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

    // Argon2 移动模式档位（复用全局设置，映射为隐写 KDF 覆写参数）
    var argon2Mode by remember { mutableStateOf(Argon2MobileMode.BALANCED) }

    // 从 DataStore 加载 Argon2 档位（仅首次组合）
    LaunchedEffect(Unit) {
        argon2Mode = Argon2MobileMode.fromKey(settings.argon2MobileMode.first())
    }

    // ---- 输出 ----
    var outDir by remember { mutableStateOf<String?>(null) }
    var outName by remember { mutableStateOf<String?>(null) }
    var outDirUri by remember { mutableStateOf<Uri?>(null) }
    var pendingSafOut by remember { mutableStateOf<PendingSafOutput?>(null) }

    // ---- 输出目录选择加载状态 ----
    var outDirLoading by remember { mutableStateOf(false) }
    var outDirPickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 待隐藏文件选择器 ----
    val secretPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u == null) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理，允许用户换选新文件
        secretPickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        secretLoading = true
        secretPickJob = scope.launch {
            val myJob = coroutineContext[Job]
            try {
                // 名称查询与文件解析全部移入 IO 线程，避免阻塞主线程
                val name = withContext(Dispatchers.IO) { extractFileName(ctx, u) }
                val path = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
                if (path != null) {
                    val (size, parent) = withContext(Dispatchers.IO) {
                        val f = File(path)
                        val sz = if (f.exists()) f.length() else null
                        sz to f.parent
                    }
                    secretUri = u
                    secretName = name
                    secretPath = path
                    secretSize = size
                    if (outDir == null) {
                        outDir = parent ?: ctx.filesDir.absolutePath
                    }
                }
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (secretPickJob === myJob) {
                    secretLoading = false
                }
            }
        }
    }

    // ---- 载体文件选择器 ----
    val carrierPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u == null) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理，允许用户换选新文件
        carrierPickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        carrierLoading = true
        carrierPickJob = scope.launch {
            val myJob = coroutineContext[Job]
            try {
                // 名称查询移入 IO 线程
                val name = withContext(Dispatchers.IO) { extractFileName(ctx, u) }
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
                // 回收旧预览图并清空，防止 native 内存泄漏与加载期间的旧预览残留
                carrierBitmap?.recycle()
                carrierBitmap = null
                val path = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
                carrierUri = u
                carrierName = name
                carrierPath = path
                carrierValid = path != null
                if (path != null) {
                    val (size, parent) = withContext(Dispatchers.IO) {
                        val f = File(path)
                        val sz = if (f.exists()) f.length() else null
                        sz to f.parent
                    }
                    carrierSize = size
                    // 生成输出文件名
                    val dotIdx = name.lastIndexOf('.')
                    outName = if (dotIdx >= 0) {
                        "${name.substring(0, dotIdx)}_stego${name.substring(dotIdx)}"
                    } else {
                        "${name}_stego"
                    }
                    if (outDir == null) {
                        outDir = parent ?: ctx.filesDir.absolutePath
                    }
                    // 加载图像预览（仅 PNG，解码在 IO 线程）
                    carrierBitmap = if (isImageCarrier(name)) {
                        withContext(Dispatchers.IO) {
                            loadThumbnail(path, 360)
                        }
                    } else {
                        null
                    }
                }
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (carrierPickJob === myJob) {
                    carrierLoading = false
                }
            }
        }
    }

    // ---- 输出目录选择器 ----
    val outDirPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { u ->
        if (u == null) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理
        outDirPickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        outDirLoading = true
        outDirPickJob = scope.launch {
            val myJob = coroutineContext[Job]
            try {
                val resolved = withContext(Dispatchers.IO) { fileOps.resolveTreeUriToPath(u) }
                if (resolved != null) {
                    outDir = resolved
                    outDirUri = u
                    // 持久化授权，使历史记录中保存的 SAF 树 URI 跨重启仍可用
                    try {
                        ctx.contentResolver.takePersistableUriPermission(
                            u,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        )
                    } catch (_: Exception) {
                        // 个别文档提供者不支持持久授权，忽略即可
                    }
                }
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (outDirPickJob === myJob) {
                    outDirLoading = false
                }
            }
        }
    }

    val hasSecret = secretPath != null
    val hasCarrier = carrierPath != null && carrierValid
    val canStart = hasSecret && hasCarrier && !isRunning && !secretLoading && !carrierLoading

    // ---- 开始隐写 ----
    fun doHide() {
        val safUri = outDirUri
        val writeDir = if (safUri != null) {
            val tmp = fileOps.createOutputTempDir()
            pendingSafOut = PendingSafOutput(safUri, tmp)
            tmp.absolutePath
        } else {
            outDir ?: secretPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath
        }
        val outFile = "$writeDir/${outName ?: "stego_output"}"
        val opts = FileStegoOptions.builder()
            .paranoid(paranoid)
            .compressed(compressed)
            .storeIntegrity(storeIntegrity)
            .stealth(stealth)
            .obfuscateSize(obfuscateSize)
            .targetSizeBytes(if (obfuscateSize) targetSizeMB * 1024L * 1024L else 0)
            .preferChunk(preferChunk)
            // 移动端：低内存档位 Argon2 参数（写入载体元数据）+ 按设备可用堆设置的大文件护栏。
            // 档位内存超过应用堆时，共享核心会自动回退到离堆（native 内存）派生
            .argon2Params(argon2Mode.toArgon2Params())
            .lowMemoryMode(true)
            .lowMemoryThresholdBytes(DeviceMemory.lowMemoryThresholdBytes())
            .build()
        vm.hide(carrierPath!!, secretPath!!, outFile, password, opts)
    }

    // ---- 结果弹窗状态 ----
    var showResultDialog by remember { mutableStateOf(false) }
    var resultTitle by remember { mutableStateOf("") }
    var resultMessage by remember { mutableStateOf("") }
    var resultDetail by remember { mutableStateOf<String?>(null) }
    var resultType by remember { mutableStateOf(ResultType.INFO) }

    // 提交 SAF 输出：将暂存临时文件复制到用户选择的 SAF 目录并清理。返回 null 表示非 SAF 输出
    suspend fun commitSafOutput(): Boolean? {
        val pending = pendingSafOut
        if (pending == null) {
            return null
        }
        val ok = withContext(Dispatchers.IO) { fileOps.copyDirectoryToTree(pending.treeUri, pending.tempDir) }
        withContext(Dispatchers.IO) { pending.tempDir.deleteRecursively() }
        pendingSafOut = null
        return ok
    }

    LaunchedEffect(progress.state) {
        when (progress.state) {
            ProgressState.State.DONE -> {
                val committed = commitSafOutput()
                when (committed) {
                    null, true -> {
                        resultTitle = "隐写完成"
                        resultMessage = "文件已成功隐藏到载体中。\n输出文件：${outName ?: ""}"
                        resultDetail = null
                        resultType = ResultType.SUCCESS
                        // 记录操作历史（隐写加密）
                        val outNameNow = outName ?: "stego_output"
                        val resolvedOutDir = outDir
                            ?: secretPath?.let { File(it).parent }
                            ?: ctx.filesDir.absolutePath
                        withContext(Dispatchers.IO) {
                            HistoryService.record(
                                OperationType.STEGO_ENCODE,
                                outNameNow,
                                "$resolvedOutDir/$outNameNow",
                                outDirUri?.toString()
                            )
                        }
                    }
                    false -> {
                        resultTitle = "隐写完成但保存失败"
                        resultMessage = "隐写已完成，但复制到所选目录失败，请检查目录权限后重试。"
                        resultDetail = null
                        resultType = ResultType.ERROR
                    }
                }
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
        // 容器透明，避免遮住全局背景图层
        containerColor = Color.Transparent,
        topBar = {
            CompactTopBar(
                title = "隐写",
                actions = {
                    IconButton(onClick = onOpenHistory) {
                        Icon(Icons.Outlined.History, contentDescription = "操作历史")
                    }
                }
            )
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

            // 低调的内存使用指示器（可在设置中关闭）
            if (showMemoryIndicator) {
                MemoryIndicator()
                Spacer(modifier = Modifier.height(6.dp))
            }

            // 所选档位超过应用堆时提示将使用离堆内存派生（速度较慢）
            if (!Argon2MobileMode.isFeasible(argon2Mode)) {
                Text(
                    "${argon2Mode.label} 档位的内存需求超过应用堆，密钥派生将使用离堆内存（速度较慢）",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(6.dp))
            }

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
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
                    onClick = { secretPicker.launch(arrayOf("*/*")) }
                ) {
                    if (secretLoading) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            PickerLoadingIndicator(
                                text = pickerLoadingText(),
                                iconSize = 40.dp,
                                vertical = true
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                pickerLoadingHint(),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                            )
                        }
                    } else {
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
                }
            } else {
                FilePickerCard(
                    fileName = secretName,
                    fileSize = secretSize,
                    onClick = { secretPicker.launch(arrayOf("*/*")) },
                    label = "点击更换待隐藏文件",
                    loading = secretLoading,
                    loadingText = pickerLoadingText(),
                    loadingHint = pickerLoadingHint()
                )
                FileActionRow(
                    onPickFile = { secretPicker.launch(arrayOf("*/*")) },
                    onRemove = {
                        secretUri = null; secretPath = null
                        secretName = null; secretSize = null
                    }
                )
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
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
                    onClick = { carrierPicker.launch(arrayOf("*/*")) }
                ) {
                    if (carrierLoading) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            PickerLoadingIndicator(
                                text = pickerLoadingText(),
                                iconSize = 40.dp,
                                vertical = true
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                pickerLoadingHint(),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                            )
                        }
                    } else {
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
                                "支持格式：PNG / ZIP / PDF / WAV / FLAC / MP4 / M4A / M4V",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                            )
                        }
                    }
                }
            } else {
                // 载体信息卡片
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        // 换选载体处理中：显示旋转圆圈提示
                        if (carrierLoading) {
                            PickerLoadingIndicator(
                                text = pickerLoadingText(),
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
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
                FileActionRow(
                    onPickFile = { carrierPicker.launch(arrayOf("*/*")) },
                    pickFileLabel = "换载体",
                    onRemove = {
                        carrierBitmap?.recycle()
                        carrierUri = null; carrierPath = null; carrierName = null
                        carrierSize = null; carrierValid = false; carrierBitmap = null
                    }
                )
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
                if (outDirLoading) {
                    PickerLoadingIndicator(
                        text = pickerLoadingText(),
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 14.dp)
                    )
                } else {
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
