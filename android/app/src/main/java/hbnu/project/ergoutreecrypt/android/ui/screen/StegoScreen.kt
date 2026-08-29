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
import androidx.compose.foundation.layout.WindowInsets
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
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.platform.OutputDirResolver
import hbnu.project.ergoutreecrypt.android.platform.PendingOutput
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.ExpandableCard
import hbnu.project.ergoutreecrypt.android.ui.component.FileActionRow
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.InfoTooltip
import hbnu.project.ergoutreecrypt.android.ui.component.LogHistoryActions
import hbnu.project.ergoutreecrypt.android.ui.component.MemoryIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.OperationLogPanel
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
import hbnu.project.ergoutreecrypt.android.viewmodel.OperationCoordinator
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.android.viewmodel.StegoViewModel
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// ==================== 提示文本常量 ====================

/** 提示文本 */
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
    // ViewModel 提升到 Activity 作用域：切换 Tab/旋转屏幕不中断正在进行的操作
    val vm: StegoViewModel = viewModel(
        key = "stegoHide",
        factory = viewModelFactory { initializer { StegoViewModel(ctx.applicationContext) } }
    )
    val progress by vm.progress.collectAsState()
    val busy by OperationCoordinator.busy.collectAsState()
    val isRunning = progress.state == ProgressState.State.RUNNING
    val showMemoryIndicator by settings.showMemoryIndicator.collectAsState(initial = true)
    var logVisible by remember { mutableStateOf(false) }
    LaunchedEffect(logVisible) {
        if (logVisible) {
            delay(80)
            scroll.animateScrollTo(scroll.maxValue)
        }
    }

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
    var storeIntegrity by remember { mutableStateOf(true) }
    var stealth by remember { mutableStateOf(false) }
    var obfuscateSize by remember { mutableStateOf(false) }
    var targetSizeMB by remember { mutableStateOf(10) }
    var preferChunk by remember { mutableStateOf(true) }

    // Argon2 移动模式档位（复用全局设置，映射为隐写 KDF 覆写参数）
    var argon2Mode by remember { mutableStateOf(Argon2MobileMode.AUTO) }

    // 从 DataStore 加载 Argon2 档位（仅首次组合）
    LaunchedEffect(Unit) {
        argon2Mode = Argon2MobileMode.fromKey(settings.argon2MobileMode.first())
    }

    // ---- 输出 ----
    var outDir by remember { mutableStateOf<String?>(null) }
    var outName by remember { mutableStateOf<String?>(null) }
    var outDirUri by remember { mutableStateOf<Uri?>(null) }
    var pendingOut by remember { mutableStateOf<PendingOutput?>(null) }

    // 默认输出目录显示路径（IO 线程解析，避免主线程 mkdirs）
    var defaultOutPath by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        defaultOutPath = withContext(Dispatchers.IO) {
            when (val r = OutputDirResolver.resolve(ctx)) {
                is OutputDirResolver.Resolved.Direct -> r.path
                is OutputDirResolver.Resolved.AppExternal -> r.path
                is OutputDirResolver.Resolved.MediaStore -> OutputDirResolver.publicDownloadPath()
            }
        }
    }

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
                    val size = withContext(Dispatchers.IO) {
                        val f = File(path)
                        if (f.exists()) f.length() else null
                    }
                    secretUri = u
                    secretName = name
                    secretPath = path
                    secretSize = size
                } else {
                    // 路径解析失败（云盘/存储权限/磁盘不足等）时给出可见提示，避免按钮静默置灰
                    Toast.makeText(ctx, "无法读取所选文件，请换用系统文件管理器或检查存储权限后重试", Toast.LENGTH_LONG).show()
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
                if (path == null) {
                    // 载体路径解析失败（云盘/存储权限/磁盘不足等）时给出可见提示，避免按钮静默置灰
                    Toast.makeText(ctx, "无法读取所选载体文件，请换用系统文件管理器或检查存储权限后重试", Toast.LENGTH_LONG).show()
                }
                if (path != null) {
                    val size = withContext(Dispatchers.IO) {
                        val f = File(path)
                        if (f.exists()) f.length() else null
                    }
                    carrierSize = size
                    // 生成输出文件名
                    val dotIdx = name.lastIndexOf('.')
                    outName = if (dotIdx >= 0) {
                        "${name.substring(0, dotIdx)}_stego${name.substring(dotIdx)}"
                    } else {
                        "${name}_stego"
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
                // 总是记录树 URI：云盘等非主卷提供者无法解析为磁盘路径，但仍可经 SAF 写入
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
                val resolved = withContext(Dispatchers.IO) { fileOps.resolveTreeUriToPath(u) }
                if (resolved != null) {
                    outDir = resolved
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
    val canStart = hasSecret && hasCarrier && password.isNotEmpty() && !isRunning && !secretLoading && !carrierLoading && !busy

    // ---- 开始隐写 ----
    fun doHide() {
        scope.launch {
            val safUri = outDirUri
            val resolved = withContext(Dispatchers.IO) { OutputDirResolver.resolve(ctx) }
            val writeDir = when {
                safUri != null -> {
                    val tmp = withContext(Dispatchers.IO) { fileOps.createOutputTempDir() }
                    pendingOut = PendingOutput.Saf(safUri, tmp)
                    tmp.absolutePath
                }
                outDir != null -> outDir!!
                resolved is OutputDirResolver.Resolved.Direct -> resolved.path
                resolved is OutputDirResolver.Resolved.MediaStore -> {
                    val tmp = withContext(Dispatchers.IO) { fileOps.createOutputTempDir() }
                    pendingOut = PendingOutput.MediaStore(resolved.relativePath, tmp)
                    tmp.absolutePath
                }
                else -> (resolved as OutputDirResolver.Resolved.AppExternal).path
            }
            val outFile = "$writeDir/${outName ?: "stego_output"}"
            val opts = FileStegoOptions.builder()
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
    }

    // ---- 结果弹窗状态 ----
    var showResultDialog by remember { mutableStateOf(false) }
    var resultTitle by remember { mutableStateOf("") }
    var resultMessage by remember { mutableStateOf("") }
    var resultDetail by remember { mutableStateOf<String?>(null) }
    var resultType by remember { mutableStateOf(ResultType.INFO) }

    // 提交暂存输出：SAF 树经 DocumentsContract、MediaStore 经公共下载目录。返回 null 表示无暂存输出
    suspend fun commitOutput(): Boolean? {
        val pending = pendingOut
        if (pending == null) {
            return null
        }
        val ok = withContext(Dispatchers.IO) { fileOps.commitOutput(pending) }
        withContext(Dispatchers.IO) { pending.tempDir.deleteRecursively() }
        pendingOut = null
        return ok
    }

    // 终态分支先捕获所需数据并 reset() 消费，再执行挂起工作：
    // 切回 Tab 或页面重建不会重复弹窗/重复记录历史
    LaunchedEffect(progress.state) {
        when (progress.state) {
            ProgressState.State.DONE -> {
                val outNameNow = outName ?: "stego_output"
                val resolvedOutDir = OutputDirResolver.historyDir(
                    ctx, outDir, secretPath?.let { File(it).parent })
                val savedTreeUri = outDirUri?.toString()
                vm.reset()
                // reset() 改变 LaunchedEffect key 会取消当前协程，挂起工作放到独立协程执行
                scope.launch {
                    val committed = commitOutput()
                    when (committed) {
                        null, true -> {
                            resultTitle = "隐写完成"
                            resultMessage = "文件已成功隐藏到载体中。\n输出文件：$outNameNow"
                            resultDetail = null
                            resultType = ResultType.SUCCESS
                            // 记录操作历史（隐写加密）
                            withContext(Dispatchers.IO) {
                                HistoryService.record(
                                    OperationType.STEGO_ENCODE,
                                    outNameNow,
                                    "$resolvedOutDir/$outNameNow",
                                    savedTreeUri
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
            }
            ProgressState.State.ERROR -> {
                val errMsg = mapErrorToChineseMessage(progress.error)
                val errDetail = progress.error
                vm.reset()
                resultTitle = "隐写失败"
                resultMessage = errMsg
                resultDetail = errDetail
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                vm.reset()
                resultTitle = "已取消"
                resultMessage = "隐写操作已被取消。"
                resultDetail = null
                resultType = ResultType.INFO
                showResultDialog = true
            }
            else -> { /* no-op */ }
        }
    }

    // 页面销毁时回收 Bitmap 预览，防止 native 内存泄漏；操作协程不再随页面销毁而取消
    DisposableEffect(Unit) {
        onDispose {
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
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            CompactTopBar(
                title = "隐写",
                actions = {
                    LogHistoryActions(
                        logVisible = logVisible,
                        onToggleLog = { logVisible = !logVisible },
                        onOpenHistory = onOpenHistory
                    )
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
            val displayPath = outDir ?: defaultOutPath ?: ""
            val displayText = if (displayPath.isNotEmpty()) {
                if (displayPath.length > 44) "…${displayPath.takeLast(44)}" else displayPath
            } else {
                "默认输出至 下载/ErgouTreeCrypt"
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
                placeholder = { Text("请输入密码") },
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
                    "请输入密码",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.error
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

            OperationLogPanel(visible = logVisible)

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
