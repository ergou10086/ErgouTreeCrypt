package hbnu.project.ergoutreecrypt.android.ui.screen

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.ui.component.ExpandableCard
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.ForegroundServiceEffect
import hbnu.project.ergoutreecrypt.android.ui.component.InfoTooltip
import hbnu.project.ergoutreecrypt.android.ui.component.PasswordStrengthMeter
import hbnu.project.ergoutreecrypt.android.ui.component.ProgressCard
import hbnu.project.ergoutreecrypt.android.ui.component.ResultDialog
import hbnu.project.ergoutreecrypt.android.ui.component.ResultType
import hbnu.project.ergoutreecrypt.android.ui.component.buildSuccessMessage
import hbnu.project.ergoutreecrypt.android.ui.component.extractFileName
import hbnu.project.ergoutreecrypt.android.ui.component.generateRandomPassword
import hbnu.project.ergoutreecrypt.android.ui.component.mapErrorToChineseMessage
import hbnu.project.ergoutreecrypt.android.viewmodel.EncryptViewModel
import hbnu.project.ergoutreecrypt.android.viewmodel.MediaCryptViewModel
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptProfile
import hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat
import hbnu.project.ergoutreecrypt.volume.EncryptRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// ==================== 工具函数 ====================

private fun formatSize(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val units = arrayOf("B", "KiB", "MiB", "GiB")
    var s = bytes.toDouble()
    var i = 0
    while (s >= 1024.0 && i < units.size - 1) { s /= 1024.0; i++ }
    return if (i == 0) "${bytes} B" else "%.1f %s".format(s, units[i])
}

/** 归档格式 */
private data class Fmt(val code: String, val label: String)
private val ARCHIVE_FORMATS = listOf(
    Fmt("", "不归档"), Fmt("ZIP", "ZIP"), Fmt("GZ", "GZ"),
    Fmt("TAR.GZ", "TAR.GZ"), Fmt("7Z", "7Z")
)

/** Argon2 移动模式 */
private enum class Argon2Mode(val label: String, val mem: Int, val passes: Int, val thr: Int) {
    STANDARD("标准 (1 GiB)", 1 shl 20, 4, 4),
    LIGHT("省电 (64 MiB)", 64 shl 10, 2, 2)
}

/** 检测文件是否为支持的媒体格式 */
private fun detectMediaFormat(fileName: String?): MediaFormat? {
    if (fileName == null) return null
    val ext = fileName.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "wav" -> MediaFormat.WAV
        "mp3" -> MediaFormat.MP3
        "mp4", "m4a", "m4v", "mov" -> MediaFormat.MP4
        else -> null
    }
}

// ==================== 桌面端对齐的提示文本 ====================

private val TIP_PARANOID = "启用后数据先经 Serpent 加密再经 XChaCha20 加密，提供双重保护。加解密速度会略有下降。"
private val TIP_RS = "使用 Reed-Solomon 纠错码，可在文件部分损坏时恢复数据。启用后文件体积增加约 6%。"
private val TIP_DENIABILITY = "创建包含两份内容的加密容器：真密码解密真实文件，伪密码（钓鱼密码）解密无害的伪装文件。即使被胁迫，也可安全交出伪密码。"
private val TIP_COMPRESS = "加密前先使用 Zstandard 压缩数据，可减小文件体积。"
private val TIP_COMPRESS_AFTER = "加密完成后将输出文件打包为指定归档格式。ZIP 格式支持 AES-256 密码保护。"
private val TIP_SPLIT = "将加密输出切分为多个指定大小的分卷文件，便于传输和存储。"
private val TIP_DEPTH = "控制文件夹迭代加密的层数。深度内的文件逐一加密为 .ergou；超出深度的子目录会先整体打包再加密。默认值为 2。"
private val TIP_KEYFILE_ORDERED = "要求按添加时的顺序提供密钥文件，顺序错误将导致解密失败。"

// ============================================================
// EncryptScreen — Android 移动端 UX 优化版
// ============================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EncryptScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val scroll = rememberScrollState()
    val fileOps = remember { AndroidFileOps(ctx.applicationContext) }
    val vm = remember { EncryptViewModel() }
    val mediaVm = remember { MediaCryptViewModel() }
    val settings = remember { AndroidSettings(ctx.applicationContext) }
    val progress by vm.progress.collectAsState()
    val mediaProgress by mediaVm.progress.collectAsState()
    val isRunning = progress.state == ProgressState.State.RUNNING
            || mediaProgress.state == ProgressState.State.RUNNING

    // ---- 文件（仅单文件或单文件夹） ----
    var inUri by remember { mutableStateOf<Uri?>(null) }
    var inPath by remember { mutableStateOf<String?>(null) }
    var inName by remember { mutableStateOf<String?>(null) }
    var inSize by remember { mutableStateOf<Long?>(null) }
    var isFolder by remember { mutableStateOf(false) }
    var outDir by remember { mutableStateOf<String?>(null) }
    var outName by remember { mutableStateOf<String?>(null) }

    // ---- 密码 ----
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    // ---- 加密选项（初始值从 DataStore 设置中加载） ----
    var paranoid by remember { mutableStateOf(false) }
    var reedSolomon by remember { mutableStateOf(false) }
    var deniability by remember { mutableStateOf(false) }
    var compressBefore by remember { mutableStateOf(false) }
    var compressAfter by remember { mutableStateOf(false) }
    var split by remember { mutableStateOf(false) }
    var encDepth by remember { mutableStateOf(2) }
    var argon2Mode by remember { mutableStateOf(Argon2Mode.STANDARD) }
    var settingsLoaded by remember { mutableStateOf(false) }

    // 从 DataStore 加载默认设置（仅首次组合）
    LaunchedEffect(Unit) {
        paranoid = settings.isDefaultParanoid.first()
        reedSolomon = settings.isDefaultReedSolomon.first()
        val argon2 = settings.argon2MobileMode.first()
        argon2Mode = if (argon2 == "LIGHT") Argon2Mode.LIGHT else Argon2Mode.STANDARD
        settingsLoaded = true
    }

    // ---- 音视频格式保持加密选项 ----
    var mediaMode by remember { mutableStateOf(false) }
    // 档位由移动端自动选择最优安全档，不开放手动选择
    var mediaParanoid by remember { mutableStateOf(false) }
    var mediaIntegrity by remember { mutableStateOf(true) }

    // 子字段
    var archiveFmt by remember { mutableStateOf("") }
    var archivePassword by remember { mutableStateOf("") }
    var splitSize by remember { mutableStateOf(100) }
    var decoyPath by remember { mutableStateOf<String?>(null) }
    var decoyName by remember { mutableStateOf<String?>(null) }
    var fakePwd by remember { mutableStateOf("") }

    // 备注
    var comments by remember { mutableStateOf("") }

    // 密钥文件
    var kfUris by remember { mutableStateOf(listOf<Uri>()) }
    var kfPaths by remember { mutableStateOf(listOf<String>()) }
    var kfNames by remember { mutableStateOf(listOf<String>()) }
    var kfOrdered by remember { mutableStateOf(false) }

    // ---- 单文件选择器 ----
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u != null) scope.launch {
            inUri = u; inName = extractFileName(u)
            inPath = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
            if (inPath != null) {
                val f = File(inPath!!)
                inSize = if (f.exists()) f.length() else null
                isFolder = f.isDirectory
                if (outDir == null) {
                    outDir = f.parent ?: ctx.filesDir.absolutePath
                }
            }
            outName = inName?.let { "$it.ergou" }
        }
    }

    // ---- 文件夹选择器 ----
    val folderPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { u ->
        if (u != null) scope.launch {
            inUri = u
            val name = extractFileName(u)
            inName = if (name == "未知文件") "选择的文件夹" else name
            inPath = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
            if (inPath != null) {
                val f = File(inPath!!)
                inSize = null
                isFolder = true
                if (outDir == null) {
                    outDir = f.parent ?: ctx.filesDir.absolutePath
                }
            }
            outName = "$inName.ergou"
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

    val keyfilePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) scope.launch {
            val nu = kfUris.toMutableList(); val np = kfPaths.toMutableList(); val nn = kfNames.toMutableList()
            for (u in uris) {
                if (u !in nu) {
                    nu.add(u); nn.add(extractFileName(u))
                    // 拷贝到安全区域，避免直接使用原始路径
                    val securePath = withContext(Dispatchers.IO) { fileOps.copyKeyfileToSecureArea(u) }
                    if (securePath != null) np.add(securePath)
                }
            }
            kfUris = nu; kfPaths = np; kfNames = nn
        }
    }

    val decoyPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u != null) scope.launch {
            decoyName = extractFileName(u)
            decoyPath = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
        }
    }

    val hasFile = inPath != null

    // ---- 开始加密 ----
    fun doEncrypt() {
        scope.launch {
            val req = EncryptRequest()
            req.inputFile = inPath
            val outFile = "${outDir ?: inPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath}/${outName ?: "encrypted.ergou"}"
            req.outputFile = outFile
            req.password = password
            req.setParanoid(paranoid)
            req.setReedSolomon(reedSolomon)
            req.setCompress(compressBefore)
            if (compressAfter) req.setCompress(true)
            req.setSplit(split)
            req.chunkSize = splitSize
            req.comments = comments
            req.argon2MemoryKib = argon2Mode.mem
            req.argon2Passes = argon2Mode.passes
            req.argon2Threads = argon2Mode.thr
            if (archiveFmt.isNotEmpty()) {
                req.archiveFormat = archiveFmt
                if (archiveFmt == "ZIP" && archivePassword.isNotEmpty()) {
                    req.archivePassword = archivePassword
                }
            }
            if (kfPaths.isNotEmpty()) { req.keyfiles = kfPaths.toList(); req.setKeyfileOrdered(kfOrdered) }
            if (deniability) {
                req.setDeniability(true)
                if (decoyPath != null) req.decoyFilePath = decoyPath
                if (fakePwd.isNotEmpty()) req.fakePassword = fakePwd
            }
            req.rsCodecs = RsCodecs()
            vm.startEncrypt(req)
        }
    }

    /** 格式保持加密入口。档位自动选择推荐安全档，不开放手动选择。 */
    fun doMediaEncrypt() {
        val outFile = "${outDir ?: inPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath}/${outName ?: "encrypted.${inName?.substringAfterLast('.') ?: "media"}"}"
        mediaVm.startEncrypt(
            input = inPath!!,
            output = outFile,
            password = password,
            profile = null, // 自动推荐档位
            paranoid = mediaParanoid,
            storeIntegrity = mediaIntegrity
        )
    }

    // 前台 Service 生命周期管理（大文件保活）
    ForegroundServiceEffect(
        ctx = ctx,
        isRunning = isRunning,
        progressState = if (mediaProgress.state == ProgressState.State.RUNNING) mediaProgress else progress,
        fileSize = inSize,
        title = if (mediaMode) "正在格式保持加密" else "正在加密",
        fileName = inName
    )

    // 加密完成后清理安全密钥文件
    LaunchedEffect(progress.state, mediaProgress.state) {
        if (progress.state == ProgressState.State.DONE ||
            progress.state == ProgressState.State.ERROR ||
            progress.state == ProgressState.State.CANCELLED) {
            withContext(Dispatchers.IO) { fileOps.cleanupSecureKeyfiles() }
        }
        if (mediaProgress.state == ProgressState.State.DONE ||
            mediaProgress.state == ProgressState.State.ERROR ||
            mediaProgress.state == ProgressState.State.CANCELLED) {
            withContext(Dispatchers.IO) { fileOps.cleanupSecureKeyfiles() }
        }
    }

    // ---- 结果弹窗状态 ----
    var showResultDialog by remember { mutableStateOf(false) }
    var resultTitle by remember { mutableStateOf("") }
    var resultMessage by remember { mutableStateOf("") }
    var resultDetail by remember { mutableStateOf<String?>(null) }
    var resultType by remember { mutableStateOf(ResultType.INFO) }

    // 监听加密完成/失败状态，触发结果弹窗
    LaunchedEffect(progress.state) {
        when (progress.state) {
            ProgressState.State.DONE -> {
                resultTitle = "加密完成"
                resultMessage = buildSuccessMessage("加密", outName)
                resultDetail = null
                resultType = ResultType.SUCCESS
                showResultDialog = true
            }
            ProgressState.State.ERROR -> {
                resultTitle = "加密失败"
                resultMessage = mapErrorToChineseMessage(progress.error)
                resultDetail = progress.error
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                resultTitle = "已取消"
                resultMessage = "加密操作已被取消。"
                resultDetail = null
                resultType = ResultType.INFO
                showResultDialog = true
            }
            else -> { /* no-op */ }
        }
    }

    // 监听媒体加密完成/失败状态
    LaunchedEffect(mediaProgress.state) {
        when (mediaProgress.state) {
            ProgressState.State.DONE -> {
                resultTitle = "格式保持加密完成"
                resultMessage = buildSuccessMessage("加密", outName)
                resultDetail = null
                resultType = ResultType.SUCCESS
                showResultDialog = true
            }
            ProgressState.State.ERROR -> {
                resultTitle = "格式保持加密失败"
                resultMessage = mapErrorToChineseMessage(mediaProgress.error)
                resultDetail = mediaProgress.error
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                resultTitle = "已取消"
                resultMessage = "格式保持加密操作已被取消。"
                resultDetail = null
                resultType = ResultType.INFO
                showResultDialog = true
            }
            else -> { /* no-op */ }
        }
    }

    // 离开页面时取消正在进行的操作，防止后台协程泄漏
    DisposableEffect(Unit) {
        onDispose {
            vm.cancel()
            mediaVm.cancel()
        }
    }

    // 结果弹窗
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
            TopAppBar(
                title = { Text("文件加密") }
            )
        },
        bottomBar = {
            if (isRunning) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    val activeProgress = if (mediaProgress.state == ProgressState.State.RUNNING) mediaProgress else progress
                    val cancelAction = {
                        if (mediaProgress.state == ProgressState.State.RUNNING) mediaVm.cancel() else vm.cancel()
                    }
                    ProgressCard(progressState = activeProgress, onCancel = cancelAction)
                }
            } else {
                Box(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    Button(
                        onClick = { if (mediaMode) doMediaEncrypt() else doEncrypt() },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = hasFile // 允许无密码模式
                    ) {
                        Icon(Icons.Default.Lock, null)
                        Text(if (mediaMode) "  格式保持加密" else "  加密")
                    }
                }
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp).verticalScroll(scroll)
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            // ============================================================
            // 一、文件选择区（仅单文件或单文件夹）
            // ============================================================
            if (!hasFile) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                        onClick = { filePicker.launch(arrayOf("*/*")) }
                    ) {
                        Column(modifier = Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.AutoMirrored.Filled.InsertDriveFile, null, Modifier.size(40.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.height(8.dp))
                            Text("点击选择单个文件", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            if (mediaMode) {
                                Spacer(Modifier.height(4.dp))
                                Text("格式保持加密仅支持 MP3 / MP4 / WAV 单文件", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f))
                            }
                        }
                    }
                    // 格式保持加密仅支持单文件，隐藏文件夹选择
                    if (!mediaMode) {
                        Spacer(Modifier.height(8.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
                            onClick = { folderPicker.launch(null) }
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                                Text("或选择单个文件夹", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f))
                            }
                        }
                    }
                }
            } else {
                // 已选文件卡片
                FilePickerCard(fileName = inName, fileSize = inSize, onClick = { filePicker.launch(arrayOf("*/*")) }, label = "点击更换文件")

                // 更换/移除按钮行
                Row(modifier = Modifier.fillMaxWidth()) {
                    FilledTonalButton(
                        onClick = { filePicker.launch(arrayOf("*/*")) },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Add, null, Modifier.size(16.dp)); Text("  换文件") }
                    // 格式保持加密仅支持单文件，隐藏文件夹切换
                    if (!mediaMode) {
                        Spacer(Modifier.width(6.dp))
                        FilledTonalButton(
                            onClick = { folderPicker.launch(null) },
                            modifier = Modifier.weight(1f)
                        ) { Text("📁 换文件夹") }
                    }
                    Spacer(Modifier.width(6.dp))
                    FilledTonalButton(
                        onClick = {
                            inUri = null; inPath = null; inName = null; inSize = null
                            isFolder = false; outName = null
                        },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Delete, null, Modifier.size(16.dp)); Text("  移除") }
                }

                Spacer(Modifier.height(8.dp))

                // 输出目录选择（点击打开系统目录选择器）
                val displayPath = when {
                    outDir != null -> outDir!!
                    inPath != null -> File(inPath!!).parent ?: ""
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
            }

            Spacer(Modifier.height(16.dp))

            // ============================================================
            // 二、密码区
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

            // 强度指示器
            Spacer(Modifier.height(4.dp))
            if (password.isEmpty()) {
                Text(
                    "未输入密码 — 文件将使用系统默认约定密码进行无密码加密",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            } else {
                PasswordStrengthMeter(password = password, modifier = Modifier.fillMaxWidth())
            }

            // 密码操作按钮：复制密码 + 随机生成（方角按钮，文字自适应大小）
            Spacer(Modifier.height(8.dp))
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

            Spacer(Modifier.height(16.dp))

            // ============================================================
            // 三、高级选项
            // ============================================================
            ExpandableCard(title = "高级选项") {

                // ---- 偏执模式 (Paranoid) ----
                OptionRow("偏执模式（Serpent + XChaCha20 双重加密）", paranoid, { paranoid = it }, TIP_PARANOID, enabled = !mediaMode)
                Spacer(Modifier.height(6.dp))

                // ---- Reed-Solomon 纠错 ----
                OptionRow("Reed-Solomon 纠错（抗损坏，体积略增）", reedSolomon, { reedSolomon = it }, TIP_RS, enabled = !mediaMode)
                Spacer(Modifier.height(6.dp))

                // ---- 可否认加密 (Deniability) ----
                OptionRow("可否认加密（双卷隐藏）", deniability, { deniability = it }, TIP_DENIABILITY, enabled = !mediaMode)
                if (deniability && !mediaMode) {
                    Spacer(Modifier.height(6.dp))
                    Column(modifier = Modifier.padding(start = 36.dp)) {
                        // 钓鱼文件：与伪密码输入框等宽
                        if (decoyName != null) {
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                                Icon(Icons.AutoMirrored.Filled.InsertDriveFile, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.primary)
                                Spacer(Modifier.width(4.dp))
                                Text(decoyName!!, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                                IconButton(onClick = { decoyPath = null; decoyName = null }, modifier = Modifier.size(24.dp)) {
                                    Icon(Icons.Default.Close, "移除", Modifier.size(14.dp))
                                }
                            }
                        } else {
                            FilledTonalButton(
                                onClick = { decoyPicker.launch(arrayOf("*/*")) },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("选择钓鱼文件", style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                        Spacer(Modifier.height(6.dp))
                        OutlinedTextField(
                            value = fakePwd, onValueChange = { fakePwd = it },
                            label = { Text("伪密码") },
                            placeholder = { Text("胁迫时可安全交出此密码") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            textStyle = MaterialTheme.typography.bodyMedium,
                            visualTransformation = PasswordVisualTransformation()
                        )
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- 压缩后加密 ----
                OptionRow("压缩后加密", compressBefore, { compressBefore = it }, TIP_COMPRESS, enabled = !mediaMode)
                Spacer(Modifier.height(6.dp))

                // ---- 加密后压缩（格式保持加密下仍可用，对齐桌面端 avCompressAfterCheck） ----
                OptionRow("加密后压缩", compressAfter, { compressAfter = it }, TIP_COMPRESS_AFTER)
                if (compressAfter) {
                    Spacer(Modifier.height(4.dp))
                    Row(modifier = Modifier.padding(start = 36.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("归档格式：", style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.width(8.dp))
                        ArchiveDropdown(archiveFmt) { archiveFmt = it }
                    }
                    // ZIP 格式显示密码输入框
                    if (archiveFmt == "ZIP") {
                        Spacer(Modifier.height(4.dp))
                        OutlinedTextField(
                            value = archivePassword,
                            onValueChange = { archivePassword = it },
                            label = { Text("ZIP 压缩包密码") },
                            placeholder = { Text("为 ZIP 设置 AES-256 密码保护") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().padding(start = 36.dp),
                            textStyle = MaterialTheme.typography.bodyMedium,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
                        )
                    }
                }

                Spacer(Modifier.height(6.dp))

                // ---- 分卷输出 ----
                OptionRow("分卷输出", split, { split = it }, TIP_SPLIT, enabled = !mediaMode)
                if (split) {
                    Spacer(Modifier.height(4.dp))
                    Column(modifier = Modifier.padding(start = 36.dp)) {
                        Text("每卷大小：$splitSize MiB", style = MaterialTheme.typography.bodyMedium)
                        Slider(value = splitSize.toFloat(), onValueChange = { splitSize = it.toInt() }, valueRange = 10f..4096f, modifier = Modifier.fillMaxWidth())
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- 加密深度 ----
                val depthAlpha = if (!mediaMode) 1f else 0.38f
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("加密深度", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface.copy(alpha = depthAlpha))
                    Spacer(Modifier.width(4.dp))
                    InfoTooltip(TIP_DEPTH)
                }
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Slider(value = encDepth.toFloat(), onValueChange = { encDepth = it.toInt() }, valueRange = 1f..10f, steps = 8, modifier = Modifier.weight(1f), enabled = !mediaMode)
                    Spacer(Modifier.width(8.dp))
                    Text("$encDepth 层", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface.copy(alpha = depthAlpha))
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- Argon2 移动模式（格式保持加密使用独立的密钥派生） ----
                Text("Argon2 移动模式", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface.copy(alpha = if (!mediaMode) 1f else 0.38f))
                Spacer(Modifier.height(4.dp))
                Row {
                    androidx.compose.material3.FilterChip(selected = argon2Mode == Argon2Mode.STANDARD, onClick = { argon2Mode = Argon2Mode.STANDARD }, label = { Text("标准 1 GiB") }, enabled = !mediaMode)
                    Spacer(Modifier.width(8.dp))
                    androidx.compose.material3.FilterChip(selected = argon2Mode == Argon2Mode.LIGHT, onClick = { argon2Mode = Argon2Mode.LIGHT }, label = { Text("省电 64 MiB") }, enabled = !mediaMode)
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- 音视频格式保持加密 ----
                val mediaFmt = remember(inName) { detectMediaFormat(inName) }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = mediaMode, onCheckedChange = {
                        mediaMode = it
                        if (it) { isFolder = false } // 格式保持加密仅支持单文件
                        if (!it) { mediaParanoid = false; mediaIntegrity = true }
                    })
                    Text("格式保持加密", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f).padding(start = 4.dp))
                    if (mediaFmt != null) {
                        Text("· ${mediaFmt.name}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                    } else if (mediaMode && inName != null) {
                        Text("· 格式不支持", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
                // 仅选中且文件为支持的媒体格式时显示高级选项
                if (mediaMode && mediaFmt != null) {
                    Spacer(Modifier.height(8.dp))

                    // 档位自动选择（移动端不开放手动切换，始终取推荐的安全档位）
                    val autoProfile = remember(mediaFmt) { MediaCryptProfile.defaultFor(mediaFmt) }
                    val autoProfileLabel = when (autoProfile) {
                        MediaCryptProfile.W_FULL -> "W-FULL  全加密"
                        MediaCryptProfile.M_BODY -> "M-BODY  帧体加密"
                        MediaCryptProfile.V_MDAT -> "V-MDAT  mdat加密"
                        else -> autoProfile.name
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("档位：$autoProfileLabel", style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(4.dp))
                        InfoTooltip("移动端自动选择推荐的安全档位，加密数据范围最大，安全性最强。")
                    }

                    Spacer(Modifier.height(8.dp))

                    // 偏执模式 + 完整性校验（对齐桌面端 avParanoidCheck / avIntegrityCheck）
                    Row {
                        Checkbox(checked = mediaParanoid, onCheckedChange = { mediaParanoid = it })
                        Text("偏执模式（Serpent + XChaCha20 双重加密）", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 4.dp).weight(1f))
                        InfoTooltip("启用后 Argon2 使用 8 passes + HMAC-SHA3-512，并叠加 Serpent-CTR 外层加密，提供与普通文件加密偏执模式相同的双重保护。")
                    }
                    Row {
                        Checkbox(checked = mediaIntegrity, onCheckedChange = { mediaIntegrity = it })
                        Text("存储完整性校验", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 4.dp).weight(1f))
                        InfoTooltip("加密时将明文 MAC 存入元数据，解密后自动校验文件是否被篡改。建议保持开启。")
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- 备注 ----
                OutlinedTextField(
                    value = comments, onValueChange = { comments = it },
                    label = { Text("备注（明文存储，可选）") },
                    placeholder = { Text("该备注将以明文写入文件头") },
                    singleLine = true, modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
                )

                Spacer(Modifier.height(8.dp))

                // ---- 密钥文件（格式保持加密下不可用） ----
                val kfAlpha = if (!mediaMode) 1f else 0.38f
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("密钥文件", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = kfAlpha))
                    Spacer(Modifier.weight(1f))
                    if (kfNames.isNotEmpty() && !mediaMode) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = kfOrdered, onCheckedChange = { kfOrdered = it })
                            Text("要求顺序", style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.width(2.dp))
                            InfoTooltip(TIP_KEYFILE_ORDERED)
                        }
                    }
                    Spacer(Modifier.width(8.dp))
                    FilledTonalButton(onClick = { keyfilePicker.launch(arrayOf("*/*")) }, enabled = !mediaMode) {
                        Icon(Icons.Default.Add, null, Modifier.size(16.dp)); Text(" 添加")
                    }
                }

                if (kfNames.isEmpty() || mediaMode) {
                    Spacer(Modifier.height(4.dp))
                    Text(if (mediaMode) "格式保持加密不支持密钥文件" else "未添加密钥文件",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Spacer(Modifier.height(4.dp))
                    kfNames.forEachIndexed { i, n ->
                        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.AttachFile, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.primary)
                            Spacer(Modifier.width(8.dp))
                            Text(n, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                            IconButton(onClick = {
                                kfUris = kfUris.toMutableList().also { it.removeAt(i) }
                                kfPaths = kfPaths.toMutableList().also { it.removeAt(i) }
                                kfNames = kfNames.toMutableList().also { it.removeAt(i) }
                            }) { Icon(Icons.Default.Close, "移除", Modifier.size(16.dp)) }
                        }
                    }
                }
            } // End ExpandableCard

            Spacer(Modifier.height(80.dp))
        }
    }
}

// ==================== 辅助组件 ====================

/**
 * 选项行：Checkbox + 标签 + ⓘ 提示（提示图标在标签末尾对齐）。
 *
 * @param enabled 是否可交互，false 时整行置灰
 */
@Composable
private fun OptionRow(label: String, checked: Boolean, onToggle: (Boolean) -> Unit, tip: String, enabled: Boolean = true) {
    val alpha = if (enabled) 1f else 0.38f
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onToggle, enabled = enabled)
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f).padding(start = 4.dp), color = MaterialTheme.colorScheme.onSurface.copy(alpha = alpha))
        InfoTooltip(tip)
    }
}

/**
 * 归档格式下拉（紧凑样式，宽度更窄）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ArchiveDropdown(sel: String, onSel: (String) -> Unit) {
    var exp by remember { mutableStateOf(false) }
    val lab = ARCHIVE_FORMATS.firstOrNull { it.code == sel }?.label ?: "不归档"
    ExposedDropdownMenuBox(expanded = exp, onExpandedChange = { exp = it }) {
        OutlinedTextField(
            value = lab,
            onValueChange = {},
            readOnly = true,
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = exp) },
            modifier = Modifier.width(110.dp).menuAnchor(),
            textStyle = MaterialTheme.typography.bodySmall
        )
        ExposedDropdownMenu(expanded = exp, onDismissRequest = { exp = false }) {
            ARCHIVE_FORMATS.forEach { (c, l) ->
                DropdownMenuItem(text = { Text(l, style = MaterialTheme.typography.bodySmall) }, onClick = { onSel(c); exp = false })
            }
        }
    }
}

