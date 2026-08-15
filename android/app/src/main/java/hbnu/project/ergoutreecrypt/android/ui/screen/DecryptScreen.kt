package hbnu.project.ergoutreecrypt.android.ui.screen

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
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
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.platform.PendingSafOutput
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.ExpandableCard
import hbnu.project.ergoutreecrypt.android.ui.component.FileActionRow
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.ForegroundServiceEffect
import hbnu.project.ergoutreecrypt.android.ui.component.InfoTooltip
import hbnu.project.ergoutreecrypt.android.ui.component.MemoryIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.PickerLoadingIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.ProgressCard
import hbnu.project.ergoutreecrypt.android.ui.component.ResultDialog
import hbnu.project.ergoutreecrypt.android.ui.component.ResultType
import hbnu.project.ergoutreecrypt.android.ui.component.buildSuccessMessage
import hbnu.project.ergoutreecrypt.android.ui.component.extractFileName
import hbnu.project.ergoutreecrypt.android.ui.component.mapErrorToChineseMessage
import hbnu.project.ergoutreecrypt.android.ui.component.pickerLoadingHint
import hbnu.project.ergoutreecrypt.android.ui.component.pickerLoadingText
import hbnu.project.ergoutreecrypt.android.viewmodel.DecryptViewModel
import hbnu.project.ergoutreecrypt.android.viewmodel.MediaCryptViewModel
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationType
import hbnu.project.ergoutreecrypt.fileops.Splitter
import hbnu.project.ergoutreecrypt.volume.DecryptRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// ---- 桌面端对齐提示 ----
private val TIP_FORCE = "即使检测到数据损坏也强制解密，尽可能恢复未损坏部分的数据。"
private val TIP_AUTO_UNZIP = "如果输入的是压缩包，或文件夹中包含压缩包，解密后自动解压其中的归档文件，并递归解密解压出的 .ergou 加密文件。如果压缩包需要密码，会弹出密码输入框。"
private val TIP_VERIFY = "解密前先校验文件完整性，确认数据未被篡改后再进行解密。"
private val TIP_RECURSIVE = "默认仅解压最外层一层压缩包。开启后会递归深入解压解密内部的嵌套压缩包。递归解压存在压缩炸弹等风险，请确认来源可信后再使用。"
private val TIP_KEYFILE_ORDERED = "要求按添加时的顺序提供密钥文件，顺序错误将导致解密失败。"

private fun fmtSize(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val u = arrayOf("B", "KiB", "MiB", "GiB")
    var s = bytes.toDouble(); var i = 0
    while (s >= 1024 && i < u.size - 1) { s /= 1024; i++ }
    return if (i == 0) "${bytes} B" else "%.1f %s".format(s, u[i])
}

/** 检测文件是否为支持的媒体格式 */
private fun detectMediaFormat(fileName: String?): hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat? {
    if (fileName == null) return null
    val ext = fileName.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "wav" -> hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat.WAV
        "mp3" -> hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat.MP3
        "mp4", "m4a", "m4v", "mov" -> hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat.MP4
        else -> null
    }
}

// ============================================================
// DecryptScreen — Android 移动端 UX 优化版
// ============================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DecryptScreen(onOpenHistory: () -> Unit = {}) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val scroll = rememberScrollState()
    val fileOps = remember { AndroidFileOps(ctx.applicationContext) }
    val vm = remember { DecryptViewModel() }
    val mediaVm = remember { MediaCryptViewModel() }
    val settings = remember { AndroidSettings(ctx.applicationContext) }
    val progress by vm.progress.collectAsState()
    val mediaProgress by mediaVm.progress.collectAsState()
    val isRunning = progress.state == ProgressState.State.RUNNING
            || mediaProgress.state == ProgressState.State.RUNNING
    val showMemoryIndicator by settings.showMemoryIndicator.collectAsState(initial = true)

    // ---- 文件 ----
    var inUri by remember { mutableStateOf<Uri?>(null) }
    var inPath by remember { mutableStateOf<String?>(null) }
    var inName by remember { mutableStateOf<String?>(null) }
    var inSize by remember { mutableStateOf<Long?>(null) }
    var isFolder by remember { mutableStateOf(false) }
    var outDir by remember { mutableStateOf<String?>(null) }
    var outName by remember { mutableStateOf<String?>(null) }
    var outDirUri by remember { mutableStateOf<Uri?>(null) }
    var pendingSafOut by remember { mutableStateOf<PendingSafOutput?>(null) }

    // ---- 输入文件选择加载状态 ----
    var fileLoading by remember { mutableStateOf(false) }
    var filePickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 文件夹选择加载状态 ----
    var folderLoading by remember { mutableStateOf(false) }
    var folderPickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 输出目录选择加载状态 ----
    var outDirLoading by remember { mutableStateOf(false) }
    var outDirPickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 密码 ----
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    // ---- 解密选项（初始值从 DataStore 设置中加载） ----
    var force by remember { mutableStateOf(false) }
    var autoUnzip by remember { mutableStateOf(true) }
    var verifyFirst by remember { mutableStateOf(false) }
    var recursive by remember { mutableStateOf(false) }
    var recombine by remember { mutableStateOf(false) }
    var decryptSettingsLoaded by remember { mutableStateOf(false) }

    // 从 DataStore 加载默认设置（仅首次组合）
    LaunchedEffect(Unit) {
        autoUnzip = settings.isAutoDecompress.first()
        decryptSettingsLoaded = true
    }
    // 压缩包密码（选填，解压时使用）
    var archivePassword by remember { mutableStateOf("") }

    // ---- 音视频格式保持解密 ----
    var mediaDecryptMode by remember { mutableStateOf(false) }
    var mediaNoiseMode by remember { mutableStateOf(true) } // 噪音文件检测，默认开启

    // ---- 密钥文件 ----
    var kfUris by remember { mutableStateOf(listOf<Uri>()) }
    var kfPaths by remember { mutableStateOf(listOf<String>()) }
    var kfNames by remember { mutableStateOf(listOf<String>()) }
    var kfOrdered by remember { mutableStateOf(false) }

    // ---- 密钥文件选择加载状态 ----
    var keyfileLoading by remember { mutableStateOf(false) }
    var keyfilePickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 单文件选择器 ----
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u == null) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理，允许用户换选新文件
        filePickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        fileLoading = true
        filePickJob = scope.launch {
            val myJob = coroutineContext[Job]
            try {
                // 名称查询与文件解析全部移入 IO 线程，避免阻塞主线程
                val name = withContext(Dispatchers.IO) { extractFileName(ctx, u) }
                val path = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
                isFolder = false
                inUri = u
                inName = name
                inPath = path
                if (path != null) {
                    val (size, parent) = withContext(Dispatchers.IO) {
                        val f = File(path)
                        val sz = if (f.exists()) f.length() else null
                        sz to f.parent
                    }
                    inSize = size
                    if (outDir == null) {
                        outDir = parent ?: ctx.filesDir.absolutePath
                    }
                }
                name.let { n ->
                    outName = when {
                        n.endsWith(".ergou", true) -> n.removeSuffix(".ergou").removeSuffix(".ERGOU")
                        n.endsWith(".pcv", true) -> n.removeSuffix(".pcv").removeSuffix(".PCV")
                        else -> "$n.decrypted"
                    }
                }
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (filePickJob === myJob) {
                    fileLoading = false
                }
            }
        }
    }

    // ---- 文件夹选择器（支持选择包含加密文件的文件夹） ----
    val folderPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { u ->
        if (u == null) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理
        folderPickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        folderLoading = true
        folderPickJob = scope.launch {
            val myJob = coroutineContext[Job]
            try {
                // 名称查询与目录解析全部移入 IO 线程
                val name = withContext(Dispatchers.IO) { extractFileName(ctx, u) }
                val path = withContext(Dispatchers.IO) { fileOps.resolveTreeUriToPath(u) }
                isFolder = true
                inUri = u
                inName = if (name == "未知文件") "选择的文件夹" else name
                inPath = path
                if (path != null) {
                    val parent = withContext(Dispatchers.IO) { File(path).parent }
                    inSize = null
                    if (outDir == null) {
                        outDir = parent ?: ctx.filesDir.absolutePath
                    }
                }
                outName = "${inName}_decrypted"
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (folderPickJob === myJob) {
                    folderLoading = false
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

    val keyfilePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理
        keyfilePickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        keyfileLoading = true
        keyfilePickJob = scope.launch {
            val myJob = coroutineContext[Job]
            try {
                val nu = kfUris.toMutableList(); val np = kfPaths.toMutableList(); val nn = kfNames.toMutableList()
                for (u in uris) {
                    if (u !in nu) {
                        // 名称查询与安全区拷贝全部移入 IO 线程
                        val name = withContext(Dispatchers.IO) { extractFileName(ctx, u) }
                        val securePath = withContext(Dispatchers.IO) { fileOps.copyKeyfileToSecureArea(u) }
                        nu.add(u); nn.add(name)
                        if (securePath != null) {
                            np.add(securePath)
                        }
                    }
                }
                kfUris = nu; kfPaths = np; kfNames = nn
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (keyfilePickJob === myJob) {
                    keyfileLoading = false
                }
            }
        }
    }

    val hasFile = inPath != null

    // ---- 开始解密 ----
    fun doDecrypt() {
        scope.launch {
            // 若选择 SAF 输出目录，先写入内部临时目录，完成后再复制到 SAF 目录
            val safUri = outDirUri
            val writeDir = if (safUri != null) {
                val tmp = withContext(Dispatchers.IO) { fileOps.createOutputTempDir() }
                pendingSafOut = PendingSafOutput(safUri, tmp)
                tmp.absolutePath
            } else {
                outDir ?: inPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath
            }

            // 压缩包 / 文件夹 / 分卷碎片：走 FolderCrypt 自动识别并流式解压解密，
            // 避免把归档文件误当作单卷送入 Decryptor 导致整包读入内存
            val input = inPath
            if (input != null && (isFolder
                    || ArchiveExtractor.isArchive(File(input).toPath())
                    || Splitter.isSplitChunkPath(input))) {
                vm.startAutoDecrypt(
                    input = input,
                    outputDir = writeDir,
                    password = password,
                    archivePassword = archivePassword.ifEmpty { null },
                    forceDecrypt = force,
                    recursiveExtract = recursive,
                    keyfiles = kfPaths.toList()
                )
                return@launch
            }

            val req = DecryptRequest()
            req.inputFile = inPath
            val outFile = "$writeDir/${outName ?: "decrypted_output"}"
            req.outputFile = outFile
            req.password = password
            req.setForceDecrypt(force)
            req.setAutoUnzip(autoUnzip)
            req.setVerifyFirst(verifyFirst)
            req.setRecombine(recombine)
            if (kfPaths.isNotEmpty()) req.keyfiles = kfPaths.toList()
            req.rsCodecs = RsCodecs()
            vm.startDecrypt(req)
        }
    }

    /** 格式保持解密入口。噪音检测 + 完整性校验 + 解密。 */
    fun doMediaDecrypt() {
        val safUri = outDirUri
        val writeDir = if (safUri != null) {
            val tmp = fileOps.createOutputTempDir()
            pendingSafOut = PendingSafOutput(safUri, tmp)
            tmp.absolutePath
        } else {
            outDir ?: inPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath
        }
        val outFile = "$writeDir/${outName ?: "decrypted_${inName?.substringAfterLast('.') ?: "media"}"}"
        mediaVm.startDecrypt(
            input = inPath!!,
            output = outFile,
            password = password,
            noiseCheck = mediaNoiseMode
        )
    }

    // 前台 Service 生命周期管理（大文件保活）
    ForegroundServiceEffect(
        ctx = ctx,
        isRunning = isRunning,
        progressState = if (mediaProgress.state == ProgressState.State.RUNNING) mediaProgress else progress,
        fileSize = inSize,
        title = if (mediaDecryptMode) "正在格式保持解密" else "正在解密",
        fileName = inName
    )

    // 解密完成后清理安全密钥文件
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

    // 监听解密完成/失败状态，触发结果弹窗
    LaunchedEffect(progress.state) {
        when (progress.state) {
            ProgressState.State.DONE -> {
                val committed = commitSafOutput()
                when (committed) {
                    null, true -> {
                        resultTitle = "解密完成"
                        resultMessage = buildSuccessMessage("解密", outName)
                        resultDetail = null
                        resultType = ResultType.SUCCESS
                        // 记录操作历史：输出目录取写路径同款回退，SAF 输出同时保存树 URI
                        val outNameNow = outName ?: "decrypted_output"
                        val resolvedOutDir = outDir
                            ?: inPath?.let { File(it).parent }
                            ?: ctx.filesDir.absolutePath
                        withContext(Dispatchers.IO) {
                            HistoryService.record(
                                OperationType.GENERIC_DECRYPT,
                                outNameNow,
                                "$resolvedOutDir/$outNameNow",
                                outDirUri?.toString()
                            )
                        }
                    }
                    false -> {
                        resultTitle = "解密完成但保存失败"
                        resultMessage = "解密已完成，但复制到所选目录失败，请检查目录权限后重试。"
                        resultDetail = null
                        resultType = ResultType.ERROR
                    }
                }
                showResultDialog = true
            }
            ProgressState.State.ERROR -> {
                resultTitle = "解密失败"
                resultMessage = mapErrorToChineseMessage(progress.error)
                resultDetail = progress.error
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                resultTitle = "已取消"
                resultMessage = "解密操作已被取消。"
                resultDetail = null
                resultType = ResultType.INFO
                showResultDialog = true
            }
            else -> { /* no-op */ }
        }
    }

    // 监听媒体解密完成/失败状态
    LaunchedEffect(mediaProgress.state) {
        when (mediaProgress.state) {
            ProgressState.State.DONE -> {
                val committed = commitSafOutput()
                when (committed) {
                    null, true -> {
                        resultTitle = "格式保持解密完成"
                        resultMessage = buildSuccessMessage("解密", outName)
                        resultDetail = null
                        resultType = ResultType.SUCCESS
                        // 记录操作历史（格式保持解密）
                        val outNameNow = outName ?: "decrypted_media"
                        val resolvedOutDir = outDir
                            ?: inPath?.let { File(it).parent }
                            ?: ctx.filesDir.absolutePath
                        withContext(Dispatchers.IO) {
                            HistoryService.record(
                                OperationType.FPE_DECRYPT,
                                outNameNow,
                                "$resolvedOutDir/$outNameNow",
                                outDirUri?.toString()
                            )
                        }
                    }
                    false -> {
                        resultTitle = "格式保持解密完成但保存失败"
                        resultMessage = "解密已完成，但复制到所选目录失败，请检查目录权限后重试。"
                        resultDetail = null
                        resultType = ResultType.ERROR
                    }
                }
                showResultDialog = true
            }
            ProgressState.State.ERROR -> {
                resultTitle = "格式保持解密失败"
                resultMessage = mapErrorToChineseMessage(mediaProgress.error)
                resultDetail = mediaProgress.error
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                resultTitle = "已取消"
                resultMessage = "格式保持解密操作已被取消。"
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
        // 容器透明，避免遮住全局背景图层
        containerColor = Color.Transparent,
        topBar = {
            CompactTopBar(
                title = "文件解密",
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
                    val activeProgress = if (mediaProgress.state == ProgressState.State.RUNNING) mediaProgress else progress
                    val cancelAction = {
                        if (mediaProgress.state == ProgressState.State.RUNNING) mediaVm.cancel() else vm.cancel()
                    }
                    ProgressCard(progressState = activeProgress, onCancel = cancelAction)
                }
            } else {
                Box(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    Button(
                        onClick = { if (mediaDecryptMode) doMediaDecrypt() else doDecrypt() },
                        modifier = Modifier.fillMaxWidth(),
                        // 选择处理中禁用，避免复制未完成即开始解密
                        enabled = hasFile && !fileLoading && !folderLoading && !keyfileLoading
                    ) {
                        Icon(Icons.Default.LockOpen, null)
                        Text(if (mediaDecryptMode) "  格式保持解密" else "  解密")
                    }
                }
            }
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp).verticalScroll(scroll)) {
            Spacer(Modifier.height(8.dp))

            // 低调的内存使用指示器（可在设置中关闭）
            if (showMemoryIndicator) {
                MemoryIndicator()
                Spacer(Modifier.height(6.dp))
            }

            // ============================================================
            // 一、文件选择区（单文件或单文件夹）
            // ============================================================
            if (!hasFile) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
                        onClick = { filePicker.launch(arrayOf("*/*")) }
                    ) {
                        if (fileLoading) {
                            Column(modifier = Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                                PickerLoadingIndicator(text = pickerLoadingText(), iconSize = 40.dp, vertical = true)
                                Spacer(Modifier.height(4.dp))
                                Text(pickerLoadingHint(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f))
                            }
                        } else {
                            Column(modifier = Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(Icons.AutoMirrored.Filled.InsertDriveFile, null, Modifier.size(40.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                                Spacer(Modifier.height(8.dp))
                                Text("点击选择要解密的文件", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text(if (mediaDecryptMode) "MP3 / MP4 / WAV 加密媒体文件" else ".ergou / .pcv / 分卷碎片 / 压缩包", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f))
                            }
                        }
                    }
                    // 格式保持解密仅支持单文件，隐藏文件夹选择
                    if (!mediaDecryptMode) {
                        Spacer(Modifier.height(8.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
                            onClick = { folderPicker.launch(null) }
                        ) {
                            if (folderLoading) {
                                PickerLoadingIndicator(
                                    text = pickerLoadingText(),
                                    modifier = Modifier.fillMaxWidth().padding(16.dp)
                                )
                            } else {
                                Column(modifier = Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text("或选择包含加密文件的文件夹", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f))
                                }
                            }
                        }
                    }
                }
            } else {
                // 已选文件卡片
                FilePickerCard(
                    fileName = inName,
                    fileSize = inSize,
                    onClick = { filePicker.launch(arrayOf("*/*")) },
                    label = "点击更换文件",
                    loading = fileLoading,
                    loadingText = pickerLoadingText(),
                    loadingHint = pickerLoadingHint()
                )

                // 更换/移除按钮行（格式保持解密仅支持单文件，隐藏文件夹切换）
                FileActionRow(
                    onPickFile = { filePicker.launch(arrayOf("*/*")) },
                    onPickFolder = if (mediaDecryptMode) null else { { folderPicker.launch(null) } },
                    onRemove = { inUri = null; inPath = null; inName = null; inSize = null; outName = null }
                )

                Spacer(Modifier.height(8.dp))

                // 输出目录选择
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

                // 输出文件名
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = outName ?: "",
                    onValueChange = { outName = it },
                    label = { Text("输出文件名") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = MaterialTheme.typography.bodySmall,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
                )
            }

            Spacer(Modifier.height(16.dp))

            // ============================================================
            // 二、密码区（show/hide 切换 + 粘贴按钮）
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

            Spacer(Modifier.height(4.dp))
            if (password.isEmpty()) {
                Text("未输入密码 — 使用系统默认约定密码解密", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f))
            }

            // 粘贴按钮（方角，自适应文字大小）
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = cm.primaryClip
                    if (clip != null && clip.itemCount > 0) {
                        val text = clip.getItemAt(0).text?.toString() ?: ""
                        if (text.isNotEmpty()) {
                            password = text
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.small,
                contentPadding = ButtonDefaults.ContentPadding
            ) {
                Icon(Icons.Default.ContentPaste, null, Modifier.size(16.dp))
                Text(" 粘贴", style = MaterialTheme.typography.labelMedium)
            }

            Spacer(Modifier.height(16.dp))

            // ============================================================
            // 三、高级选项（对齐桌面端 decryptOptions）
            // ============================================================
            ExpandableCard(title = "高级选项") {

                // ---- 强制解密 ----
                OptionRow("强制解密（忽略损坏）", force, { force = it }, TIP_FORCE, enabled = !mediaDecryptMode)
                Spacer(Modifier.height(6.dp))

                // ---- 解压后解密（格式保持解密下不支持，需单独先解压再解密） ----
                OptionRow("解压后解密", autoUnzip, { autoUnzip = it }, TIP_AUTO_UNZIP, enabled = !mediaDecryptMode)
                if (autoUnzip && !mediaDecryptMode) {
                    Spacer(Modifier.height(4.dp))
                    OutlinedTextField(
                        value = archivePassword,
                        onValueChange = { archivePassword = it },
                        label = { Text("压缩包密码（选填）") },
                        placeholder = { Text("如果压缩包需要密码，请输入") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(start = 36.dp),
                        textStyle = MaterialTheme.typography.bodyMedium,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
                    )
                }

                Spacer(Modifier.height(6.dp))

                // ---- 先校验完整性 ----
                OptionRow("先校验完整性", verifyFirst, { verifyFirst = it }, TIP_VERIFY, enabled = !mediaDecryptMode)
                Spacer(Modifier.height(6.dp))

                // ---- 递归解压嵌套压缩包 ----
                OptionRow("递归解压嵌套压缩包", recursive, { recursive = it }, TIP_RECURSIVE, enabled = !mediaDecryptMode)

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- 合并分卷 ----
                val recombineAlpha = if (!mediaDecryptMode) 1f else 0.38f
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = recombine, onCheckedChange = { recombine = it }, enabled = !mediaDecryptMode)
                    Text("输入为分卷碎片，解密前先合并", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f).padding(start = 4.dp), color = MaterialTheme.colorScheme.onSurface.copy(alpha = recombineAlpha))
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

                // ---- 音视频格式保持解密 ----
                val mediaFmt = remember(inName) { detectMediaFormat(inName) }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = mediaDecryptMode, onCheckedChange = {
                        mediaDecryptMode = it
                        if (it) { isFolder = false } // 格式保持解密仅支持单文件
                    })
                    Text("格式保持解密", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f).padding(start = 4.dp))
                    if (mediaFmt != null) {
                        Text("· ${mediaFmt.name}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                    } else if (mediaDecryptMode && inName != null) {
                        Text("· 格式不支持", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
                if (mediaDecryptMode && mediaFmt != null) {
                    Spacer(Modifier.height(4.dp))
                    Text("加密参数将从文件内嵌元数据自动读取，无需手动设置。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)

                    Spacer(Modifier.height(8.dp))

                    // 噪音文件解密（对齐桌面端 avNoiseDecryptCheck，默认开启）
                    Row {
                        Checkbox(checked = mediaNoiseMode, onCheckedChange = { mediaNoiseMode = it })
                        Text("噪音文件解密", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 4.dp).weight(1f))
                        InfoTooltip("验证文件是否确实含有本工具的加密元数据（EGTC-AVE 魔数），避免误把普通媒体文件当作密文处理。不确定文件来源时建议开启。关闭时直接按文件扩展名解密。")
                    }

                    Spacer(Modifier.height(4.dp))
                    Text("解密前将自动进行完整性校验。若文件被篡改或密码错误，会给出明确的错误提示。",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }

                Spacer(Modifier.height(8.dp))

                // ---- 密钥文件（格式保持解密下不支持） ----
                val kfAlpha = if (!mediaDecryptMode) 1f else 0.38f
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("密钥文件", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = kfAlpha))
                    Spacer(Modifier.weight(1f))
                    if (kfNames.isNotEmpty() && !mediaDecryptMode) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = kfOrdered, onCheckedChange = { kfOrdered = it })
                            Text("要求顺序", style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.width(2.dp))
                            InfoTooltip(TIP_KEYFILE_ORDERED)
                        }
                    }
                    Spacer(Modifier.width(8.dp))
                    FilledTonalButton(onClick = { keyfilePicker.launch(arrayOf("*/*")) }, enabled = !mediaDecryptMode && !keyfileLoading) {
                        Icon(Icons.Default.Add, null, Modifier.size(16.dp)); Text(" 添加")
                    }
                }

                // 密钥文件复制到安全区处理中：显示旋转圆圈提示
                if (keyfileLoading) {
                    Spacer(Modifier.height(4.dp))
                    PickerLoadingIndicator(text = pickerLoadingText())
                }

                if (kfNames.isEmpty() || mediaDecryptMode) {
                    Spacer(Modifier.height(4.dp))
                    Text(if (mediaDecryptMode) "格式保持解密不支持密钥文件" else "未添加密钥文件",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
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
