package hbnu.project.ergoutreecrypt.android.ui.screen

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import androidx.compose.ui.graphics.Color
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
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.platform.KdfPreflight
import hbnu.project.ergoutreecrypt.android.platform.OutputDirResolver
import hbnu.project.ergoutreecrypt.android.platform.PendingOutput
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.FileActionRow
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.LogHistoryActions
import hbnu.project.ergoutreecrypt.android.ui.component.MemoryIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.OperationLogPanel
import hbnu.project.ergoutreecrypt.android.ui.component.PickerLoadingIndicator
import hbnu.project.ergoutreecrypt.android.ui.component.ProgressCard
import hbnu.project.ergoutreecrypt.android.ui.component.ResultDialog
import hbnu.project.ergoutreecrypt.android.ui.component.ResultType
import hbnu.project.ergoutreecrypt.android.ui.component.buildSuccessMessage
import hbnu.project.ergoutreecrypt.android.ui.component.extractFileName
import hbnu.project.ergoutreecrypt.android.ui.component.generateRandomPassword
import hbnu.project.ergoutreecrypt.android.ui.component.mapErrorToChineseMessage
import hbnu.project.ergoutreecrypt.android.ui.component.pickerLoadingHint
import hbnu.project.ergoutreecrypt.android.ui.component.pickerLoadingText
import hbnu.project.ergoutreecrypt.android.viewmodel.OperationCoordinator
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.android.viewmodel.StegoViewModel
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.Paths

/**
 * 隐写提取页面。
 *
 * <p>用户选择一个包含隐写数据的载体文件（PNG/ZIP/PDF/WAV/FLAC/MP4 等），
 * 输入密码后提取隐藏的文件内容。支持所有 {@link hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierAdapter}
 * 注册的载体格式。
 *
 * <p>提取过程自动检测载体格式并匹配对应的适配器，通过
 * {@link hbnu.project.ergoutreecrypt.filestego.FileStegoCodec#extract} 完成解密与还原。
 *
 * @author ErgouTree
 * @since 2026/8/12
 */
@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun StegoExtractScreen(onOpenHistory: () -> Unit = {}) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val scroll = rememberScrollState()
    val fileOps = remember { AndroidFileOps(ctx.applicationContext) }
    // ViewModel 提升到 Activity 作用域：切换 Tab/旋转屏幕不中断正在进行的操作
    val vm: StegoViewModel = viewModel(
        key = "stegoExtract",
        factory = viewModelFactory { initializer { StegoViewModel(ctx.applicationContext) } }
    )
    val settings = remember { AndroidSettings(ctx.applicationContext) }
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

    // ---- 隐写文件 ----
    var stegoUri by remember { mutableStateOf<Uri?>(null) }
    var stegoPath by remember { mutableStateOf<String?>(null) }
    var stegoName by remember { mutableStateOf<String?>(null) }
    var stegoSize by remember { mutableStateOf<Long?>(null) }

    // ---- 隐写预检结果（KDF 档位 / 加密前压缩） ----
    var stegoCompressed by remember { mutableStateOf(false) }
    var stegoSlowKdf by remember { mutableStateOf(false) }

    // ---- 隐写文件选择加载状态 ----
    var stegoLoading by remember { mutableStateOf(false) }
    var stegoPickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 密码 ----
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    // ---- 输出目录 ----
    var outDir by remember { mutableStateOf<String?>(null) }
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

    // ---- 隐写文件选择器 ----
    val stegoPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u == null) {
            return@rememberLauncherForActivityResult
        }
        // 取消上一次仍在进行的处理，允许用户换选新文件
        stegoPickJob?.cancel()
        // 同步置位加载状态，确保当帧即显示旋转圆圈
        stegoLoading = true
        stegoPickJob = scope.launch {
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
                    stegoUri = u
                    stegoName = name
                    stegoPath = path
                    stegoSize = size
                    // 只读预检：识别桌面端 1 GiB 档（较慢）与「加密前压缩」（移动端无法解压）
                    val preflight = withContext(Dispatchers.IO) {
                        KdfPreflight.peekStego(Paths.get(path))
                    }
                    stegoCompressed = preflight?.compressed == true
                    stegoSlowKdf = preflight != null &&
                            (preflight.argon2MemoryKib == null ||
                                    preflight.argon2MemoryKib!! > (256 shl 10))
                } else {
                    // 路径解析失败（云盘/存储权限/磁盘不足等）时给出可见提示，避免按钮静默置灰
                    Toast.makeText(ctx, "无法读取所选文件，请换用系统文件管理器或检查存储权限后重试", Toast.LENGTH_LONG).show()
                }
            } finally {
                // 仅当自身仍是最新一次选择时才复位加载状态
                if (stegoPickJob === myJob) {
                    stegoLoading = false
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

    val hasFile = stegoPath != null
    val canStart = hasFile && password.isNotEmpty() && !isRunning && !stegoLoading && !busy
            && !stegoCompressed

    // ---- 开始提取 ----
    fun doExtract() {
        scope.launch {
            val safUri = outDirUri
            val resolved = withContext(Dispatchers.IO) { OutputDirResolver.resolve(ctx) }
            val outputDir = when {
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
            vm.extract(stegoPath!!, outputDir, password)
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

    // 丢弃暂存输出（失败/取消时）：仅删除临时目录、不提交，避免残留半成品文件
    suspend fun discardPendingOutput() {
        val pending = pendingOut
        if (pending != null) {
            withContext(Dispatchers.IO) { pending.tempDir.deleteRecursively() }
            // 仅当暂存输出未被新操作替换时才清空，避免误清新操作的暂存目录
            if (pendingOut === pending) {
                pendingOut = null
            }
        }
    }

    // 终态分支先捕获所需数据并 reset() 消费，再执行挂起工作：
    // 切回 Tab 或页面重建不会重复弹窗/重复记录历史
    LaunchedEffect(progress.state) {
        when (progress.state) {
            ProgressState.State.DONE -> {
                val extractedName = if (progress.info.isNotEmpty()) progress.info else ""
                val resolvedOutDir = OutputDirResolver.historyDir(
                    ctx, outDir, stegoPath?.let { File(it).parent })
                val savedTreeUri = outDirUri?.toString()
                vm.reset()
                // reset() 改变 LaunchedEffect key 会取消当前协程，挂起工作放到独立协程执行
                scope.launch {
                    val committed = commitOutput()
                    when (committed) {
                        null, true -> {
                            resultTitle = "提取完成"
                            resultMessage = "隐藏文件已成功提取。\n文件名：$extractedName"
                            resultDetail = null
                            resultType = ResultType.SUCCESS
                            // 记录操作历史（隐写提取）
                            val extractedFile = extractedName.ifEmpty { "extracted" }
                            withContext(Dispatchers.IO) {
                                HistoryService.record(
                                    OperationType.STEGO_EXTRACT,
                                    extractedFile,
                                    "$resolvedOutDir/$extractedFile",
                                    savedTreeUri
                                )
                            }
                        }
                        false -> {
                            resultTitle = "提取完成但保存失败"
                            resultMessage = "文件已提取，但复制到所选目录失败，请检查目录权限后重试。"
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
                scope.launch { discardPendingOutput() }
                resultTitle = "提取失败"
                resultMessage = errMsg
                resultDetail = errDetail
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                vm.reset()
                scope.launch { discardPendingOutput() }
                resultTitle = "已取消"
                resultMessage = "提取操作已被取消。"
                resultDetail = null
                resultType = ResultType.INFO
                showResultDialog = true
            }
            else -> { /* no-op */ }
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
                title = "隐写提取",
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
                        onClick = { doExtract() },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = canStart
                    ) {
                        Icon(Icons.Default.VisibilityOff, null)
                        Text("  提取隐藏文件")
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

            // ============================================================
            // 一、隐写文件选择区
            // ============================================================
            if (!hasFile) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
                    onClick = { stegoPicker.launch(arrayOf("*/*")) }
                ) {
                    if (stegoLoading) {
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
                                Icons.Default.VisibilityOff, null,
                                Modifier.size(40.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "点击选择隐写文件",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "支持 PNG / ZIP / PDF / WAV / FLAC / MP4 等载体格式",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                            )
                        }
                    }
                }
            } else {
                FilePickerCard(
                    fileName = stegoName,
                    fileSize = stegoSize,
                    onClick = { stegoPicker.launch(arrayOf("*/*")) },
                    label = "点击更换隐写文件",
                    loading = stegoLoading,
                    loadingText = pickerLoadingText(),
                    loadingHint = pickerLoadingHint()
                )
                FileActionRow(
                    onPickFile = { stegoPicker.launch(arrayOf("*/*")) },
                    onRemove = {
                        stegoUri = null; stegoPath = null
                        stegoName = null; stegoSize = null
                        stegoCompressed = false; stegoSlowKdf = false
                    }
                )
            }

            // 预检警告：加密前压缩（移动端无法解压，禁用提取）/ 1 GiB 档（较慢）
            if (stegoCompressed) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Delete, null,
                            tint = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "该文件使用了「加密前压缩」（Zstandard），移动端无法提取，请在桌面端提取。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            } else if (stegoSlowKdf) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.8f)
                    )
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Refresh, null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "该文件使用 1 GiB 密钥派生参数，提取较慢（约十几秒）。建议在桌面端用较小档位重新隐写。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ============================================================
            // 二、输出目录
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

            Spacer(modifier = Modifier.height(16.dp))

            // ============================================================
            // 三、密码区
            // ============================================================
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("密码") },
                placeholder = { Text("请输入隐写时使用的密码") },
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

            // 提示信息
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                )
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        "提取说明",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "• 选择包含隐写数据的载体文件\n" +
                                "• 输入隐写时使用的密码\n" +
                                "• 系统将自动检测载体格式并提取隐藏文件\n" +
                                "• 提取的文件恢复为原始文件名",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f)
                    )
                }
            }

            OperationLogPanel(visible = logVisible)

            Spacer(modifier = Modifier.height(80.dp))
        }
    }
}
