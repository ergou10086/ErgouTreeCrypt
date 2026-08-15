package hbnu.project.ergoutreecrypt.android.ui.screen

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
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.outlined.History
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
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.platform.PendingSafOutput
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.FileActionRow
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.MemoryIndicator
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
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.android.viewmodel.StegoViewModel
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

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
    val vm = remember { StegoViewModel(ctx.applicationContext) }
    val settings = remember { AndroidSettings(ctx.applicationContext) }
    val progress by vm.progress.collectAsState()
    val isRunning = progress.state == ProgressState.State.RUNNING
    val showMemoryIndicator by settings.showMemoryIndicator.collectAsState(initial = true)

    // ---- 隐写文件 ----
    var stegoUri by remember { mutableStateOf<Uri?>(null) }
    var stegoPath by remember { mutableStateOf<String?>(null) }
    var stegoName by remember { mutableStateOf<String?>(null) }
    var stegoSize by remember { mutableStateOf<Long?>(null) }

    // ---- 隐写文件选择加载状态 ----
    var stegoLoading by remember { mutableStateOf(false) }
    var stegoPickJob by remember { mutableStateOf<Job?>(null) }

    // ---- 密码 ----
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    // ---- 输出目录 ----
    var outDir by remember { mutableStateOf<String?>(null) }
    var outDirUri by remember { mutableStateOf<Uri?>(null) }
    var pendingSafOut by remember { mutableStateOf<PendingSafOutput?>(null) }

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
                    val (size, parent) = withContext(Dispatchers.IO) {
                        val f = File(path)
                        val sz = if (f.exists()) f.length() else null
                        sz to f.parent
                    }
                    stegoUri = u
                    stegoName = name
                    stegoPath = path
                    stegoSize = size
                    if (outDir == null) {
                        outDir = parent ?: ctx.filesDir.absolutePath
                    }
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

    val hasFile = stegoPath != null
    val canStart = hasFile && !isRunning && !stegoLoading

    // ---- 开始提取 ----
    fun doExtract() {
        val safUri = outDirUri
        val outputDir = if (safUri != null) {
            val tmp = fileOps.createOutputTempDir()
            pendingSafOut = PendingSafOutput(safUri, tmp)
            tmp.absolutePath
        } else {
            outDir ?: stegoPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath
        }
        vm.extract(stegoPath!!, outputDir, password)
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
                val extractedName = if (progress.info.isNotEmpty()) progress.info else ""
                val committed = commitSafOutput()
                when (committed) {
                    null, true -> {
                        resultTitle = "提取完成"
                        resultMessage = "隐藏文件已成功提取。\n文件名：$extractedName"
                        resultDetail = null
                        resultType = ResultType.SUCCESS
                        // 记录操作历史（隐写提取）
                        val extractedFile = extractedName.ifEmpty { "extracted" }
                        val resolvedOutDir = outDir
                            ?: stegoPath?.let { File(it).parent }
                            ?: ctx.filesDir.absolutePath
                        withContext(Dispatchers.IO) {
                            HistoryService.record(
                                OperationType.STEGO_EXTRACT,
                                extractedFile,
                                "$resolvedOutDir/$extractedFile",
                                outDirUri?.toString()
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
            ProgressState.State.ERROR -> {
                resultTitle = "提取失败"
                resultMessage = mapErrorToChineseMessage(progress.error)
                resultDetail = progress.error
                resultType = ResultType.ERROR
                showResultDialog = true
            }
            ProgressState.State.CANCELLED -> {
                resultTitle = "已取消"
                resultMessage = "提取操作已被取消。"
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
                title = "隐写提取",
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
                    }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ============================================================
            // 二、输出目录
            // ============================================================
            val displayPath = when {
                outDir != null -> outDir!!
                else -> ""
            }
            val displayText = if (displayPath.isNotEmpty()) {
                if (displayPath.length > 44) "…${displayPath.takeLast(44)}" else displayPath
            } else {
                "默认输出至隐写文件同级目录"
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
                placeholder = { Text("请输入隐写时使用的密码（可留空尝试无密码模式）") },
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
                    "未输入密码 — 将尝试使用系统默认约定密码进行无密码提取",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
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

            Spacer(modifier = Modifier.height(80.dp))
        }
    }
}
