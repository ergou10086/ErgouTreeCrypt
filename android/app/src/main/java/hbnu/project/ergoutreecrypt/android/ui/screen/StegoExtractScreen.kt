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
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.ui.component.FilePickerCard
import hbnu.project.ergoutreecrypt.android.ui.component.ProgressCard
import hbnu.project.ergoutreecrypt.android.ui.component.ResultDialog
import hbnu.project.ergoutreecrypt.android.ui.component.ResultType
import hbnu.project.ergoutreecrypt.android.ui.component.buildSuccessMessage
import hbnu.project.ergoutreecrypt.android.ui.component.extractFileName
import hbnu.project.ergoutreecrypt.android.ui.component.generateRandomPassword
import hbnu.project.ergoutreecrypt.android.ui.component.mapErrorToChineseMessage
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.android.viewmodel.StegoViewModel
import kotlinx.coroutines.Dispatchers
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
fun StegoExtractScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val scroll = rememberScrollState()
    val fileOps = remember { AndroidFileOps(ctx.applicationContext) }
    val vm = remember { StegoViewModel(ctx.applicationContext) }
    val progress by vm.progress.collectAsState()
    val isRunning = progress.state == ProgressState.State.RUNNING

    // ---- 隐写文件 ----
    var stegoUri by remember { mutableStateOf<Uri?>(null) }
    var stegoPath by remember { mutableStateOf<String?>(null) }
    var stegoName by remember { mutableStateOf<String?>(null) }
    var stegoSize by remember { mutableStateOf<Long?>(null) }

    // ---- 密码 ----
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    // ---- 输出目录 ----
    var outDir by remember { mutableStateOf<String?>(null) }

    // ---- 隐写文件选择器 ----
    val stegoPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { u ->
        if (u != null) scope.launch {
            stegoUri = u
            stegoName = extractFileName(u)
            stegoPath = withContext(Dispatchers.IO) { fileOps.resolveToPath(u) }
            if (stegoPath != null) {
                val f = File(stegoPath!!)
                stegoSize = if (f.exists()) f.length() else null
                if (outDir == null) {
                    outDir = f.parent ?: ctx.filesDir.absolutePath
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

    val hasFile = stegoPath != null
    val canStart = hasFile && !isRunning

    // ---- 开始提取 ----
    fun doExtract() {
        val outputDir = outDir ?: stegoPath?.let { File(it).parent } ?: ctx.filesDir.absolutePath
        vm.extract(stegoPath!!, outputDir, password)
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
                val extractedName = if (progress.info.isNotEmpty()) progress.info else ""
                resultTitle = "提取完成"
                resultMessage = "隐藏文件已成功提取。\n文件名：$extractedName"
                resultDetail = null
                resultType = ResultType.SUCCESS
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
        topBar = {
            TopAppBar(title = { Text("隐写提取") })
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

            // ============================================================
            // 一、隐写文件选择区
            // ============================================================
            if (!hasFile) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    onClick = { stegoPicker.launch(arrayOf("*/*")) }
                ) {
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
            } else {
                FilePickerCard(
                    fileName = stegoName,
                    fileSize = stegoSize,
                    onClick = { stegoPicker.launch(arrayOf("*/*")) },
                    label = "点击更换隐写文件"
                )
                Row(modifier = Modifier.fillMaxWidth()) {
                    FilledTonalButton(
                        onClick = { stegoPicker.launch(arrayOf("*/*")) },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Add, null, Modifier.size(16.dp)); Text("  换文件") }
                    Spacer(Modifier.width(6.dp))
                    FilledTonalButton(
                        onClick = {
                            stegoUri = null; stegoPath = null
                            stegoName = null; stegoSize = null
                        },
                        modifier = Modifier.weight(1f)
                    ) { Icon(Icons.Default.Delete, null, Modifier.size(16.dp)); Text("  移除") }
                }
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
