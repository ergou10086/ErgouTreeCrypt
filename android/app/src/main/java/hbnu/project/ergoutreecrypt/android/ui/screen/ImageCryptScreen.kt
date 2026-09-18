package hbnu.project.ergoutreecrypt.android.ui.screen

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.ForegroundServiceEffect
import hbnu.project.ergoutreecrypt.android.ui.component.ProgressCard
import hbnu.project.ergoutreecrypt.android.viewmodel.ImageCryptDirection
import hbnu.project.ergoutreecrypt.android.viewmodel.ImageCryptResultInfo
import hbnu.project.ergoutreecrypt.android.viewmodel.ImageCryptUiState
import hbnu.project.ergoutreecrypt.android.viewmodel.ImageCryptViewModel
import hbnu.project.ergoutreecrypt.android.viewmodel.OperationCoordinator
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Android 独立图片加密页面。
 *
 * <p>页面只负责文件选择和表单展示，协议算法、密码规范化、流式读写与提交事务均由
 * Activity 作用域 {@link ImageCryptViewModel} 处理。页面不会解码输入 Bitmap，因此大图的
 * 工作内存不随原始分辨率线性增长。
 *
 * @param onOpenHistory 打开操作历史回调
 */
@Composable
fun ImageCryptScreen(onOpenHistory: () -> Unit = {}) {
    val context = LocalContext.current
    val activity = context as ComponentActivity
    val viewModel: ImageCryptViewModel = viewModel(viewModelStoreOwner = activity)
    val state by viewModel.uiState.collectAsState()
    val globalBusy by OperationCoordinator.busy.collectAsState()
    val running = state.progress.state == ProgressState.State.RUNNING

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            viewModel.selectInput(uri)
        }
    }
    val outputPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri != null) {
            viewModel.setOutputTree(uri)
        }
    }

    ForegroundServiceEffect(
        ctx = context,
        isRunning = running,
        progressState = state.progress,
        fileSize = state.inputBytes.takeIf { it > 0L },
        title = if (state.direction == ImageCryptDirection.ENCRYPT) {
            "正在加密图片"
        } else {
            "正在还原图片"
        },
        fileName = state.inputName
    )

    state.result?.let { result ->
        ImageCryptResultDialog(
            result = result,
            onShare = { viewModel.shareResult() },
            onDismiss = { viewModel.dismissResult() }
        )
    }

    Scaffold(
        containerColor = Color.Transparent,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            CompactTopBar(
                title = "图片加密",
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
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            DirectionSelector(
                direction = state.direction,
                enabled = !running,
                onDirection = viewModel::setDirection
            )

            InputCard(
                state = state,
                enabled = !running && !state.selecting,
                onPick = { filePicker.launch(arrayOf("image/*")) },
                onClear = viewModel::clearInput
            )

            if (state.direction == ImageCryptDirection.ENCRYPT) {
                ProtectionSelector(
                    mode = state.mode,
                    enabled = !running,
                    onMode = viewModel::setMode
                )
            }

            TransportProtectionCard(
                direction = state.direction,
                errorCorrection = state.errorCorrection,
                bestEffort = state.bestEffort,
                enabled = !running,
                onErrorCorrection = viewModel::setErrorCorrection,
                onBestEffort = viewModel::setBestEffort
            )

            val requiresPassword = if (state.direction == ImageCryptDirection.ENCRYPT) {
                state.mode == ImageCryptMode.PASSWORD
            } else {
                state.metadata?.requiresPassword() == true
            }
            if (requiresPassword) {
                PasswordFields(
                    password = state.password,
                    confirmPassword = state.confirmPassword,
                    showConfirmation = state.direction == ImageCryptDirection.ENCRYPT,
                    enabled = !running,
                    onPassword = viewModel::setPassword,
                    onConfirmation = viewModel::setConfirmPassword
                )
                KdfSummary(state)
            } else if (state.direction == ImageCryptDirection.ENCRYPT || state.metadata != null) {
                PublicRecoveryWarning()
            }

            OutputTargetCard(
                target = state.outputTarget,
                custom = state.outputTreeUri != null,
                enabled = !running,
                onChoose = { outputPicker.launch(null) },
                onReset = { viewModel.setOutputTree(null) }
            )

            state.formError?.let { error ->
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            ProgressCard(progressState = state.progress, onCancel = viewModel::cancel)

            state.resultPreviewPath?.let { path ->
                ResultPreviewCard(
                    title = state.resultPreviewTitle ?: "处理结果预览",
                    path = path
                )
            }

            Button(
                onClick = viewModel::start,
                enabled = !running && !globalBusy && state.inputName != null && !state.selecting,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = if (state.direction == ImageCryptDirection.ENCRYPT) {
                        Icons.Default.Lock
                    } else {
                        Icons.Default.LockOpen
                    },
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (state.direction == ImageCryptDirection.ENCRYPT) "加密为 PNG" else "认证并还原")
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

/**
 * 图片传输纠错与尽力恢复选项。
 *
 * @param direction 当前操作方向
 * @param errorCorrection 是否启用抗重编码载体
 * @param bestEffort 是否允许有损尽力恢复
 * @param enabled 是否允许修改
 * @param onErrorCorrection 纠错选项回调
 * @param onBestEffort 尽力恢复选项回调
 */
@Composable
private fun TransportProtectionCard(
    direction: ImageCryptDirection,
    errorCorrection: Boolean,
    bestEffort: Boolean,
    enabled: Boolean,
    onErrorCorrection: (Boolean) -> Unit,
    onBestEffort: (Boolean) -> Unit
) {
    val encrypting = direction == ImageCryptDirection.ENCRYPT
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("传输保护", style = MaterialTheme.typography.titleMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = if (encrypting) errorCorrection else bestEffort,
                    onCheckedChange = if (encrypting) onErrorCorrection else onBestEffort,
                    enabled = enabled
                )
                Text(if (encrypting) "启用抗重编码纠错码" else "尽力解密损坏图片")
            }
            Text(
                text = if (encrypting) {
                    "使用灰度调制、交织与 Reed-Solomon 抵抗聊天软件重编码；大图可能转为有损 JPEG 副本。"
                } else {
                    "仅在纠错后仍失败时使用；输出可能局部损坏，密码校验不会被绕过。"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * 加密/还原方向选择器。
 *
 * @param direction 当前方向
 * @param enabled 是否可切换
 * @param onDirection 切换回调
 */
@Composable
private fun DirectionSelector(
    direction: ImageCryptDirection,
    enabled: Boolean,
    onDirection: (ImageCryptDirection) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FilterChip(
            selected = direction == ImageCryptDirection.ENCRYPT,
            onClick = { onDirection(ImageCryptDirection.ENCRYPT) },
            label = { Text("加密图片") },
            enabled = enabled,
            modifier = Modifier.weight(1f)
        )
        FilterChip(
            selected = direction == ImageCryptDirection.RESTORE,
            onClick = { onDirection(ImageCryptDirection.RESTORE) },
            label = { Text("还原图片") },
            enabled = enabled,
            modifier = Modifier.weight(1f)
        )
    }
}

/**
 * 输入选择与元数据显示卡片。
 *
 * @param state 页面状态
 * @param enabled 是否允许选择
 * @param onPick 选择或重新选择回调
 * @param onClear 清空选择回调
 */
@Composable
private fun InputCard(
    state: ImageCryptUiState,
    enabled: Boolean,
    onPick: () -> Unit,
    onClear: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Image, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(state.inputName ?: "尚未选择图片", style = MaterialTheme.typography.bodyLarge)
                    val detail = when {
                        state.selecting -> "正在流式读取并验证…"
                        state.inputDescription.isNotBlank() -> state.inputDescription
                        state.direction == ImageCryptDirection.ENCRYPT ->
                            "支持 PNG/APNG、JPEG、GIF、BMP、WebP"
                        else -> "选择本工具生成的 .egimg.png"
                    }
                    Text(
                        detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            state.inputPreviewPath?.let { path ->
                Spacer(modifier = Modifier.height(10.dp))
                BoundedImagePreview(
                    path = path,
                    contentDescription = "当前选择图片预览",
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(180.dp)
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onPick,
                    enabled = enabled,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(if (state.inputName == null) "选择图片" else "重新选择")
                }
                if (state.inputName != null) {
                    TextButton(onClick = onClear, enabled = enabled) {
                        Text("清空选择")
                    }
                }
            }
        }
    }
}

/**
 * 页面下方的处理结果缩略预览。
 *
 * @param title 结果预览标题
 * @param path 私有暂存或直接输出路径
 */
@Composable
private fun ResultPreviewCard(title: String, path: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            BoundedImagePreview(
                path = path,
                contentDescription = title,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(220.dp)
            )
        }
    }
}

/**
 * 从本地路径异步解码有界缩略图。
 *
 * @param path 图片路径
 * @param contentDescription 无障碍说明
 * @param modifier 修饰符
 */
@Composable
private fun BoundedImagePreview(
    path: String,
    contentDescription: String,
    modifier: Modifier = Modifier
) {
    val preview by produceState<Pair<Boolean, Bitmap?>>(false to null, path) {
        value = withContext(Dispatchers.IO) {
            true to decodeBoundedBitmap(File(path), 1024, 1024)
        }
    }
    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        when {
            !preview.first -> Text("正在生成预览…", style = MaterialTheme.typography.bodySmall)
            preview.second == null -> Text(
                "当前图片无法生成预览",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            else -> Image(
                bitmap = requireNotNull(preview.second).asImageBitmap(),
                contentDescription = contentDescription,
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize()
            )
        }
    }
}

/**
 * 使用二次采样把图片解码到指定边界内。
 *
 * @param file 图片文件
 * @param maxWidth 最大解码宽度
 * @param maxHeight 最大解码高度
 * @return 缩略位图；平台不支持该编码时返回 {@code null}
 */
private fun decodeBoundedBitmap(file: File, maxWidth: Int, maxHeight: Int): Bitmap? {
    if (!file.isFile) {
        return null
    }
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeFile(file.absolutePath, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
        return null
    }
    var sample = 1
    while (bounds.outWidth / sample > maxWidth * 2 ||
        bounds.outHeight / sample > maxHeight * 2
    ) {
        sample *= 2
    }
    return BitmapFactory.decodeFile(
        file.absolutePath,
        BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
    )
}

/**
 * 新建密文的显式保护模式选择器。
 *
 * @param mode 当前模式
 * @param enabled 是否可切换
 * @param onMode 模式回调
 */
@Composable
private fun ProtectionSelector(
    mode: ImageCryptMode,
    enabled: Boolean,
    onMode: (ImageCryptMode) -> Unit
) {
    Column {
        Text("保护模式", style = MaterialTheme.typography.titleSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = mode == ImageCryptMode.PUBLIC_RECOVERY,
                onClick = { onMode(ImageCryptMode.PUBLIC_RECOVERY) },
                label = { Text("公开恢复") },
                enabled = enabled,
                modifier = Modifier.weight(1f)
            )
            FilterChip(
                selected = mode == ImageCryptMode.PASSWORD,
                onClick = { onMode(ImageCryptMode.PASSWORD) },
                label = { Text("密码保护") },
                enabled = enabled,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

/**
 * 密码输入区域。
 *
 * @param password 密码
 * @param confirmPassword 确认密码
 * @param showConfirmation 是否展示确认输入
 * @param enabled 是否可编辑
 * @param onPassword 密码变更回调
 * @param onConfirmation 确认密码变更回调
 */
@Composable
private fun PasswordFields(
    password: String,
    confirmPassword: String,
    showConfirmation: Boolean,
    enabled: Boolean,
    onPassword: (String) -> Unit,
    onConfirmation: (String) -> Unit
) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = password,
        onValueChange = onPassword,
        label = { Text("密码") },
        singleLine = true,
        enabled = enabled,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            IconButton(onClick = { visible = !visible }) {
                Icon(
                    if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    contentDescription = if (visible) "隐藏密码" else "显示密码"
                )
            }
        },
        modifier = Modifier.fillMaxWidth()
    )
    if (showConfirmation) {
        OutlinedTextField(
            value = confirmPassword,
            onValueChange = onConfirmation,
            label = { Text("确认密码") },
            singleLine = true,
            enabled = enabled,
            visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )
    }
}

/**
 * 固定 KDF 参数与可行性提示。
 *
 * @param state 页面状态
 */
@Composable
private fun KdfSummary(state: ImageCryptUiState) {
    val assessment = state.kdfAssessment
    val execution = when {
        assessment == null -> "正在评估设备资源"
        assessment.heapFeasible -> "可在应用堆内执行"
        assessment.nativeAvailable -> "将使用原生离堆实现"
        assessment.likelyFeasible -> "将使用 Java 离堆实现"
        else -> "当前可用内存偏低"
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Text(
            text = "EGTC-IMG v1 固定 Argon2id 65,536 KiB / 3 passes / 4 lanes\n$execution。此参数不受全局 Argon2 档位影响。",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp)
        )
    }
}

/**
 * 公开恢复无保密性警告。
 */
@Composable
private fun PublicRecoveryWarning() {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
        Text(
            text = "公开恢复只会混淆视觉内容，不提供保密性；任何拿到文件和本工具的人都能还原原图。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
            modifier = Modifier.padding(12.dp)
        )
    }
}

/**
 * 输出位置卡片。
 *
 * @param target 当前目标说明
 * @param custom 是否为用户选择的 SAF 目录
 * @param enabled 是否可修改
 * @param onChoose 选择目录回调
 * @param onReset 恢复默认目录回调
 */
@Composable
private fun OutputTargetCard(
    target: String,
    custom: Boolean,
    enabled: Boolean,
    onChoose: () -> Unit,
    onReset: () -> Unit
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Folder, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("输出位置", style = MaterialTheme.typography.labelLarge)
                    Text(
                        target.ifBlank { "正在解析默认位置…" },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onChoose, enabled = enabled, modifier = Modifier.weight(1f)) {
                    Text("选择文件夹")
                }
                if (custom) {
                    TextButton(onClick = onReset, enabled = enabled) { Text("使用默认") }
                }
            }
        }
    }
}

/**
 * 图片任务成功结果弹窗。
 *
 * @param result 成功结果
 * @param onShare PNG 分享回调
 * @param onDismiss 关闭回调
 */
@Composable
private fun ImageCryptResultDialog(
    result: ImageCryptResultInfo,
    onShare: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = {
            Icon(
                if (result.sharePath != null) Icons.Default.Send else Icons.Default.LockOpen,
                contentDescription = null
            )
        },
        title = { Text(result.title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(result.message)
                if (result.sharePath != null) {
                    Text(
                        "分享 MIME 固定为 image/png。请在接收应用中选择“作为文件发送”，不要压缩照片。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = {
            if (result.sharePath != null) {
                Button(onClick = onShare) {
                    Icon(Icons.Default.Send, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("作为文件分享")
                }
            } else {
                Button(onClick = onDismiss) { Text("确定") }
            }
        },
        dismissButton = if (result.sharePath != null) {
            { TextButton(onClick = onDismiss) { Text("关闭") } }
        } else {
            null
        }
    )
}
