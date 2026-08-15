package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * 操作结果弹窗。
 *
 * <p>根据操作结果显示不同图标和颜色的结果信息。支持成功、错误、信息三种类型。
 * 提供复制错误详情到剪贴板的功能。
 *
 * @param title        弹窗标题
 * @param message      结果描述信息
 * @param detail       可选的技术详情（如堆栈信息），可复制
 * @param type         结果类型（SUCCESS / ERROR / INFO）
 * @param onDismiss    关闭回调
 * @param onConfirm    确认按钮回调（通常与 onDismiss 相同）
 * @param confirmLabel 确认按钮文字
 * @author ErgouTree
 * @since 2026/8/12
 */
@Composable
fun ResultDialog(
    title: String,
    message: String,
    detail: String? = null,
    type: ResultType = ResultType.INFO,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit = onDismiss,
    confirmLabel: String = "确定"
) {
    val (icon, tint) = when (type) {
        ResultType.SUCCESS -> Icons.Default.CheckCircle to Color(0xFF4CAF50)
        ResultType.ERROR -> Icons.Default.Error to MaterialTheme.colorScheme.error
        ResultType.INFO -> Icons.Default.Info to MaterialTheme.colorScheme.primary
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        icon = {
            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
                tint = tint
            )
        },
        title = {
            Text(
                text = title,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
                if (!detail.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = onConfirm) {
                Text(confirmLabel)
            }
        },
        dismissButton = if (detail != null) {
            {
                TextButton(onClick = {
                    // 复制详情到剪贴板的回调由外层处理
                    onDismiss()
                }) {
                    Text("关闭")
                }
            }
        } else {
            null
        }
    )
}

/**
 * 结果类型枚举。
 */
enum class ResultType {
    /** 操作成功 */
    SUCCESS,
    /** 操作失败 */
    ERROR,
    /** 一般信息 */
    INFO
}

// ==================== 错误消息映射 ====================

/**
 * 将常见加解密异常映射为中文用户友好消息。
 *
 * <p>对于未知异常，返回原始异常的 localizedMessage 或类名。
 *
 * @param error 异常消息（来自 Exception.localizedMessage 或 ProgressState.error）
 * @return 中文用户友好消息
 */
fun mapErrorToChineseMessage(error: String?): String {
    if (error == null) return "未知错误"

    return when {
        // 密码相关
        error.contains("password", ignoreCase = true) ||
        error.contains("MAC", ignoreCase = true) ||
        error.contains("HMAC", ignoreCase = true) ||
        error.contains("BLAKE2", ignoreCase = true) ||
        error.contains("authentication", ignoreCase = true) ||
        error.contains("tag mismatch", ignoreCase = true) ->
            "密码错误或文件已损坏，无法解密。请检查密码是否正确。"

        // Argon2 内存不足
        error.contains("OutOfMemory", ignoreCase = true) ||
        error.contains("内存不足", ignoreCase = true) ||
        (error.contains("memory", ignoreCase = true) &&
         (error.contains("argon", ignoreCase = true) ||
          error.contains("Argon2", ignoreCase = true))) ->
            "内存不足：操作所需内存超过设备可用堆。\n" +
                "• 加密/隐写：请在设置中降低 Argon2 内存档位后重试（操作前会自动按设备内存降档）。\n" +
                "• 解密/提取：文件创建时的 Argon2 内存参数已随文件固定，与当前档位无关，请改用桌面端处理。"

        // 文件不存在/无法读取
        error.contains("NoSuchFile", ignoreCase = true) ||
        error.contains("FileNotFound", ignoreCase = true) ||
        error.contains("not found", ignoreCase = true) ->
            "文件不存在或已被移动/删除，请重新选择文件。"

        // 权限被拒
        error.contains("Permission denied", ignoreCase = true) ||
        error.contains("Access denied", ignoreCase = true) ||
        error.contains("SecurityException", ignoreCase = true) ->
            "没有读取该文件的权限，请重新选择文件并授予权限。"

        // 磁盘空间不足
        error.contains("No space", ignoreCase = true) ||
        error.contains("disk", ignoreCase = true) ->
            "磁盘空间不足，无法完成加解密操作。请清理存储空间后重试。"

        // 格式不支持
        error.contains("format", ignoreCase = true) &&
        (error.contains("unsupported", ignoreCase = true) ||
         error.contains("not supported", ignoreCase = true)) ->
            "不支持的文件格式，请检查文件类型。"

        // 文件被占用
        error.contains("being used", ignoreCase = true) ||
        error.contains("locked", ignoreCase = true) ->
            "文件正在被其他程序使用，请关闭相关程序后重试。"

        // 数据损坏
        error.contains("corrupt", ignoreCase = true) ||
        error.contains("RS", ignoreCase = true) && error.contains("fail", ignoreCase = true) ->
            "文件数据已损坏且 Reed-Solomon 纠错无法修复。请尝试使用\"强制解密\"选项。"

        // 密钥文件
        error.contains("keyfile", ignoreCase = true) ->
            "密钥文件验证失败。请确保添加了正确的密钥文件，且顺序正确。"

        // 操作被取消
        error.contains("cancel", ignoreCase = true) ||
        error.contains("interrupt", ignoreCase = true) ->
            "操作已被取消。"

        // 压缩包密码
        error.contains("zip", ignoreCase = true) && error.contains("password", ignoreCase = true) ->
            "压缩包密码错误，请检查输入的压缩包密码。"

        // ===== 隐写（stego）相关错误 =====

        // 载体格式不支持
        error.contains("不支持的载体格式", ignoreCase = true) ||
        error.contains("不支持的载体", ignoreCase = true) ||
        (error.contains("载体", ignoreCase = true) && error.contains("不支持", ignoreCase = true)) ->
            "不支持的载体文件格式。请选择 PNG、ZIP、PDF、WAV、FLAC 或 MP4 文件作为载体。"

        // 载体容量不足
        error.contains("载体容量不足", ignoreCase = true) ||
        error.contains("容量不足", ignoreCase = true) ->
            "载体文件容量不足，无法容纳待隐藏的文件。请选择更大的载体文件，或使用 ZIP/PNG 等无容量限制的载体格式。"

        // 未检测到隐写数据
        error.contains("未检测到", ignoreCase = true) ||
        error.contains("不是有效的", ignoreCase = true) && error.contains("PNG", ignoreCase = true) ->
            "未检测到可识别的隐写数据。请确认所选文件是否包含本工具生成的隐写内容。"

        // 隐写密码错误/隐蔽魔数不匹配
        error.contains("隐蔽魔数", ignoreCase = true) ||
        error.contains("隐蔽模式", ignoreCase = true) && error.contains("密码", ignoreCase = true) ->
            "隐蔽模式验证失败：密码错误或文件数据已损坏。"

        // 载体嵌入/提取失败（通用）
        error.contains("载体嵌入失败", ignoreCase = true) ||
        error.contains("载体提取失败", ignoreCase = true) ->
            "载体操作失败：${error}. 请确认载体文件格式正确且未损坏。"

        // 文件大小混淆异常
        error.contains("目标大小", ignoreCase = true) && error.contains("混淆", ignoreCase = true) ->
            "文件大小混淆失败：目标大小必须大于当前输出文件大小。请增大目标大小。"

        // InterruptedException (cancel)
        error.contains("InterruptedException", ignoreCase = true) ->
            "操作已被取消。"

        // 默认：返回原始错误
        else -> error
    }
}

/**
 * 生成操作成功的提示信息。
 *
 * @param operation 操作类型（"加密" / "解密"）
 * @param outputFile 输出文件路径
 * @return 成功提示信息
 */
fun buildSuccessMessage(operation: String, outputFile: String?): String {
    val fileInfo = if (outputFile != null) {
        val name = outputFile.substringAfterLast('/')
        "输出文件：$name"
    } else {
        ""
    }
    return "${operation}完成！$fileInfo"
}
