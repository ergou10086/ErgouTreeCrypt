package hbnu.project.ergoutreecrypt.android.ui.component

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import java.security.SecureRandom

/**
 * 密码输入组件
 *
 * <p>包含密码输入框、显示/隐藏切换、强度指示器、生成随机密码、复制到剪贴板、以及确认密码输入。
 *
 * @param password         当前密码值
 * @param onPasswordChange 密码变更回调
 * @param label            输入框标签，默认"密码"
 * @param enabled          是否启用，默认 true
 * @param showConfirm      是否显示确认密码输入框，默认 false
 * @param confirmPassword  确认密码值
 * @param onConfirmChange  确认密码变更回调
 * @param showStrength     是否显示强度指示器，默认 true
 * @param showActions      是否显示生成/复制操作按钮，默认 true
 * @param modifier         修饰符
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun PasswordField(
    password: String,
    onPasswordChange: (String) -> Unit,
    label: String = "密码",
    enabled: Boolean = true,
    showConfirm: Boolean = false,
    confirmPassword: String = "",
    onConfirmChange: (String) -> Unit = {},
    showStrength: Boolean = true,
    showActions: Boolean = true,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var passwordVisible by remember { mutableStateOf(false) }

    Column(modifier = modifier.fillMaxWidth()) {
        // 密码输入框 + 显示/隐藏切换
        OutlinedTextField(
            value = password,
            onValueChange = onPasswordChange,
            label = { Text(label) },
            enabled = enabled,
            singleLine = true,
            placeholder = { Text("请输入密码") },
            modifier = Modifier.fillMaxWidth(),
            visualTransformation = if (passwordVisible) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = if (showConfirm) ImeAction.Next else ImeAction.Done
            ),
            trailingIcon = {
                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                    Icon(
                        imageVector = if (passwordVisible) {
                            Icons.Default.VisibilityOff
                        } else {
                            Icons.Default.Visibility
                        },
                        contentDescription = if (passwordVisible) "隐藏密码" else "显示密码"
                    )
                }
            }
        )

        // 强度指示器 + 操作按钮行
        if (showStrength || showActions) {
            Spacer(modifier = Modifier.height(4.dp))
            Row(modifier = Modifier.fillMaxWidth()) {
                if (showStrength) {
                    PasswordStrengthMeter(
                        password = password,
                        modifier = Modifier.weight(1f)
                    )
                } else {
                    Spacer(modifier = Modifier.weight(1f))
                }
                if (showActions && enabled) {
                    Spacer(modifier = Modifier.width(4.dp))
                    FilledTonalButton(
                        onClick = {
                            val newPwd = generateRandomPassword(20)
                            onPasswordChange(newPwd)
                            if (showConfirm) {
                                onConfirmChange(newPwd)
                            }
                            passwordVisible = true
                        },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = "生成随机密码",
                            modifier = Modifier.size(16.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(4.dp))
                    FilledTonalButton(
                        onClick = {
                            copyToClipboard(context, password)
                        },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            Icons.Default.ContentCopy,
                            contentDescription = "复制密码",
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }
        }

        // 确认密码输入框
        if (showConfirm) {
            Spacer(modifier = Modifier.height(8.dp))
            val mismatch = confirmPassword.isNotEmpty() && password != confirmPassword
            OutlinedTextField(
                value = confirmPassword,
                onValueChange = onConfirmChange,
                label = { Text("确认密码") },
                enabled = enabled,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                visualTransformation = if (passwordVisible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onDone = { /* 触发加密操作由外部处理 */ }
                ),
                isError = mismatch,
                supportingText = if (mismatch) {
                    { Text("两次输入的密码不一致", color = MaterialTheme.colorScheme.error) }
                } else {
                    null
                }
            )
        }
    }
}

/** 安全随机字符集 */
private val PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?"

/**
 * 生成指定长度的安全随机密码。
 *
 * @param length 密码长度
 * @return 随机密码字符串
 */
fun generateRandomPassword(length: Int): String {
    val random = SecureRandom()
    return (1..length).map { PASSWORD_CHARS[random.nextInt(PASSWORD_CHARS.length)] }.joinToString("")
}

/**
 * 将文本复制到系统剪贴板。
 *
 * @param context Android 上下文
 * @param text    待复制的文本
 */
private fun copyToClipboard(context: Context, text: String) {
    if (text.isEmpty()) return
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("password", text)
    clipboard.setPrimaryClip(clip)
}
