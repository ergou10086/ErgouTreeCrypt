package hbnu.project.ergoutreecrypt.android.ui.screen

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.ui.component.CompactTopBar
import hbnu.project.ergoutreecrypt.android.ui.component.MemoryIndicator
import hbnu.project.ergoutreecrypt.classical.CipherRegistry
import hbnu.project.ergoutreecrypt.classical.ClassicalCipher
import hbnu.project.ergoutreecrypt.classical.CipherInfo
import hbnu.project.ergoutreecrypt.i18n.Messages

/**
 * 文本加密页面（古典与现代密码）。
 *
 * <p>列出所有注册的密码算法（现代密码在前，古典密码在后），点击展开后可进行字符串加密/解密操作。
 * 每种算法的参数由 {@link CipherInfo#params()} 动态定义，UI 据此自动渲染输入控件。
 *
 * <p>加密核心逻辑直接复用共享核心中的各 {@link ClassicalCipher} 实现，
 * 与桌面端 100% 一致。已作为底部导航栏独立 Tab。
 *
 * @author ErgouTree
 * @since 2026/8/12
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ClassicalScreen(onOpenHistory: () -> Unit = {}) {
    val ctx = LocalContext.current
    val ciphers = remember { CipherRegistry.getAll() }
    val settings = remember { AndroidSettings(ctx.applicationContext) }
    val showMemoryIndicator by settings.showMemoryIndicator.collectAsState(initial = true)

    Scaffold(
        // 容器透明，避免遮住全局背景图层
        containerColor = Color.Transparent,
        topBar = {
            CompactTopBar(
                title = "文本加密",
                actions = {
                    IconButton(onClick = onOpenHistory) {
                        Icon(Icons.Outlined.History, contentDescription = "操作历史")
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            item { Spacer(modifier = Modifier.height(8.dp)) }
            item {
                Text(
                    text = "密码算法工具箱（古典与现代），支持加密与解密。与桌面版共享同一套密码算法实现。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            item { Spacer(modifier = Modifier.height(8.dp)) }
            // 低调的内存使用指示器（可在设置中关闭）
            if (showMemoryIndicator) {
                item { MemoryIndicator() }
                item { Spacer(modifier = Modifier.height(12.dp)) }
            }
            items(ciphers) { info ->
                CipherCard(
                    cipher = CipherRegistry.get(info.id()) ?: return@items,
                    info = info,
                    ctx = ctx
                )
                Spacer(modifier = Modifier.height(8.dp))
            }
            item { Spacer(modifier = Modifier.height(16.dp)) }
        }
    }
}

/**
 * 单个密码算法的可展开卡片。
 *
 * <p>折叠时显示算法名称与描述，点击展开后可输入明文/密文、设置参数并执行加解密。
 *
 * @param cipher 算法实例
 * @param info   算法元数据
 * @param ctx    Android Context（用于剪贴板操作）
 */
@Composable
private fun CipherCard(
    cipher: ClassicalCipher,
    info: CipherInfo,
    ctx: Context
) {
    var expanded by remember { mutableStateOf(false) }
    // 翻译名称与描述（Messages 基于 ResourceBundle）
    val name = remember(info.id()) {
        try { Messages.get(info.nameKey()) } catch (_: Exception) { info.id() }
    }
    val desc = remember(info.id()) {
        try { Messages.get(info.descKey()) } catch (_: Exception) { "" }
    }

    // 参数值状态
    val paramStates = remember(info.id()) {
        info.params().associate { it.key() to mutableStateOf(it.defaultValue()) }
    }

    // 输入/输出
    var inputText by remember { mutableStateOf("") }
    var outputText by remember { mutableStateOf("") }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (expanded)
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
        ),
        onClick = { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // 头部：名称 + 展开/折叠图标
            Row(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = name,
                        style = MaterialTheme.typography.titleSmall
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    if (!expanded && desc.isNotEmpty()) {
                        Text(
                            text = desc,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2
                        )
                    }
                }
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (expanded) "收起" else "展开",
                    modifier = Modifier.size(24.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // 可展开的加解密区域（阻止点击事件冒泡到 Card 的 onClick）
            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(),
                exit = shrinkVertically()
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Spacer(modifier = Modifier.height(8.dp))

                    // 算法描述
                    if (desc.isNotEmpty()) {
                        Text(
                            text = desc,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    HorizontalDivider()
                    Spacer(modifier = Modifier.height(8.dp))

                    // ---- 参数输入 ----
                    info.params().forEach { param ->
                        val state = paramStates[param.key()] ?: return@forEach
                        val label = try {
                            Messages.get(param.labelKey())
                        } catch (_: Exception) {
                            param.key()
                        }
                        if (param.type() == "number") {
                            OutlinedTextField(
                                value = state.value,
                                onValueChange = { state.value = it },
                                label = { Text(label) },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Number,
                                    imeAction = ImeAction.Next
                                ),
                                textStyle = MaterialTheme.typography.bodyMedium
                            )
                        } else if (param.type() == "password") {
                            // "password" 类型：掩码显示，带可见性切换
                            var passwordVisible by remember(info.id() + param.key()) {
                                mutableStateOf(false)
                            }
                            OutlinedTextField(
                                value = state.value,
                                onValueChange = { state.value = it },
                                label = { Text(label) },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                                visualTransformation = if (passwordVisible) {
                                    VisualTransformation.None
                                } else {
                                    PasswordVisualTransformation()
                                },
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Password,
                                    imeAction = ImeAction.Next
                                ),
                                trailingIcon = {
                                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                        Icon(
                                            imageVector = if (passwordVisible) {
                                                Icons.Default.VisibilityOff
                                            } else {
                                                Icons.Default.Visibility
                                            },
                                            contentDescription = "切换密码可见性"
                                        )
                                    }
                                },
                                textStyle = MaterialTheme.typography.bodyMedium
                            )
                        } else {
                            // "text" 类型
                            OutlinedTextField(
                                value = state.value,
                                onValueChange = { state.value = it },
                                label = { Text(label) },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                                textStyle = MaterialTheme.typography.bodyMedium
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                    }

                    // ---- 输入文本 ----
                    OutlinedTextField(
                        value = inputText,
                        onValueChange = { inputText = it },
                        label = { Text("输入文本") },
                        placeholder = { Text("请输入明文或密文") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                        maxLines = 6,
                        textStyle = MaterialTheme.typography.bodyMedium,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Default)
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    // ---- 加密 / 解密按钮 ----
                    Row(modifier = Modifier.fillMaxWidth()) {
                        Button(
                            onClick = {
                                val params = paramStates.mapValues { it.value.value }
                                try {
                                    outputText = cipher.encrypt(inputText, params)
                                } catch (e: Exception) {
                                    outputText = "加密失败：${e.localizedMessage ?: e.javaClass.simpleName}"
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("加密")
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        FilledTonalButton(
                            onClick = {
                                val params = paramStates.mapValues { it.value.value }
                                try {
                                    outputText = cipher.decrypt(inputText, params)
                                } catch (e: Exception) {
                                    outputText = "解密失败：${e.localizedMessage ?: e.javaClass.simpleName}"
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("解密")
                        }
                    }

                    // ---- 输出文本 + 复制按钮 ----
                    if (outputText.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedTextField(
                            value = outputText,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("输出结果") },
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 3,
                            maxLines = 6,
                            textStyle = MaterialTheme.typography.bodyMedium,
                            trailingIcon = {
                                IconButton(onClick = {
                                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    cm.setPrimaryClip(ClipData.newPlainText("classical_result", outputText))
                                    Toast.makeText(ctx, "已复制到剪贴板", Toast.LENGTH_SHORT).show()
                                }) {
                                    Icon(Icons.Default.ContentCopy, contentDescription = "复制结果")
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}
