package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings

/**
 * 显示密码本下拉箭头，并在用户选择后返回对应密码。
 *
 * @param onPasswordSelected 密码选择回调
 */
@Composable
fun PasswordBookDropdownIcon(onPasswordSelected: (String) -> Unit) {
    val context = LocalContext.current
    val settings = remember { AndroidSettings(context.applicationContext) }
    val entries by settings.passwordBookEntries.collectAsState(initial = emptyList())
    var expanded by remember { mutableStateOf(false) }

    Box {
        IconButton(onClick = { expanded = true }) {
            Icon(Icons.Default.ArrowDropDown, contentDescription = "从密码本选择")
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            if (entries.isEmpty()) {
                DropdownMenuItem(
                    text = { Text("密码本为空") },
                    onClick = { expanded = false },
                    enabled = false
                )
            } else {
                entries.forEach { entry ->
                    DropdownMenuItem(
                        text = { Text(entry.name) },
                        onClick = {
                            expanded = false
                            onPasswordSelected(entry.password)
                        }
                    )
                }
            }
        }
    }
}

/**
 * 显示密码本下拉箭头与密码可见性按钮。
 *
 * @param passwordVisible   当前是否显示明文密码
 * @param onVisibilityChange 密码可见性变更回调
 * @param onPasswordSelected 密码选择回调
 */
@Composable
fun PasswordBookVisibilityIcons(
    passwordVisible: Boolean,
    onVisibilityChange: (Boolean) -> Unit,
    onPasswordSelected: (String) -> Unit
) {
    Row {
        PasswordBookDropdownIcon(onPasswordSelected)
        IconButton(onClick = { onVisibilityChange(!passwordVisible) }) {
            Icon(
                imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                contentDescription = if (passwordVisible) "隐藏密码" else "显示密码"
            )
        }
    }
}
