package hbnu.project.ergoutreecrypt.android.ui.component

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import hbnu.project.ergoutreecrypt.android.platform.PermissionManager

/**
 * 权限管理区块。
 *
 * <p>在设置页展示通知权限（API 33+）与"所有文件访问权限"（API 30+）的
 * 当前状态，并提供授权/跳转按钮。返回应用（从系统设置页切回）时自动刷新
 * 状态。所有文件访问权限为可选增强：未授予时应用自动降级为 SAF/MediaStore
 * 流程，不影响加解密功能。
 *
 * @author ErgouTree
 * @since 2026/8/25
 */
@Composable
fun PermissionSection() {
    val ctx = LocalContext.current
    var notificationsGranted by remember { mutableStateOf(PermissionManager.notificationsEnabled(ctx)) }
    var allFilesGranted by remember { mutableStateOf(PermissionManager.hasAllFilesAccess(ctx)) }

    // 从系统设置页返回时刷新权限状态
    LifecycleResumeEffect(Unit) {
        notificationsGranted = PermissionManager.notificationsEnabled(ctx)
        allFilesGranted = PermissionManager.hasAllFilesAccess(ctx)
        onPauseOrDispose { }
    }

    // 通知权限弹窗（仅 API 33+ 有运行时权限）
    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        notificationsGranted = granted
    }

    // ---- 通知权限 ----
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        PermissionRow(
            title = "通知权限",
            description = "显示加解密进度与完成通知（前台服务依赖）。未授予时操作仍会执行，但后台无进度提示。",
            granted = notificationsGranted,
            onGrantClick = { notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) },
            onSettingsClick = { ctx.startActivity(PermissionManager.buildAppNotificationSettingsIntent(ctx)) }
        )
        Spacer(modifier = Modifier.height(12.dp))
    }

    // ---- 所有文件访问权限（可选增强） ----
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        PermissionRow(
            title = "所有文件访问权限（可选）",
            description = "授予后可直接读写任意目录（如输入文件同级目录）；未授予时自动通过系统文件接口保存到 下载/ErgouTreeCrypt，不影响使用。",
            granted = allFilesGranted,
            onGrantClick = { ctx.startActivity(PermissionManager.buildAllFilesAccessIntent(ctx)) },
            onSettingsClick = null // 授权只能经系统"所有文件访问权限"页面完成
        )
    }
}

/**
 * 单个权限行：标题 + 描述 + 状态与操作按钮。
 *
 * @param title          权限名称
 * @param description    权限说明
 * @param granted        当前是否已授予
 * @param onGrantClick   点击"去授权"回调（弹窗申请或跳转系统页）
 * @param onSettingsClick 点击"设置"回调（权限被永久拒绝后跳应用通知设置）；null 表示不显示
 */
@Composable
private fun PermissionRow(
    title: String,
    description: String,
    granted: Boolean,
    onGrantClick: () -> Unit,
    onSettingsClick: (() -> Unit)?
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = if (granted) "已授予" else "未授予",
                style = MaterialTheme.typography.labelMedium,
                color = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
            )
            Spacer(modifier = Modifier.weight(1f))
            if (!granted) {
                Button(onClick = onGrantClick) {
                    Text("去授权", style = MaterialTheme.typography.labelMedium)
                }
            } else if (onSettingsClick != null) {
                OutlinedButton(onClick = onSettingsClick) {
                    Text("设置", style = MaterialTheme.typography.labelMedium)
                }
            }
        }
        Text(
            text = description,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
