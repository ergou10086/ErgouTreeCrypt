package hbnu.project.ergoutreecrypt.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.platform.PermissionManager
import hbnu.project.ergoutreecrypt.android.ui.navigation.ErgouNavGraph
import hbnu.project.ergoutreecrypt.android.ui.theme.ErgouTheme

/**
 * 主 Activity — 应用唯一入口。
 *
 * <p>使用 Jetpack Compose 渲染所有 UI，不依赖传统 XML 布局。
 * 在 setContent 中装配主题与导航。主题模式由设置中的 DataStore 驱动。
 * 首次启动时按 Android 版本申请必要运行时权限：
 * <ul>
 *   <li>API 33+：通知权限（前台服务进度通知）</li>
 *   <li>API 26–28：读/写外部存储（旧版存储权限）</li>
 *   <li>API 29–32：读外部存储（可选，直接路径读取）</li>
 * </ul>
 * "所有文件访问权限"不在此弹窗申请（Play 政策限制），改为设置页引导跳转，
 * 未授予时应用自动降级为 SAF/MediaStore 流程，不影响使用。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val settings = remember { AndroidSettings(applicationContext) }
            val themeMode by settings.themeMode.collectAsState(initial = "SYSTEM")

            // ---- 运行时权限申请（仅首次启动，拒绝后由设置页引导） ----
            val singlePermissionLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.RequestPermission()
            ) { /* 结果由 PermissionManager 实时查询，无需在此处理 */ }
            val multiPermissionLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.RequestMultiplePermissions()
            ) { /* 结果由 PermissionManager 实时查询，无需在此处理 */ }
            LaunchedEffect(Unit) {
                val sdk = Build.VERSION.SDK_INT
                // API 33+：通知权限（前台服务通知展示）
                if (sdk >= 33) {
                    if (!PermissionManager.notificationsEnabled(applicationContext)) {
                        singlePermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                }
                // API 26–28：旧版存储权限（同一权限组，一次弹窗）
                else if (sdk <= Build.VERSION_CODES.P) {
                    val missing = listOf(
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                    ).filter {
                        ContextCompat.checkSelfPermission(applicationContext, it) !=
                                PackageManager.PERMISSION_GRANTED
                    }
                    if (missing.isNotEmpty()) {
                        multiPermissionLauncher.launch(missing.toTypedArray())
                    }
                }
                // API 29–32：读外部存储（可选，直接路径读取增强）
                else {
                    if (ContextCompat.checkSelfPermission(
                            applicationContext, Manifest.permission.READ_EXTERNAL_STORAGE
                        ) != PackageManager.PERMISSION_GRANTED
                    ) {
                        singlePermissionLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                    }
                }
            }

            val darkTheme = when (themeMode) {
                "LIGHT" -> false
                "DARK" -> true
                else -> isSystemInDarkTheme() // SYSTEM
            }

            ErgouTheme(darkTheme = darkTheme) {
                // 不透明根表面：与 XML windowBackground 一起兜底，避免透明内容露出系统黑窗
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ErgouNavGraph()
                }
            }
        }
    }
}
