package hbnu.project.ergoutreecrypt.android.ui.component

import android.content.Context
import android.content.Intent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.core.content.ContextCompat
import hbnu.project.ergoutreecrypt.android.platform.CryptoForegroundService
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState

/**
 * 前台 Service 生命周期管理器。
 *
 * <p>加解密进行期间自动启动前台 Service，使进程获得前台优先级，
 * 降低被系统或国产 ROM 后台策略（澎湃OS/MIUI 等）杀死的概率。
 * 操作完成后自动停止 Service。
 *
 * <p>注意：Service 仅作为通知宿主，实际加解密仍运行在 ViewModel 协程中；
 * 若进程被强制回收（如厂商一键清理），小文件操作仍可能中断。
 *
 * @param ctx           Android Context
 * @param isRunning     是否有加解密操作正在运行
 * @param progressState 当前进度状态
 * @param fileSize      输入文件大小（字节），null 表示未知
 * @param title         通知标题（"正在加密" / "正在解密"）
 * @param fileName      文件名
 * @author ErgouTree
 * @since 2026/8/12
 */
@Composable
fun ForegroundServiceEffect(
    ctx: Context,
    isRunning: Boolean,
    progressState: ProgressState,
    fileSize: Long?,
    title: String,
    fileName: String?
) {
    // 加解密开始或结束时管理前台 Service
    LaunchedEffect(isRunning, progressState.state) {
        if (isRunning) {
            // 启动前台 Service（后台启动受限等异常时静默降级，不影响加解密本身）
            try {
                val serviceIntent = Intent(ctx, CryptoForegroundService::class.java).apply {
                    action = CryptoForegroundService.ACTION_START
                    putExtra(CryptoForegroundService.EXTRA_TITLE, title)
                }
                ContextCompat.startForegroundService(ctx, serviceIntent)
            } catch (_: Exception) {
                // Android 12+ 后台启动前台服务受限；个别 OEM 亦有额外限制，忽略即可
            }
        } else if (!isRunning) {
            // 停止前台 Service
            val stopIntent = Intent(ctx, CryptoForegroundService::class.java).apply {
                action = CryptoForegroundService.ACTION_STOP
            }
            ctx.startService(stopIntent)
        }
    }
}
