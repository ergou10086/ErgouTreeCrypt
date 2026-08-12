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
 * <p>当加解密正在进行且文件大于 100 MiB 时，自动启动前台 Service 防止
 * Android 系统杀死进程。操作完成后自动停止 Service。
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
    val largeFile = (fileSize ?: 0) >= 100L * 1024 * 1024 // 100 MiB

    // 大文件加解密开始或结束时管理前台 Service
    LaunchedEffect(isRunning, progressState.state) {
        if (isRunning && largeFile) {
            // 启动前台 Service
            val serviceIntent = Intent(ctx, CryptoForegroundService::class.java).apply {
                action = CryptoForegroundService.ACTION_START
                putExtra(CryptoForegroundService.EXTRA_TITLE, title)
            }
            ContextCompat.startForegroundService(ctx, serviceIntent)
        } else if (!isRunning) {
            // 停止前台 Service
            val stopIntent = Intent(ctx, CryptoForegroundService::class.java).apply {
                action = CryptoForegroundService.ACTION_STOP
            }
            ctx.startService(stopIntent)
        }
    }
}
