package hbnu.project.ergoutreecrypt.android.platform

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * 加解密前台 Service。
 *
 * <p>通过前台通知保证加解密任务在后台不被系统杀死。
 * 本 Service 仅作为通知宿主，实际的加解密逻辑仍在 ViewModel 协程中执行。
 *
 * <p>启动时应传入额外数据指定通知标题与进度。
 *
 * <p>用法：
 * <pre>{@code
 *   val intent = Intent(context, CryptoForegroundService::class.java).apply {
 *       action = ACTION_START
 *       putExtra(EXTRA_TITLE, "正在加密")
 *   }
 *   ContextCompat.startForegroundService(context, intent)
 *   // ... 加密中通过 updateProgress() 更新通知 ...
 *   // 完成后：
 *   context.stopService(intent)
 * }</pre>
 *
 * @author ErgouTree
 * @since 2026/8/12
 */
class CryptoForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val title = intent?.getStringExtra(EXTRA_TITLE) ?: "处理中"
        val notification = NotificationHelper.buildProgressNotification(
            this, title, 0, ""
        )
        // 后台启动受限（Android 12+）或个别 OEM 限制时静默降级：
        // 前台通知失败不影响实际加解密（其在 ViewModel 协程中执行）
        try {
            startForeground(NotificationHelper.FOREGROUND_NOTIFICATION_ID, notification)
        } catch (_: Exception) {
            stopSelf()
            return START_NOT_STICKY
        }

        return START_NOT_STICKY
    }

    /**
     * 更新前台通知的进度。
     *
     * @param title    通知标题
     * @param progress 进度百分比（0-100）
     * @param info     附加信息
     */
    fun updateProgress(title: String, progress: Int, info: String) {
        val notification = NotificationHelper.buildProgressNotification(this, title, progress, info)
        val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
        nm.notify(NotificationHelper.FOREGROUND_NOTIFICATION_ID, notification)
    }

    /**
     * 显示完成通知并停止前台状态。
     *
     * @param title   通知标题
     * @param message 结果信息
     * @param success 是否成功
     */
    fun showResult(title: String, message: String, success: Boolean) {
        val notification = NotificationHelper.buildResultNotification(this, title, message, success)
        val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
        nm.notify(NotificationHelper.FOREGROUND_NOTIFICATION_ID + 1, notification)
        stopForeground(STOP_FOREGROUND_DETACH)
        stopSelf()
    }

    companion object {
        const val ACTION_START = "hbnu.project.ergoutreecrypt.android.action.START_CRYPTO"
        const val ACTION_STOP = "hbnu.project.ergoutreecrypt.android.action.STOP_CRYPTO"
        const val EXTRA_TITLE = "hbnu.project.ergoutreecrypt.android.extra.TITLE"

        private const val TAG = "CryptoForegroundSvc"
    }
}
