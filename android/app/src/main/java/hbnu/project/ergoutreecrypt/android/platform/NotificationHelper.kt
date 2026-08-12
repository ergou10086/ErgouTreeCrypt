package hbnu.project.ergoutreecrypt.android.platform

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import hbnu.project.ergoutreecrypt.android.MainActivity

/**
 * 通知工具类。
 *
 * <p>负责创建加解密进度通知所需的 NotificationChannel，并构建前台 Service 通知。
 * 在 Android 13+ 上需要 {@code POST_NOTIFICATIONS} 权限（运行时申请）。
 *
 * @author ErgouTree
 * @since 2026/8/12
 */
object NotificationHelper {

    /** 加解密进度通知渠道 ID */
    const val CHANNEL_ID = "crypto_progress"
    /** 前台 Service 通知 ID */
    const val FOREGROUND_NOTIFICATION_ID = 1001

    /**
     * 创建通知渠道（需在 Application.onCreate() 中调用）。
     *
     * @param context 应用上下文
     */
    fun createChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "加解密进度",
                NotificationManager.IMPORTANCE_LOW // 低重要性 = 不发出声音
            ).apply {
                description = "显示文件加解密操作进度"
                setShowBadge(false)
            }
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    /**
     * 构建前台 Service 进度通知。
     *
     * @param context  应用上下文
     * @param title    通知标题（"正在加密" / "正在解密"）
     * @param progress 当前进度百分比（0-100）
     * @param info     附加信息（文件名、速度等）
     * @return 通知对象
     */
    fun buildProgressNotification(
        context: Context,
        title: String,
        progress: Int,
        info: String
    ): Notification {
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(info.ifEmpty { "正在处理..." })
            .setSmallIcon(android.R.drawable.ic_menu_upload)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(pendingIntent)
            .setProgress(100, progress, progress <= 0)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    /**
     * 构建操作完成通知。
     *
     * @param context 应用上下文
     * @param title   通知标题
     * @param message 结果信息
     * @param success 是否成功
     * @return 通知对象
     */
    fun buildResultNotification(
        context: Context,
        title: String,
        message: String,
        success: Boolean
    ): Notification {
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(message)
            .setSmallIcon(if (success) android.R.drawable.ic_menu_upload else android.R.drawable.ic_menu_report_image)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()
    }
}
