package hbnu.project.ergoutreecrypt.android.platform

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * 运行时权限统一查询与跳转工具。
 *
 * <p>移动端在国产 ROM（澎湃OS / MIUI / ColorOS / OriginOS）上的权限行为差异较大，
 * 本类集中封装各 Android 版本的权限矩阵，供首次启动申请与设置页展示使用：
 * <ul>
 *   <li>API 26–28：READ/WRITE_EXTERNAL_STORAGE（旧版存储权限，运行时申请）</li>
 *   <li>API 29–32：READ_EXTERNAL_STORAGE（可选，直接路径读取）</li>
 *   <li>API 30+：MANAGE_EXTERNAL_STORAGE（可选增强，仅经系统设置页跳转，
 *       未授予时应用自动降级为 SAF/MediaStore 流程，不影响使用）</li>
 *   <li>API 33+：POST_NOTIFICATIONS（前台服务进度通知，运行时申请）</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/25
 */
object PermissionManager {

    /**
     * 是否已授予"所有文件访问权限"。
     *
     * <p>仅 API 30+ 存在该权限概念；低版本恒返回 false，由调用方按旧版存储权限判断。
     *
     * @param context 应用上下文
     * @return true 表示可直接读写公共存储任意目录
     */
    fun hasAllFilesAccess(context: Context): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && Environment.isExternalStorageManager()
    }

    /**
     * 是否已授予旧版写入外部存储权限（仅 API≤28 有意义）。
     *
     * @param context 应用上下文
     * @return true 表示可直写公共存储目录
     */
    fun hasLegacyWriteAccess(context: Context): Boolean {
        return Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
                ContextCompat.checkSelfPermission(
                    context, Manifest.permission.WRITE_EXTERNAL_STORAGE
                ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * 是否已授予通知权限（API 33+ 运行时权限）。
     *
     * <p>API 32 及以下无此运行时权限，恒返回 true。
     *
     * @param context 应用上下文
     * @return true 表示前台服务通知可正常展示
     */
    fun notificationsEnabled(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 33) {
            return true
        }
        return NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    /**
     * 构建"所有文件访问权限"系统设置页跳转意图。
     *
     * <p>依次尝试应用专属页面、通用页面，二者均无处理器（部分国产 ROM 阉割）
     * 时回退到应用详情页，保证用户总能到达可授予权限的入口。
     *
     * @param context 应用上下文
     * @return 可直接 startActivity 的设置页意图
     */
    fun buildAllFilesAccessIntent(context: Context): Intent {
        val pkgUri = Uri.parse("package:${context.packageName}")
        val candidates = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            listOf(
                Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkgUri),
                Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
            )
        } else {
            emptyList()
        }
        for (intent in candidates) {
            if (intent.resolveActivity(context.packageManager) != null) {
                return intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }
        return Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    /**
     * 构建应用通知设置页跳转意图（API 26+ 均可用）。
     *
     * @param context 应用上下文
     * @return 可直接 startActivity 的通知设置页意图
     */
    fun buildAppNotificationSettingsIntent(context: Context): Intent {
        return Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
}
