package hbnu.project.ergoutreecrypt.android.platform

import android.content.Context
import android.os.Build
import android.os.Environment
import java.io.File

/**
 * 移动端默认输出目录解析器。
 *
 * <p>桌面端习惯把产物写到输入文件同级目录，但 Android 10+ 分区存储下
 * 应用默认无权直写公共目录（澎湃OS/MIUI 等国产 ROM 上更严格），直接写
 * {@code /storage/emulated/0/...} 会抛 AccessDeniedException，表现为
 * "解密失败"。本类按当前权限能力决定默认输出策略：
 * <ul>
 *   <li>API 30+ 且已授予"所有文件访问权限"→ 直写公共 下载/ErgouTreeCrypt</li>
 *   <li>API 26–28 且有旧版写入权限 → 直写公共 下载/ErgouTreeCrypt</li>
 *   <li>API 26–28 无写入权限 → 应用专属外部目录（永远可写）</li>
 *   <li>其余（API 29+ 无全盘权限）→ 先写内部临时目录，
 *       完成后经 MediaStore 提交到 下载/ErgouTreeCrypt</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/25
 */
object OutputDirResolver {

    /** 默认输出子目录名。 */
    const val FOLDER_NAME = "ErgouTreeCrypt"

    /** MediaStore 相对路径（相对外部存储主卷，不带尾部斜杠）。 */
    val MEDIA_RELATIVE_PATH = "${Environment.DIRECTORY_DOWNLOADS}/$FOLDER_NAME"

    /**
     * 输出目录解析结果。
     */
    sealed interface Resolved {
        /** 可直接按路径写入的目录。 */
        data class Direct(val path: String) : Resolved

        /** 需先写临时目录、完成后经 MediaStore 提交的相对路径。 */
        data class MediaStore(val relativePath: String) : Resolved

        /** 应用专属外部目录（永远可写，但用户不便浏览）。 */
        data class AppExternal(val path: String) : Resolved
    }

    /**
     * 按当前权限能力解析默认输出目录策略。
     *
     * @param context 应用上下文
     * @return 输出目录策略（Direct/AppExternal 已确保目录存在）
     */
    fun resolve(context: Context): Resolved {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return if (PermissionManager.hasAllFilesAccess(context)) {
                Resolved.Direct(publicDownloadPath())
            } else {
                Resolved.MediaStore(MEDIA_RELATIVE_PATH)
            }
        }
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) {
            return if (PermissionManager.hasLegacyWriteAccess(context)) {
                Resolved.Direct(publicDownloadPath())
            } else {
                val dir = File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), FOLDER_NAME)
                dir.mkdirs()
                Resolved.AppExternal(dir.absolutePath)
            }
        }
        // API 29：无全盘权限概念，也无可运行时申请的写权限，统一走 MediaStore
        return Resolved.MediaStore(MEDIA_RELATIVE_PATH)
    }

    /**
     * 公共下载目录下的应用子目录绝对路径（并确保其存在）。
     *
     * @return 如 {@code /storage/emulated/0/Download/ErgouTreeCrypt}
     */
    fun publicDownloadPath(): String {
        val dir = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            FOLDER_NAME
        )
        dir.mkdirs()
        return dir.absolutePath
    }

    /**
     * 统一解析"历史记录输出目录"回退链。
     *
     * <p>SAF 输出时优先用解析出的磁盘路径；MediaStore 提交时产物物理落盘于
     * 公共下载子目录；均不可用时回退输入文件父目录、应用 filesDir。
     *
     * @param context     应用上下文
     * @param outDir      用户显式选择的输出目录（可为 null）
     * @param inputParent 输入文件的父目录（可为 null）
     * @return 历史记录展示用的输出目录路径
     */
    fun historyDir(context: Context, outDir: String?, inputParent: String?): String {
        if (outDir != null) {
            return outDir
        }
        return when (val r = resolve(context)) {
            is Resolved.Direct -> r.path
            is Resolved.MediaStore -> publicDownloadPath()
            is Resolved.AppExternal -> r.path
        } ?: inputParent ?: context.filesDir.absolutePath
    }
}
