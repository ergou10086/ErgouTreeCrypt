package hbnu.project.ergoutreecrypt.android.platform

import android.content.Context
import android.net.Uri
import android.provider.MediaStore
import java.io.File
import java.io.InputStream
import java.util.UUID

/**
 * Android 文件系统适配器。
 *
 * <p>负责将 SAF (Storage Access Framework) 返回的 Content URI 转换为传统文件路径，供共享核心的 {@code java.nio.file.Path} API 使用。
 *
 * <p>策略：
 * <ol>
 *   <li>{@code file://} URI → 直接返回路径</li>
 *   <li>{@code content://} URI → 通过 MediaStore 查询真实路径</li>
 *   <li>无法查询时 → 拷贝到应用内部存储临时目录</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class AndroidFileOps(private val context: Context) {

    /**
     * 将 Content URI 解析为可直接使用的文件路径。
     *
     * @param uri 文件 URI（通常来自文件选择器）
     * @return 文件绝对路径；若无法解析返回 null
     */
    fun resolveToPath(uri: Uri): String? {
        // 1. file 协议直接返回路径
        if (uri.scheme == "file") {
            return uri.path
        }

        // 2. 通过 MediaStore 查询真实路径
        val path = queryMediaStorePath(uri)
        if (path != null && File(path).exists()) {
            return path
        }

        // 3. 拷贝到内部存储
        return copyToInternal(uri)
    }

    /**
     * 通过 MediaStore 查询文件真实路径。
     */
    private fun queryMediaStorePath(uri: Uri): String? {
        val projection = arrayOf(MediaStore.Files.FileColumns.DATA)
        return try {
            context.contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(MediaStore.Files.FileColumns.DATA)
                    if (idx >= 0) cursor.getString(idx) else null
                } else {
                    null
                }
            }
        } catch (_: SecurityException) {
            null
        }
    }

    /**
     * 将 URI 内容拷贝到应用内部临时目录。
     *
     * @return 拷贝后的临时文件路径，调用方负责在使用后清理
     */
    private fun copyToInternal(uri: Uri): String? {
        val tmpDir = File(context.filesDir, "crypto_tmp")
        tmpDir.mkdirs()
        val tmpFile = File(tmpDir, UUID.randomUUID().toString())
        return try {
            openInputStream(uri)?.use { input ->
                tmpFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            tmpFile.absolutePath
        } catch (e: Exception) {
            tmpFile.delete()
            null
        }
    }

    /**
     * 安全打开输入流（处理 SecurityException）。
     */
    fun openInputStream(uri: Uri): InputStream? {
        return try {
            context.contentResolver.openInputStream(uri)
        } catch (_: SecurityException) {
            null
        }
    }

    /**
     * 清理加密过程产生的临时文件。
     */
    fun cleanupTempFiles() {
        val tmpDir = File(context.filesDir, "crypto_tmp")
        if (tmpDir.isDirectory) {
            tmpDir.listFiles()?.forEach { it.delete() }
        }
    }

    // ==================== 密钥文件安全区域 ====================

    /**
     * 将密钥文件安全地拷贝到应用私有存储。
     *
     * <p>密钥文件是敏感数据，不应保留在用户可访问的目录中。
     * 本方法将密钥文件内容拷贝到 {@code filesDir/keyfiles/} 下，
     * 使用 UUID 命名以避免泄露原始文件名。
     *
     * @param uri 密钥文件 URI
     * @return 安全副本的绝对路径；拷贝失败返回 null
     */
    fun copyKeyfileToSecureArea(uri: Uri): String? {
        val secureDir = File(context.filesDir, "keyfiles")
        if (!secureDir.exists()) {
            secureDir.mkdirs()
        }
        val secureFile = File(secureDir, UUID.randomUUID().toString())
        return try {
            openInputStream(uri)?.use { input ->
                secureFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            // 设置文件为仅本应用可读
            secureFile.setReadable(true, true)
            secureFile.setWritable(true, true)
            secureFile.setExecutable(false)
            secureFile.absolutePath
        } catch (e: Exception) {
            secureFile.delete()
            null
        }
    }

    /**
     * 批量拷贝密钥文件到安全区域。
     *
     * @param uris 密钥文件 URI 列表
     * @return 安全副本路径列表（与输入一一对应，拷贝失败的项为 null）
     */
    fun copyKeyfilesToSecureArea(uris: List<Uri>): List<String?> {
        return uris.map { copyKeyfileToSecureArea(it) }
    }

    /**
     * 清理所有安全区域中的密钥文件副本。
     *
     * <p>应在加解密操作完成后调用，避免密钥数据残留。
     */
    fun cleanupSecureKeyfiles() {
        val secureDir = File(context.filesDir, "keyfiles")
        if (secureDir.isDirectory) {
            secureDir.listFiles()?.forEach { file ->
                // 覆写后删除（安全擦除）
                file.writeBytes(ByteArray(file.length().toInt().coerceAtMost(4096)))
                file.delete()
            }
        }
    }

    /**
     * 获取安全密钥文件目录的路径。
     *
     * @return 安全密钥目录绝对路径
     */
    fun getSecureKeyfileDir(): String {
        val secureDir = File(context.filesDir, "keyfiles")
        if (!secureDir.exists()) {
            secureDir.mkdirs()
        }
        return secureDir.absolutePath
    }
}
