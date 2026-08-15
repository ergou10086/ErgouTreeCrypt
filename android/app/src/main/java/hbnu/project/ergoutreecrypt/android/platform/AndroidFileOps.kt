package hbnu.project.ergoutreecrypt.android.platform

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.provider.OpenableColumns
import androidx.core.content.FileProvider
import hbnu.project.ergoutreecrypt.history.OperationRecord
import java.io.File
import java.io.InputStream
import java.util.UUID

/** 系统外部存储提供者（DocumentsUI）的 authority。 */
private const val EXTERNAL_STORAGE_PROVIDER_AUTHORITY = "com.android.externalstorage.documents"

/** 拷贝文件使用的缓冲区大小（64 KiB），比默认 8 KiB 更快地流式复制大文件。 */
private const val COPY_BUFFER_SIZE = 64 * 1024

/**
 * 待复制到 SAF 目录的输出暂存信息。
 *
 * @property treeUri 目标目录树 URI
 * @property tempDir 后端写入输出的临时目录
 */
data class PendingSafOutput(val treeUri: Uri, val tempDir: File)

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
 * <p>解析成功的 URI→路径结果会缓存，重复选择同一文件时直接返回，避免再次复制大文件。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class AndroidFileOps(private val context: Context) {

    /** 已解析成功的 URI→路径缓存（同一页面实例内复用）。 */
    private val resolvedCache = java.util.concurrent.ConcurrentHashMap<Uri, String>()

    /**
     * 将 Content URI 解析为可直接使用的文件路径。
     *
     * @param uri 文件 URI（通常来自文件选择器）
     * @return 文件绝对路径；若无法解析返回 null
     */
    fun resolveToPath(uri: Uri): String? {
        // 0. 命中缓存且文件仍存在时直接返回（临时文件可能已被清理）
        resolvedCache[uri]?.let { cached ->
            if (File(cached).exists()) {
                return cached
            }
            resolvedCache.remove(uri)
        }

        // 1. file 协议直接返回路径
        if (uri.scheme == "file") {
            return uri.path?.also { resolvedCache[uri] = it }
        }

        // 2. 通过 MediaStore 查询真实路径
        val path = queryMediaStorePath(uri)
        if (path != null && File(path).exists()) {
            resolvedCache[uri] = path
            return path
        }

        // 3. 拷贝到内部存储
        return copyToInternal(uri)?.also { resolvedCache[uri] = it }
    }

    /**
     * 将目录树 URI（OpenDocumentTree 选择结果）解析为真实文件系统目录路径。
     *
     * <p>SAF 目录选择器返回的树 URI 无法通过 {@link #resolveToPath(Uri)} 处理。
     * 本方法仅支持系统外部存储提供者（ExternalStorageProvider）返回的树 URI，
     * 通过解析文档 ID 中的卷名与相对路径拼接为绝对路径；其他提供者（如云盘）返回 null。
     *
     * @param uri 目录树 URI
     * @return 目录绝对路径；无法解析返回 null
     */
    fun resolveTreeUriToPath(uri: Uri): String? {
        if (uri.scheme == "file") {
            return uri.path
        }
        if (uri.authority != EXTERNAL_STORAGE_PROVIDER_AUTHORITY) {
            return null
        }
        return try {
            val parts = DocumentsContract.getTreeDocumentId(uri).split(":", limit = 2)
            if (parts.size != 2) {
                null
            } else {
                val root = resolveStorageVolumeRoot(parts[0])
                val relative = parts[1]
                val path = root?.let { if (relative.isEmpty()) it else "$it/$relative" }
                if (path != null && File(path).isDirectory) path else null
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 根据文档 ID 中的卷名解析卷根目录的绝对路径。
     *
     * <p>主存储卷（primary/home）直接映射到 {@link Environment#getExternalStorageDirectory()}；
     * 次级存储卷（如 SD 卡）通过遍历应用专属目录向上反推卷根。
     *
     * @param volume 卷名（文档 ID 冒号前的部分）
     * @return 卷根目录绝对路径；未找到返回 null
     */
    private fun resolveStorageVolumeRoot(volume: String): String? {
        if (volume == "primary" || volume == "home") {
            return Environment.getExternalStorageDirectory().absolutePath
        }
        for (dir in context.getExternalFilesDirs(null)) {
            if (dir == null) {
                continue
            }
            var cur: File? = dir
            while (cur != null) {
                if (cur.name.equals(volume, ignoreCase = true)) {
                    return cur.absolutePath
                }
                cur = cur.parentFile
            }
        }
        return null
    }

    /**
     * 创建一个用于暂存输出文件的内部临时目录。
     *
     * <p>当输出目标是 SAF 目录时，后端先写入该临时目录，提交时再复制到 SAF 目录。
     *
     * @return 新建的空临时目录
     */
    fun createOutputTempDir(): File {
        val dir = File(context.cacheDir, "saf_out_${UUID.randomUUID()}")
        dir.mkdirs()
        return dir
    }

    /**
     * 将临时目录中的所有内容（保留子目录结构）递归复制到 SAF 目录树 URI 指定的目录中（覆盖同名文件）。
     *
     * <p>用于自定义输出目录场景：后端先写入内部临时目录，再通过本方法
     * 将产物复制到用户选择的 SAF 目录，规避 Android 分区存储对直接写外部目录的限制。
     * 归档解密的产物可能位于子目录（如 {@code <归档名>/} 下），因此按目录结构递归复制。
     *
     * @param treeUri   目录树 URI（OpenDocumentTree 选择结果）
     * @param sourceDir 包含待复制内容的临时目录
     * @return 是否全部复制成功
     */
    fun copyDirectoryToTree(treeUri: Uri, sourceDir: File): Boolean {
        val files = sourceDir.listFiles() ?: return false
        if (files.isEmpty()) {
            return false
        }
        val resolver = context.contentResolver
        return try {
            val treeDocId = DocumentsContract.getTreeDocumentId(treeUri)
            var success = true
            for (f in files) {
                if (!copyEntryToTree(resolver, treeUri, treeDocId, f)) {
                    success = false
                }
            }
            success
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 将单个文件或目录递归复制到 SAF 目录树中指定父文档 ID 下（覆盖同名文件，复用同名目录）。
     *
     * @param resolver    ContentResolver
     * @param treeUri     目录树 URI
     * @param parentDocId 目标父目录的文档 ID
     * @param entry       待复制的文件或目录
     * @return 是否复制成功
     */
    private fun copyEntryToTree(resolver: ContentResolver, treeUri: Uri, parentDocId: String, entry: File): Boolean {
        if (entry.isDirectory) {
            // 目录：优先复用 SAF 侧同名目录，否则新建，再递归复制内容
            val dirDocId = findChildDocIdByName(resolver, treeUri, parentDocId, entry.name, true)
                ?: createChildDocument(resolver, treeUri, parentDocId, entry.name,
                    DocumentsContract.Document.MIME_TYPE_DIR)
                ?: return false
            val children = entry.listFiles() ?: return false
            var success = true
            for (child in children) {
                if (!copyEntryToTree(resolver, treeUri, dirDocId, child)) {
                    success = false
                }
            }
            return success
        }
        // 文件：先删除同名旧文档，再创建并写入
        deleteDocumentByName(resolver, treeUri, parentDocId, entry.name)
        val docId = createChildDocument(resolver, treeUri, parentDocId, entry.name,
                "application/octet-stream")
            ?: return false
        val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
        val out = resolver.openOutputStream(docUri) ?: return false
        out.use { stream ->
            entry.inputStream().use { input -> input.copyTo(stream) }
        }
        return true
    }

    /**
     * 在 SAF 目录树指定父文档下新建文档并返回其文档 ID。
     *
     * @param resolver    ContentResolver
     * @param treeUri     目录树 URI
     * @param parentDocId 父目录文档 ID
     * @param name        新文档名
     * @param mimeType    新文档 MIME 类型
     * @return 新文档的文档 ID；创建失败返回 null
     */
    private fun createChildDocument(resolver: ContentResolver, treeUri: Uri, parentDocId: String,
                                    name: String, mimeType: String): String? {
        return try {
            val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId)
            val docUri = DocumentsContract.createDocument(resolver, parentUri, mimeType, name)
            docUri?.let { DocumentsContract.getDocumentId(it) }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 在 SAF 目录树指定父文档下查找指定名称的子文档 ID（可选限定为目录）。
     *
     * @param resolver      ContentResolver
     * @param treeUri       目录树 URI
     * @param parentDocId   父目录文档 ID
     * @param name          子文档名
     * @param directoryOnly 为 true 时仅匹配目录（MIME_TYPE_DIR）
     * @return 匹配的子文档 ID；未找到返回 null
     */
    private fun findChildDocIdByName(resolver: ContentResolver, treeUri: Uri, parentDocId: String,
                                     name: String, directoryOnly: Boolean): String? {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocId)
        return try {
            resolver.query(
                childrenUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE
                ),
                null, null, null
            )?.use { cursor ->
                val idCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val nameCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val mimeCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                if (idCol < 0 || nameCol < 0) {
                    return null
                }
                var found: String? = null
                while (cursor.moveToNext()) {
                    if (cursor.getString(nameCol) != name) {
                        continue
                    }
                    val mime = if (mimeCol >= 0) cursor.getString(mimeCol) else ""
                    if (directoryOnly && mime != DocumentsContract.Document.MIME_TYPE_DIR) {
                        continue
                    }
                    found = cursor.getString(idCol)
                    break
                }
                found
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 删除 SAF 目录下与指定名称相同的既有文档（用于覆盖输出）。
     *
     * @param resolver    ContentResolver
     * @param treeUri     目录树 URI
     * @param parentDocId 父目录文档 ID
     * @param name        目标文档名
     */
    private fun deleteDocumentByName(resolver: ContentResolver, treeUri: Uri, parentDocId: String, name: String) {
        try {
            val docId = findChildDocIdByName(resolver, treeUri, parentDocId, name, false)
            if (docId != null) {
                val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                DocumentsContract.deleteDocument(resolver, docUri)
            }
        } catch (_: Exception) {
            // 查询或删除失败时忽略，交由创建阶段处理
        }
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
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 将 URI 内容拷贝到应用内部临时目录。
     *
     * <p>临时文件名保留原扩展名，否则后端按扩展名检测载体/格式（如隐写嵌入）会因
     * 无扩展名而失败。
     *
     * <p>使用 64 KiB 缓冲手动循环流式复制，大文件（如大 PNG）耗时明显低于
     * {@code copyTo} 默认的 8 KiB 缓冲。
     *
     * @return 拷贝后的临时文件路径，调用方负责在使用后清理
     */
    private fun copyToInternal(uri: Uri): String? {
        val tmpDir = File(context.filesDir, "crypto_tmp")
        tmpDir.mkdirs()
        val tmpFile = File(tmpDir, UUID.randomUUID().toString() + queryExtension(uri))
        return try {
            openInputStream(uri)?.use { input ->
                tmpFile.outputStream().use { output ->
                    copyStream(input, output)
                }
            }
            tmpFile.absolutePath
        } catch (e: Exception) {
            tmpFile.delete()
            null
        }
    }

    /**
     * 以 64 KiB 缓冲将输入流复制到输出流。
     *
     * @param input  输入流
     * @param output 输出流
     */
    private fun copyStream(input: InputStream, output: java.io.OutputStream) {
        val buffer = ByteArray(COPY_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) {
                break
            }
            if (read > 0) {
                output.write(buffer, 0, read)
            } else {
                // 个别流可能返回 0，逐字节读取避免死循环
                val one = input.read()
                if (one < 0) {
                    break
                }
                output.write(one)
            }
        }
    }

    /**
     * 查询 Uri 对应文件的扩展名（含 "." 前缀，小写）。
     *
     * <p>优先通过 {@link OpenableColumns#DISPLAY_NAME} 获取真实文件名，失败时回退到
     * {@link Uri#getLastPathSegment()}；无法确定时返回空字符串。
     *
     * @param uri 文件 Uri
     * @return 文件扩展名；无法确定时返回空字符串
     */
    private fun queryExtension(uri: Uri): String {
        val name = queryDisplayName(uri) ?: uri.lastPathSegment ?: return ""
        val dot = name.lastIndexOf('.')
        return if (dot >= 0) name.substring(dot).lowercase() else ""
    }

    /**
     * 查询 Uri 对应的显示名。
     *
     * @param uri 文件 Uri
     * @return 显示名；查询失败返回 null
     */
    private fun queryDisplayName(uri: Uri): String? {
        return try {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) cursor.getString(idx) else null
                } else {
                    null
                }
            }
        } catch (_: Exception) {
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
     * <p>使用 64 KiB 缓冲流式复制（见 {@link #copyStream}），大密钥文件同样受益。
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
                    copyStream(input, output)
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
                // 覆写后删除
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

    // ==================== 操作历史：打开输出文件夹 ====================

    /**
     * 打开操作历史记录对应的输出文件夹。
     *
     * <p>依次尝试（全程捕获异常，绝不抛出）：
     * <ol>
     *   <li>记录携带 SAF 目录树 URI 时，构建树根文档 URI 交给系统文件管理器；</li>
     *   <li>磁盘路径存在时，经 FileProvider 以目录形式打开；</li>
     *   <li>目录打开失败时，回退为打开输出文件本身。</li>
     * </ol>
     *
     * @param record 历史记录
     * @return 是否成功发起打开动作；文件夹不存在或无法打开时返回 false，由调用方给出友好提示
     */
    fun openOutputFolder(record: OperationRecord): Boolean {
        // 1. SAF 树 URI 优先（历史记录保存了用户选择的输出目录树）
        val treeUri = record.outputUri
        if (treeUri != null) {
            try {
                val tree = Uri.parse(treeUri)
                val docId = DocumentsContract.getTreeDocumentId(tree)
                val dirUri = DocumentsContract.buildDocumentUriUsingTree(tree, docId)
                if (startViewIntent(dirUri, DocumentsContract.Document.MIME_TYPE_DIR)) {
                    return true
                }
            } catch (_: Exception) {
                // SAF 权限失效等情况，回退到磁盘路径
            }
        }

        // 2. 磁盘路径：打开输出文件所在目录，失败则回退为打开文件本身
        val path = record.outputPath
        if (path != null) {
            val file = File(path)
            if (!file.exists()) {
                return false
            }
            val dir = if (file.isDirectory) file else file.parentFile
            if (dir != null && dir.exists()) {
                try {
                    val dirUri = FileProvider.getUriForFile(
                        context, "${context.packageName}.fileprovider", dir)
                    if (startViewIntent(dirUri, DocumentsContract.Document.MIME_TYPE_DIR)) {
                        return true
                    }
                } catch (_: Exception) {
                    // 目录 URI 打开失败，回退到打开文件本身
                }
            }
            try {
                val fileUri = FileProvider.getUriForFile(
                    context, "${context.packageName}.fileprovider", file)
                return startViewIntent(fileUri, "*/*")
            } catch (_: Exception) {
                return false
            }
        }
        return false
    }

    /**
     * 发起 ACTION_VIEW 查看意图。
     *
     * @param uri      目标 Uri
     * @param mimeType MIME 类型
     * @return 成功启动返回 true；无可用处理器或权限不足返回 false
     */
    private fun startViewIntent(uri: Uri, mimeType: String): Boolean {
        return try {
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, mimeType)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (intent.resolveActivity(context.packageManager) == null) {
                false
            } else {
                context.startActivity(intent)
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}
