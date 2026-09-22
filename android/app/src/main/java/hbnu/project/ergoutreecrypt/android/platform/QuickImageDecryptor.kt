package hbnu.project.ergoutreecrypt.android.platform

import android.content.ContentUris
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationType
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress
import kotlinx.coroutines.ensureActive
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import kotlin.coroutines.coroutineContext

/** 默认系统相册的 MediaStore 相对路径。 */
private const val DEFAULT_ALBUM_RELATIVE_PATH = "DCIM/Camera"

/**
 * 快速图片解密配置。
 *
 * @property albumTreeUri 自定义 SAF 相册目录；null 表示系统 DCIM/Camera
 * @property scanLimit 单次最多扫描图片数
 */
data class QuickDecryptConfig(
    val albumTreeUri: String?,
    val scanLimit: Int
)

/**
 * 快速图片解密完成报告。
 *
 * @property scanned 实际扫描图片数
 * @property decrypted 成功还原图片数
 * @property deleted 成功删除混淆图数
 * @property passwordProtected 跳过的密码保护图片数
 * @property unrelated 跳过的普通或非协议图片数
 * @property failed 解密或保存失败数
 * @property deleteFailed 已还原但源图删除失败数
 * @property failureNames 失败图片名摘要
 */
data class QuickDecryptReport(
    val scanned: Int,
    val decrypted: Int,
    val deleted: Int,
    val passwordProtected: Int,
    val unrelated: Int,
    val failed: Int,
    val deleteFailed: Int,
    val failureNames: List<String>
) {
    /**
     * 生成结果弹窗正文。
     *
     * @return 多行统计文本
     */
    fun summary(): String = buildString {
        append("扫描图片：$scanned 张")
        append("\n公开恢复并解密：$decrypted 张")
        append("\n已逐张删除混淆图：$deleted 张")
        append("\n忽略密码保护：$passwordProtected 张")
        append("\n跳过普通图片：$unrelated 张")
        append("\n解密或保存失败：$failed 张")
        if (deleteFailed > 0) {
            append("\n源图删除失败：$deleteFailed 张")
        }
        if (failureNames.isNotEmpty()) {
            append("\n\n失败文件：")
            failureNames.take(10).forEach { append("\n• $it") }
        }
    }
}

/**
 * Android 相册“公开恢复”图片的批量快速解密器。
 *
 * <p>每张图片单独完成认证、输出提交与源图删除，任何一张失败都不会影响之前已经提交的结果。
 *
 * @param context 应用上下文
 */
class QuickImageDecryptor(context: Context) {

    private val appContext = context.applicationContext
    private val fileOps = AndroidFileOps(appContext)
    private val codec = ImageCryptCodec()

    /**
     * 扫描配置相册并快速还原所有公开恢复图片。
     *
     * @param config 扫描配置
     * @param onProgress 已处理数量、总数量与当前文件名回调
     * @return 分类统计报告
     */
    suspend fun run(
        config: QuickDecryptConfig,
        onProgress: (processed: Int, total: Int, name: String) -> Unit
    ): QuickDecryptReport {
        val safeConfig = config.copy(scanLimit = config.scanLimit.coerceIn(1, 1000))
        val candidates = listCandidates(safeConfig)
        var decrypted = 0
        var deleted = 0
        var passwordProtected = 0
        var unrelated = 0
        var failed = 0
        var deleteFailed = 0
        val failureNames = mutableListOf<String>()

        candidates.forEachIndexed { index, candidate ->
            coroutineContext.ensureActive()
            onProgress(index, candidates.size, candidate.name)
            try {
                val input = fileOps.materializeImageInput(candidate.uri)
                if (input == null) {
                    failed++
                    failureNames.add(candidate.name)
                    return@forEachIndexed
                }
                var outputDir: File? = null
                try {
                    val metadata = KdfPreflight.peekImageMetadata(input.file.toPath())
                    if (metadata == null) {
                        unrelated++
                        return@forEachIndexed
                    }
                    if (metadata.requiresPassword()) {
                        passwordProtected++
                        return@forEachIndexed
                    }

                    outputDir = fileOps.createOutputTempDir()
                    val output = codec.decrypt(
                        input.file.toPath(),
                        outputDir.toPath(),
                        null,
                        false,
                        false,
                        ImageCryptProgress.NONE
                    )
                    if (!commitOutput(outputDir, safeConfig)) {
                        throw IllegalStateException("无法把还原图片写入相册")
                    }
                    decrypted++
                    HistoryService.record(
                        OperationType.IMAGE_DECRYPT,
                        output.fileName.toString(),
                        albumDescription(safeConfig),
                        safeConfig.albumTreeUri
                    )

                    val sourceDeleted = fileOps.deleteSource(
                        candidate.uri,
                        candidate.directPath,
                        safeConfig.albumTreeUri?.let(Uri::parse),
                        null
                    )
                    if (sourceDeleted) {
                        deleted++
                    } else {
                        deleteFailed++
                        failureNames.add("${candidate.name}（源图未删除）")
                    }
                } catch (_: Exception) {
                    failed++
                    failureNames.add(candidate.name)
                } finally {
                    fileOps.cleanupImageInput(input)
                    outputDir?.deleteRecursively()
                }
            } finally {
                onProgress(index + 1, candidates.size, candidate.name)
            }
        }

        return QuickDecryptReport(
            scanned = candidates.size,
            decrypted = decrypted,
            deleted = deleted,
            passwordProtected = passwordProtected,
            unrelated = unrelated,
            failed = failed,
            deleteFailed = deleteFailed,
            failureNames = failureNames.toList()
        )
    }

    /**
     * 按配置列出相册中的前若干张图片。
     *
     * @param config 扫描配置
     * @return 按最近修改时间降序排列的候选图片
     */
    private fun listCandidates(config: QuickDecryptConfig): List<Candidate> {
        return if (config.albumTreeUri.isNullOrBlank()) {
            listDefaultAlbum(config.scanLimit)
        } else {
            listTreeAlbum(Uri.parse(config.albumTreeUri), config.scanLimit)
        }
    }

    /**
     * 从默认系统相册列出图片。
     *
     * @param limit 最大数量
     * @return 候选图片
     */
    private fun listDefaultAlbum(limit: Int): List<Candidate> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            val directory = File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM),
                "Camera"
            )
            return directory.listFiles()
                ?.asSequence()
                ?.filter(File::isFile)
                ?.filter { isImageName(it.name) }
                ?.sortedByDescending(File::lastModified)
                ?.take(limit)
                ?.map { Candidate(Uri.fromFile(it), it.name, it.absolutePath) }
                ?.toList()
                ?: emptyList()
        }
        val resolver = appContext.contentResolver
        val collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        val projection = arrayOf(
            MediaStore.Images.Media._ID,
            MediaStore.Images.Media.DISPLAY_NAME
        )
        val result = mutableListOf<Candidate>()
        resolver.query(
            collection,
            projection,
            "${MediaStore.Images.Media.RELATIVE_PATH} LIKE ?",
            arrayOf("$DEFAULT_ALBUM_RELATIVE_PATH/%"),
            "${MediaStore.Images.Media.DATE_ADDED} DESC"
        )?.use { cursor ->
            val idIndex = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
            val nameIndex = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DISPLAY_NAME)
            while (cursor.moveToNext() && result.size < limit) {
                val uri = ContentUris.withAppendedId(collection, cursor.getLong(idIndex))
                result.add(Candidate(uri, cursor.getString(nameIndex) ?: "image", null))
            }
        }
        return result
    }

    /**
     * 从用户授权的 SAF 目录列出图片。
     *
     * @param treeUri 目录树 URI
     * @param limit 最大数量
     * @return 候选图片
     */
    private fun listTreeAlbum(treeUri: Uri, limit: Int): List<Candidate> {
        val resolver = appContext.contentResolver
        val treeId = DocumentsContract.getTreeDocumentId(treeUri)
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeId)
        val result = mutableListOf<TimedCandidate>()
        resolver.query(
            children,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED
            ),
            null,
            null,
            null
        )?.use { cursor ->
            val idIndex = cursor.getColumnIndexOrThrow(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID
            )
            val nameIndex = cursor.getColumnIndexOrThrow(
                DocumentsContract.Document.COLUMN_DISPLAY_NAME
            )
            val mimeIndex = cursor.getColumnIndexOrThrow(
                DocumentsContract.Document.COLUMN_MIME_TYPE
            )
            val modifiedIndex = cursor.getColumnIndex(
                DocumentsContract.Document.COLUMN_LAST_MODIFIED
            )
            while (cursor.moveToNext()) {
                val name = cursor.getString(nameIndex) ?: "image"
                val mime = cursor.getString(mimeIndex) ?: ""
                if (!mime.startsWith("image/") && !isImageName(name)) {
                    continue
                }
                val documentUri = DocumentsContract.buildDocumentUriUsingTree(
                    treeUri,
                    cursor.getString(idIndex)
                )
                val modified = if (modifiedIndex >= 0) cursor.getLong(modifiedIndex) else 0L
                result.add(TimedCandidate(Candidate(documentUri, name, null), modified))
            }
        }
        return result.sortedByDescending(TimedCandidate::modified)
            .take(limit)
            .map(TimedCandidate::candidate)
    }

    /**
     * 提交单张已还原图片到扫描来源相册。
     *
     * @param outputDir 单张输出暂存目录
     * @param config 扫描配置
     * @return 提交成功时返回 true
     */
    private fun commitOutput(outputDir: File, config: QuickDecryptConfig): Boolean {
        val customUri = config.albumTreeUri?.let(Uri::parse)
        if (customUri != null) {
            return fileOps.commitOutput(PendingOutput.Saf(customUri, outputDir))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return fileOps.commitOutput(
                PendingOutput.MediaStore(
                    DEFAULT_ALBUM_RELATIVE_PATH,
                    outputDir,
                    MediaStoreCollection.IMAGES
                )
            )
        }
        val targetDir = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM),
            "Camera"
        )
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            return false
        }
        return outputDir.listFiles()?.all { output ->
            val target = targetDir.toPath().resolve(output.name)
            Files.copy(output.toPath(), target, StandardCopyOption.REPLACE_EXISTING)
            fileOps.scanImageFile(target.toFile())
            true
        } == true
    }

    /**
     * 返回报告和历史记录使用的相册说明。
     *
     * @param config 扫描配置
     * @return 相册说明
     */
    private fun albumDescription(config: QuickDecryptConfig): String =
        config.albumTreeUri ?: DEFAULT_ALBUM_RELATIVE_PATH

    /**
     * 按扩展名判断文件是否可能是图片。
     *
     * @param name 文件名
     * @return 常见图片扩展名返回 true
     */
    private fun isImageName(name: String): Boolean {
        return name.substringAfterLast('.', "").lowercase() in setOf(
            "png", "jpg", "jpeg", "webp", "gif", "bmp"
        )
    }

    /**
     * 单张候选图片。
     *
     * @property uri 图片内容 URI
     * @property name 图片显示名称
     * @property directPath 旧版 Android 可直接删除的文件路径
     */
    private data class Candidate(val uri: Uri, val name: String, val directPath: String?)

    /**
     * 带修改时间的候选图片。
     *
     * @property candidate 候选图片
     * @property modified 最后修改时间戳
     */
    private data class TimedCandidate(val candidate: Candidate, val modified: Long)
}
