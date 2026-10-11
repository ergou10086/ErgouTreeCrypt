package hbnu.project.ergoutreecrypt.android.platform

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File
import java.io.IOException
import java.util.UUID

/**
 * 在独占 SAF 目录内导出完整任务，失败时只删除本次创建的目录。
 *
 * SAF 不提供通用的原子不覆盖替换；每次导出使用随机新目录保护已有内容。
 * @param context 提供文档解析器的上下文
 */
class FastSafOutput(private val context: Context) {
    /**
     * 全部写入并关闭成功后，将本次目录移除 incomplete 后缀。
     * @param tree 用户授权的目标目录树
     * @param source 本次私有输出目录
     * @param cancelled 导出取消状态
     * @return 是否完整提交
     */
    fun commit(tree: Uri, source: File, cancelled: () -> Boolean = { false }): Boolean {
        val resolver = context.contentResolver
        var owned: Uri? = null
        return try {
            val files = source.listFiles() ?: throw IOException("无法读取导出目录")
            check(files.isNotEmpty()) { "没有待导出的文件" }
            val parent = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
            val name = "ErgouTreeCrypt-${UUID.randomUUID()}"
            owned = DocumentsContract.createDocument(resolver, parent,
                DocumentsContract.Document.MIME_TYPE_DIR, "$name.incomplete")
                ?: throw IOException("无法创建导出目录")
            for (file in files) copy(owned, file, cancelled)
            check(!cancelled()) { "导出已取消" }
            owned = DocumentsContract.renameDocument(resolver, owned, name)
                ?: throw IOException("文档提供者不支持完成提交")
            true
        } catch (_: Exception) {
            owned?.let { runCatching { DocumentsContract.deleteDocument(resolver, it) } }
            false
        }
    }

    /**
     * 仅向本次目录创建新条目，逐块响应取消，关闭失败也触发整次回滚。
     * @param parent 本次创建的父目录
     * @param source 源文件或目录
     * @param cancelled 取消状态
     */
    private fun copy(parent: Uri, source: File, cancelled: () -> Boolean) {
        check(!cancelled()) { "导出已取消" }
        val resolver = context.contentResolver
        val target = DocumentsContract.createDocument(resolver, parent,
            if (source.isDirectory) DocumentsContract.Document.MIME_TYPE_DIR else "application/octet-stream",
            source.name) ?: throw IOException("无法创建导出条目")
        if (source.isDirectory) {
            for (child in source.listFiles() ?: throw IOException("无法读取子目录")) copy(target, child, cancelled)
        } else {
            val output = resolver.openOutputStream(target) ?: throw IOException("无法打开导出条目")
            output.use { out ->
                source.inputStream().use { input ->
                    val buffer = ByteArray(256 * 1024)
                    while (true) {
                        check(!cancelled()) { "导出已取消" }
                        val count = input.read(buffer)
                        if (count < 0) break
                        out.write(buffer, 0, count)
                    }
                }
            }
        }
    }
}
