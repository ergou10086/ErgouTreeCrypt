package hbnu.project.ergoutreecrypt.android

import android.net.Uri
import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** 真实 ContentResolver 的 FAST 导出、已有内容保护、取消及失败回滚。 */
@RunWith(AndroidJUnit4::class)
class FastSafTest {
    /** SAF 测试提供者无真实路径列，必须经文档 API 完成事务。 */
    @Test fun exportAndRollback() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val resolver = context.contentResolver
        val control = resolver
        val base = Uri.parse("content://hbnu.project.ergoutreecrypt.fast.tests")
        val tree = DocumentsContract.buildTreeDocumentUri(base.authority, "root")
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, "root")
        val source = Files.createTempDirectory(context.cacheDir.toPath(), "fast-saf-").toFile()
        fun children(): List<String> = resolver.query(
            DocumentsContract.buildChildDocumentsUriUsingTree(tree, "root"),
            arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)!!.use { cursor ->
            val column = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            buildList { while (cursor.moveToNext()) add(cursor.getString(column)) }
        }
        control.call(base, "fast.reset", null, null)
        try {
            val input = source.resolve("中文🔐.bin").apply { writeText("真实 SAF 输入") }
            val cipher = source.resolve("中文🔐.bin.ergou")
            FastValidationBridge.encrypt(input, cipher, "测试密码")
            assertEquals(65536, FastValidationBridge.memory(cipher))
            assertEquals(false, FastValidationBridge.compressed(cipher))
            val existing = DocumentsContract.createDocument(resolver, parent, "application/octet-stream", cipher.name)!!
            resolver.openOutputStream(existing)!!.use { it.write("已有文件".toByteArray()) }
            assertTrue(FastValidationBridge.commit(context, tree, source, false))
            assertEquals("已有文件", resolver.openInputStream(existing)!!.bufferedReader().use { it.readText() })
            assertEquals(2, children().size)
            val session = children().single { it != cipher.name }
            val exported = DocumentsContract.buildDocumentUriUsingTree(tree, "root/$session/${cipher.name}")
            val downloaded = source.resolve("exported.fast")
            resolver.openInputStream(exported)!!.use { stream -> downloaded.outputStream().use { stream.copyTo(it) } }
            assertArrayEquals(cipher.readBytes(), downloaded.readBytes())
            val restored = source.resolve("restored.bin")
            FastValidationBridge.authenticateAndDecrypt(downloaded, restored, "测试密码")
            assertArrayEquals(input.readBytes(), restored.readBytes())
            val before = children().toSet()
            for (failure in listOf("fast.failWrite", "fast.failRename")) {
                control.call(base, failure, "true", null)
                assertFalse(FastValidationBridge.commit(context, tree, source, false))
                control.call(base, failure, "false", null)
                assertEquals(before, children().toSet())
            }
            assertFalse(FastValidationBridge.commit(context, tree, source, true))
            assertEquals(before, children().toSet())
        } finally {
            source.deleteRecursively()
            control.call(base, "fast.reset", null, null)
        }
    }
}
