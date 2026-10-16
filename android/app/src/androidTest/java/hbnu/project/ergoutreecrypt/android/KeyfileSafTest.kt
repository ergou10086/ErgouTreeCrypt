package hbnu.project.ergoutreecrypt.android

import android.net.Uri
import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.keyfile.KeyfileInteropSupport
import hbnu.project.ergoutreecrypt.volume.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 通过真实 ContentResolver 读取密钥，验证私有副本和权限失败行为。 */
@RunWith(AndroidJUnit4::class)
class KeyfileSafTest {
    /** 单个 56.55 MB 密钥也必须流式复制且不改变内容，安全副本可与桌面原文件互换。 */
    @Test fun copiesRealKeyfilesAndUsesTheirContents() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val name = InstrumentationRegistry.getArguments().getString("keyfileRoot")!!
        require(name.matches(Regex("keyfile-interop-[a-f0-9]{32}")))
        val root = File(context.filesDir, name)
        val resolver = context.contentResolver
        val tree = DocumentsContract.buildTreeDocumentUri("hbnu.project.ergoutreecrypt.fast.tests", "root")
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, "root")
        val directory = DocumentsContract.createDocument(resolver, parent, DocumentsContract.Document.MIME_TYPE_DIR, name)!!
        val copies = mutableListOf<File>()
        val sources = listOf("key-a", "key-b", "real.m4a").map { File(root, "corpus/$it") }
        val operations = AndroidFileOps(context)
        try {
            for (source in sources) {
                val document = DocumentsContract.createDocument(resolver, directory, "application/octet-stream", source.name)!!
                resolver.openOutputStream(document)!!.use { output -> source.inputStream().use { it.copyTo(output) } }
                val path = operations.copyKeyfileToSecureArea(document) ?: error("密钥安全副本创建失败")
                val copy = File(path)
                copies.add(copy)
                assertNotEquals(source.name, copy.name)
                assertEquals(KeyfileInteropSupport.sha256(source.toPath()), KeyfileInteropSupport.sha256(copy.toPath()))
            }
            val source = File(root, "corpus/sample.bin")
            val cipher = File(root, "saf.ergou")
            val request = EncryptRequest().apply {
                inputFile = source.path; outputFile = cipher.path; password = ""
                keyfiles = copies.map { it.path }; setKeyfileOrdered(true); rsCodecs = RsCodecs()
                argon2MemoryKib = 4096; argon2Passes = 1; argon2Threads = 2
            }
            Encryptor.encrypt(request)
            val verify = VerifyRequest().apply {
                inputFile = cipher.path; password = ""; keyfiles = sources.map { it.path }; rsCodecs = RsCodecs()
            }
            assertTrue(Verifier.verify(verify))
            val restored = File(root, "saf-restored")
            Decryptor.decrypt(DecryptRequest().apply {
                inputFile = cipher.path; outputFile = restored.path; password = ""
                keyfiles = verify.keyfiles; rsCodecs = RsCodecs()
            })
            assertArrayEquals(source.readBytes(), restored.readBytes())
            assertEquals(KeyfileInteropSupport.sha256(source.toPath()), KeyfileInteropSupport.sha256(restored.toPath()))
        } finally {
            copies.forEach { assertTrue(it.delete()) }
            assertTrue(DocumentsContract.deleteDocument(resolver, directory))
        }
    }

    /** 权限被拒绝时不得返回不存在的路径或遗留部分密钥副本。 */
    @Test fun deniedStreamReturnsFailureWithoutPhantomPath() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.filesDir, "keyfiles")
        val before = directory.list()?.toSet() ?: emptySet()
        val denied = DocumentsContract.buildDocumentUri("hbnu.project.ergoutreecrypt.fast.tests", "root/keyfile-denied")
        assertNull(AndroidFileOps(context).copyKeyfileToSecureArea(denied))
        assertEquals(before, directory.list()?.toSet() ?: emptySet<String>())
    }
}
