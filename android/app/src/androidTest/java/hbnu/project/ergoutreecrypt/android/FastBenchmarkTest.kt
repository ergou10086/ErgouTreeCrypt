package hbnu.project.ergoutreecrypt.android

import androidx.test.platform.app.InstrumentationRegistry
import java.nio.file.Files
import android.net.Uri
import android.provider.DocumentsContract
import org.junit.Test

/** 显式启用的实体机完整生产入口性能基准，普通回归不启动大型任务。 */
class FastBenchmarkTest {
    /** 原始真实文件由外部脚本放入本次独占目录；原始 CSV 由脚本取回。 */
    @Test fun productionTasks() {
        val arguments = InstrumentationRegistry.getArguments()
        require(arguments.getString("fastBenchmark") == "true")
        val name = arguments.getString("fastRoot") ?: error("缺少目录")
        require(name.matches(Regex("fast-benchmark-[a-f0-9]{32}")))
        val root = InstrumentationRegistry.getInstrumentation().targetContext.filesDir.toPath().resolve(name)
        val source = root.resolve("source.bin")
        if (arguments.getString("large") == "true") {
            FastValidationBridge.large(source.toFile(), root.resolve("results").toFile())
            return
        }
        val input = root.resolve("input.bin")
        val repeat = arguments.getString("repeat")?.toInt() ?: 20
        require(repeat in 1..100)
        Files.newOutputStream(input).use { output ->
            repeat(repeat) { Files.newInputStream(source).use { it.copyTo(output, 1024 * 1024) } }
        }
        try {
            FastValidationBridge.benchmark(input.toFile(), root.resolve("results").toFile())
            exportBenchmark(input.toFile(), root.resolve("results").toFile())
        }
        finally { Files.deleteIfExists(input) }
    }

    /** @param input 完整真实输入 @param results CSV 结果目录 */
    private fun exportBenchmark(input: java.io.File, results: java.io.File) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val resolver = context.contentResolver
        val base = Uri.parse("content://hbnu.project.ergoutreecrypt.fast.tests")
        val tree = DocumentsContract.buildTreeDocumentUri(base.authority, "root")
        val source = java.io.File(input.parentFile, "export-source").apply { check(mkdir()) }
        val cipher = java.io.File(source, "benchmark.ergou")
        fun hash(stream: java.io.InputStream): ByteArray = stream.use {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(1024 * 1024)
            while (true) { val n = it.read(buffer); if (n < 0) break; digest.update(buffer, 0, n) }
            digest.digest()
        }
        try {
            FastValidationBridge.encrypt(input, cipher, "导出基准🔐")
            val expected = hash(cipher.inputStream())
            java.io.File(results, "saf-export.csv").bufferedWriter().use { csv ->
                csv.write("round,bytes,nanos,provider\n")
                for (round in 1..3) {
                    resolver.call(base, "fast.reset", null, null)
                    val started = System.nanoTime()
                    check(FastValidationBridge.commit(context, tree, source, false))
                    val elapsed = System.nanoTime() - started
                    val childUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, "root")
                    val session = resolver.query(childUri, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID), null, null, null)!!.use {
                        check(it.moveToFirst()); it.getString(0)
                    }
                    val exported = DocumentsContract.buildDocumentUriUsingTree(tree, "$session/${cipher.name}")
                    check(expected.contentEquals(hash(resolver.openInputStream(exported)!!)))
                    csv.write("$round,${cipher.length()},$elapsed,test-contract-provider\n")
                    csv.flush()
                }
            }
        } finally {
            source.deleteRecursively()
            resolver.call(base, "fast.reset", null, null)
        }
    }
}
