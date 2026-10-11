package hbnu.project.ergoutreecrypt.android

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.junit.Test
import org.junit.runner.RunWith

/** 非调试 R8 验收包的独占语料搬运入口，不需要 run-as 或放宽生产包权限。 */
@RunWith(AndroidJUnit4::class)
class FastTransferTest {
    /** 只允许脚本创建的随机 FAST 目录，并校验 ZIP 路径不越界。 */
    @Test
    fun transfer() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val relative = args.getString("transferPath") ?: error("缺少目录")
        val parts = relative.split('/')
        require(parts.size in 2..3 && parts[0] == "files")
        val name = parts[1]
        require(name.matches(Regex("fast-(interop|benchmark)-[a-f0-9]{32}")))
        if (parts.size == 3) require(parts[2] in setOf("desktop", "android", "results"))
        val base = File(instrumentation.targetContext.filesDir, name)
        val target = if (parts.size == 3) File(base, parts[2]) else base
        val resolver = instrumentation.targetContext.contentResolver
        val relay = Uri.parse("content://hbnu.project.ergoutreecrypt.fast.tests/relay/$name.zip")
        when (args.getString("transferOperation")) {
            "upload" -> {
                check(!target.exists() && target.mkdirs())
                resolver.openInputStream(relay)!!.use { input ->
                    ZipInputStream(input.buffered()).use { zip ->
                        while (true) {
                            val entry = zip.nextEntry ?: break
                            val output = File(target, entry.name).canonicalFile
                            require(output.path.startsWith(target.canonicalPath + File.separator))
                            if (entry.isDirectory) check(output.mkdirs() || output.isDirectory)
                            else {
                                output.parentFile!!.mkdirs()
                                output.outputStream().use { zip.copyTo(it) }
                            }
                            zip.closeEntry()
                        }
                    }
                }
                resolver.delete(relay, null, null)
            }
            "download" -> {
                check(target.isDirectory)
                resolver.openOutputStream(relay, "wt")!!.use { output ->
                    ZipOutputStream(output.buffered()).use { zip ->
                        target.walkTopDown().filter { it.isFile }.forEach { file ->
                            zip.putNextEntry(ZipEntry(file.relativeTo(target).invariantSeparatorsPath))
                            file.inputStream().use { it.copyTo(zip) }
                            zip.closeEntry()
                        }
                    }
                }
            }
            "cleanup" -> {
                check(!base.exists() || base.deleteRecursively())
                resolver.delete(relay, null, null)
            }
            else -> error("未知搬运操作")
        }
    }
}
