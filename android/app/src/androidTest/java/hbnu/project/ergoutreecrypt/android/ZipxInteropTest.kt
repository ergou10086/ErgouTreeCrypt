package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor
import hbnu.project.ergoutreecrypt.fileops.ZipxArchive
import hbnu.project.ergoutreecrypt.fileops.ZipxInteropSupport
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException

/** Exchanges the same real file between desktop JVM and an actual Android ART process. */
@RunWith(AndroidJUnit4::class)
class ZipxInteropTest {
    /** Reads desktop artifacts, then produces and self-verifies Android artifacts. */
    @Test fun desktopToAndroidAndAndroidToAndroidThenExport() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.filesDir, "zipx-interop")
        val desktop = File(root, "desktop")
        assertTrue("Transfer the desktop corpus first", File(desktop, "manifest.properties").isFile)
        ZipxInteropSupport.verifyAll(desktop.toPath(), File(root, "desktop-on-android").toPath())
        ZipxInteropSupport.generate(File(root, "android").toPath(), File(desktop, "source.m4a").toPath(), true)
    }

    /** Independent fixtures validate codec/AES interoperability and failure handling on ART. */
    @Test fun independentFixturesAndFailuresOnArt() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = File(instrumentation.targetContext.cacheDir, "zipx-golden").apply { mkdirs() }
        val assets = instrumentation.context.assets
        var tested = 0
        for (name in assets.list("zipx/golden")!!.filter { it.endsWith(".zipx") }) {
            val archive = File(root, name)
            assets.open("zipx/golden/$name").use { input -> archive.outputStream().use { input.copyTo(it) } }
            val output = File(root, "out-$name")
            val password = if (name.contains("aes")) "reference-password" else null
            if (name.startsWith("unsupported-")) {
                try {
                    ArchiveExtractor.extract(archive.toPath(), output.toPath(), password)
                    fail("PPMd must report an unsupported method")
                } catch (error: IOException) { assertTrue(error.message!!.contains("98")) }
            } else {
                ZipxArchive.verify(archive.toPath(), password)
                val files = ArchiveExtractor.extract(archive.toPath(), output.toPath(), password)
                assertTrue(files.any { it.toFile().readBytes().contentEquals("Independent ZIPX reference\n".repeat(32).toByteArray()) })
                if (password != null) {
                    try { ZipxArchive.verify(archive.toPath(), "wrong"); fail("Wrong password accepted") }
                    catch (_: IOException) { }
                }
            }
            tested++
        }
        assertEquals("All independent fixtures must run on ART", 23, tested)
        val linkedOutput = File(root, "linked-output").apply { mkdirs() }
        val outside = File(root, "outside").apply { mkdirs() }
        val link = File(linkedOutput, "目录").toPath()
        java.nio.file.Files.createSymbolicLink(link, outside.toPath())
        try {
            ArchiveExtractor.extract(File(root, "python-store-zip64.zipx").toPath(), linkedOutput.toPath(), null)
            fail("Archive must not follow an entry-controlled destination symlink")
        } catch (_: IOException) {
            assertEquals(0, outside.listFiles()!!.size)
        } finally { java.nio.file.Files.deleteIfExists(link) }
    }
}
