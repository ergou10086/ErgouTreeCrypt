package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.Lz4InteropSupport
import org.junit.Test
import org.junit.Assert.assertTrue
import org.junit.runner.RunWith
import java.io.File

/** Runs on ART. adb pushes desktop artifacts, then pulls mobile artifacts for JVM verification. */
@RunWith(AndroidJUnit4::class)
class Lz4InteropTest {
    @Test fun desktopToAndroidAndAndroidToAndroidThenExport() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.filesDir, "lz4-interop")
        val desktop = File(root, "desktop")
        assertTrue("Push target/lz4-interop/desktop to ${desktop.absolutePath} first", File(desktop, "manifest.properties").isFile)
        Lz4InteropSupport.verifyAll(desktop.toPath(), File(root, "desktop-on-android").toPath())
        Lz4InteropSupport.generate(File(root, "android").toPath(), File(desktop, "source.m4a").toPath(), true)
    }
    @Test fun referenceFramesAndCorruptionAreValidatedOnArt() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = File(instrumentation.targetContext.cacheDir, "lz4-reference-tests").apply { mkdirs() }
        val assets = instrumentation.context.assets
        val payload = assets.open("lz4/golden/payload.txt").use { it.readBytes() }
        for (name in listOf("independent", "linked-k64", "block-checksum", "empty", "concatenated", "reference.tar")) {
            val archive = File(root, "$name.lz4")
            assets.open("lz4/golden/$name.lz4").use { input -> archive.outputStream().use { input.copyTo(it) } }
            val dest = File(root, "out-$name")
            val files = hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor.extract(archive.toPath(), dest.toPath(), null)
            when(name) {
                "reference.tar" -> {
                    org.junit.Assert.assertEquals(2, files.size)
                    org.junit.Assert.assertArrayEquals(payload, File(dest, "目录/payload.txt").readBytes())
                }
                "empty" -> org.junit.Assert.assertEquals(0L, files[0].toFile().length())
                "linked-k64", "concatenated" -> {
                    val expected = java.io.ByteArrayOutputStream()
                    repeat(if (name == "linked-k64") 100 else 2) { expected.write(payload) }
                    org.junit.Assert.assertArrayEquals(expected.toByteArray(), files[0].toFile().readBytes())
                }
                else -> org.junit.Assert.assertArrayEquals(payload, files[0].toFile().readBytes())
            }
            if (name == "independent" || name == "reference.tar") {
                for (truncated in listOf(false,true)) {
                    val bytes = archive.readBytes()
                    val damaged = if (truncated) bytes.copyOf(bytes.size - 3) else bytes.apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
                    val bad = File(root, "bad-$truncated-$name.lz4").apply { writeBytes(damaged) }
                    val badOut = File(root, "bad-out-$truncated-$name")
                    try {
                        hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor.extract(bad.toPath(), badOut.toPath(), null)
                        org.junit.Assert.fail("Corrupt LZ4 frame must fail")
                    } catch (_: java.io.IOException) {
                        org.junit.Assert.assertEquals(0, badOut.listFiles()!!.size)
                    }
                }
            }
        }
    }
}
