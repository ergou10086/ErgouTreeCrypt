package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport
import hbnu.project.ergoutreecrypt.fileops.Splitter
import hbnu.project.ergoutreecrypt.volume.FolderCrypt
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.nio.file.Files

/** 在 ART 中读取桌面真实分卷，并生成手机分卷供桌面互解和认证。 */
@RunWith(AndroidJUnit4::class)
class SplitInteropTest {
    /** 电脑 → 手机、手机 → 手机的校验和解密，导出手机加密结果。 */
    @Test fun desktopOnArtAndArtOnArtThenExport() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val root=File(context.filesDir,"split-interop")
        val desktop=File(root,"desktop")
        assertTrue(File(desktop,"manifest.properties").isFile)
        assertTrue(SplitInteropSupport.verifyAll(desktop.toPath(),File(root,"desktop-on-android").toPath())>=38)
        val slow=InstrumentationRegistry.getArguments().getString("splitSlow")=="true"
        val count=SplitInteropSupport.generate(File(root,"android").toPath(),File(desktop,"source.bin").toPath(),true,slow)
        assertEquals(count,SplitInteropSupport.verifyAll(File(root,"android").toPath(),File(root,"android-self").toPath()))
        if(slow)for(runtime in listOf("desktop","android")) {
            SplitInteropSupport.deniabilityDecoyRegression(File(root,runtime).toPath(),File(context.cacheDir,"split-decoy-$runtime").toPath())
        }
    }

    /** ART 的深目录、串并行及归档分卷回归。 */
    @Test fun folderDepthAndParallelOptionsOnArt() {
        val root=File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,"split-folders")
        assertEquals(18,SplitInteropSupport.directoryRegression(root.toPath()))
        SplitInteropSupport.readOnlySourceRegression(File(root.parentFile,"split-readonly").toPath())
    }

    /** 实际 ART 中的 RS 修复、密钥文件重试和普通损坏拒绝。 */
    @Test fun rsRecoveryAndCorruptionOnArt() {
        val root=File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,"split-corruption")
        SplitInteropSupport.corruptionRegression(root.toPath())
        SplitInteropSupport.advancedOptionsRegression(File(root.parentFile,"split-advanced").toPath())
    }

    /** ART 的空文件、缺首中末卷、同名完整文件与源目录清单检查。 */
    @Test fun completenessAndMissingVolumesOnArt() {
        val root=File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,"split-edge").apply{mkdirs()}
        for(size in listOf(0,1,1023,1024,1025,2050)) {
            val base=File(root,"edge-$size.pcv").toPath()
            val bytes=ByteArray(size){(it%251).toByte()};Files.write(base,bytes)
            Splitter.split(base,1024)
            assertTrue(Splitter.inspect(base).totalKnown())
            val merged=File(root,"merged-$size").toPath();Splitter.recombine(merged,base.toString())
            assertArrayEquals(bytes,Files.readAllBytes(merged))
        }
        for(index in 0..2) {
            val folder=File(root,"missing-$index").apply{mkdirs()}
            val base=File(folder,"same.ergou").toPath();Files.write(base,ByteArray(2050));Splitter.split(base,1024);Files.delete(base)
            Files.delete(File(folder,"same.ergou.$index").toPath())
            assertEquals("same.ergou",FolderCrypt.detectChunkBase(folder.toPath()))
            assertEquals(listOf(index),Splitter.inspect(base).missing())
            val output=File(root,"keep-$index").apply{writeText("keep")}
            try{Splitter.recombine(output.toPath(),base.toString());fail("Missing chunk accepted")}
            catch(e:IOException){assertTrue(e.message!!.contains(".$index"))}
            assertEquals("keep",output.readText())
        }
    }
}
