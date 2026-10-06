package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport
import hbnu.project.ergoutreecrypt.fileops.SplitMetadataSupport
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 内嵌元数据迁移的 ART 互操作，分别覆盖认证与解密，不重跑先前完整矩阵。 */
@RunWith(AndroidJUnit4::class)
class SplitMetadataTest {
    /** 电脑 → Android、Android → Android 两组认证与解密，并导出真实 Android 生成的分卷。 */
    @Test fun desktopOnArtAndArtOnArt() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val root=File(context.filesDir,"split-metadata")
        val desktop=File(root,"desktop")
        assertTrue(File(desktop,"manifest.properties").isFile)
        assertTrue(SplitInteropSupport.verifyAll(desktop.toPath(),File(root,"desktop-on-android").toPath())>=10)
        assertEquals(20,SplitMetadataSupport.mutations(desktop.toPath(),File(root,"desktop-mutated").toPath()))
        val slow=InstrumentationRegistry.getArguments().getString("splitSlow")=="true"
        val android=File(root,"android")
        val count=SplitInteropSupport.generateMetadata(android.toPath(),File(desktop,"source.bin").toPath(),true,slow)
        assertEquals(count,SplitInteropSupport.verifyAll(android.toPath(),File(root,"android-self").toPath()))
        assertEquals(20,SplitMetadataSupport.mutations(android.toPath(),File(root,"android-mutated").toPath()))
    }
    /** 实际 ART 的空文件、边界、极小卷、重分卷和随机批次标识。 */
    @Test fun metadataBoundariesOnArt() {
        val root=File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,"split-metadata-boundaries")
        assertEquals(23,SplitMetadataSupport.boundaries(root.toPath()))
    }
}
