package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport
import hbnu.project.ergoutreecrypt.fileops.SplitMetadataSupport
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 传统随机伪装分卷的清单回退，独立追加八方向，保留前一轮已通过的内嵌结果。 */
@RunWith(AndroidJUnit4::class)
class SplitLegacyFallbackTest {
    /** 电脑 → ART、ART → ART 的认证和解密，以及缺首中末和全部卷的拒绝。 */
    @Test fun manifestFallbackAcrossRuntimes() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val root=File(context.filesDir,"split-legacy-fallback")
        val desktop=File(root,"desktop")
        assertEquals(1,SplitInteropSupport.verifyAll(desktop.toPath(),File(root,"desktop-on-art").toPath()))
        assertEquals(4,SplitMetadataSupport.legacyMissing(desktop.toPath(),File(root,"desktop-missing").toPath()))
        val android=File(root,"android")
        assertEquals(1,SplitInteropSupport.generateLegacyFallback(android.toPath(),File(desktop,"sample.bin").toPath(),true))
        assertEquals(1,SplitInteropSupport.verifyAll(android.toPath(),File(root,"android-self").toPath()))
        assertEquals(4,SplitMetadataSupport.legacyMissing(android.toPath(),File(root,"android-missing").toPath()))
    }
}
