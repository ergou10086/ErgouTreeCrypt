package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 在已有真实 ART 语料上续跑，避免中断后重复所有加密计算。 */
@RunWith(AndroidJUnit4::class)
class SplitResumeTest {
    /** 重写密码 ZIP 后分别读取两端完整语料，再检查原生目录矩阵。 */
    @Test fun resumeRealCorpusOnArt() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val root=File(context.filesDir,"split-interop")
        SplitInteropSupport.repairPasswordZipCases(File(root,"android").toPath())
        for(runtime in listOf("desktop","android")) {
            assertEquals(40,SplitInteropSupport.verifyAll(File(root,runtime).toPath(),File(context.cacheDir,"split-resume-$runtime").toPath()))
        }
        assertEquals(18,SplitInteropSupport.directoryRegression(File(context.cacheDir,"split-resume-folders").toPath()))
    }
}
