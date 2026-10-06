package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 针对现有双端语料的高级分卷选项补充检查，可独立重跑。 */
@RunWith(AndroidJUnit4::class)
class SplitAdvancedTest {
    /** 两种生成端的诱饵密码均在 ART 校验和解密。 */
    @Test fun decoyBranchesOnArt() {
        if(InstrumentationRegistry.getArguments().getString("splitSlow")!="true")return
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        for(runtime in listOf("desktop","android")) {
            SplitInteropSupport.deniabilityDecoyRegression(File(context.filesDir,"split-interop/$runtime").toPath(),File(context.cacheDir,"split-extra-decoy-$runtime").toPath())
        }
    }

    /** 双端生成的双重可否认分卷，单字节 RS 损坏均可校验和解密恢复。 */
    @Test fun rsRecoveryInDualDecoyOnArt() {
        if(InstrumentationRegistry.getArguments().getString("splitSlow")!="true")return
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        for(runtime in listOf("desktop","android")) {
            SplitInteropSupport.deniabilityRsRecoveryRegression(File(context.filesDir,"split-interop/$runtime").toPath(),File(context.cacheDir,"split-extra-rs-decoy-$runtime").toPath())
        }
    }

    /** 原生只读目录、密钥无序、强制解密和 RS 损坏恢复。 */
    @Test fun forceUnorderedReadonlyAndRsOnArt() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        SplitInteropSupport.advancedOptionsRegression(File(context.cacheDir,"split-extra-advanced").toPath())
        SplitInteropSupport.readOnlySourceRegression(File(context.cacheDir,"split-extra-readonly").toPath())
        SplitInteropSupport.corruptionRegression(File(context.cacheDir,"split-extra-corruption").toPath())
        SplitInteropSupport.repeatedPasswordZipSplitRegression(File(context.cacheDir,"split-extra-repeat-zip").toPath())
    }
}
