package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.keyfile.KeyfileBatchInteropSupport
import hbnu.project.ergoutreecrypt.keyfile.KeyfileInteropSupport
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 真实 ART 的目录串并行与深度互通。 */
@RunWith(AndroidJUnit4::class)
class KeyfileBatchInteropTest {
    /** 认证桌面目录产物，生成本端产物并自读，再交还桌面。 */
    @Test fun eightDirectionBridge() {
        val name = InstrumentationRegistry.getArguments().getString("keyfileRoot")!!
        require(name.matches(Regex("keyfile-interop-[a-f0-9]{32}")))
        val root = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, name).toPath()
        val temporary = java.nio.file.Files.createDirectories(root.resolve("tmp"))
        System.setProperty("java.io.tmpdir", temporary.toString())
        val scratch = root.resolve("scratch")
        assertEquals(12, KeyfileBatchInteropSupport.verify(root.resolve("corpus"), root.resolve("desktop"), scratch))
        KeyfileInteropSupport.delete(scratch)
        val profiles = InstrumentationRegistry.getArguments().getString("keyfileProfiles") != "false"
        assertEquals(12, KeyfileBatchInteropSupport.produce(root.resolve("corpus"), root.resolve("android"), true, profiles))
        assertEquals(12, KeyfileBatchInteropSupport.verify(root.resolve("corpus"), root.resolve("android"), scratch))
        KeyfileInteropSupport.delete(scratch)
    }
}
