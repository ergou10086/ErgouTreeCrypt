package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.keyfile.KeyfileInteropSupport
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 实际 ART 分别认证、解密桌面和 Android 生产端的相同密文。 */
@RunWith(AndroidJUnit4::class)
class KeyfileInteropTest {
    /** 本次独占设备目录由入口脚本传入，禁止操作应用原有数据。 */
    @Test fun eightDirectionBridge() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val name = arguments.getString("keyfileRoot") ?: error("缺少测试目录")
        require(name.matches(Regex("keyfile-interop-[a-f0-9]{32}")))
        val root = File(instrumentation.targetContext.filesDir, name).toPath()
        val slow = arguments.getString("keyfileSlow") == "true"
        val temporary = root.resolve("tmp")
        java.nio.file.Files.createDirectories(temporary)
        System.setProperty("java.io.tmpdir", temporary.toString())
        val scratch = root.resolve("scratch")
        assertEquals(if (slow) 172 else 164, KeyfileInteropSupport.verify(root.resolve("corpus"), root.resolve("desktop"), scratch))
        KeyfileInteropSupport.delete(scratch)
        val count = KeyfileInteropSupport.produce(root.resolve("corpus"), root.resolve("android"), true, slow)
        assertEquals(if (slow) 172 else 164, count)
        assertEquals(count, KeyfileInteropSupport.verify(root.resolve("corpus"), root.resolve("android"), scratch))
        KeyfileInteropSupport.delete(scratch)
    }
}
