package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.volume.FastInteropSupport
import java.nio.file.Files
import org.junit.Test
import org.junit.runner.RunWith

/** 在实际 ART 读取桌面产物并生产 Android 产物，覆盖两个读取方向的认证与解密。 */
@RunWith(AndroidJUnit4::class)
class FastInteropTest {
    /** 语料位置必须由脚本指定为应用私有目录中的独占子目录。 */
    @Test
    fun desktopToAndroidAndAndroidToAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val name = InstrumentationRegistry.getArguments().getString("fastRoot") ?: error("缺少语料目录")
        require(name.matches(Regex("fast-interop-[a-f0-9]{32}")))
        val root = instrumentation.targetContext.filesDir.toPath().resolve(name)
        val scratch = Files.createDirectory(root.resolve("scratch"))
        FastInteropSupport.verify(root.resolve("desktop"), root.resolve("desktop/ciphers"), scratch)
        FastInteropSupport.produce(root.resolve("desktop"), root.resolve("android"))
        FastInteropSupport.verify(root.resolve("desktop"), root.resolve("android"), scratch)
    }
}
