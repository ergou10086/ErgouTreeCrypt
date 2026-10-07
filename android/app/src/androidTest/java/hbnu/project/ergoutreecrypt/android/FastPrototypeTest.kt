package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import hbnu.project.ergoutreecrypt.volume.FastPrototypeSupport
import hbnu.project.ergoutreecrypt.volume.FastGoldenSupport
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith

/** 在 APK 的真实 ART 环境执行 P0 完整流原型，不能由宿主 JVM 测试代替。 */
@RunWith(AndroidJUnit4::class)
class FastPrototypeTest {
    /** 同时验证 AES128、AES256、RAW 输出、AAD、截断和尾随数据。 */
    @Test
    fun officialStreamingPrimitiveWorksOnArt() { FastPrototypeSupport.smoke() }

    /** 使用 APK 内同一黄金向量核对实际 ART 的 KDF、头、认证及完整流。 */
    @Test
    fun independentGoldenVectorWorksOnArt() {
        InstrumentationRegistry.getInstrumentation().context.assets.open("fast/v1/golden.properties").use {
            FastGoldenSupport.verify(it)
        }
    }
}
