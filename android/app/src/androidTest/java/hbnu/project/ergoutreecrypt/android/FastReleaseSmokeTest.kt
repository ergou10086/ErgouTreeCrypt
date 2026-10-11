package hbnu.project.ergoutreecrypt.android

import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test

/** 实际启动经过 R8 的候选应用主页。 */
class FastReleaseSmokeTest {
    /** 启动与资源加载必须完成，窗口须已装配内容。 */
    @Test fun startsPackagedActivity() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                assertNotNull(activity.window.decorView)
                assertFalse(activity.isFinishing)
            }
        }
    }
}
