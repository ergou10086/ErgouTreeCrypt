package hbnu.project.ergoutreecrypt.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import hbnu.project.ergoutreecrypt.android.ui.screen.EncryptScreen
import hbnu.project.ergoutreecrypt.i18n.Messages
import org.junit.Rule
import org.junit.Test

/** 实际 Compose 配置切换；标准配置在 FAST 任务中禁用，返回时恢复。 */
class FastModeUiTest {
    @get:Rule val compose = createComposeRule()

    /** 对同一界面的真实复选框执行切换与恢复。 */
    @Test fun standardOptionsAreRestored() {
        compose.setContent { MaterialTheme { EncryptScreen() } }
        compose.onNodeWithText("高级选项").performScrollTo().performClick()
        val rs = compose.onNodeWithContentDescription("Reed-Solomon 纠错（抗损坏，体积略增）")
        rs.performScrollTo()
        if (!rs.isOn()) rs.performClick()
        rs.assertIsOn()
        val fast = compose.onNodeWithContentDescription(Messages.get("options.fast"))
        fast.performScrollTo().performClick()
        rs.assertIsOff().assertIsNotEnabled()
        fast.performClick()
        rs.assertIsOn().assertIsEnabled()
    }

    /** @return 节点是否已选中 */
    private fun SemanticsNodeInteraction.isOn(): Boolean =
        fetchSemanticsNode().config[androidx.compose.ui.semantics.SemanticsProperties.ToggleableState] ==
            androidx.compose.ui.state.ToggleableState.On
}
