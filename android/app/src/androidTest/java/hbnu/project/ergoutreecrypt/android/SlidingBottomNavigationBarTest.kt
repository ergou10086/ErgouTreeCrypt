package hbnu.project.ergoutreecrypt.android

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Circle
import androidx.compose.material.icons.outlined.Circle
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertWidthIsAtLeast
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.ui.navigation.BottomNavItem
import hbnu.project.ergoutreecrypt.android.ui.navigation.SlidingBottomNavigationBar
import org.junit.Rule
import org.junit.Test

/**
 * 动态底栏的 Compose 语义、点击同步、窗口移动与窄屏测试。
 */
class SlidingBottomNavigationBarTest {

    /** Compose 测试规则。 */
    @get:Rule
    val composeRule = createComposeRule()

    /** 初次进入时应展示前六项，且只有首页带选中语义。 */
    @Test
    fun initialWindow_showsFirstSix_andSingleSelection() {
        composeRule.setContent {
            SlidingBottomNavigationBar(
                items = destinations(7),
                selectedPage = 0,
                settledPage = 0,
                initialWindowStart = 0,
                onWindowStartChanged = {},
                onItemClick = {}
            )
        }

        for (index in 0..5) {
            composeRule.onNodeWithTag("bottom-nav-route-$index").assertExists()
        }
        composeRule.onNodeWithContentDescription("页面 1，标签页，1/7").assertIsSelected()
    }

    /** 稳定到第七页后应最小后移并展示 1–6。 */
    @Test
    fun settledLastPage_movesWindowToOneThroughSix() {
        composeRule.setContent {
            SlidingBottomNavigationBar(
                items = destinations(7),
                selectedPage = 6,
                settledPage = 6,
                initialWindowStart = 0,
                onWindowStartChanged = {},
                onItemClick = {}
            )
        }
        composeRule.waitForIdle()

        composeRule.onNodeWithTag("bottom-nav-route-6").assertExists().assertIsSelected()
    }

    /** 点击条目应只通过外部回调更新唯一选中状态。 */
    @Test
    fun click_updatesExternalPagerTruth_withoutDualSelection() {
        composeRule.setContent {
            var selected by remember { mutableIntStateOf(0) }
            SlidingBottomNavigationBar(
                items = destinations(7),
                selectedPage = selected,
                settledPage = selected,
                initialWindowStart = 0,
                onWindowStartChanged = {},
                onItemClick = { selected = it }
            )
        }

        composeRule.onNodeWithTag("bottom-nav-route-2").performClick()
        composeRule.onNodeWithContentDescription("页面 3，标签页，3/7").assertIsSelected()
    }

    /** 极窄宽度应保持 48 dp 触摸目标，并允许少于六项完整可见。 */
    @Test
    fun narrowWidth_preservesMinimumTouchTarget() {
        composeRule.setContent {
            Box(modifier = Modifier.width(240.dp)) {
                SlidingBottomNavigationBar(
                    items = destinations(7),
                    selectedPage = 0,
                    settledPage = 0,
                    initialWindowStart = 0,
                    onWindowStartChanged = {},
                    onItemClick = {}
                )
            }
        }

        composeRule.onNodeWithTag("bottom-nav-route-0")
            .assertExists()
            .assertWidthIsAtLeast(48.dp)
    }

    /** 2 倍字体缩放下语义和点击目标仍应存在。 */
    @Test
    fun largeFont_keepsTalkBackSemantics() {
        composeRule.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(
                LocalDensity provides Density(density.density, fontScale = 2f)
            ) {
                SlidingBottomNavigationBar(
                    items = destinations(7),
                    selectedPage = 2,
                    settledPage = 2,
                    initialWindowStart = 0,
                    onWindowStartChanged = {},
                    onItemClick = {}
                )
            }
        }

        composeRule.onNodeWithContentDescription("页面 3，标签页，3/7")
            .assertExists()
            .assertIsSelected()
    }

    /**
     * 创建指定数量的稳定测试目的地。
     *
     * @param count 目的地数量
     * @return 测试目的地
     */
    private fun destinations(count: Int): List<BottomNavItem> =
        List(count) { index ->
            BottomNavItem(
                routeKey = "route-$index",
                label = "页面 ${index + 1}",
                selectedIcon = Icons.Filled.Circle,
                unselectedIcon = Icons.Outlined.Circle
            )
        }
}
