package hbnu.project.ergoutreecrypt.android.ui.navigation

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 动态底栏最小窗口算法测试。
 */
class NavigationWindowTest {

    /** 七项中选择前六项时窗口应保持 0–5。 */
    @Test
    fun sevenItems_firstSix_keepInitialWindow() {
        for (page in 0..5) {
            assertEquals(0, nextWindowStart(page, 0, 7))
        }
    }

    /** 七项中进入末页后窗口应最小后移为 1–6。 */
    @Test
    fun sevenItems_lastPage_movesOneItem() {
        assertEquals(1, nextWindowStart(6, 0, 7))
    }

    /** 从后移窗口返回首页时窗口应复位。 */
    @Test
    fun sevenItems_returnFirstPage_resetsWindow() {
        assertEquals(0, nextWindowStart(0, 1, 7))
    }

    /** 八项直接选择末页时窗口应移动到 2–7。 */
    @Test
    fun eightItems_lastPage_movesToTwo() {
        assertEquals(2, nextWindowStart(7, 0, 8))
    }

    /** 十二项中的相邻越界只应移动一个条目。 */
    @Test
    fun twelveItems_nextPage_movesMinimumDistance() {
        assertEquals(4, nextWindowStart(9, 3, 12))
    }

    /** 不超过六项时任何合法选择都应保持首窗口。 */
    @Test
    fun fiveAndSixItems_neverMoveWindow() {
        for (count in 5..6) {
            for (page in 0 until count) {
                assertEquals(0, nextWindowStart(page, 4, count))
            }
        }
    }

    /** 非法页码和窗口参数应被边界约束而不越界。 */
    @Test
    fun invalidIndices_areClamped() {
        assertEquals(0, nextWindowStart(-10, -4, 7))
        assertEquals(1, nextWindowStart(99, 99, 7))
        assertEquals(0, nextWindowStart(0, 0, 0))
        assertEquals(0, nextWindowStart(0, 0, 7, 0))
    }
}
