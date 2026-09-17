package hbnu.project.ergoutreecrypt.android.ui.navigation

import androidx.compose.foundation.gestures.snapping.rememberSnapFlingBehavior
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.distinctUntilChanged

/** 单个动态底栏窗口最多完整显示的目的地数量。 */
const val MAX_VISIBLE_NAV_ITEMS = 6

/** 动态底栏条目的最小触摸宽度。 */
private val MIN_NAV_ITEM_WIDTH = 48.dp

/**
 * 计算能包含选中页面且移动距离最短的底栏窗口起点。
 *
 * @param selectedPage 当前选中的页面索引
 * @param currentStart 当前窗口首项索引
 * @param itemCount 目的地总数
 * @param visibleCount 单个窗口最多显示的条目数
 * @return 经过边界约束的新窗口首项索引
 */
fun nextWindowStart(
    selectedPage: Int,
    currentStart: Int,
    itemCount: Int,
    visibleCount: Int = MAX_VISIBLE_NAV_ITEMS
): Int {
    if (itemCount <= 0 || visibleCount <= 0) {
        return 0
    }
    val selected = selectedPage.coerceIn(0, itemCount - 1)
    val maxStart = (itemCount - visibleCount).coerceAtLeast(0)
    val start = currentStart.coerceIn(0, maxStart)
    return when {
        selected < start -> selected
        selected >= start + visibleCount -> selected - visibleCount + 1
        else -> start
    }.coerceIn(0, maxStart)
}

/**
 * 一次最多展示六项、支持手动拖动与条目吸附的底部导航栏。
 *
 * <p>手动拖动只改变可见窗口；点击条目才请求切换 Pager。自动窗口移动由已稳定页面
 * {@code settledPage} 驱动，选中高亮则立即读取 {@code selectedPage}，因此动画途中不会出现
 * 第二份选中状态。
 *
 * @param items 全部一级目的地
 * @param selectedPage Pager 当前页
 * @param settledPage Pager 已稳定页
 * @param initialWindowStart Activity 重建后恢复的窗口起点
 * @param onWindowStartChanged 窗口起点变化回调
 * @param onItemClick 条目点击回调，参数为页面索引
 * @param modifier 修饰符
 */
@Composable
fun SlidingBottomNavigationBar(
    items: List<BottomNavItem>,
    selectedPage: Int,
    settledPage: Int,
    initialWindowStart: Int,
    onWindowStartChanged: (Int) -> Unit,
    onItemClick: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val clampedStart = initialWindowStart.coerceIn(
        0,
        (items.size - MAX_VISIBLE_NAV_ITEMS).coerceAtLeast(0)
    )
    val listState = rememberLazyListState(initialFirstVisibleItemIndex = clampedStart)

    AutoScrollSelectedDestination(
        listState = listState,
        settledPage = settledPage,
        itemCount = items.size,
        onWindowStartChanged = onWindowStartChanged
    )

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .testTag("sliding-bottom-navigation"),
        color = MaterialTheme.colorScheme.surfaceContainer,
        tonalElevation = 3.dp
    ) {
        BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
            val itemWidth = (maxWidth / MAX_VISIBLE_NAV_ITEMS).coerceAtLeast(MIN_NAV_ITEM_WIDTH)
            LazyRow(
                state = listState,
                flingBehavior = rememberSnapFlingBehavior(lazyListState = listState),
                modifier = Modifier.fillMaxWidth()
            ) {
                itemsIndexed(
                    items = items,
                    key = { _, item -> item.routeKey }
                ) { index, item ->
                    SlidingNavigationItem(
                        label = item.label,
                        position = index,
                        totalCount = items.size,
                        selected = selectedPage == index,
                        selectedIcon = item.selectedIcon,
                        unselectedIcon = item.unselectedIcon,
                        width = itemWidth,
                        onClick = { onItemClick(index) },
                        modifier = Modifier.testTag("bottom-nav-${item.routeKey}")
                    )
                }
            }
        }
    }
}

/**
 * 监听稳定页与手动底栏滚动，并保持可见窗口和持久状态一致。
 *
 * @param listState 底栏列表状态
 * @param settledPage Pager 已稳定页
 * @param itemCount 目的地总数
 * @param onWindowStartChanged 窗口起点变化回调
 */
@Composable
private fun AutoScrollSelectedDestination(
    listState: LazyListState,
    settledPage: Int,
    itemCount: Int,
    onWindowStartChanged: (Int) -> Unit
) {
    LaunchedEffect(settledPage, itemCount) {
        val next = nextWindowStart(
            selectedPage = settledPage,
            currentStart = listState.firstVisibleItemIndex,
            itemCount = itemCount
        )
        if (next != listState.firstVisibleItemIndex) {
            listState.animateScrollToItem(next)
        }
        onWindowStartChanged(next)
    }
    LaunchedEffect(listState, itemCount) {
        snapshotFlow { listState.firstVisibleItemIndex }
            .distinctUntilChanged()
            .collect { first ->
                val maxStart = (itemCount - MAX_VISIBLE_NAV_ITEMS).coerceAtLeast(0)
                onWindowStartChanged(first.coerceIn(0, maxStart))
            }
    }
}
