package hbnu.project.ergoutreecrypt.android.ui.navigation

import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import hbnu.project.ergoutreecrypt.android.ui.component.BackgroundOverlay
import hbnu.project.ergoutreecrypt.android.ui.screen.ClassicalScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.DecryptScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.EncryptScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.HistoryScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.SettingsScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.StegoExtractScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.StegoScreen
import kotlinx.coroutines.launch

/**
 * 底部导航路由索引常量。
 */
object Routes {
    /** 加密 Tab 索引 */
    const val ENCRYPT_PAGE = 0
    /** 解密 Tab 索引 */
    const val DECRYPT_PAGE = 1
    /** 文本加密（经典密码）Tab 索引 */
    const val TEXT_CRYPTO_PAGE = 2
    /** 隐写 Tab 索引 */
    const val STEGO_PAGE = 3
    /** 隐写提取 Tab 索引 */
    const val STEGO_EXTRACT_PAGE = 4
    /** 设置 Tab 索引 */
    const val SETTINGS_PAGE = 5
}

/**
 * 底部导航条目。
 */
data class BottomNavItem(
    val page: Int,
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

/**
 * 应用导航图。
 *
 * <p>使用 Scaffold + BottomNavigationBar（6 个标签：
 * 加密 / 解密 / 文本加密 / 隐写 / 隐写提取 / 设置）。
 * 页面之间支持左右滑动切换（HorizontalPager），滑动与底部导航双向同步。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun ErgouNavGraph() {
    val pagerState = rememberPagerState(pageCount = { 6 })
    val scope = rememberCoroutineScope()
    // 操作历史全屏覆盖页开关（由各页右上角时钟图标触发）
    var showHistory by remember { mutableStateOf(false) }

    val bottomNavItems = listOf(
        BottomNavItem(Routes.ENCRYPT_PAGE, "加密", Icons.Filled.Lock, Icons.Outlined.Lock),
        BottomNavItem(Routes.DECRYPT_PAGE, "解密", Icons.Filled.LockOpen, Icons.Outlined.LockOpen),
        BottomNavItem(Routes.TEXT_CRYPTO_PAGE, "文本加密", Icons.Filled.Edit, Icons.Outlined.Edit),
        BottomNavItem(Routes.STEGO_PAGE, "隐写", Icons.Filled.Visibility, Icons.Outlined.Visibility),
        BottomNavItem(Routes.STEGO_EXTRACT_PAGE, "隐写提取", Icons.Filled.VisibilityOff, Icons.Outlined.VisibilityOff),
        BottomNavItem(Routes.SETTINGS_PAGE, "设置", Icons.Filled.Settings, Icons.Outlined.Settings)
    )

    Box(modifier = Modifier.fillMaxSize()) {
        // 背景图片层（置于最底层）
        BackgroundOverlay(modifier = Modifier.fillMaxSize())

        // 应用主体内容
        // Scaffold 默认容器色为不透明背景色，会遮住下层 BackgroundOverlay，故设为透明
        Scaffold(
            containerColor = Color.Transparent,
            bottomBar = {
                NavigationBar {
                    bottomNavItems.forEach { item ->
                        val selected = pagerState.currentPage == item.page

                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                scope.launch {
                                    pagerState.animateScrollToPage(item.page)
                                }
                            },
                            icon = {
                                Icon(
                                    imageVector = if (selected) item.selectedIcon else item.unselectedIcon,
                                    contentDescription = item.label
                                )
                            },
                            label = { Text(item.label) }
                        )
                    }
                }
            }
        ) { innerPadding ->
            HorizontalPager(
                state = pagerState,
                // 保持全部 6 页处于组合状态：离屏页不销毁，加解密任务跨 Tab 继续运行
                beyondViewportPageCount = 5,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) { page ->
                when (page) {
                    Routes.ENCRYPT_PAGE -> EncryptScreen(onOpenHistory = { showHistory = true })
                    Routes.DECRYPT_PAGE -> DecryptScreen(onOpenHistory = { showHistory = true })
                    Routes.TEXT_CRYPTO_PAGE -> ClassicalScreen(onOpenHistory = { showHistory = true })
                    Routes.STEGO_PAGE -> StegoScreen(onOpenHistory = { showHistory = true })
                    Routes.STEGO_EXTRACT_PAGE -> StegoExtractScreen(onOpenHistory = { showHistory = true })
                    Routes.SETTINGS_PAGE -> SettingsScreen(onOpenHistory = { showHistory = true })
                }
            }
        }

        // 操作历史覆盖页：盖在 pager 之上（而非整屏替换），
        // 保证底层页面保持组合，正在运行的加解密操作不被销毁
        if (showHistory) {
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    // 吞掉点击，防止事件穿透到底层 Pager
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null
                    ) { },
                color = MaterialTheme.colorScheme.background
            ) {
                HistoryScreen(onBack = { showHistory = false })
            }
        }
    }
}
