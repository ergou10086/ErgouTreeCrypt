package hbnu.project.ergoutreecrypt.android.ui.navigation

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.HideImage
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.HideImage
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import hbnu.project.ergoutreecrypt.android.ui.component.BackgroundOverlay
import hbnu.project.ergoutreecrypt.android.ui.screen.ClassicalScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.DecryptScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.EncryptScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.HistoryScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.ImageCryptScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.SettingsScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.StegoExtractScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.StegoScreen
import hbnu.project.ergoutreecrypt.android.ui.screen.StorageScreen
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

/**
 * 一级目的地的稳定路由和当前产品顺序。
 *
 * <p>持久化使用 route key，不使用枚举 ordinal；页面索引只描述当前集合中的位置。
 */
object Routes {
    /** 通用加密稳定路由。 */
    const val ENCRYPT = "encrypt"
    /** 通用解密稳定路由。 */
    const val DECRYPT = "decrypt"
    /** 图片加密稳定路由。 */
    const val IMAGE_CRYPT = "image-crypt"
    /** 字符串加密稳定路由。 */
    const val TEXT_CRYPTO = "text-crypto"
    /** 隐写稳定路由。 */
    const val STEGO = "stego"
    /** 隐写提取稳定路由。 */
    const val STEGO_EXTRACT = "stego-extract"
    /** 设置稳定路由。 */
    const val SETTINGS = "settings"

    /** 加密页面索引。 */
    const val ENCRYPT_PAGE = 0
    /** 解密页面索引。 */
    const val DECRYPT_PAGE = 1
    /** 图片加密页面索引。 */
    const val IMAGE_CRYPT_PAGE = 2
    /** 字符串加密页面索引。 */
    const val TEXT_CRYPTO_PAGE = 3
    /** 隐写页面索引。 */
    const val STEGO_PAGE = 4
    /** 隐写提取页面索引。 */
    const val STEGO_EXTRACT_PAGE = 5
    /** 设置页面索引。 */
    const val SETTINGS_PAGE = 6
}

/**
 * 底部导航目的地。
 *
 * @property routeKey 跨重建持久化的稳定路由键
 * @property label 显示名称
 * @property selectedIcon 选中图标
 * @property unselectedIcon 未选中图标
 */
data class BottomNavItem(
    val routeKey: String,
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

/**
 * 应用一级导航图。
 *
 * <p>{@code PagerState} 是选中页面唯一真值。目的地数量完全从集合推导，底栏最多展示六项，
 * 已稳定页面驱动最小窗口移动。Pager 仅保留相邻一页，表单和长任务由 Activity 作用域
 * ViewModel 保存，页面数增长不会线性增加首帧与内存开销。
 */
@Composable
fun ErgouNavGraph() {
    val bottomNavItems = remember { createBottomNavItems() }
    var savedRoute by rememberSaveable { mutableStateOf(Routes.ENCRYPT) }
    var savedWindowStart by rememberSaveable { mutableIntStateOf(0) }
    val initialPage = bottomNavItems.indexOfFirst { it.routeKey == savedRoute }
        .takeIf { it >= 0 }
        ?: 0
    val pagerState = rememberPagerState(
        initialPage = initialPage,
        pageCount = { bottomNavItems.size }
    )
    val scope = rememberCoroutineScope()
    var showHistory by remember { mutableStateOf(false) }
    var showStorage by remember { mutableStateOf(false) }

    LaunchedEffect(pagerState, bottomNavItems) {
        snapshotFlow { pagerState.settledPage }
            .distinctUntilChanged()
            .collect { page ->
                bottomNavItems.getOrNull(page)?.let { savedRoute = it.routeKey }
            }
    }

    /**
     * 请求切换到指定稳定路由。
     *
     * @param routeKey 目标稳定路由键
     */
    fun navigateTo(routeKey: String) {
        val page = bottomNavItems.indexOfFirst { it.routeKey == routeKey }
        if (page >= 0) {
            scope.launch { pagerState.animateScrollToPage(page) }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        BackgroundOverlay(modifier = Modifier.fillMaxSize())
        Scaffold(
            containerColor = Color.Transparent,
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            bottomBar = {
                SlidingBottomNavigationBar(
                    items = bottomNavItems,
                    selectedPage = pagerState.currentPage,
                    settledPage = pagerState.settledPage,
                    initialWindowStart = savedWindowStart,
                    onWindowStartChanged = { savedWindowStart = it },
                    onItemClick = { page ->
                        if (page in bottomNavItems.indices) {
                            scope.launch { pagerState.animateScrollToPage(page) }
                        }
                    }
                )
            }
        ) { innerPadding ->
            HorizontalPager(
                state = pagerState,
                key = { page -> bottomNavItems[page].routeKey },
                beyondViewportPageCount = 1,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) { page ->
                when (bottomNavItems[page].routeKey) {
                    Routes.ENCRYPT -> EncryptScreen(
                        onOpenHistory = { showHistory = true },
                        onNavigateToImageCrypt = { navigateTo(Routes.IMAGE_CRYPT) }
                    )
                    Routes.DECRYPT -> DecryptScreen(
                        onOpenHistory = { showHistory = true },
                        onNavigateToImageCrypt = { navigateTo(Routes.IMAGE_CRYPT) }
                    )
                    Routes.IMAGE_CRYPT -> ImageCryptScreen(onOpenHistory = { showHistory = true })
                    Routes.TEXT_CRYPTO -> ClassicalScreen(onOpenHistory = { showHistory = true })
                    Routes.STEGO -> StegoScreen(onOpenHistory = { showHistory = true })
                    Routes.STEGO_EXTRACT -> StegoExtractScreen(onOpenHistory = { showHistory = true })
                    Routes.SETTINGS -> SettingsScreen(
                        onOpenHistory = { showHistory = true },
                        onOpenStorage = { showStorage = true }
                    )
                }
            }
        }

        if (showHistory) {
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null
                    ) { },
                color = MaterialTheme.colorScheme.background
            ) {
                HistoryScreen(onBack = { showHistory = false })
            }
        }

        if (showStorage) {
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null
                    ) { },
                color = MaterialTheme.colorScheme.background
            ) {
                StorageScreen(onBack = { showStorage = false })
            }
        }
    }
}

/**
 * 创建当前产品的一级目的地集合。
 *
 * @return 顺序稳定的七个目的地
 */
private fun createBottomNavItems(): List<BottomNavItem> = listOf(
    BottomNavItem(Routes.ENCRYPT, "加密", Icons.Filled.Lock, Icons.Outlined.Lock),
    BottomNavItem(Routes.DECRYPT, "解密", Icons.Filled.LockOpen, Icons.Outlined.LockOpen),
    BottomNavItem(Routes.IMAGE_CRYPT, "图片加解密", Icons.Filled.HideImage, Icons.Outlined.HideImage),
    BottomNavItem(Routes.TEXT_CRYPTO, "字符串加密", Icons.Filled.Edit, Icons.Outlined.Edit),
    BottomNavItem(Routes.STEGO, "隐写", Icons.Filled.Visibility, Icons.Outlined.Visibility),
    BottomNavItem(Routes.STEGO_EXTRACT, "隐写提取", Icons.Filled.VisibilityOff, Icons.Outlined.VisibilityOff),
    BottomNavItem(Routes.SETTINGS, "设置", Icons.Filled.Settings, Icons.Outlined.Settings)
)
