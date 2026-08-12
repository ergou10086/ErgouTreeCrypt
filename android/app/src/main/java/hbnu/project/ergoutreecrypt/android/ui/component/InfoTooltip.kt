package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties

/** ⓘ 图标的固定尺寸，用于定位计算。 */
private val ICON_SIZE = 18.dp

/**
 * 信息提示图标组件。
 *
 * <p>圆形 "i" 图标，点击后在图标下方悬浮显示详情文字卡片。
 * 卡片方向根据图标在屏幕上的位置动态调整：
 * <ul>
 *   <li>图标靠左 → 卡片向右展开</li>
 *   <li>图标靠右 → 卡片向左展开，避免溢出屏幕</li>
 * </ul>
 * 点击卡片外部区域或按返回键可关闭。
 *
 * @param text     提示文本内容
 * @param modifier 修饰符
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun InfoTooltip(
    text: String,
    modifier: Modifier = Modifier
) {
    val density = LocalDensity.current
    val config = LocalConfiguration.current
    val screenWidthDp = config.screenWidthDp.dp

    var showPopup by remember { mutableStateOf(false) }

    // 记录图标在窗口中的坐标（用于动态定位悬浮卡片）
    var iconXDp by remember { mutableStateOf(0.dp) }
    var iconYDp by remember { mutableStateOf(0.dp) }
    var iconHeightDp by remember { mutableStateOf(0.dp) }

    // 判断图标位于屏幕左侧还是右侧
    val isOnRightHalf = iconXDp > screenWidthDp / 2

    // 卡片顶部 Y 坐标（图标底部 + 2dp 间距）
    val cardTopY = iconYDp + iconHeightDp + 2.dp

    // 卡片最大宽度：不超过 280dp，且不超出屏幕边界
    val cardMaxWidth = if (isOnRightHalf) {
        // 图标靠右 → 卡片向左展开，可用空间 = 图标左边缘到屏幕左边缘的距离
        minOf(280.dp, iconXDp - 8.dp)
    } else {
        // 图标靠左 → 卡片向右展开，可用空间 = 图标右边缘到屏幕右边缘的距离
        minOf(280.dp, screenWidthDp - iconXDp - ICON_SIZE - 8.dp)
    }

    Box(modifier = modifier) {
        // ⓘ 图标
        Box(
            modifier = Modifier
                .size(ICON_SIZE)
                .onGloballyPositioned { coords ->
                    val pos = coords.localToWindow(androidx.compose.ui.geometry.Offset.Zero)
                    iconXDp = with(density) { pos.x.toDp() }
                    iconYDp = with(density) { pos.y.toDp() }
                    iconHeightDp = with(density) { coords.size.height.toDp() }
                }
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f))
                .clickable { showPopup = !showPopup },
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "i",
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center
            )
        }

        // 悬浮提示卡片
        if (showPopup) {
            Popup(
                onDismissRequest = { showPopup = false },
                properties = PopupProperties(focusable = true, dismissOnBackPress = true)
            ) {
                // 全屏透明遮罩，点击外部关闭
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null
                        ) { showPopup = false }
                ) {
                    if (isOnRightHalf) {
                        // ---- 图标靠右 → 卡片右对齐，向左展开 ----
                        Card(
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .offset(
                                    // 卡片右边缘对齐图标右边缘
                                    x = -(screenWidthDp - iconXDp - ICON_SIZE),
                                    y = cardTopY
                                )
                                .widthIn(max = cardMaxWidth)
                                .clickable(
                                    interactionSource = remember { MutableInteractionSource() },
                                    indication = null
                                ) { /* 消费点击，防止穿透 */ },
                            shape = RoundedCornerShape(8.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.inverseSurface
                            ),
                            elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
                        ) {
                            Text(
                                text = text,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.inverseOnSurface,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    } else {
                        // ---- 图标靠左 → 卡片左对齐，向右展开 ----
                        Card(
                            modifier = Modifier
                                .align(Alignment.TopStart)
                                .offset(
                                    // 卡片左边缘对齐图标左边缘
                                    x = iconXDp,
                                    y = cardTopY
                                )
                                .widthIn(max = cardMaxWidth)
                                .clickable(
                                    interactionSource = remember { MutableInteractionSource() },
                                    indication = null
                                ) { /* 消费点击，防止穿透 */ },
                            shape = RoundedCornerShape(8.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.inverseSurface
                            ),
                            elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
                        ) {
                            Text(
                                text = text,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.inverseOnSurface,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * 行内标签 + ⓘ 提示。
 *
 * <p>标签文本在前，ⓘ 图标在文本末尾对齐。
 *
 * @param label 标签文本
 * @param tip   提示文本
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun LabelWithTip(
    label: String,
    tip: String
) {
    androidx.compose.foundation.layout.Row(
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium
        )
        InfoTooltip(text = tip)
    }
}
