package hbnu.project.ergoutreecrypt.android.ui.navigation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * 动态底栏中的单个紧凑导航条目。
 *
 * <p>条目保持至少 48 dp 的触摸宽度，并显式提供“名称、标签页序号、选中状态”语义，
 * 避免 TalkBack 只能读到图标。选中状态只由外部 Pager 传入，本组件不保存第二份状态。
 *
 * @param label 目的地显示名称
 * @param position 条目在全部目的地中的零基索引
 * @param totalCount 目的地总数
 * @param selected 是否为 Pager 当前页
 * @param selectedIcon 选中图标
 * @param unselectedIcon 未选中图标
 * @param width 条目触摸区域宽度
 * @param onClick 点击回调
 * @param modifier 修饰符
 */
@Composable
fun SlidingNavigationItem(
    label: String,
    position: Int,
    totalCount: Int,
    selected: Boolean,
    selectedIcon: ImageVector,
    unselectedIcon: ImageVector,
    width: Dp,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .width(width)
            .height(64.dp)
            .semantics(mergeDescendants = true) {
                contentDescription = "$label，标签页，${position + 1}/$totalCount"
                this.selected = selected
            }
            .selectable(
                selected = selected,
                onClick = onClick,
                role = Role.Tab
            ),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(5.dp))
        Surface(
            shape = RoundedCornerShape(18.dp),
            color = if (selected) {
                MaterialTheme.colorScheme.secondaryContainer
            } else {
                MaterialTheme.colorScheme.surface.copy(alpha = 0f)
            },
            contentColor = if (selected) {
                MaterialTheme.colorScheme.onSecondaryContainer
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }
        ) {
            Icon(
                imageVector = if (selected) selectedIcon else unselectedIcon,
                contentDescription = null,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp).size(24.dp)
            )
        }
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = label,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            style = MaterialTheme.typography.labelSmall,
            color = if (selected) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }
        )
    }
}
