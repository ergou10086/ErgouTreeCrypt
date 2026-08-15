package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * 紧凑透明页面标题条。
 *
 * <p>替代默认 {@code TopAppBar}：标题收窄为略宽于文字的圆角胶囊，
 * 紧贴屏幕顶部（状态栏之下）且靠左对齐，背景半透明，避免遮挡全局背景图。
 * 右侧预留 {@code actions} 槽位，用于放置图标按钮（如操作历史入口）。
 *
 * @param title    页面标题文字
 * @param modifier 修饰符
 * @param actions  标题右侧的操作区（图标按钮等）
 * @author ErgouTree
 * @since 2026/8/14
 */
@Composable
fun CompactTopBar(
    title: String,
    modifier: Modifier = Modifier,
    actions: @Composable RowScope.() -> Unit = {}
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .statusBarsPadding()
            .padding(top = 2.dp)
            .padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Surface(
            shape = RoundedCornerShape(50),
            color = MaterialTheme.colorScheme.surface.copy(alpha = 0.45f),
            contentColor = MaterialTheme.colorScheme.onSurface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 18.dp, vertical = 5.dp)
            )
        }
        Spacer(modifier = Modifier.weight(1f))
        Row(content = actions)
    }
}
