package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.i18n.Messages

/**
 * 文件选择处理中的加载指示器。
 *
 * <p>在文件选择器返回结果后、文件处理（路径解析/复制/缩略图解码）完成前，
 * 显示旋转圆圈与提示文本，避免大文件处理期间界面看似无响应。
 *
 * @param text     加载提示文本
 * @param modifier 修饰符
 * @param iconSize 旋转圆圈直径
 * @param vertical 为 true 时垂直居中排列（用于空状态卡片），否则水平排列（用于行内提示）
 * @author ErgouTree
 * @since 2026/8/15
 */
@Composable
fun PickerLoadingIndicator(
    text: String,
    modifier: Modifier = Modifier,
    iconSize: Dp = 20.dp,
    vertical: Boolean = false
) {
    if (vertical) {
        Column(
            modifier = modifier,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(iconSize),
                strokeWidth = 3.dp,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    } else {
        Row(
            modifier = modifier,
            verticalAlignment = Alignment.CenterVertically
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(iconSize),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * 获取本地化的"文件处理中"提示文本。
 *
 * @return 本地化文案，缺失时回退为中文
 */
fun pickerLoadingText(): String {
    return try {
        Messages.get("picker.loading")
    } catch (_: Exception) {
        "正在处理所选文件…"
    }
}

/**
 * 获取本地化的"文件处理中"辅助提示。
 *
 * @return 本地化文案，缺失时回退为中文
 */
fun pickerLoadingHint(): String {
    return try {
        Messages.get("picker.loading.hint")
    } catch (_: Exception) {
        "文件较大时可能需要一些时间，请稍候"
    }
}
