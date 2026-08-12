package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * 选项数据类。
 *
 * @property key      选项唯一标识
 * @property label    选项显示文本
 * @property selected 当前是否选中
 * @property enabled  是否可交互，默认 true
 */
data class OptionItem(
    val key: String,
    val label: String,
    val selected: Boolean,
    val enabled: Boolean = true
)

/**
 * 选项芯片组组件。
 *
 * <p>以 FlowRow 排列的 FilterChip 组，用于展示和切换布尔类型的加密选项。
 *
 * @param options         选项列表
 * @param onOptionToggle  选项切换回调（传入选项 key）
 * @param modifier        修饰符
 * @author ErgouTree
 * @since 2026/8/11
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun OptionChips(
    options: List<OptionItem>,
    onOptionToggle: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    FlowRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        options.forEach { option ->
            FilterChip(
                selected = option.selected,
                onClick = { onOptionToggle(option.key) },
                enabled = option.enabled,
                label = {
                    Text(
                        text = option.label,
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            )
        }
    }
}
