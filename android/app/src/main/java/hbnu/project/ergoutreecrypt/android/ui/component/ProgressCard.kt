package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState

/**
 * 进度卡片组件。
 *
 * <p>在加密/解密进行中显示进度条、状态文本和取消按钮。
 * 根据进度状态自动切换显示模式。
 *
 * <p>取消按钮为进度条右侧的小圆形红叉图标，操作进行中始终可用，
 * 点击后立即向 ViewModel 发出取消信号（中断无副作用、正确撤回、不残留文件）。
 *
 * @param progressState 进度状态
 * @param onCancel      取消操作回调
 * @param modifier      修饰符
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun ProgressCard(
    progressState: ProgressState,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isActive = progressState.state == ProgressState.State.RUNNING

    AnimatedVisibility(
        visible = isActive || progressState.state == ProgressState.State.DONE
                || progressState.state == ProgressState.State.ERROR,
        enter = fadeIn(),
        exit = fadeOut()
    ) {
        Card(
            modifier = modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                // 状态文本
                Text(
                    text = progressState.statusText.ifEmpty {
                        when (progressState.state) {
                            ProgressState.State.DONE -> "操作完成"
                            ProgressState.State.ERROR -> "操作失败"
                            ProgressState.State.CANCELLED -> "已取消"
                            else -> "准备中…"
                        }
                    },
                    style = MaterialTheme.typography.bodyMedium
                )

                Spacer(modifier = Modifier.height(8.dp))

                // 进度条 + 右侧圆形红叉取消按钮（操作进行中始终显示）
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    LinearProgressIndicator(
                        progress = { progressState.progress.coerceIn(0f, 1f) },
                        modifier = Modifier.weight(1f)
                    )
                    if (isActive) {
                        Spacer(modifier = Modifier.width(12.dp))
                        IconButton(
                            onClick = onCancel,
                            modifier = Modifier
                                .size(32.dp)
                                .background(
                                    color = MaterialTheme.colorScheme.error,
                                    shape = CircleShape
                                )
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Close,
                                contentDescription = "取消操作",
                                tint = Color.White,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(4.dp))

                // 进度信息（速度等）
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "${(progressState.progress * 100).toInt()}%",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    if (progressState.info.isNotEmpty()) {
                        Text(
                            text = " · ${progressState.info}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                // 错误信息
                if (progressState.state == ProgressState.State.ERROR
                        && progressState.error != null
                ) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = progressState.error,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}
