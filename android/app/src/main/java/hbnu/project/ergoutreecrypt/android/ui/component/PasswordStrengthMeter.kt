package hbnu.project.ergoutreecrypt.android.ui.component

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * 密码强度等级。
 */
enum class StrengthLevel(val label: String, val fraction: Float, val color: Color) {
    /** 无密码 / 空密码 */
    NONE("无密码模式", 0f, Color.Gray),
    /** 弱 */
    WEAK("弱", 0.25f, Color(0xFFDC2626)),
    /** 中等 */
    MEDIUM("中等", 0.5f, Color(0xFFF59E0B)),
    /** 强 */
    STRONG("强", 1f, Color(0xFF16A34A))
}

/**
 * 密码强度指示器。
 *
 * <p>以文字 + 进度条形式展示密码强度，与桌面端的文本型强度指示器风格一致。
 *
 * @param password 当前密码文本
 * @param modifier 修饰符
 * @author ErgouTree
 * @since 2026/8/11
 */
@Composable
fun PasswordStrengthMeter(
    password: String,
    modifier: Modifier = Modifier
) {
    val strength = remember(password) { evaluateStrength(password) }

    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = "强度：${strength.label}",
            style = MaterialTheme.typography.labelMedium,
            color = strength.color
        )
        Spacer(modifier = Modifier.width(8.dp))
        LinearProgressIndicator(
            progress = { strength.fraction },
            modifier = Modifier
                .weight(1f)
                .height(4.dp),
            color = strength.color,
            trackColor = strength.color.copy(alpha = 0.15f)
        )
    }
}

/**
 * 评估密码强度。
 *
 * <p>规则（与桌面端一致）：
 * <ul>
 *   <li>空 → 无密码模式</li>
 *   <li>长度 &lt; 8 → 弱</li>
 *   <li>仅有字母或仅有数字 → 弱</li>
 *   <li>长度 ≥ 12 且有 3+ 类字符 → 强</li>
 *   <li>长度 ≥ 8 且有 2+ 类字符 → 中等</li>
 *   <li>其余 → 弱</li>
 * </ul>
 *
 * @param password 密码文本
 * @return 强度等级
 */
fun evaluateStrength(password: String): StrengthLevel {
    if (password.isEmpty()) {
        return StrengthLevel.NONE
    }

    val hasLower = password.any { it.isLowerCase() }
    val hasUpper = password.any { it.isUpperCase() }
    val hasDigit = password.any { it.isDigit() }
    val hasSpecial = password.any { !it.isLetterOrDigit() }

    val categories = listOf(hasLower, hasUpper, hasDigit, hasSpecial).count { it }

    return when {
        password.length < 8 -> StrengthLevel.WEAK
        password.length >= 12 && categories >= 3 -> StrengthLevel.STRONG
        password.length >= 8 && categories >= 2 -> StrengthLevel.MEDIUM
        categories <= 1 -> StrengthLevel.WEAK
        else -> StrengthLevel.MEDIUM
    }
}
