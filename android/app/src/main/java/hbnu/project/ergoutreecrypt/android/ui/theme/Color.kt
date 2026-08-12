package hbnu.project.ergoutreecrypt.android.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * ErgouTreeCrypt 调色板。
 *
 * <p>以蓝紫渐变色为主色调，支持亮色与暗色两套方案。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */

// --- 主色 ---
val Primary = Color(0xFF1A56DB)          // 深蓝（亮色模式主色）
val PrimaryDark = Color(0xFF1E40AF)      // 更深的蓝
val PrimaryLight = Color(0xFF3B82F6)     // 浅蓝
val OnPrimary = Color(0xFFFFFFFF)

// --- 辅色 ---
val Secondary = Color(0xFF7C3AED)        // 紫色
val SecondaryDark = Color(0xFF6D28D9)
val OnSecondary = Color(0xFFFFFFFF)

// --- 语义色 ---
val ErrorColor = Color(0xFFDC2626)
val SuccessColor = Color(0xFF16A34A)
val WarningColor = Color(0xFFF59E0B)

// --- 暗色模式背景 ---
val DarkBackground = Color(0xFF0F0F0F)
val DarkSurface = Color(0xFF1C1C1E)
val DarkSurfaceVariant = Color(0xFF2C2C2E)

// --- 亮色模式背景 ---
val LightBackground = Color(0xFFF8FAFC)
val LightSurface = Color(0xFFFFFFFF)
val LightSurfaceVariant = Color(0xFFF1F5F9)
