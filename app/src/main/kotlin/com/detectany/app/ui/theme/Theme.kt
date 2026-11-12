package com.detectany.app.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Material 3 主题：Android 12+ 动态取色（Monet），低版本回退品牌色板；
 * 明暗双主题自动跟随系统。
 *
 * 2026-11-12 UI 美化（v18 设计系统）：
 * - 全字阶调校（标题统一 SemiBold，正文 12sp 底线）
 * - Shapes 统一（8/10/14/20）——消灭散乱的 RoundedCornerShape 字面量
 * - 严重度四色 token 化（critical/warning/watch/clean × 明暗），经
 *   CompositionLocal 下发——徽章/状态/分数色深浅主题都保证对比度
 */
private val LightColors = lightColorScheme(
    primary = Color(0xFF1B6EF3),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD8E2FF),
    onPrimaryContainer = Color(0xFF001A41),
    secondary = Color(0xFF575E71),
    secondaryContainer = Color(0xFFDBE2F9),
    tertiary = Color(0xFF705575),
    surface = Color(0xFFF9F9FF),
    surfaceVariant = Color(0xFFE1E2EC),
    onSurface = Color(0xFF191C20),
    onSurfaceVariant = Color(0xFF44474E),
    background = Color(0xFFF9F9FF),
    outline = Color(0xFF74777F),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFAEC6FF),
    onPrimary = Color(0xFF002D6D),
    primaryContainer = Color(0xFF00419B),
    onPrimaryContainer = Color(0xFFD8E2FF),
    secondary = Color(0xFFBFC6DC),
    secondaryContainer = Color(0xFF3F4759),
    surface = Color(0xFF111318),
    surfaceVariant = Color(0xFF44474E),
    onSurface = Color(0xFFE1E2E9),
    onSurfaceVariant = Color(0xFFC5C6D0),
    background = Color(0xFF111318),
    outline = Color(0xFF8E9099),
)

/** 全字阶：标题 SemiBold 收紧层级；正文/标签保持 sp 语义（≥12sp 无障碍底线）。 */
private val AppTypography = Typography(
    headlineMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 26.sp, lineHeight = 32.sp),
    headlineSmall = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 22.sp, lineHeight = 28.sp),
    titleLarge = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 20.sp, lineHeight = 26.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp),
    titleSmall = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 14.sp, lineHeight = 20.sp),
    bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 17.sp),
    labelLarge = TextStyle(fontWeight = FontWeight.Medium, fontSize = 14.sp, lineHeight = 20.sp),
    labelMedium = TextStyle(fontWeight = FontWeight.Medium, fontSize = 12.sp, lineHeight = 16.sp),
    labelSmall = TextStyle(fontWeight = FontWeight.Medium, fontSize = 11.sp, lineHeight = 15.sp),
)

/** 统一形状系统：卡片/分段/胶囊全族取自此处。 */
private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/** 严重度四色（风险分/徽章/状态共用一套语义，明暗各自保证对比度）。 */
data class SeverityColors(
    val critical: Color,
    val warning: Color,
    val watch: Color,
    val clean: Color,
)

private val SeverityLight = SeverityColors(
    critical = Color(0xFFC62828),
    warning = Color(0xFF9A4D00),
    watch = Color(0xFF5F6368),
    clean = Color(0xFF2E7D32),
)

private val SeverityDark = SeverityColors(
    critical = Color(0xFFFFB4AB),
    warning = Color(0xFFFFB77C),
    watch = Color(0xFFC4C6D0),
    clean = Color(0xFF8BD894),
)

val LocalSeverityColors = staticCompositionLocalOf { SeverityLight }

/** 等宽强调样式（风险分/原始观测/元信息）——安全工具语言。 */
val MonoEmphasis = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontWeight = FontWeight.SemiBold,
    fontSize = 14.sp,
)

@Composable
fun DetectAnyTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }
    CompositionLocalProvider(LocalSeverityColors provides if (darkTheme) SeverityDark else SeverityLight) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = AppTypography,
            shapes = AppShapes,
            content = content,
        )
    }
}
