package com.detectany.app.ui

import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// 严重度配色（重点突出）— 亮色主题
private val ScoreCriticalLight = Color(0xFFC62828)
private val ScoreWarningLight = Color(0xFFEF6C00)
private val ScoreCleanLight = Color(0xFF2E7D32)
private val BadgeStrongLight = Color(0xFFC62828)
private val BadgeMediumLight = Color(0xFFEF6C00)
private val BadgeWeakLight = Color(0xFF757575)
private val StatusOkLight = Color(0xFF2E7D32)
private val StatusDegradedLight = Color(0xFFEF6C00)
private val StatusBlockedLight = Color(0xFFC62828)

// 暗色主题变体（更高亮度，暗色背景对比度 WCAG AA）
private val ScoreCriticalDark = Color(0xFFEF5350)
private val ScoreWarningDark = Color(0xFFFFA726)
private val ScoreCleanDark = Color(0xFF66BB6A)
private val BadgeStrongDark = Color(0xFFEF5350)
private val BadgeMediumDark = Color(0xFFFFA726)
private val BadgeWeakDark = Color(0xFFBDBDBD)
private val StatusOkDark = Color(0xFF66BB6A)
private val StatusDegradedDark = Color(0xFFFFA726)
private val StatusBlockedDark = Color(0xFFEF5350)

// 全局公开（亮色，暗色场景通过 scoreColor() 动态切换）
val ScoreCritical = ScoreCriticalLight
val ScoreWarning = ScoreWarningLight
val ScoreClean = ScoreCleanLight
val BadgeStrong = BadgeStrongLight
val BadgeMedium = BadgeMediumLight
val BadgeWeak = BadgeWeakLight
val StatusOk = StatusOkLight
val StatusDegraded = StatusDegradedLight
val StatusBlocked = StatusBlockedLight

/** B5: 主题感知严重度色 */
@Composable
fun themedScoreColor(score: Int): Color {
    val dark = androidx.compose.foundation.isSystemInDarkTheme()
    return when {
        score >= 70 -> if (dark) ScoreCriticalDark else ScoreCriticalLight
        score >= 40 -> if (dark) ScoreWarningDark else ScoreWarningLight
        else -> if (dark) ScoreCleanDark else ScoreCleanLight
    }
}

@Composable
fun scoreColor(score: Int): Color = themedScoreColor(score)

/** 风险仪表盘：环形进度 + 动画分数 + 判定文案。 */
@Composable
fun ScoreGauge(score: Int, conclusive: Boolean, modifier: Modifier = Modifier, diameter: Dp = 148.dp) {
    val animated by animateIntAsState(score, animationSpec = tween(700), label = "score")
    val color = scoreColor(score)
    val track = MaterialTheme.colorScheme.surfaceVariant
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = modifier) {
        Box(contentAlignment = Alignment.Center) {
            Canvas(modifier = Modifier.size(diameter)) {
                val stroke = Stroke(width = size.minDimension * 0.085f, cap = StrokeCap.Round)
                val inset = stroke.width / 2
                drawArc(
                    color = track,
                    startAngle = 150f, sweepAngle = 240f, useCenter = false,
                    topLeft = Offset(inset, inset),
                    size = androidx.compose.ui.geometry.Size(size.width - inset * 2, size.height - inset * 2),
                    style = stroke,
                )
                drawArc(
                    color = color,
                    startAngle = 150f,
                    sweepAngle = 240f * (animated.coerceIn(0, 100) / 100f),
                    useCenter = false,
                    topLeft = Offset(inset, inset),
                    size = androidx.compose.ui.geometry.Size(size.width - inset * 2, size.height - inset * 2),
                    style = stroke,
                )
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    "$animated",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 40.sp,
                    color = color,
                )
                Text("Risk Score", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        VerdictBadge(conclusive)
    }
}

/** 判定徽标（大号、重点突出）。 */
@Composable
fun VerdictBadge(conclusive: Boolean, modifier: Modifier = Modifier) {
    val (bg, text) = if (conclusive) ScoreCritical to "Detected · conclusive evidence" else ScoreClean to "Inconclusive · insufficient evidence"
    Text(
        text,
        color = Color.White,
        fontWeight = FontWeight.SemiBold,
        style = MaterialTheme.typography.titleSmall,
        modifier = modifier
            .background(bg, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

/** 置信徽标：强/中/弱。 */
@Composable
fun ConfidenceBadge(label: String, modifier: Modifier = Modifier) {
    val color = when (label) {
        "STRONG" -> BadgeStrong
        "MED" -> BadgeMedium
        else -> BadgeWeak
    }
    Text(
        label,
        color = Color.White,
        style = MaterialTheme.typography.labelSmall,
        modifier = modifier
            .background(color, RoundedCornerShape(4.dp))
            .padding(horizontal = 7.dp, vertical = 2.dp),
    )
}

/** 采集器状态徽标。 */
@Composable
fun StatusChip(status: String, modifier: Modifier = Modifier) {
    val (color, label) = when (status) {
        "OK" -> StatusOk to "OK"
        "DEGRADED" -> StatusDegraded to "Degraded"
        else -> StatusBlocked to "Blocked"
    }
    Text(
        label,
        color = Color.White,
        style = MaterialTheme.typography.labelSmall,
        modifier = modifier
            .background(color, RoundedCornerShape(4.dp))
            .padding(horizontal = 7.dp, vertical = 2.dp),
    )
}

/** 分组卡片标题行。 */
@Composable
fun SectionHeader(title: String, count: Int? = null, trailing: @Composable (() -> Unit)? = null) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        if (count != null) {
            Text(
                "$count",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier
                    .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 1.dp),
            )
        }
        androidx.compose.foundation.layout.Spacer(modifier = Modifier.weight(1f))
        trailing?.invoke()
    }
}
