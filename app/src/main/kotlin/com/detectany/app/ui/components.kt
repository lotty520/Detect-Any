package com.detectany.app.ui

import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.detectany.app.R
import com.detectany.app.ui.theme.LocalSeverityColors
import com.detectany.app.ui.theme.MonoEmphasis
import com.detectany.app.ui.theme.SeverityColors

/** 严重度语义色（明暗各自保证对比度；token 由 DetectAnyTheme 下发）。 */
@Composable
fun severityColors(): SeverityColors = LocalSeverityColors.current

/** 风险分 → 严重度色（≥70 critical / ≥40 warning / 其余 clean）。 */
@Composable
fun scoreColor(score: Int): Color = with(severityColors()) {
    when {
        score >= 70 -> critical
        score >= 40 -> warning
        else -> clean
    }
}

/**
 * 风险仪表盘 v2：轨道弧 + 圆头进度弧 + 动画扫角。
 * 尺寸自适应（宽度约束内取 ≤200dp，不再固定 148dp）；
 * 分数字号与环径成比例并按 fontScale 反向补偿（大数据数字属视觉元素，
 * 任何字体缩放下不裁切；caption 走正常 sp 缩放，≥12sp）。
 */
@Composable
fun ScoreGauge(score: Int, conclusive: Boolean, modifier: Modifier = Modifier) {
    val animated by animateIntAsState(score, animationSpec = tween(700), label = "score")
    val color = scoreColor(score)
    val track = MaterialTheme.colorScheme.surfaceVariant
    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        BoxWithConstraints(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            val diameter = maxWidth.coerceAtMost(200.dp)
            Box(contentAlignment = Alignment.Center) {
                Canvas(modifier = Modifier.size(diameter)) {
                    val stroke = Stroke(width = size.minDimension * 0.09f, cap = StrokeCap.Round)
                    val inset = stroke.width / 2
                    val arcSize = Size(size.width - inset * 2, size.height - inset * 2)
                    drawArc(
                        color = track,
                        startAngle = 150f, sweepAngle = 240f, useCenter = false,
                        topLeft = Offset(inset, inset),
                        size = arcSize,
                        style = stroke,
                    )
                    drawArc(
                        color = color,
                        startAngle = 150f,
                        sweepAngle = 240f * (animated.coerceIn(0, 100) / 100f),
                        useCenter = false,
                        topLeft = Offset(inset, inset),
                        size = arcSize,
                        style = stroke,
                    )
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    // 字号随环径缩放，fontScale 反向补偿（视觉数字，不参与无障碍缩放）
                    val density = LocalDensity.current
                    val numeralSp = with(density) { (diameter.toPx() * 0.21f / fontScale).toSp() }
                    Text(
                        "$animated",
                        fontFamily = MonoEmphasis.fontFamily,
                        fontWeight = FontWeight.Bold,
                        fontSize = numeralSp,
                        color = color,
                    )
                    Text(
                        stringResource(R.string.risk_score),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        VerdictBadge(conclusive)
    }
}

/** 判定徽标（软底色样式：明暗主题均保证对比度）。 */
@Composable
fun VerdictBadge(conclusive: Boolean, modifier: Modifier = Modifier) {
    val sev = severityColors()
    val (color, text) = if (conclusive) {
        sev.critical to stringResource(R.string.verdict_detected)
    } else {
        sev.clean to stringResource(R.string.verdict_inconclusive)
    }
    Text(
        text,
        color = color,
        fontWeight = FontWeight.SemiBold,
        style = MaterialTheme.typography.titleSmall,
        modifier = modifier
            .background(color.copy(alpha = 0.14f), MaterialTheme.shapes.small)
            .padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

/** 置信徽标：STRONG/MED/WEAK（软底色）。 */
@Composable
fun ConfidenceBadge(label: String, modifier: Modifier = Modifier) {
    val sev = severityColors()
    val color = when (label) {
        "STRONG" -> sev.critical
        "MED" -> sev.warning
        else -> sev.watch
    }
    Text(
        label,
        color = color,
        style = MaterialTheme.typography.labelSmall,
        modifier = modifier
            .background(color.copy(alpha = 0.14f), MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 7.dp, vertical = 2.dp),
    )
}

/** 采集器状态徽标（软底色）。 */
@Composable
fun StatusChip(status: String, modifier: Modifier = Modifier) {
    val sev = severityColors()
    val (color, label) = when (status) {
        "OK" -> sev.clean to "OK"
        "DEGRADED" -> sev.warning to stringResource(R.string.status_degraded)
        else -> sev.critical to stringResource(R.string.status_blocked)
    }
    Text(
        label,
        color = color,
        style = MaterialTheme.typography.labelSmall,
        modifier = modifier
            .background(color.copy(alpha = 0.14f), MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 7.dp, vertical = 2.dp),
    )
}

/** 统一信息卡：全 app 卡片共用 padding/shape/elevation，消灭散乱字面量。 */
@Composable
fun InfoCard(
    modifier: Modifier = Modifier,
    container: Color = MaterialTheme.colorScheme.surface,
    elevation: androidx.compose.ui.unit.Dp = 1.dp,
    content: @Composable () -> Unit,
) {
    Card(
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = container),
        elevation = CardDefaults.cardElevation(defaultElevation = elevation),
        modifier = modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            content()
        }
    }
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
                    .background(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.shapes.extraSmall)
                    .padding(horizontal = 8.dp, vertical = 1.dp),
            )
        }
        Spacer(modifier = Modifier.weight(1f))
        trailing?.invoke()
    }
}
