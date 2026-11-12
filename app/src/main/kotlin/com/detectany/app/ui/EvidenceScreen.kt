package com.detectany.app.ui

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.detectany.app.R
import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.feature.report.ReportModel

/**
 * 威胁页（原证据页）：按「威胁」组织——用户心智：我中了什么、多严重、证据是什么。
 * 2026-11-12 v18：筛选行 FlowRow（字体放大不溢出）；威胁卡左缘严重度色条；
 * ruleId 等宽字体（安全工具语言）。
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun EvidenceScreen(controller: ScanController, scrollToThreat: String? = null) {
    val m = controller.reportModel
    if (m == null) {
        EmptyPage(
            stringResource(R.string.threats_empty_title),
            stringResource(R.string.threats_empty_hint),
        )
        return
    }
    var filterConfidence by remember { mutableStateOf<String?>(null) }

    val filtered = remember(m, filterConfidence) {
        if (filterConfidence == null) m.findings
        else m.findings.filter { it.confidenceLabel == filterConfidence }
    }
    val groups = remember(filtered) { groupByThreat(filtered) }

    Column(Modifier.fillMaxSize()) {
        FlowRow(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            val strong = m.findings.count { it.confidenceLabel == "STRONG" }
            val medium = m.findings.count { it.confidenceLabel == "MED" }
            val weak = m.findings.count { it.confidenceLabel == "WEAK" }
            val sev = severityColors()
            FilterChip(
                selected = filterConfidence == "STRONG",
                onClick = { filterConfidence = if (filterConfidence == "STRONG") null else "STRONG" },
                label = { Text(stringResource(R.string.filter_strong, strong)) },
                leadingIcon = { Box(Modifier.size(8.dp).background(sev.critical, MaterialTheme.shapes.extraSmall)) },
                shape = MaterialTheme.shapes.small,
            )
            FilterChip(
                selected = filterConfidence == "MED",
                onClick = { filterConfidence = if (filterConfidence == "MED") null else "MED" },
                label = { Text(stringResource(R.string.filter_med, medium)) },
                leadingIcon = { Box(Modifier.size(8.dp).background(sev.warning, MaterialTheme.shapes.extraSmall)) },
                shape = MaterialTheme.shapes.small,
            )
            FilterChip(
                selected = filterConfidence == "WEAK",
                onClick = { filterConfidence = if (filterConfidence == "WEAK") null else "WEAK" },
                label = { Text(stringResource(R.string.filter_weak, weak)) },
                leadingIcon = { Box(Modifier.size(8.dp).background(sev.watch, MaterialTheme.shapes.extraSmall)) },
                shape = MaterialTheme.shapes.small,
            )
            Text(
                stringResource(R.string.threats_count, groups.size, m.findings.size),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 12.dp),
            )
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(groups, key = { it.key }) { g -> ThreatCard(g) }
        }
    }
}

@Composable
private fun ThreatCard(g: ThreatGroup) {
    var expanded by remember { mutableStateOf(false) }
    val sev = severityColors()
    val catColor = categoryColor(g.category)
    val worstLabel = when (g.worst) { Confidence.A -> "STRONG"; Confidence.B -> "MED"; else -> "WEAK" }

    Card(
        shape = MaterialTheme.shapes.medium,
        elevation = CardDefaults.cardElevation(defaultElevation = if (g.worst == Confidence.A) 2.dp else 1.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.height(IntrinsicSize.Min).animateContentSize()) {
            // 左缘严重度色条：一眼分级
            Box(
                Modifier
                    .width(4.dp)
                    .fillMaxHeight()
                    .background(if (g.worst == Confidence.A) sev.critical else if (g.worst == Confidence.B) sev.warning else sev.watch),
            )
            Column(Modifier.padding(start = 12.dp, end = 14.dp, top = 14.dp, bottom = 14.dp).weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded },
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(g.name, style = MaterialTheme.typography.titleMedium)
                        if (g.desc.isNotEmpty()) {
                            Text(
                                g.desc,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    ConfidenceBadge(worstLabel)
                    Text(
                        "${g.findings.size}",
                        style = MaterialTheme.typography.titleSmall,
                        color = catColor,
                    )
                    Icon(
                        if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (expanded) {
                    g.findings.forEachIndexed { idx, f -> FindingItem(idx, f) }
                }
            }
        }
    }
}

@Composable
fun FindingItem(idx: Int, f: ReportModel.FindingView) {
    var expanded by remember { mutableStateOf(false) }
    Column(
        Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .clickable { expanded = !expanded }
            .animateContentSize(),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ConfidenceBadge(f.confidenceLabel)
            Text(
                f.ruleId.substringAfterLast('.'),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (expanded) {
            Column(Modifier.padding(top = 6.dp, start = 8.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(f.detail, style = MaterialTheme.typography.bodySmall)
                val src = runCatching { CollectorId.valueOf(f.collector).shortName }.getOrDefault(f.collector)
                Text(
                    stringResource(R.string.finding_source, src, f.ruleId, categoryLabel(f.category)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (f.raw.isNotEmpty()) {
                    Text(
                        stringResource(R.string.raw_observations),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    f.raw.forEach { (k, v) ->
                        Text(
                            "  $k = $v",
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

/** 威胁类别 → 严重度语义色（v18 token 化，明暗各自对比度）。 */
@Composable
fun categoryColor(category: Finding.Category): Color = with(severityColors()) {
    when (category) {
        Finding.Category.HOOK, Finding.Category.ZYGISK -> critical
        Finding.Category.ANTI_DETECT_PRESENT, Finding.Category.REPACKAGED -> warning
        else -> warning
    }
}

@Composable
fun EmptyPage(title: String, hint: String) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(title, style = MaterialTheme.typography.titleLarge)
        Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
