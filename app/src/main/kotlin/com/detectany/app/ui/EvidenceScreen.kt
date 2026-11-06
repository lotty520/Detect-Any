package com.detectany.app.ui

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.feature.report.ReportModel

/**
 * 威胁页（原证据页）：按「威胁」组织——用户心智：我中了什么、多严重、证据是什么。
 */
@Composable
fun EvidenceScreen(controller: ScanController) {
    val m = controller.reportModel
    if (m == null) {
        EmptyPage("尚无结果", "先在「扫描」页执行一次扫描")
        return
    }
    var filterConfidence by remember { mutableStateOf<String?>(null) }

    val filtered = remember(m, filterConfidence) {
        if (filterConfidence == null) m.findings
        else m.findings.filter { it.confidenceLabel == filterConfidence }
    }
    val groups = remember(filtered) { groupByThreat(filtered) }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val strong = m.findings.count { it.confidenceLabel == "强" }
            val medium = m.findings.count { it.confidenceLabel == "中" }
            val weak = m.findings.count { it.confidenceLabel == "弱" }
            FilterChip(
                selected = filterConfidence == "强",
                onClick = { filterConfidence = if (filterConfidence == "强") null else "强" },
                label = { Text("强 $strong") },
                leadingIcon = { Box(Modifier.size(8.dp).background(BadgeStrong, RoundedCornerShape(4.dp))) },
            )
            FilterChip(
                selected = filterConfidence == "中",
                onClick = { filterConfidence = if (filterConfidence == "中") null else "中" },
                label = { Text("中 $medium") },
                leadingIcon = { Box(Modifier.size(8.dp).background(BadgeMedium, RoundedCornerShape(4.dp))) },
            )
            FilterChip(
                selected = filterConfidence == "弱",
                onClick = { filterConfidence = if (filterConfidence == "弱") null else "弱" },
                label = { Text("弱 $weak") },
                leadingIcon = { Box(Modifier.size(8.dp).background(BadgeWeak, RoundedCornerShape(4.dp))) },
            )
            Spacer(Modifier.weight(1f))
            Text(
                "${groups.size} 个威胁 · ${m.findings.size} 条证据",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
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
    val catColor = categoryColor(g.category)
    val worstLabel = when (g.worst) { Confidence.A -> "强"; Confidence.B -> "中"; else -> "弱" }

    Card(
        shape = RoundedCornerShape(14.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = if (g.worst == Confidence.A) 2.dp else 1.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp).animateContentSize()) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded },
            ) {
                Column(Modifier.weight(1f)) {
                    Text(g.name, style = MaterialTheme.typography.titleMedium)
                    if (g.desc.isNotEmpty()) {
                        Text(g.desc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                ConfidenceBadge(worstLabel)
                Text("${g.findings.size}", style = MaterialTheme.typography.titleSmall, color = catColor)
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
            Text(f.ruleId.substringAfterLast('.'), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f), maxLines = 1)
        }
        if (expanded) {
            Column(Modifier.padding(top = 6.dp, start = 8.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(f.detail, style = MaterialTheme.typography.bodySmall)
                val src = runCatching { CollectorId.valueOf(f.collector).shortName }.getOrDefault(f.collector)
                Text(
                    "来源: $src · 规则 ${f.ruleId} · 分类 ${categoryLabel(f.category)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (f.raw.isNotEmpty()) {
                    Text("原始观测:", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    f.raw.forEach { (k, v) ->
                        Text("  $k = $v", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

fun categoryColor(category: Finding.Category): Color = when (category) {
    Finding.Category.HOOK, Finding.Category.ZYGISK -> BadgeStrong
    Finding.Category.ANTI_DETECT_PRESENT, Finding.Category.REPACKAGED -> ScoreWarning
    else -> BadgeMedium
}

@Composable
private fun SummaryPill(label: String, color: Color) {
    Text(
        label,
        color = Color.White,
        style = MaterialTheme.typography.labelMedium,
        modifier = Modifier
            .background(color, RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 3.dp),
    )
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
