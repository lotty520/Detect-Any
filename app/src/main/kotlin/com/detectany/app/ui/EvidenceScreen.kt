package com.detectany.app.ui

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import com.detectany.feature.report.ReportModel

/** 证据页：按采集器模块分组 + 置信概览 + 逐项证据回放。 */
@Composable
fun EvidenceScreen(controller: ScanController) {
    val m = controller.reportModel
    if (m == null) {
        EmptyPage("尚无证据", "先在「扫描」页执行一次扫描")
        return
    }
    val groups = remember(m) {
        m.findings.groupBy { it.collector }.entries
            .sortedBy { (id, _) -> CollectorId.entries.indexOf(CollectorId.valueOf(id)) }
    }

    Column(Modifier.fillMaxSize()) {
        if (m.findings.isEmpty()) {
            Column(
                Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text("✓ 干净：无命中观测", color = ScoreClean, style = MaterialTheme.typography.titleMedium)
                Text("本次扫描未产生任何证据", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val strong = m.findings.count { it.confidenceLabel == "强" }
            val medium = m.findings.count { it.confidenceLabel == "中" }
            val weak = m.findings.count { it.confidenceLabel == "弱" }
            SummaryPill("强 $strong", BadgeStrong)
            SummaryPill("中 $medium", BadgeMedium)
            SummaryPill("弱 $weak", BadgeWeak)
            Spacer(Modifier.weight(1f))
            Text("${m.findings.size} 条", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(groups, key = { it.key }) { entry ->
                CollectorGroup(entry.key, entry.value)
            }
        }
    }
}

@Composable
private fun CollectorGroup(collectorId: String, findings: List<ReportModel.FindingView>) {
    var expanded by remember { mutableStateOf(false) }
    val worst = if (findings.any { it.confidenceLabel == "强" }) "强"
    else if (findings.any { it.confidenceLabel == "中" }) "中" else "弱"
    val displayName = runCatching { CollectorId.valueOf(collectorId).displayName }.getOrDefault(collectorId)

    Card(shape = RoundedCornerShape(12.dp), elevation = CardDefaults.cardElevation(defaultElevation = 1.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp).animateContentSize()) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded },
            ) {
                Text(displayName, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                ConfidenceBadge(worst)
                Text("${findings.size}", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Icon(
                    if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (expanded) {
                findings.forEachIndexed { idx, f -> FindingItem(idx, f) }
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
            Text(f.framework ?: categoryLabel(f.category), style = MaterialTheme.typography.bodyMedium)
            Text(
                f.ruleId.substringAfterLast('.'),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
                maxLines = 1,
            )
        }
        if (expanded) {
            Column(Modifier.padding(top = 6.dp, start = 8.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(f.detail, style = MaterialTheme.typography.bodySmall)
                Text(
                    "规则 ${f.ruleId} · 采集器 ${f.collector} · 分类 ${categoryLabel(f.category)}",
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
