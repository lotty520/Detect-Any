package com.detectany.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.detectany.core.model.ScanTier
import com.detectany.feature.report.ReportModel

/** 首页：扫描主流程 + 重点结论概览。 */
@Composable
fun ScanScreen(controller: ScanController, onOpenEvidence: (String?) -> Unit) {
    val m = controller.reportModel
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Root / Hook / Spoofing Detection", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        // 主操作区
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            ScanButton(
                "L2 Full Scan", Icons.Filled.Radar, primary = true, enabled = !controller.scanning,
                subtitle = "All 12 collectors · signature DB v17",
                modifier = Modifier.weight(1.6f),
            ) { controller.runScan(ScanTier.L2) }
            ScanButton(
                "L1 Quick Scan", Icons.Filled.Bolt, primary = false, enabled = !controller.scanning,
                subtitle = "Fast signals · milliseconds",
                modifier = Modifier.weight(1f),
            ) { controller.runScan(ScanTier.L1) }
        }

        // P2-1：L3 深度档（L2 + 硬件证明，C13 采集器 L3 专用注入）
        ScanButton(
            "L3 Deep Scan", Icons.Filled.Verified, primary = false, enabled = !controller.scanning,
            subtitle = "L2 + hardware key attestation · seconds",
            modifier = Modifier.fillMaxWidth(),
        ) { controller.runScan(ScanTier.L3) }

        if (controller.scanning) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Text(
                    "Scanning · mount forensics / supercall probes / instruction integrity",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (m == null && !controller.scanning) {
            EmptyHero()
        } else if (m != null) {
            ResultHero(m, controller, onOpenEvidence)
        }

        controller.statusLine?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ScanButton(
    label: String,
    icon: ImageVector,
    primary: Boolean,
    enabled: Boolean,
    subtitle: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (!enabled) MaterialTheme.colorScheme.surfaceVariant
            else if (primary) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondaryContainer,
        ),
        modifier = modifier,
        onClick = onClick.takeIf { enabled } ?: {},
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Icon(icon, contentDescription = label, tint = if (primary && enabled) Color.White else MaterialTheme.colorScheme.onSurface)
            Text(label, style = MaterialTheme.typography.titleMedium, color = if (primary && enabled) Color.White else MaterialTheme.colorScheme.onSurface)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = if (primary && enabled) Color.White.copy(alpha = 0.8f) else MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun EmptyHero() {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            Modifier.padding(20.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(Icons.Filled.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.height(44.dp))
            Text("Run your first scan", style = MaterialTheme.typography.titleLarge)
            Text(
                "12 capability domains · 25+ target frameworks",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
            )
            // B6: 能力域一览（首次引导）
            CapabilityDomain.entries.forEach { domain ->
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("·", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
                    Column {
                        Text(domain.title, style = MaterialTheme.typography.bodySmall)
                        Text(domain.desc, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            Text(
                "Weighted risk score (0-100) + threat breakdown + per-item evidence replay",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ResultHero(m: ReportModel, controller: ScanController, onOpenEvidence: (String?) -> Unit) {
    Card(shape = RoundedCornerShape(16.dp), elevation = CardDefaults.cardElevation(defaultElevation = 2.dp), modifier = Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(20.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ScoreGauge(score = m.riskScore, conclusive = m.conclusive)

            if (m.antiDetectPresent) {
                Text(
                    "⚠ Hiding stack detected (anti-detection module active)",
                    color = ScoreCritical,
                    style = MaterialTheme.typography.titleSmall,
                )
            }

            // B1: 对比上次
            controller.lastDelta?.let { d ->
                DeltaCard(d)
            }

            Text(
                "${m.tier} · ${m.elapsedMs}ms · ${m.degradedCollectors.size} collector(s) degraded",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace,
            )

            if (m.frameworkScores.isNotEmpty()) {
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SectionHeader("Framework Hits")
                    androidx.compose.foundation.layout.FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        m.frameworkScores.entries.sortedByDescending { it.value }.forEach { (fw, score) ->
                            AssistChip(
                                onClick = { onOpenEvidence(fw) },
                                label = { Text(fw) },
                                leadingIcon = {
                                    Text(
                                        "$score",
                                        color = scoreColor(score),
                                        fontFamily = FontFamily.Monospace,
                                        style = MaterialTheme.typography.labelMedium,
                                    )
                                },
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                ),
                            )
                        }
                    }
                }
            }

            if (m.findings.isNotEmpty()) {
                Button(onClick = { onOpenEvidence(null) }, modifier = Modifier.fillMaxWidth()) {
                    Text("View ${m.findings.size} findings")
                }
            } else {
                Text("✓ Clean: no findings", color = ScoreClean, style = MaterialTheme.typography.titleMedium)
            }
        }
    }
}

@Composable
private fun DeltaCard(d: ScanController.ScanDelta) {
    val scoreColor = when {
        d.scoreDiff > 0 -> ScoreCritical
        d.scoreDiff < 0 -> ScoreClean
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val arrow = when { d.scoreDiff > 0 -> "↑"; d.scoreDiff < 0 -> "↓"; else -> "→" }
    Card(
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                "$arrow vs last ${if (d.scoreDiff != 0) "${if (d.scoreDiff > 0) "+" else ""}${d.scoreDiff}" else "no change"}",
                color = scoreColor,
                style = MaterialTheme.typography.titleSmall,
            )
            if (d.newThreats.isNotEmpty()) {
                Text("New: ${d.newThreats.joinToString(", ")}", style = MaterialTheme.typography.bodySmall, color = ScoreCritical)
            }
            if (d.goneThreats.isNotEmpty()) {
                Text("Gone: ${d.goneThreats.joinToString(", ")}", style = MaterialTheme.typography.bodySmall, color = ScoreClean)
            }
            if (d.newThreats.isEmpty() && d.goneThreats.isEmpty()) {
                Text("No environment change", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
