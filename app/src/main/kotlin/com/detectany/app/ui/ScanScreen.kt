package com.detectany.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.detectany.app.R
import com.detectany.app.ui.theme.MonoEmphasis
import com.detectany.core.model.ScanTier
import com.detectany.data.signature.BundledSignatureDb
import com.detectany.feature.report.ReportModel

/**
 * 首页：扫描主流程 + 重点结论概览。
 * 2026-11-12 v18 重排：三档统一分段选择器 + 单一主 CTA（修「三兄弟三布局/无主行动点」）；
 * 空态瘦身（3 亮点 stat + 跳转能力页，移除 12 域堆砌）。
 */
@Composable
fun ScanScreen(
    controller: ScanController,
    onOpenEvidence: (String?) -> Unit,
    onOpenCapabilities: () -> Unit = {},
) {
    val m = controller.reportModel
    var tier by remember { mutableStateOf(ScanTier.L2) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            stringResource(R.string.scan_subtitle),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // 主操作区：分段选择器 + 唯一主 CTA
        InfoCard(container = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f), elevation = 0.dp) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = tier == ScanTier.L1,
                    onClick = { tier = ScanTier.L1 },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 3),
                ) { Text(stringResource(R.string.tier_l1)) }
                SegmentedButton(
                    selected = tier == ScanTier.L2,
                    onClick = { tier = ScanTier.L2 },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 3),
                ) { Text(stringResource(R.string.tier_l2)) }
                SegmentedButton(
                    selected = tier == ScanTier.L3,
                    onClick = { tier = ScanTier.L3 },
                    shape = SegmentedButtonDefaults.itemShape(index = 2, count = 3),
                ) { Text(stringResource(R.string.tier_l3)) }
            }
            Text(
                tierDescription(tier),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = { controller.runScan(tier) },
                enabled = !controller.scanning,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = MaterialTheme.shapes.medium,
                colors = ButtonDefaults.buttonColors(),
            ) {
                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.start_scan), fontWeight = FontWeight.SemiBold)
            }
        }

        if (controller.scanning) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Text(
                    stringResource(R.string.scanning_status),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (m == null && !controller.scanning) {
            EmptyHero(onOpenCapabilities)
        } else if (m != null) {
            ResultHero(m, controller, onOpenEvidence)
        }

        controller.statusLine?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun tierDescription(tier: ScanTier): String = when (tier) {
    ScanTier.L1 -> stringResource(R.string.tier_l1_desc)
    ScanTier.L2 -> stringResource(R.string.tier_l2_desc, BundledSignatureDb.db.version)
    ScanTier.L3 -> stringResource(R.string.tier_l3_desc)
}

@Composable
private fun EmptyHero(onOpenCapabilities: () -> Unit) {
    InfoCard(elevation = 0.dp, container = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)) {
        Column(
            Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // 盾形主视觉：软底色圆托底（外层只做居中，尺寸交给内层——避免 padding 压扁圆形）
            Box(contentAlignment = Alignment.Center) {
                Box(
                    Modifier.size(72.dp).background(
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                        CircleShape,
                    ),
                )
                Icon(
                    Icons.Filled.Shield,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp),
                )
            }
            Text(stringResource(R.string.empty_title), style = MaterialTheme.typography.titleLarge)
            // 三个亮点 stat（原 12 域列表堆砌移除——能力清单归 Capabilities 页）
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatBlock(stringResource(R.string.stat_domains))
                StatDivider()
                StatBlock(stringResource(R.string.stat_frameworks))
                StatDivider()
                StatBlock(stringResource(R.string.stat_signals))
            }
            OutlinedButton(onClick = onOpenCapabilities, shape = MaterialTheme.shapes.medium) {
                Text(stringResource(R.string.browse_capabilities))
            }
        }
    }
}

@Composable
private fun StatBlock(label: String) {
    Text(
        label,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun StatDivider() {
    Box(
        Modifier
            .width(1.dp)
            .height(14.dp)
            .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)),
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ResultHero(m: ReportModel, controller: ScanController, onOpenEvidence: (String?) -> Unit) {
    InfoCard(elevation = 2.dp) {
        Column(
            Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ScoreGauge(score = m.riskScore, conclusive = m.conclusive)

            if (m.antiDetectPresent) {
                Text(
                    stringResource(R.string.hiding_stack),
                    color = severityColors().critical,
                    style = MaterialTheme.typography.titleSmall,
                )
            }

            // B1: 对比上次
            controller.lastDelta?.let { d ->
                DeltaCard(d)
            }

            Text(
                stringResource(R.string.scan_meta, m.tier, m.elapsedMs, m.degradedCollectors.size),
                style = MonoEmphasis.copy(fontSize = MaterialTheme.typography.bodySmall.fontSize),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (m.frameworkScores.isNotEmpty()) {
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SectionHeader(stringResource(R.string.framework_hits))
                    FlowRow(
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
                                shape = MaterialTheme.shapes.small,
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f),
                                ),
                            )
                        }
                    }
                }
            }

            if (m.findings.isNotEmpty()) {
                Button(
                    onClick = { onOpenEvidence(null) },
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.medium,
                ) {
                    Text(stringResource(R.string.view_findings, m.findings.size))
                }
            } else {
                Text(
                    stringResource(R.string.clean_no_findings),
                    color = severityColors().clean,
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }
    }
}

@Composable
private fun DeltaCard(d: ScanController.ScanDelta) {
    val sev = severityColors()
    val color = when {
        d.scoreDiff > 0 -> sev.critical
        d.scoreDiff < 0 -> sev.clean
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val arrow = when { d.scoreDiff > 0 -> "↑"; d.scoreDiff < 0 -> "↓"; else -> "→" }
    val diffText = if (d.scoreDiff != 0) {
        (if (d.scoreDiff > 0) "+" else "") + d.scoreDiff
    } else {
        stringResource(R.string.delta_no_change)
    }
    Column(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f), MaterialTheme.shapes.small)
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            "$arrow ${stringResource(R.string.delta_vs_last)} $diffText",
            color = color,
            style = MaterialTheme.typography.titleSmall,
        )
        if (d.newThreats.isNotEmpty()) {
            Text(
                stringResource(R.string.delta_new, d.newThreats.joinToString(", ")),
                style = MaterialTheme.typography.bodySmall,
                color = sev.critical,
            )
        }
        if (d.goneThreats.isNotEmpty()) {
            Text(
                stringResource(R.string.delta_gone, d.goneThreats.joinToString(", ")),
                style = MaterialTheme.typography.bodySmall,
                color = sev.clean,
            )
        }
        if (d.newThreats.isEmpty() && d.goneThreats.isEmpty()) {
            Text(
                stringResource(R.string.delta_stable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
