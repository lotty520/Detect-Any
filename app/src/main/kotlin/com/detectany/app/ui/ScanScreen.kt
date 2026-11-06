package com.detectany.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
fun ScanScreen(controller: ScanController, onOpenEvidence: () -> Unit) {
    val m = controller.reportModel
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Root / Hook / 伪装框架检测", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        // 主操作区
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            ScanButton(
                "L2 完整扫描", Icons.Filled.Radar, primary = true, enabled = !controller.scanning,
                subtitle = "全部 8 采集器 + 证明",
                modifier = Modifier.weight(1.6f),
            ) { controller.runScan(ScanTier.L2) }
            ScanButton(
                "L1 快扫", Icons.Filled.Bolt, primary = false, enabled = !controller.scanning,
                subtitle = "快信号 · 毫秒级",
                modifier = Modifier.weight(1f),
            ) { controller.runScan(ScanTier.L1) }
        }

        if (controller.scanning) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                CircularProgressIndicator()
                Text("采集中…（挂载取证 / supercall 探针 / 完整性校验）", style = MaterialTheme.typography.bodySmall)
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
            Modifier.padding(24.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(Icons.Filled.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.height(44.dp))
            Text("执行首次扫描", style = MaterialTheme.typography.titleLarge)
            Text(
                "覆盖 Magisk / KernelSU 系 / APatch / LSPosed / Zygisk 系 / TrickyStore / susfs 等 13 项目标，输出风险分与逐项证据",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ResultHero(m: ReportModel, controller: ScanController, onOpenEvidence: () -> Unit) {
    Card(shape = RoundedCornerShape(16.dp), elevation = CardDefaults.cardElevation(defaultElevation = 2.dp), modifier = Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(20.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ScoreGauge(score = m.riskScore, conclusive = m.conclusive)

            if (m.antiDetectPresent) {
                Text(
                    "⚠ 检出隐藏栈（反检测模块在运行）",
                    color = ScoreCritical,
                    style = MaterialTheme.typography.titleSmall,
                )
            }

            Text(
                "${m.tier} · ${m.elapsedMs}ms · 采集器 ${m.degradedCollectors.size} 降级",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace,
            )

            if (m.frameworkScores.isNotEmpty()) {
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    SectionHeader("框架命中")
                    m.frameworkScores.entries.sortedByDescending { it.value }.take(5).forEach { (fw, score) ->
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(fw, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "$score",
                                color = scoreColor(score),
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.titleSmall,
                            )
                        }
                    }
                }
            }

            if (m.findings.isNotEmpty()) {
                Button(onClick = onOpenEvidence, modifier = Modifier.fillMaxWidth()) {
                    Text("查看 ${m.findings.size} 条证据")
                }
            } else {
                Text("✓ 干净：无命中观测", color = ScoreClean, style = MaterialTheme.typography.titleMedium)
            }
        }
    }
}
