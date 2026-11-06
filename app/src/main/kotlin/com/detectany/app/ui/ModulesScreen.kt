package com.detectany.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult

/** 模块页：采集器矩阵（状态 / 耗时 / 命中数 / 元信息）——分模块显示的核心页。 */
@Composable
fun ModulesScreen(controller: ScanController) {
    val report = controller.rawReport
    if (report == null) {
        EmptyPage("尚无模块数据", "先在「扫描」页执行一次扫描")
        return
    }
    val results = report.collectorResults

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "${results.count { it.status == CollectorResult.Status.OK }} 正常 · " +
                    "${results.count { it.status == CollectorResult.Status.DEGRADED }} 降级 · " +
                    "${results.count { it.status == CollectorResult.Status.BLOCKED }} 阻塞",
                style = MaterialTheme.typography.labelLarge,
            )
            androidx.compose.foundation.layout.Spacer(Modifier.weight(1f))
            Text(
                "总耗时 ${report.elapsedMs}ms",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            itemsIndexed(results, key = { _, r -> r.collector }) { _, r ->
                ModuleCard(r)
            }
        }
    }
}

@Composable
private fun ModuleCard(r: CollectorResult) {
    Card(shape = RoundedCornerShape(12.dp), elevation = CardDefaults.cardElevation(defaultElevation = 1.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(r.collector.displayName, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                val ms = r.meta["elapsedMs"]
                if (ms != null) {
                    Text(
                        "${ms}ms",
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                StatusChip(r.status.name)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    if (r.findings.isEmpty()) "无命中" else "命中 ${r.findings.size}",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (r.findings.isEmpty()) ScoreClean else ScoreCritical,
                )
                r.meta.filterKeys { it !in setOf("elapsedMs", "error") }.entries.take(4).forEach { (k, v) ->
                    Text("$k=$v", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            r.meta["error"]?.let {
                Text("错误: $it", style = MaterialTheme.typography.bodySmall, color = StatusBlocked)
            }
        }
    }
}
