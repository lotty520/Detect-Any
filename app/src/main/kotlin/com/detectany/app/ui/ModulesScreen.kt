package com.detectany.app.ui

import androidx.compose.animation.animateContentSize
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult

/**
 * 能力页（原模块页）：按「检测能力域」组织（文件与挂载环境 / 属性一致性 / 行为探针…），
 * 不暴露 C1-C8 工程件编号；域卡可展开看成员探针状态与耗时。
 */
@Composable
fun ModulesScreen(controller: ScanController) {
    val report = controller.rawReport
    if (report == null) {
        EmptyPage("尚无能力数据", "先在「扫描」页执行一次扫描")
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
                "${CapabilityDomain.entries.size} 个能力域 · ${results.count { it.status == CollectorResult.Status.OK }} 正常 · " +
                    "${results.count { it.status == CollectorResult.Status.DEGRADED }} 降级 · " +
                    "${results.count { it.status == CollectorResult.Status.BLOCKED }} 阻塞",
                style = MaterialTheme.typography.labelLarge,
            )
            Spacer(Modifier.weight(1f))
            Text(
                "总耗时 ${report.elapsedMs}ms",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(CapabilityDomain.entries.toList()) { domain ->
                DomainCard(domain, results)
            }
        }
    }
}

@Composable
private fun DomainCard(domain: CapabilityDomain, results: List<CollectorResult>) {
    var expanded by remember { mutableStateOf(false) }
    val members = results.filter { it.collector in domain.members }
    if (members.isEmpty()) return
    val totalMs = members.sumOf { it.meta["elapsedMs"]?.toLongOrNull() ?: 0L }
    val worstStatus = members.minByOrNull { it.status.ordinal }?.status ?: CollectorResult.Status.BLOCKED
    val hitCount = members.sumOf { it.findings.size }

    Card(
        shape = RoundedCornerShape(14.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp).animateContentSize()) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded },
            ) {
                Column(Modifier.weight(1f)) {
                    Text(domain.title, style = MaterialTheme.typography.titleSmall)
                    Text(domain.desc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (hitCount > 0) {
                    Text("$hitCount", style = MaterialTheme.typography.titleSmall, color = BadgeStrong)
                }
                Text(
                    if (totalMs > 0) "${totalMs}ms" else "—",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                StatusChip(worstStatus.name)
                Icon(
                    if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (expanded) {
                members.forEach { r ->
                    Row(
                        Modifier.fillMaxWidth().padding(top = 8.dp, start = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(r.collector.shortName, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        val ms = r.meta["elapsedMs"]
                        if (ms != null) {
                            Text(
                                "${ms}ms",
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Text(
                            if (r.findings.isEmpty()) "无命中" else "${r.findings.size}",
                            style = MaterialTheme.typography.labelMedium,
                            color = if (r.findings.isEmpty()) ScoreClean else BadgeStrong,
                        )
                        StatusChip(r.status.name)
                    }
                    r.meta.filterKeys { it !in setOf("elapsedMs", "error") }.entries.take(3).forEach { (k, v) ->
                        val humanKey = when (k) {
                            "unixGate" -> "套接字通道"
                            "probed" -> "已探测路径数"
                            "count" -> "属性总数"
                            "mounts" -> "挂载条目"
                            "tmpfs" -> "tmpfs 挂载"
                            "mappings" -> "内存映射"
                            "execAnon" -> "匿名可执行段"
                            "stdev" -> "设备号采样"
                            "ksuRet" -> "KSU supercall"
                            "apatchRet" -> "APatch supercall"
                            "apatchNs" -> "APatch 耗时(ns)"
                            "nativebridgeError" -> "NativeBridge"
                            "ptraceMsg" -> "ptrace 残留"
                            "ppid" -> "父进程PID"
                            else -> k
                        }
                        Text(
                            "  $humanKey = $v",
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    r.meta["error"]?.let {
                        Text("  错误: $it", style = MaterialTheme.typography.bodySmall, color = StatusBlocked)
                    }
                }
            }
        }
    }
}
