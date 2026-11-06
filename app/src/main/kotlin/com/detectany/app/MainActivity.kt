package com.detectany.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.detectany.core.engine.DetectionEngine
import com.detectany.core.model.ScanTier
import com.detectany.feature.report.ReportExporter
import com.detectany.feature.report.ReportModel
import com.detectany.feature.report.ReportPresenter
import java.io.File

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val orchestrator = ScanOrchestrator(applicationContext)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ScanScreen(orchestrator)
                }
            }
        }
    }
}

@Composable
fun ScanScreen(orchestrator: ScanOrchestrator) {
    val context = LocalContext.current
    var report by remember { mutableStateOf<ReportModel?>(null) }
    var rawReport by remember { mutableStateOf<DetectionEngine.ScanReport?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var statusLine by remember { mutableStateOf<String?>(null) }

    fun runScan(tier: ScanTier) {
        scanning = true
        statusLine = null
        Thread {
            val raw = orchestrator.scan(tier)
            rawReport = raw
            report = ReportPresenter.present(raw)
            scanning = false
        }.start()
    }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            statusLine = "已取消导入"
        } else {
            runCatching {
                context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
            }.getOrNull()?.let { text ->
                statusLine = orchestrator.importSignatureUpdate(text)
            } ?: run { statusLine = "导入失败：无法读取文件" }
        }
    }

    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Detect-Any", style = MaterialTheme.typography.headlineMedium)
        Text("Root / Hook / 伪装框架检测 · 工业级", style = MaterialTheme.typography.bodySmall)

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ActionButton("L1 快扫", scanning) { runScan(ScanTier.L1) }
            ActionButton("L2 标准扫描", scanning) { runScan(ScanTier.L2) }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ActionButton("导出报告", scanning) {
                val raw = rawReport
                if (raw == null) {
                    statusLine = "尚无报告可导出（先执行扫描）"
                } else {
                    runCatching {
                        val json = ReportExporter.export(raw)
                        val dir = context.getExternalFilesDir(null) ?: context.cacheDir
                        val out = File(dir, "detectany_report_${System.currentTimeMillis()}.json")
                        out.writeText(json)
                        out.absolutePath
                    }.fold(
                        onSuccess = { statusLine = "已导出: $it" },
                        onFailure = { statusLine = "导出失败: ${it.message}" },
                    )
                }
            }
            ActionButton("导入特征", scanning) {
                statusLine = "选择特征文件…"
                importLauncher.launch(arrayOf("application/json", "text/*", "*/*"))
            }
        }

        statusLine?.let { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
        if (scanning) CircularProgressIndicator()

        report?.let { m -> ReportView(m) }
    }
}

@Composable
private fun ActionButton(label: String, disabled: Boolean, onClick: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(10.dp),
        color = if (disabled) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.primary,
        modifier = Modifier.clickable(enabled = !disabled, onClick = onClick),
    ) {
        Text(
            label,
            color = if (disabled) MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f) else MaterialTheme.colorScheme.onPrimary,
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 10.dp),
        )
    }
}

@Composable
fun ReportView(m: ReportModel) {
    val scoreColor = when {
        m.riskScore >= 70 -> Color(0xFFC62828)
        m.riskScore >= 40 -> Color(0xFFEF6C00)
        else -> Color(0xFF2E7D32)
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                "${m.riskScore}",
                style = MaterialTheme.typography.displayMedium,
                color = scoreColor,
                fontFamily = FontFamily.Monospace,
            )
            Column {
                Text(if (m.conclusive) "检出（判定性证据成立）" else "未达定性", style = MaterialTheme.typography.titleSmall)
                Text("${m.tier} · ${m.elapsedMs}ms · 降级采集 ${m.degradedCollectors.size}", style = MaterialTheme.typography.bodySmall)
                if (m.antiDetectPresent) {
                    Text("⚠ 隐藏栈特征", color = Color(0xFFC62828), style = MaterialTheme.typography.titleSmall)
                }
            }
        }

        if (m.frameworkScores.isNotEmpty()) {
            Text("框架命中", style = MaterialTheme.typography.titleSmall)
            m.frameworkScores.entries.sortedByDescending { it.value }.forEach { (fw, score) ->
                Text("· $fw  $score", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        }

        Text("命中明细（点击展开证据回放）", style = MaterialTheme.typography.titleSmall)
        LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f, fill = false)) {
            items(m.findings, key = { it.ruleId }) { f ->
                FindingItem(f)
            }
        }
        if (m.findings.isEmpty()) {
            Text("干净：无命中观测", color = Color(0xFF2E7D32))
        }
    }
}

@Composable
fun FindingItem(f: ReportModel.FindingView) {
    var expanded by remember { mutableStateOf(false) }
    val badgeColor = when (f.confidenceLabel) {
        "强" -> Color(0xFFC62828)
        "中" -> Color(0xFFEF6C00)
        else -> Color(0xFF757575)
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .animateContentSize()
            .clickable { expanded = !expanded },
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                f.confidenceLabel,
                color = Color.White,
                modifier = Modifier
                    .background(badgeColor, RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 1.dp),
                style = MaterialTheme.typography.labelSmall,
            )
            Text(
                f.framework ?: f.category,
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(f.ruleId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        }
        if (expanded) {
            Column(modifier = Modifier.padding(top = 4.dp, start = 8.dp)) {
                Text(f.detail, style = MaterialTheme.typography.bodySmall)
                Text("采集器: ${f.collector} · 分类: ${f.category}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (f.raw.isNotEmpty()) {
                    Text("原始观测:", style = MaterialTheme.typography.labelSmall)
                    f.raw.forEach { (k, v) ->
                        Text("  $k = $v", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
