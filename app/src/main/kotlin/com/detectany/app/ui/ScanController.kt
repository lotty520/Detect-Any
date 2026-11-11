package com.detectany.app.ui

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.detectany.app.ScanOrchestrator
import com.detectany.core.engine.DetectionEngine
import com.detectany.core.model.CollectorId
import com.detectany.core.model.ScanTier
import com.detectany.feature.report.ReportExporter
import com.detectany.feature.report.ReportModel
import com.detectany.feature.report.ReportPresenter
import java.io.File

/**
 * 扫描会话状态（UI 唯一数据源）。
 * 报告与展示模型同源直译（specs/evidence-report「逐项一致」），UI 只渲染不加工。
 */
class ScanController(private val orchestrator: ScanOrchestrator) {

    var scanning by mutableStateOf(false)
        private set
    var reportModel by mutableStateOf<ReportModel?>(null)
        private set
    var rawReport by mutableStateOf<DetectionEngine.ScanReport?>(null)
        private set
    var lastTier by mutableStateOf<ScanTier?>(null)
        private set
    var statusLine by mutableStateOf<String?>(null)

    /** 扫描历史（最近 5 次，B1「对比上次」数据源） */
    val scanHistory = androidx.compose.runtime.mutableStateListOf<ReportModel>()
    private val maxHistory = 5

    fun runScan(tier: ScanTier, onDone: () -> Unit = {}) {
        if (scanning) return
        scanning = true
        statusLine = null
        Thread {
            val raw = orchestrator.scan(tier)
            rawReport = raw
            val model = ReportPresenter.present(raw)
            val prev = reportModel
            reportModel = model
            lastTier = tier
            // B1: 记录历史 + 计算 delta
            scanHistory.add(model)
            if (scanHistory.size > maxHistory) scanHistory.removeAt(0)
            lastDelta = prev?.let { computeDelta(it, model) }
            scanning = false
            onDone()
        }.start()
    }

    /** B1: Δ分数 + 新增/消失威胁 */
    var lastDelta by mutableStateOf<ScanDelta?>(null)
        private set

    data class ScanDelta(
        val scoreDiff: Int,
        val newThreats: List<String>,
        val goneThreats: List<String>,
    )

    private fun computeDelta(prev: ReportModel, curr: ReportModel): ScanDelta {
        val prevThreats = prev.findings.mapNotNull { it.framework }.toSet()
        val currThreats = curr.findings.mapNotNull { it.framework }.toSet()
        return ScanDelta(
            scoreDiff = curr.riskScore - prev.riskScore,
            newThreats = (currThreats - prevThreats).toList(),
            goneThreats = (prevThreats - currThreats).toList(),
        )
    }

    /** 导出当前报告；返回结果消息。 */
    fun exportReport(context: Context): String {
        val raw = rawReport ?: return "No report to export yet (run a scan first)"
        return runCatching {
            val json = ReportExporter.export(raw, appVersion = com.detectany.app.BuildConfig.VERSION_NAME)
            val dir = context.getExternalFilesDir(null) ?: context.cacheDir
            val out = File(dir, "detectany_report_${System.currentTimeMillis()}.json")
            out.writeText(json)
            out.absolutePath
        }.fold({ "Exported: $it" }, { "Export failed: ${it.message}" })
    }

    fun importSignature(jsonText: String) {
        statusLine = orchestrator.importSignatureUpdate(jsonText)
    }

    val hasFindings: Boolean get() = (reportModel?.findings?.size ?: 0) > 0
}

/** 分类标签中文。 */
val categoryLabel: (String) -> String = {
    when (it) {
        "ROOT_KERNEL" -> "Kernel Root"
        "ROOT_USERSPACE" -> "Userspace Root"
        "HOOK" -> "Hook Injection"
        "ZYGISK" -> "Zygisk Injection"
        "ATTESTATION_SPOOF" -> "Attestation Spoofing"
        "REPACKAGED" -> "Repackaged"
        "ANTI_DETECT_PRESENT" -> "Hiding Stack"
        "INSTRUMENTATION" -> "Dynamic Instrumentation"
        "VIRTUAL_ENV" -> "Virtual Environment"
        "EMULATOR" -> "Emulator"
        "NETWORK_MITM" -> "Network MITM"
        "AUTOMATION" -> "Automation"
        "SPEED_HACK" -> "Speed Hack"
        "GPS_SPOOF" -> "GPS Spoofing"
        "SCREEN_SHARE" -> "Screen Sharing"
        "REMOTE_CONTROL" -> "Remote Control"
        "OVERLAY_INJECTION" -> "Overlay Injection"
        else -> it
    }
}
