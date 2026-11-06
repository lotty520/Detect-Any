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
        val raw = rawReport ?: return "尚无报告可导出（先执行扫描）"
        return runCatching {
            val json = ReportExporter.export(raw)
            val dir = context.getExternalFilesDir(null) ?: context.cacheDir
            val out = File(dir, "detectany_report_${System.currentTimeMillis()}.json")
            out.writeText(json)
            out.absolutePath
        }.fold({ "已导出: $it" }, { "导出失败: ${it.message}" })
    }

    fun importSignature(jsonText: String) {
        statusLine = orchestrator.importSignatureUpdate(jsonText)
    }

    val hasFindings: Boolean get() = (reportModel?.findings?.size ?: 0) > 0
}

/** 分类标签中文。 */
val categoryLabel: (String) -> String = {
    when (it) {
        "ROOT_KERNEL" -> "内核 Root"
        "ROOT_USERSPACE" -> "用户态 Root"
        "HOOK" -> "Hook 注入"
        "ZYGISK" -> "Zygisk 注入"
        "ATTESTATION_SPOOF" -> "证明伪造"
        "REPACKAGED" -> "重打包"
        "ANTI_DETECT_PRESENT" -> "隐藏栈"
        else -> it
    }
}
