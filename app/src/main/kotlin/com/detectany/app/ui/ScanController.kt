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

    fun runScan(tier: ScanTier, onDone: () -> Unit = {}) {
        if (scanning) return
        scanning = true
        statusLine = null
        Thread {
            val raw = orchestrator.scan(tier)
            rawReport = raw
            reportModel = ReportPresenter.present(raw)
            lastTier = tier
            scanning = false
            onDone()
        }.start()
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

/** 采集器中文显示名（证据页/模块页分组标题）。 */
val CollectorId.displayName: String
    get() = when (this) {
        CollectorId.C1_PATH -> "C1 · 路径探测"
        CollectorId.C2_MOUNT -> "C2 · 挂载与设备号"
        CollectorId.C3_PROPERTY -> "C3 · 属性快照"
        CollectorId.C4_ENDPOINT -> "C4 · 网络端点"
        CollectorId.C5_APP_FINGERPRINT -> "C5 · 应用指纹"
        CollectorId.C6_MEMORY_MAP -> "C6 · 内存映射"
        CollectorId.C7_CODE_INTEGRITY -> "C7 · 指令完整性"
        CollectorId.C8_BEHAVIOR -> "C8 · 接口行为"
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
