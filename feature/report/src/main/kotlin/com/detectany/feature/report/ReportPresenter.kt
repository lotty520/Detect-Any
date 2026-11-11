package com.detectany.feature.report

import com.detectany.core.engine.DetectionEngine
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * 报告展示模型（任务 7.1/7.2）：UI 渲染的唯一数据源——「逐项与引擎输出一致」由
 * Presenter 直译保证（无二次加工），单测断言全量一致性。
 */
data class ReportModel(
    val tier: String,
    val riskScore: Int,
    val conclusive: Boolean,
    val categories: List<String>,
    val frameworkScores: Map<String, Int>,
    val antiDetectPresent: Boolean,
    val findings: List<FindingView>,
    val degradedCollectors: List<String>,
    val elapsedMs: Long,
) {
    data class FindingView(
        val ruleId: String,
        val collector: String,
        /** 强/中/弱 */
        val confidenceLabel: String,
        val category: String,
        val framework: String?,
        val detail: String,
        /** 证据回放：原始观测键值（已脱敏形态） */
        val raw: Map<String, String>,
    )
}

object ReportPresenter {

    fun present(report: DetectionEngine.ScanReport): ReportModel = ReportModel(
        tier = report.tier.name,
        riskScore = report.verdict.riskScore,
        conclusive = report.verdict.conclusive,
        categories = report.verdict.categories.map { it.name },
        frameworkScores = report.verdict.frameworkScores,
        antiDetectPresent = report.verdict.antiDetectPresent,
        findings = report.collectorResults.flatMap { r -> r.findings }.map { it.toView() },
        degradedCollectors = report.degradedCollectors.map { it.name },
        elapsedMs = report.elapsedMs,
    )

    private fun Finding.toView() = ReportModel.FindingView(
        ruleId = ruleId,
        collector = collector.name,
        confidenceLabel = when (confidence) {
            Confidence.A -> "强"
            Confidence.B -> "中"
            Confidence.C -> "弱"
        },
        category = category.name,
        framework = framework,
        detail = detail,
        raw = raw.mapValues { Redactor.redactValue(ruleId, it.key, it.value) },
    )
}

/**
 * 出端脱敏（specs/evidence-report「呈现与出端分离」）：
 * 属性类观测只出哈希；路径/socket 名等特征条目自身可出；其余值截断。
 */
object Redactor {
    private val HASH_KEYS = setOf("valueHash")

    fun redactValue(ruleId: String, key: String, value: String): String = when {
        key in HASH_KEYS -> value // 本就为哈希
        ruleId.startsWith("prop.") && key == "key" -> value.hashCode().toString()
        value.length > 96 -> value.take(96) + "…"
        else -> value
    }

    /** detail 中出现的属性键明文同样以哈希形态替换（specs：出端仅哈希化属性键）。 */
    fun redactDetail(ruleId: String, detail: String, raw: Map<String, String>): String {
        if (!ruleId.startsWith("prop.")) return detail
        val plainKey = raw["key"] ?: return detail
        return detail.replace(plainKey, "#${plainKey.hashCode()}")
    }
}

/**
 * 结构化导出（任务 7.3）：完整证据向量 + 脱敏；JSON 文本由调用方落盘/分享。
 */
object ReportExporter {

    @Serializable
    data class ExportedReport(
        val exportedAtMs: Long,
        val appVersion: String,
        val schemaVersion: Int = 1, // 2026-11-10 审计：导出格式演进保护（消费方可按版本分支）
        val tier: String,
        val riskScore: Int,
        val conclusive: Boolean,
        val categories: List<String>,
        val frameworkScores: Map<String, Int>,
        val evidenceVector: List<String>,
        val findings: List<ExportedFinding>,
        val degradedCollectors: List<String>,
        val elapsedMs: Long,
    ) {
        @Serializable
        data class ExportedFinding(
            val ruleId: String,
            val collector: String,
            val confidence: String,
            val category: String,
            val framework: String?,
            val detail: String,
            val raw: Map<String, String>,
        )
    }

    fun export(
        report: DetectionEngine.ScanReport,
        appVersion: String = "0.1.0",
        nowMs: Long = System.currentTimeMillis(),
    ): String {
        val findings = report.collectorResults.flatMap { r -> r.findings }
        val model = ExportedReport(
            exportedAtMs = nowMs,
            appVersion = appVersion,
            tier = report.tier.name,
            riskScore = report.verdict.riskScore,
            conclusive = report.verdict.conclusive,
            categories = report.verdict.categories.map { it.name },
            frameworkScores = report.verdict.frameworkScores,
            evidenceVector = report.verdict.evidenceVector,
            findings = findings.map {
                ExportedReport.ExportedFinding(
                    ruleId = it.ruleId,
                    collector = it.collector.name,
                    confidence = it.confidence.name,
                    category = it.category.name,
                    framework = it.framework,
                    detail = Redactor.redactDetail(it.ruleId, it.detail, it.raw),
                    raw = it.raw.mapValues { v -> Redactor.redactValue(it.ruleId, v.key, v.value) },
                )
            },
            degradedCollectors = report.degradedCollectors.map { it.name },
            elapsedMs = report.elapsedMs,
        )
        return Json { prettyPrint = true }.encodeToString(ExportedReport.serializer(), model)
    }
}
