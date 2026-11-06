package com.detectany.core.engine

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.ScanTier
import com.detectany.core.rules.RulesEngine

/**
 * 检测引擎（任务 4.4）：编排采集器 → 规则 → 评分 → 分级输出。
 * L1 快通道（≤10ms 预算）：仅快采集器；L2 标准（≤100ms）；L3 异步证明由 feature:attestation 接线。
 */
class DetectionEngine(
    private val collectors: List<Collector>,
    private val rules: RulesEngine,
    private val scoreModel: ScoreModel = ScoreModel(),
    /** L1 快集合（快信号布尔：特征路径 + 属性） */
    private val fastCollectorIds: Set<CollectorId> = setOf(CollectorId.C1_PATH, CollectorId.C3_PROPERTY),
) {

    data class ScanReport(
        val tier: ScanTier,
        val verdict: ScanVerdict,
        val collectorResults: List<CollectorResult>,
        val degradedCollectors: List<CollectorId>,
        val elapsedMs: Long,
    ) {
        val l1Boolean: Boolean get() = verdict.conclusive
    }

    fun scan(input: ScanInput, tier: ScanTier = ScanTier.L2, extraFindings: List<Finding> = emptyList()): ScanReport {
        val start = System.nanoTime()
        val selected = when (tier) {
            ScanTier.L1 -> collectors.filter { it.id in fastCollectorIds }
            ScanTier.L2, ScanTier.L3 -> collectors
        }
        val results = selected.mapNotNull { c ->
            // 单项采集失败 MUST NOT 中断整体扫描（specs：采集能力降级透明）
            val t0 = System.nanoTime()
            val r = runCatching { c.collect(input) }.getOrElse {
                CollectorResult(c.id, CollectorResult.Status.BLOCKED, meta = mapOf("error" to (it.message ?: it.javaClass.simpleName)))
            }
            val ms = (System.nanoTime() - t0) / 1_000_000
            r.copy(meta = r.meta + ("elapsedMs" to ms.toString()))
        }
        val findings = results.flatMap { it.findings } + extraFindings
        val hits = rules.evaluate(findings)
        val verdict = scoreModel.score(findings, hits)
        val elapsed = (System.nanoTime() - start) / 1_000_000
        return ScanReport(
            tier = tier,
            verdict = verdict,
            collectorResults = results,
            degradedCollectors = results.filter { it.status != CollectorResult.Status.OK }.map { it.collector },
            elapsedMs = elapsed,
        )
    }
}
