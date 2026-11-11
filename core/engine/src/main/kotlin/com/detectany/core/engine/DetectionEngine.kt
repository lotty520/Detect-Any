package com.detectany.core.engine

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.ScanTier
import com.detectany.core.rules.RulesEngine
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * 检测引擎（任务 4.4 + 时延优化 2026-11-06）：
 * - 并行采集器执行（L2: 总耗时 ≈ max(单采集器) 而非 sum）
 * - L1 快通道（≤10ms）：仅 C1 路径 + C3 属性，共享 daemon 线程池
 * - 逐采集器耗时注入 meta
 */
class DetectionEngine(
    private val collectors: List<Collector>,
    private val rules: RulesEngine,
    private val scoreModel: ScoreModel = ScoreModel(),
    /** P2-1：L3 档专属采集器（硬件证明）；null = L3 退化为 L2 同集 */
    private val attestationCollector: Collector? = null,
    /** L1 快集合 */
    private val fastCollectorIds: Set<CollectorId> = setOf(CollectorId.C1_PATH, CollectorId.C3_PROPERTY),
    /** 并行线程池（daemon：不阻塞 JVM 退出；IO 型采集器为主，核数即够） */
    private val executor: ExecutorService = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors().coerceIn(2, 4),
    ) { r ->
        Thread(r, "DetectAny-Collector").apply { isDaemon = true }
    },
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
            ScanTier.L2 -> collectors
            ScanTier.L3 -> collectors + listOfNotNull(attestationCollector)
        }

        // 并行执行全部选中采集器（单项失败不中断整体，specs：降级透明）
        val futures = selected.associateWith { c ->
            CompletableFuture.supplyAsync({
                val t0 = System.nanoTime()
                val r = runCatching { c.collect(input) }.getOrElse {
                    CollectorResult(c.id, CollectorResult.Status.BLOCKED, meta = mapOf("error" to (it.message ?: it.javaClass.simpleName)))
                }
                val ms = (System.nanoTime() - t0) / 1_000_000
                r.copy(meta = r.meta + ("elapsedMs" to ms.toString()))
            }, executor)
        }

        // 等待全部完成，按原始顺序返回
        val results = selected.mapNotNull { c ->
            futures[c]?.join()
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

    fun shutdown() {
        executor.shutdown()
    }
}
