package com.detectany.feature.attestation

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * C13 硬件证明采集器（P2-1，2026-11-11）：把 AttestationService 接入 Collector 管道——
 * L3 档专用（DetectionEngine 注入），L1/L2 永不触发（Keymaster 慢/无响应不得拖垮快扫）。
 *
 * 超时治理：service.run()（含 KeyPairGenerator 同步等待 Keymaster）跑在专用单线程，
 * [timeoutMs] 预算内未返回 → DEGRADED + 超时 info finding（不采信不误报——specs 契约）。
 *
 * challenge 新鲜性：AttestationClient 每次调用内生成 32 字节 SecureRandom 并嵌入
 * attestation 扩展，Verifier echo 校验证明「链为本调用现铸」——扫描级防重放已满足；
 * 外部 nonce 绑定属服务端流程（Play Integrity 域，不在此层）。
 */
class AttestationCollector(
    private val service: AttestationService,
    private val timeoutMs: Long = 5000L,
) : Collector {

    override val id: CollectorId = CollectorId.C13_ATTESTATION

    // 2026-11-11 华为真机实证：单线程池被一次超时的卡死任务占用后，后续扫描必然
    // 排队饿死 → 永久 timeout。改为 volatile 引用 + 超时后 shutdownNow 重建。
    @Volatile
    private var executor: java.util.concurrent.ExecutorService = newExecutor()

    private fun newExecutor(): java.util.concurrent.ExecutorService =
        Executors.newSingleThreadExecutor { r ->
            Thread(r, "DetectAny-Attest").apply { isDaemon = true }
        }

    override fun collect(input: ScanInput): CollectorResult = try {
        val future = executor.submit { runCatching { service.run() }.getOrNull() }
        val outcome = try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            android.util.Log.w("C13", "attestation timeout after ${timeoutMs}ms; recycling executor")
            future.cancel(true)
            // 卡死任务可能不响应中断继续占用线程——丢弃整个池重建，后续扫描不再饿死
            runCatching { executor.shutdownNow() }
            executor = newExecutor()
            null
        }

        when (outcome) {
            null -> CollectorResult(
                collector = id,
                status = CollectorResult.Status.DEGRADED,
                findings = listOf(timeoutInfo()),
                meta = mapOf("attest" to "timeout", "budgetMs" to timeoutMs.toString()),
            )
            is AttestationService.Outcome.Trusted -> CollectorResult(
                collector = id,
                status = CollectorResult.Status.OK,
                findings = outcome.findings,
                meta = mapOf(
                    "attest" to "trusted",
                    "verdict" to "hardware-backed chain verified",
                    "patchLevel" to (outcome.description.rootOfTrust?.verifiedBootState?.toString() ?: "?"),
                ),
            )
            is AttestationService.Outcome.Degraded -> CollectorResult(
                collector = id,
                status = CollectorResult.Status.DEGRADED,
                findings = outcome.findings,
                meta = mapOf("attest" to "degraded", "reason" to outcome.reason.take(120)),
            )
            is AttestationService.Outcome.SpoofSuspected -> CollectorResult(
                collector = id,
                status = CollectorResult.Status.OK,
                findings = outcome.findings,
                meta = mapOf("attest" to "spoof_suspected", "reason" to outcome.reason.take(120)),
            )
            else -> CollectorResult(collector = id, status = CollectorResult.Status.DEGRADED, meta = mapOf("attest" to "unreachable"))
        }
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    private fun timeoutInfo() = Finding(
        ruleId = "attest.degraded.timeout",
        collector = id,
        confidence = Confidence.C,
        category = Finding.Category.ATTESTATION_SPOOF,
        framework = null,
        detail = "Hardware attestation exceeded ${timeoutMs}ms budget (Keymaster cold start / throttling) — collect, do not trust",
        raw = mapOf("budgetMs" to timeoutMs.toString()),
    )
}
