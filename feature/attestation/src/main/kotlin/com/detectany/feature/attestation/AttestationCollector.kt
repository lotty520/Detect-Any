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
    private val timeoutMs: Long = 3000L,
) : Collector {

    override val id: CollectorId = CollectorId.C13_ATTESTATION

    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "DetectAny-Attest").apply { isDaemon = true }
    }

    override fun collect(input: ScanInput): CollectorResult = try {
        val future = executor.submit { runCatching { service.run() }.getOrNull() }
        val outcome = try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            future.cancel(true) // KeyPairGenerator 不可中断时线程驻留至进程退出（daemon）
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
        detail = "硬件证明 ${timeoutMs}ms 内未返回（Keymaster 慢/无响应）——只采集不采信",
        raw = mapOf("budgetMs" to timeoutMs.toString()),
    )
}
