package com.detectany.feature.attestation

import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding

/**
 * C9 编排（任务 5.3）：发起 → 链校验 → CRL → 字段交叉 → first_api_level 降级。
 * 输出 Finding 供引擎聚合（attestation_spoof / anti_detect 类）。
 */
class AttestationService(
    private val client: AttestationSource = AttestationClient(),
    private val verifier: AttestationVerifier,
    private val crl: CrlStore,
    /** first_api_level 读取（PropJni.propGet("ro.product.first_api_level") 装配层注入） */
    private val firstApiLevel: () -> Int?,
    private val ownPackageName: String? = null,
    private val crossInput: AttestationVerifier.CrossInput = AttestationVerifier.CrossInput(),
) {
    sealed interface Outcome {
        /** 硬件可信 */
        data class Trusted(val description: KeyDescriptionParser.KeyDescription, val findings: List<Finding>) : Outcome

        /** 只采集不采信（first_api_level<26 / 软件链 / 不可用）——降级标注 */
        data class Degraded(val reason: String, val findings: List<Finding>) : Outcome

        /** 证明链异常 = 伪造证据（A 级）
         *  吊销命中 / RootOfTrust 与系统声称矛盾等 */
        data class SpoofSuspected(val reason: String, val findings: List<Finding>) : Outcome
    }

    fun run(): Outcome {
        val fal = firstApiLevel()
        if (fal != null && fal < 26) {
            // specs/attestation-verify：首发 API <26 设备硬件链不保证（软件链可被完整伪造）→ 只采集不采信
            val attested = client.attest()
            client.cleanup()
            return Outcome.Degraded(
                "first_api_level=$fal < 26",
                attested?.let { listOf(infoFinding("attest.degraded.first_api_level", "证明已采集但不采信（首发 API $fal）")) } ?: emptyList(),
            )
        }

        val attested = client.attest()
            ?: return Outcome.Degraded("attestation unavailable (no keymaster or error)", emptyList())
        try {
            val revoked = runCatching { crl.revokedSerials() }.getOrDefault(emptySet())
            return when (val v = verifier.verify(attested.chain, attested.challenge, ownPackageName, revoked, AttestationVerifier.RkpPolicy(fal))) {
                is AttestationVerifier.Verdict.Revoked -> Outcome.SpoofSuspected(
                    "revoked serial ${v.serialHex}",
                    listOf(
                        Finding(
                            ruleId = "attest.keybox_revoked",
                            collector = CollectorId.C13_ATTESTATION, // P2-1：独立编号取代 C1 占位
                            confidence = Confidence.A,
                            category = Finding.Category.ATTESTATION_SPOOF,
                            framework = "trickystore",
                            detail = "Certificate chain serial ${v.serialHex} hit revocation list (note: CRL-clean is not proof of trust — Google has shadow downgrades Strong→Device not in CRL)",
                            raw = mapOf("serial" to v.serialHex),
                        ),
                    ),
                )

                is AttestationVerifier.Verdict.Rejected -> Outcome.Degraded(
                    "chain rejected: ${v.reason}",
                    listOf(infoFinding("attest.rejected", v.reason)),
                )

                is AttestationVerifier.Verdict.SoftwareBacked -> Outcome.Degraded(
                    "software-backed attestation (forgeable)",
                    listOf(
                        Finding(
                            ruleId = "attest.software_backed",
                            collector = CollectorId.C13_ATTESTATION,
                            confidence = Confidence.B,
                            category = Finding.Category.ATTESTATION_SPOOF,
                            framework = null,
                            detail = "Attestation is software-backed (forgeable with AOSP software keybox)",
                            raw = emptyMap(),
                        ),
                    ),
                )

                is AttestationVerifier.Verdict.Trusted -> {
                    val anomalies = verifier.crossCheck(v.description, crossInput)
                    val findings = anomalies.map {
                        Finding(
                            ruleId = "attest.cross.${it.kind}",
                            collector = CollectorId.C13_ATTESTATION,
                            confidence = Confidence.A,
                            category = Finding.Category.ATTESTATION_SPOOF,
                            framework = "trickystore",
                            detail = it.detail,
                            raw = emptyMap(),
                        )
                    }
                    if (findings.isEmpty()) Outcome.Trusted(v.description, emptyList())
                    else Outcome.SpoofSuspected("cross-check anomalies: ${anomalies.size}", findings)
                }
            }
        } catch (e: Throwable) {
            // 2026-11-10 审计修复：原 try 只有 finally 无 catch——ASN.1 解析异常
            // （历史教训：deviceLocked BOOLEAN schema 变体曾致崩）会穿透冒泡。
            // 证明层异常 = 优雅降级（不采信不误报），永不上抛扫描流程。
            return Outcome.Degraded("attestation parse error: " + e.javaClass.simpleName, emptyList())
        } finally {
            client.cleanup()
        }
    }

    private fun infoFinding(id: String, detail: String) = Finding(
        ruleId = id,
        collector = CollectorId.C13_ATTESTATION,
        confidence = Confidence.C,
        category = Finding.Category.ATTESTATION_SPOOF,
        framework = null,
        detail = detail,
        raw = emptyMap(),
    )
}
