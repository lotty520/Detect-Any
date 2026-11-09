package com.detectany.feature.report

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.ScanTier
import com.detectany.core.engine.DetectionEngine
import com.detectany.core.rules.BundledRuleSet
import com.detectany.core.rules.RulesEngine
import com.detectany.data.signature.BundledSignatureDb
import com.detectany.data.signature.SignatureStore
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 7.2/7.3 验证：证据回放与引擎输出一致 + 导出脱敏断言 + 导入等价在线更新。 */
class ReportTest {

    private class FixedCollector : Collector {
        override val id = CollectorId.C8_BEHAVIOR
        override fun collect(input: ScanInput) = CollectorResult(
            id,
            CollectorResult.Status.OK,
            listOf(
                Finding("behavior.ksu_supercall", CollectorId.C8_BEHAVIOR, Confidence.B, Finding.Category.ROOT_KERNEL, "ksu", "reboot 双魔数命中", mapOf("fd" to "anon_inode:[ksu_driver]")),
                Finding("prop.init_svc_magisk", CollectorId.C3_PROPERTY, Confidence.C, Finding.Category.ROOT_USERSPACE, "magisk", "属性命中 init.svc.magisk_p92=running", mapOf("key" to "init.svc.magisk_p92", "valueHash" to "12345")),
            ),
        )
    }

    private fun engineReport(): DetectionEngine.ScanReport =
        DetectionEngine(listOf(FixedCollector()), RulesEngine(BundledRuleSet.ruleSet))
            .scan(ScanInput(ScanTier.L2, 35, 35, "6.1.75", "arm64-v8a"))

    @Test
    fun presenterMatchesEngineOutputExactly() {
        val report = engineReport()
        val model = ReportPresenter.present(report)
        val engineFindings = report.collectorResults.flatMap { it.findings }
        // 逐项一致：数量、ruleId、采集器、置信、原始观测键
        assertEquals(engineFindings.size, model.findings.size)
        engineFindings.zip(model.findings).forEach { (f, v) ->
            assertEquals(f.ruleId, v.ruleId)
            assertEquals(f.collector.name, v.collector)
            assertEquals(f.raw.keys, v.raw.keys)
        }
        assertEquals(report.verdict.riskScore, model.riskScore)
        assertEquals(report.verdict.conclusive, model.conclusive)
        assertEquals(report.verdict.evidenceVector.size, model.findings.map { it.ruleId }.distinct().size)
        // 证据级别标签
        assertTrue(model.findings.any { it.confidenceLabel == "中" && it.ruleId == "behavior.ksu_supercall" })
    }

    @Test
    fun exportIsRedactedAndComplete() {
        val json = ReportExporter.export(engineReport(), appVersion = "test", nowMs = 42L)
        // 完整证据向量 + 结论字段
        assertTrue(json.contains("\"evidenceVector\""))
        assertTrue(json.contains("behavior.ksu_supercall"))
        assertTrue(json.contains("\"riskScore\""))
        // 脱敏断言：属性键不以明文出现（仅哈希），valueHash 本就为哈希可出现
        assertTrue(!json.contains("init.svc.magisk_p92"), "属性键明文不得出现在导出")
        assertTrue(json.contains("12345"), "valueHash 为哈希形态可出现")
        // 解析回读完整
        val back = kotlinx.serialization.json.Json.decodeFromString(
            ReportExporter.ExportedReport.serializer(), json,
        )
        assertEquals(2, back.findings.size)
        assertEquals(42L, back.exportedAtMs)
    }

    @Test
    fun signatureImportEquivalentToOnlineApply() {
        val (pub, priv) = run {
            val kp = KeyPairGenerator.getInstance("Ed25519").genKeyPair()
            Base64.getEncoder().encodeToString(kp.public.encoded) to kp.private
        }
        val store = SignatureStore(verifier = com.detectany.data.signature.SignatureVerifier(pub))
        val delta = BundledSignatureDb.db.copy(version = 6)
        val sig = Signature.getInstance("Ed25519").apply {
            initSign(priv)
            update(com.detectany.data.signature.UpdateCodec.payloadBytes(delta))
        }
        val json = com.detectany.data.signature.BundledSignatureDb.json.encodeToString(
            com.detectany.data.signature.SignedUpdate.serializer(),
            com.detectany.data.signature.SignedUpdate(6, null, delta, Base64.getEncoder().encodeToString(sig.sign())),
        )
        // 手动导入
        val imported = SignatureImport(store).import(json)
        assertTrue(imported is SignatureImport.Result.Applied && imported.version == 6L, imported.toString())
        // 与在线路径同构：同一 store 状态推进语义（导入即 apply）
        assertEquals(6L, store.current().version)
    }

    @Test
    fun signatureImportRejectsGarbage() {
        val store = SignatureStore(verifier = null)
        val r = SignatureImport(store).import("{ not json")
        assertTrue(r is SignatureImport.Result.Rejected)
    }
}
