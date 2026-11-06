package com.detectany.core.engine

import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.rules.BundledRuleSet
import com.detectany.core.rules.RulesEngine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 8.1 验证：扩展规则条目的样例观测回放。 */
class ExtendedRulesReplayTest {

    private fun f(ruleId: String, fw: String? = null, cat: Finding.Category = Finding.Category.ROOT_KERNEL, c: Confidence = Confidence.B) =
        Finding(ruleId, CollectorId.C8_BEHAVIOR, c, cat, fw, "replay", emptyMap())

    private val engine = RulesEngine(BundledRuleSet.ruleSet)

    @Test
    fun lsppatchVectorViaRepackagedFindings() {
        // LSPatch 场景：目标 app 被重打包 → 自保护签名钉住命中（A）+ 嵌入 lspd 运行时 maps 痕迹
        val hits = engine.evaluate(
            listOf(
                f("selfguard.repackaged_signature", null, Finding.Category.REPACKAGED, Confidence.A),
                f("mem.known_path", "lsposed", Finding.Category.HOOK, Confidence.C),
            ),
        )
        assertTrue(hits.any { it.rule.id == "rule.repackaged" })
        assertTrue(hits.any { it.rule.id == "rule.lsposed" })
    }

    @Test
    fun trickystoreVectorViaAttestationFindings() {
        val hits = engine.evaluate(
            listOf(
                f("attest.keybox_revoked", "trickystore", Finding.Category.ATTESTATION_SPOOF, Confidence.A),
                f("attest.cross.bootloader_lock_mismatch", "trickystore", Finding.Category.ATTESTATION_SPOOF, Confidence.A),
            ),
        )
        val hit = hits.first { it.rule.id == "rule.trickystore" }
        assertEquals("trickystore", hit.rule.framework)
    }

    @Test
    fun susfsVectorViaFstypeCross() {
        val hits = engine.evaluate(listOf(f("mount.fstype_cross.123", null, Finding.Category.ROOT_KERNEL, Confidence.A)))
        assertEquals("susfs", hits.first { it.rule.id == "rule.susfs" }.rule.framework)
    }

    @Test
    fun shamikoVectorViaTooClean() {
        val hits = engine.evaluate(listOf(f("mount.too_clean", null, Finding.Category.ANTI_DETECT_PRESENT, Confidence.B)))
        assertTrue(hits.any { it.rule.id == "rule.anti_detect" })
    }


}
