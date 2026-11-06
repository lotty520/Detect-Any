package com.detectany.core.engine

import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * 任务 4.4 验证：判定权限矩阵（单 B 不定性、强单条定性、C 仅加权、anti_detect 权重更高）。
 */
class ScoreModelTest {

    private fun f(ruleId: String, c: Confidence, fw: String? = null, cat: Finding.Category = Finding.Category.ROOT_KERNEL) =
        Finding(ruleId, CollectorId.C8_BEHAVIOR, c, cat, fw, "test", emptyMap())

    private val model = ScoreModel()

    @Test
    fun singleBIsNotConclusive() {
        val v = model.score(listOf(f("behavior.ksu_supercall", Confidence.B, "ksu")), emptyList())
        assertFalse(v.conclusive)
        assertTrue(v.riskScore < 50)
    }

    @Test
    fun singleAIsConclusive() {
        val v = model.score(listOf(f("behavior.triple_diff", Confidence.A, null, Finding.Category.HOOK)), emptyList())
        assertTrue(v.conclusive)
        assertTrue(v.riskScore >= 50)
        assertEquals(listOf("behavior.triple_diff"), v.evidenceVector)
    }

    @Test
    fun twoBInSameFrameworkResonate() {
        val v = model.score(
            listOf(
                f("behavior.ksu_supercall", Confidence.B, "ksu"),
                f("app.ksu", Confidence.B, "ksu"),
            ),
            emptyList(),
        )
        assertTrue(v.conclusive)
        assertTrue(v.frameworkScores.containsKey("ksu"))
    }

    @Test
    fun bPlusCInSameFrameworkResonate() {
        val v = model.score(
            listOf(
                f("app.magisk", Confidence.B, "magisk"),
                f("path.debug_ramdisk.magisk", Confidence.C, "magisk"),
            ),
            emptyList(),
        )
        assertTrue(v.conclusive)
    }

    @Test
    fun cOnlyNeverConclusive() {
        val v = model.score(
            (0 until 5).map { f("path.su.$it", Confidence.C, null) },
            emptyList(),
        )
        assertFalse(v.conclusive)
        assertTrue(v.riskScore < 50)
    }

    @Test
    fun crossDomainTwoBsResonate() {
        // 2026-11-06 校准：跨域双 B 也共振（真机教训：APatch B + zygiskdetect B 曾误判未定性）
        val v = model.score(
            listOf(
                f("behavior.ksu_supercall", Confidence.B, "ksu"),
                f("app.magisk", Confidence.B, "magisk"),
            ),
            emptyList(),
        )
        assertTrue(v.conclusive)
    }

    @Test
    fun rootedDeviceManagerPlusToolIsConclusive() {
        // 真机实证形态：root 管理器内容指纹(B, ROOT_KERNEL) + zygisk 工具(B, ZYGISK)
        val v = model.score(
            listOf(
                Finding("app.apatch", CollectorId.C5_APP_FINGERPRINT, Confidence.B, Finding.Category.ROOT_KERNEL, "apatch", "t", emptyMap()),
                Finding("app.zygiskdetect", CollectorId.C5_APP_FINGERPRINT, Confidence.B, Finding.Category.ZYGISK, "zygiskdetect", "t", emptyMap()),
            ),
            emptyList(),
        )
        assertTrue(v.conclusive, "rooted 设备双 B 必须定性")
        assertTrue(v.riskScore >= 50)
    }

    @Test
    fun antiDetectWeightsHigherThanPlainRoot() {
        val plain = model.score(listOf(f("x", Confidence.B, "magisk")), emptyList())
        val anti = model.score(listOf(f("mount.too_clean", Confidence.B, null, Finding.Category.ANTI_DETECT_PRESENT)), emptyList())
        assertTrue(anti.riskScore >= plain.riskScore)
        assertTrue(anti.antiDetectPresent)
        assertFalse(plain.antiDetectPresent)
    }
}
