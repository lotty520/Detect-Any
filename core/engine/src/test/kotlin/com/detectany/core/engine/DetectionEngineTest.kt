package com.detectany.core.engine

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.ScanTier
import com.detectany.core.rules.BundledRuleSet
import com.detectany.core.rules.RulesEngine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 4.3/4.4/4.5 验证：规则前缀匹配 + 引擎编排/L1 子集/降级透明 + 各框架样例观测回放。 */
class DetectionEngineTest {

    private class FixedCollector(
        override val id: CollectorId,
        private val result: CollectorResult,
    ) : Collector {
        override fun collect(input: ScanInput): CollectorResult = result
    }

    private class ThrowingCollector(override val id: CollectorId) : Collector {
        override fun collect(input: ScanInput): CollectorResult = error("collector exploded")
    }

    private fun finding(ruleId: String, c: Confidence, fw: String? = null, cat: Finding.Category = Finding.Category.ROOT_KERNEL) =
        Finding(ruleId, CollectorId.C8_BEHAVIOR, c, cat, fw, "replay", emptyMap())

    private fun engine(vararg collectors: Collector): DetectionEngine =
        DetectionEngine(collectors.toList(), RulesEngine(BundledRuleSet.ruleSet))

    private val input = ScanInput(ScanTier.L2, 35, 35, "6.1.75", "arm64-v8a")

    // ---- 4.3 规则引擎 ----

    @Test
    fun rulePrefixMatching() {
        val hits = RulesEngine(BundledRuleSet.ruleSet).evaluate(
            listOf(
                finding("app.ksu", Confidence.B, "ksu"),
                finding("behavior.ksu_supercall", Confidence.B, "ksu"),
                finding("unrelated_rule_id", Confidence.C),
            ),
        )
        assertTrue(hits.any { it.rule.id == "rule.ksu" && it.matchedFindingRuleIds.size == 2 })
        assertTrue(hits.none { it.matchedFindingRuleIds.contains("unrelated_rule_id") })
    }

    // ---- 4.4 引擎编排 ----

    @Test
    fun l1RunsOnlyFastCollectors() {
        val slow = FixedCollector(
            CollectorId.C8_BEHAVIOR,
            CollectorResult(CollectorId.C8_BEHAVIOR, CollectorResult.Status.OK, listOf(finding("behavior.ksu_supercall", Confidence.B, "ksu"))),
        )
        val fast = FixedCollector(CollectorId.C1_PATH, CollectorResult(CollectorId.C1_PATH, CollectorResult.Status.OK))
        val report = engine(slow, fast).scan(input, ScanTier.L1)
        assertEquals(listOf(CollectorId.C1_PATH), report.collectorResults.map { it.collector })
    }

    @Test
    fun throwingCollectorDoesNotAbortScan() {
        val ok = FixedCollector(CollectorId.C1_PATH, CollectorResult(CollectorId.C1_PATH, CollectorResult.Status.OK))
        val report = engine(ThrowingCollector(CollectorId.C2_MOUNT), ok).scan(input, ScanTier.L2)
        assertEquals(2, report.collectorResults.size)
        assertTrue(CollectorId.C2_MOUNT in report.degradedCollectors)
        assertEquals(CollectorResult.Status.BLOCKED, report.collectorResults.first { it.collector == CollectorId.C2_MOUNT }.status)
    }

    // ---- 4.5 框架样例观测回放（design.md D9 主信号） ----

    @Test
    fun replayKsuSupercallPlusManagerIsConclusive() {
        val report = engine(
            FixedCollector(
                CollectorId.C8_BEHAVIOR,
                CollectorResult(
                    CollectorId.C8_BEHAVIOR,
                    CollectorResult.Status.OK,
                    listOf(
                        finding("behavior.ksu_supercall", Confidence.B, "ksu"),
                        finding("app.ksu", Confidence.B, "ksu"),
                    ),
                ),
            ),
        ).scan(input)
        assertTrue(report.verdict.conclusive)
        assertTrue((report.verdict.frameworkScores["ksu"] ?: 0) > 0)
    }

    @Test
    fun replayMagiskWeakPlusManagerResonates() {
        val report = engine(
            FixedCollector(
                CollectorId.C5_APP_FINGERPRINT,
                CollectorResult(
                    CollectorId.C5_APP_FINGERPRINT,
                    CollectorResult.Status.OK,
                    listOf(
                        finding("app.magisk", Confidence.B, "magisk"),
                        finding("path.debug_ramdisk.magisk", Confidence.C, "magisk", Finding.Category.ROOT_USERSPACE),
                    ),
                ),
            ),
        ).scan(input)
        assertTrue(report.verdict.conclusive)
        assertTrue((report.verdict.frameworkScores["magisk"] ?: 0) > 0)
    }

    @Test
    fun replayStrongHookSignalAloneIsConclusive() {
        val report = engine(
            FixedCollector(
                CollectorId.C7_CODE_INTEGRITY,
                CollectorResult(
                    CollectorId.C7_CODE_INTEGRITY,
                    CollectorResult.Status.OK,
                    listOf(finding("integrity.prologue.x", Confidence.A, null, Finding.Category.HOOK)),
                ),
            ),
        ).scan(input)
        assertTrue(report.verdict.conclusive)
        assertTrue(Finding.Category.HOOK in report.verdict.categories)
    }

    @Test
    fun replayAntiDetectEnvironmentFlagged() {
        val report = engine(
            FixedCollector(
                CollectorId.C2_MOUNT,
                CollectorResult(
                    CollectorId.C2_MOUNT,
                    CollectorResult.Status.OK,
                    listOf(finding("mount.too_clean", Confidence.B, null, Finding.Category.ANTI_DETECT_PRESENT)),
                ),
            ),
        ).scan(input)
        assertTrue(report.verdict.antiDetectPresent)
    }

    @Test
    fun cleanScanVerdictIsQuiet() {
        val report = engine(FixedCollector(CollectorId.C1_PATH, CollectorResult(CollectorId.C1_PATH, CollectorResult.Status.OK))).scan(input)
        assertEquals(0, report.verdict.riskScore)
        assertTrue(report.verdict.evidenceVector.isEmpty())
        assertFalse2(report.verdict.conclusive)
    }

    private fun assertFalse2(b: Boolean) = kotlin.test.assertFalse(b)
}
