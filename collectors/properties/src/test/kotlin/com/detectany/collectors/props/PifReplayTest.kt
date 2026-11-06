package com.detectany.collectors.props

import com.detectany.core.rules.BundledRuleSet
import com.detectany.core.rules.RulesEngine
import kotlin.test.Test
import kotlin.test.assertEquals

/** 任务 8.1：PIF 成对属性偏离 → 分析器命中 → 规则回放。 */
class PifReplayTest {

    private val engine = RulesEngine(BundledRuleSet.ruleSet)

    @Test
    fun pifPairMismatchAnalyzerAndRule() {
        val map = mapOf(
            "ro.build.fingerprint" to "google/oriole/spoofed",
            "ro.bootimage.build.fingerprint" to "google/oriole/original",
        )
        val findings = PropertyAnalyzer.analyze(map, emptyList())
        assertEquals(1, findings.size)
        assertEquals("prop.build_pair.fingerprint", findings[0].ruleId)
        assertEquals("pif", findings[0].framework)

        val hits = engine.evaluate(findings)
        assertEquals("pif", hits.first { it.rule.id == "rule.pif" }.rule.framework)
    }

    @Test
    fun pifCleanPairsNoFalsePositive() {
        val map = mapOf(
            "ro.build.fingerprint" to "google/oriole/same",
            "ro.bootimage.build.fingerprint" to "google/oriole/same",
            "ro.build.version.incremental" to "x",
        )
        assertEquals(0, PropertyAnalyzer.analyze(map, emptyList()).filter { it.ruleId.startsWith("prop.build_pair") }.size)
    }
}
