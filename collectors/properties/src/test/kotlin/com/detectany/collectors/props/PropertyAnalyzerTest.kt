package com.detectany.collectors.props

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 3.3 验证：属性分析 + 属性区空洞。 */
class PropertyAnalyzerTest {

    @Test
    fun detectsInitSvcMagiskFamily() {
        val map = mapOf("ro.build.fingerprint" to "google/x", "init.svc.magiskd" to "running")
        val findings = PropertyAnalyzer.analyze(map, defaultPropertyEntries())
        val f = findings.first { it.ruleId == "prop.init_svc_magisk" }
        assertTrue(f.detail.contains("init.svc.magiskd"))
    }

    @Test
    fun detectsDebuggableAndTestKeys() {
        val map = mapOf("ro.debuggable" to "1", "ro.build.tags" to "release-keys")
        val findings = PropertyAnalyzer.analyze(map, emptyList())
        assertEquals(1, findings.size)
        assertEquals("prop.debuggable", findings[0].ruleId)

        val map2 = mapOf("ro.build.tags" to "test-keys")
        assertEquals("prop.test_keys", PropertyAnalyzer.analyze(map2, emptyList()).single().ruleId)
    }

    @Test
    fun cleanEnvironmentNoFindings() {
        val map = mapOf("ro.build.tags" to "release-keys", "ro.debuggable" to "0", "ro.build.fingerprint" to "google/pixel")
        assertEquals(0, PropertyAnalyzer.analyze(map, defaultPropertyEntries()).size)
    }

    @Test
    fun propertyAreaAnomalyDetected() {
        val files = listOf(
            PropertyCollector.PropertyAreaFile("uobject_r0-1234", 112L, readable = true, ownerUid = null),
            PropertyCollector.PropertyAreaFile("uobject_r0-5678", 0L, readable = true, ownerUid = null),     // 空洞
            PropertyCollector.PropertyAreaFile("uobject_r0-abcd", 96L, readable = false, ownerUid = null),   // 不可读
        )
        val findings = PropertyAnalyzer.analyzeArea(files)
        assertEquals(2, findings.size)
        assertTrue(findings.all { it.category == com.detectany.core.model.Finding.Category.ANTI_DETECT_PRESENT })
    }
}
