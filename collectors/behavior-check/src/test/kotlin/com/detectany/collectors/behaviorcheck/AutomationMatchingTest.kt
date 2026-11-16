package com.detectany.collectors.behaviorcheck

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** fixture 含真机实证样本（Redmi harmonizerx / 小米 carlink / androidx.test 截断线程名）。 */
class AutomationMatchingTest {

    private val known = setOf(
        "org.autojs.autojs", "com.arlosoft.macrodroid", "com.touchsprite.android",
        "com.example.easyclick", "ieasyclick.app",
    )
    private val markers = setOf("uiautomator", "appium")

    @Test
    fun knownPackagesHit() {
        // Redmi 实测自动化工具（随机包名形态之外的已知族）
        assertTrue(AutomationMatching.isKnownAutomation("org.autojs.autojs/.Service", known, markers))
        assertTrue(AutomationMatching.isKnownAutomation("com.touchsprite.android/org.autojs.ApiService", known, markers))
    }

    @Test
    fun componentMarkersCatchArbitraryTestPackages() {
        // uiautomator2 服务寄宿于任意包名（2026-11-12 盲区修正）
        assertTrue(AutomationMatching.isKnownAutomation("com.example.mytest/androidx.test.uiautomator.UiAutomatorService", known, markers))
        assertTrue(AutomationMatching.isKnownAutomation("io.appium.uiautomator2.server/.server.AccessibilityService", known, markers))
    }

    @Test
    fun oemAndNormalServicesNotFlagged() {
        // 小米 CarWith（2026-11-12 白名单实证）/ 设置服务 / 未知第三方不误伤
        assertFalse(AutomationMatching.isKnownAutomation("com.miui.carlink/com.carwith.common.accessibility.FocusAccessibilityService", known, markers))
        assertFalse(AutomationMatching.isKnownAutomation("com.android.settings/.accessibility.accessibilitymenu.AccessibilityMenuService", known, markers))
        // Redmi 实测未知自动化（随机包名）——不含标记 → 不判 known（C 级 unknown 由采集器另行产出）
        assertFalse(AutomationMatching.isKnownAutomation("processor.harmonizerx.assembler/processor.harmonizerx.assembler.psszinjixsbadbvpjaj", known, markers))
    }

    @Test
    fun instrumentationThreadForms() {
        // androidx.test 1.6.2 实测（Pixel 4）：InstrumentationThread 截断为 "Instrumentation"
        assertTrue(AutomationMatching.isInstrumentationThread("Instrumentation"))
        assertTrue(AutomationMatching.isInstrumentationThread("instrumentation"))
        // AOSP 老路径前缀（截断保留前缀）
        assertTrue(AutomationMatching.isInstrumentationThread("Instr: androidx.t"))
        // 正常线程不命中
        assertFalse(AutomationMatching.isInstrumentationThread("RenderThread"))
        assertFalse(AutomationMatching.isInstrumentationThread("instrumentation-worker-x")) // 非截断等值形态，保守不命中
    }
}
