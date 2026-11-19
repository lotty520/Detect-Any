package com.detectany.collectors.screenshare

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * 虚拟显示器分类器主机测试（change virtual-display-detect）。
 * Android 采集面（DisplayManager/MediaRouter/Settings）由模拟器双向验证覆盖（tasks 3.1）。
 */
class VirtualDisplayClassifierTest {

    private fun snap(id: Int = 2, name: String?, self: Boolean = true, flags: Int = 0x1000) =
        VirtualDisplayClassifier.DisplaySnapshot(displayId = id, name = name, flags = flags, isSelf = self)

    private fun ctx(
        overlay: String? = null,
        adb: Boolean = false,
        routes: Set<String> = emptySet(),
    ) = VirtualDisplayClassifier.ClassifyContext(overlaySimulateSetting = overlay, adbPresent = adb, castRouteNames = routes)

    // ---- 五类各一 ----

    @Test
    fun shellOwnedByName() {
        val c = VirtualDisplayClassifier.classify(snap(name = "scrcpy"), ctx(adb = true))
        assertEquals(VirtualDisplayClassifier.DisplayClass.SHELL_OWNED, c.cls)
        assertTrue("SHELL_DISPLAY_NAMES" in c.chain.single())
    }

    @Test
    fun containerAppByInjectedPattern() {
        // 生产 CONTAINER_DISPLAY_PATTERNS 为空（无实证样本不入库）——注入样例特征验证分类路径
        val c = VirtualDisplayClassifier.classify(
            snap(name = "DualSpace Display"),
            ctx(),
            containerPatterns = listOf(Regex("DualSpace")),
        )
        assertEquals(VirtualDisplayClassifier.DisplayClass.CONTAINER_APP, c.cls)
    }

    @Test
    fun legitCastByRouteCrossReference() {
        val c = VirtualDisplayClassifier.classify(snap(name = "Living Room TV"), ctx(routes = setOf("Living Room TV")))
        assertEquals(VirtualDisplayClassifier.DisplayClass.LEGIT_CAST_OEM, c.cls)
    }

    @Test
    fun devSimulateDoubleEvidence() {
        val c = VirtualDisplayClassifier.classify(snap(name = "Overlay #1"), ctx(overlay = "1080x1920/420"))
        assertEquals(VirtualDisplayClassifier.DisplayClass.DEV_SIMULATE, c.cls)
        assertTrue(c.chain.single().contains("双证"))
    }

    @Test
    fun devSimulateNameOnly() {
        val c = VirtualDisplayClassifier.classify(snap(name = "Overlay #2"), ctx())
        assertEquals(VirtualDisplayClassifier.DisplayClass.DEV_SIMULATE, c.cls)
        assertTrue(c.chain.single().contains("单证"))
    }

    @Test
    fun unknownFallbackWithAdbContext() {
        val c = VirtualDisplayClassifier.classify(snap(name = "VD-42", flags = 0x2004), ctx(adb = true))
        assertEquals(VirtualDisplayClassifier.DisplayClass.UNKNOWN, c.cls)
        assertTrue(c.chain.any { it.contains("flags=0x2004") })
        assertTrue(c.chain.any { it.contains("adb 姿态在场") }) // 旁证入链但不据此归因
    }

    // ---- 审计 F3 反例：cast 在场不得掩蔽 shell 屏；多屏独立 ----

    @Test
    fun castRouteDoesNotMaskShellDisplay() {
        // 同一屏：名为 scrcpy，但投屏路由存在（另一块屏在投）——仍必须归 shell-owned
        val c = VirtualDisplayClassifier.classify(snap(name = "scrcpy"), ctx(routes = setOf("Chromecast")))
        assertEquals(VirtualDisplayClassifier.DisplayClass.SHELL_OWNED, c.cls)
    }

    @Test
    fun multiDisplayIndependence() {
        // 两屏并存：scrcpy 屏 + Overlay 屏，各自独立归类互不掩蔽
        val shell = VirtualDisplayClassifier.classify(snap(id = 2, name = "scrcpy", self = true), ctx())
        val overlay = VirtualDisplayClassifier.classify(snap(id = 3, name = "Overlay #1", self = false), ctx())
        assertEquals(VirtualDisplayClassifier.DisplayClass.SHELL_OWNED, shell.cls)
        assertEquals(VirtualDisplayClassifier.DisplayClass.DEV_SIMULATE, overlay.cls)
    }

    @Test
    fun legitClassNeverCompositeB() {
        // 复合 B 仅对 shell-owned 开放——合法类/未知类即使 adb 在场也不触发
        assertFalse(VirtualDisplayClassifier.compositeShellControl(VirtualDisplayClassifier.DisplayClass.LEGIT_CAST_OEM, adbPresent = true))
        assertFalse(VirtualDisplayClassifier.compositeShellControl(VirtualDisplayClassifier.DisplayClass.UNKNOWN, adbPresent = true))
        assertFalse(VirtualDisplayClassifier.compositeShellControl(VirtualDisplayClassifier.DisplayClass.DEV_SIMULATE, adbPresent = true))
    }

    @Test
    fun compositeRequiresBothSignals() {
        assertTrue(VirtualDisplayClassifier.compositeShellControl(VirtualDisplayClassifier.DisplayClass.SHELL_OWNED, adbPresent = true))
        assertFalse(VirtualDisplayClassifier.compositeShellControl(VirtualDisplayClassifier.DisplayClass.SHELL_OWNED, adbPresent = false))
        assertFalse(VirtualDisplayClassifier.compositeShellControl(null, adbPresent = true))
    }
}
