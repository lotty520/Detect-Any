package com.detectany.app

import android.content.Context
import android.hardware.display.DisplayManager
import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.detectany.collectors.screenshare.ScreenShareCollector
import com.detectany.collectors.screenshare.VirtualDisplayClassifier
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.ScanInput
import com.detectany.core.model.ScanTier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 虚拟显示器 TP 设备侧验证（change virtual-display-detect · 任务 3.1 TP 方向）。
 *
 * 前置：宿主机 `scrcpy --new-display=<WxH>[/<dpi>]` 会话存活（取证与流程见
 * docs/calibration/virtual-displays.md）。无会话时 Assume 跳过——不破坏常规
 * connectedDebugAndroidTest 的干净断言。
 *
 * 在 app 进程内证明三点：
 *  1. DisplayManager 可枚举 name="scrcpy" 的虚拟屏（app 可观测性——/proc/net/unix 在
 *     API 35 对 app uid EACCES，socket A 级失效场景下这是关键向量）
 *  2. 全链路：ScreenShareCollector.collect 对活 scrcpy 屏产出 SHELL_OWNED 分类 finding
 *  3. 复合 B 条件成立：SHELL_OWNED + ADB 姿态 → compositeShellControl=true
 * isSelf=true 的 B 级复合 finding 需 MainActivity 真实落屏（onResume 供数），
 * 由 VirtualDisplayClassifierTest 与接线代码覆盖；此处以 observed 链路证明采集面真实可用。
 */
@RunWith(AndroidJUnit4::class)
class VirtualDisplayTpTest {

    private fun input() = ScanInput(ScanTier.L2, apiLevel = 35, targetSdk = 35, kernelRelease = "test", abi = "arm64-v8a")

    @Test
    fun liveScrcpyDisplayCollectedAsShellOwned() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val dm = ctx.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        val scrcpyDisplay = dm.displays.firstOrNull { it.name.equals("scrcpy", ignoreCase = true) }
        assumeTrue("scrcpy --new-display session not alive — TP test skipped", scrcpyDisplay != null)
        assertNotNull(scrcpyDisplay)

        // 1) 全链路：采集器对活 scrcpy 屏产出分类 finding
        val r = ScreenShareCollector(ctx).collect(input())
        assertEquals(CollectorResult.Status.OK, r.status)
        val vdFindings = r.findings.filter { it.ruleId.startsWith("screenshare.virtual_display") }
        assertTrue("expected virtual-display findings, got: ${r.findings.map { it.ruleId }}", vdFindings.isNotEmpty())
        val shell = vdFindings.first { it.raw["name"].equals("scrcpy", ignoreCase = true) }
        assertEquals("SHELL_OWNED", shell.raw["class"])
        assertTrue(shell.raw["chain"]!!.contains("SHELL_DISPLAY_NAMES"))

        // 2) 复合 B 条件：SHELL_OWNED + 同 scan ADB 姿态（真实读取，不硬编码）
        val adb = Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        assumeTrue("ADB posture not present (expected on emulator with scrcpy session)", adb)
        assertTrue(
            VirtualDisplayClassifier.compositeShellControl(
                VirtualDisplayClassifier.DisplayClass.SHELL_OWNED,
                adbPresent = adb,
            ),
        )

        // 3) 反向边界：合法类/未知类不触发复合（链路级断言，非仅单测）
        assertTrue(
            !VirtualDisplayClassifier.compositeShellControl(
                VirtualDisplayClassifier.DisplayClass.LEGIT_CAST_OEM,
                adbPresent = adb,
            ),
        )
    }
}
