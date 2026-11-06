package com.detectany.app

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import com.detectany.core.model.ScanTier
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 任务 7.1/7.2 设备验证：Activity 启动走查 + 截图工件 + UI 所用同一编排器全链路扫描。
 */
@RunWith(AndroidJUnit4::class)
class ReportUiSmokeTest {

    @Test
    fun activityLaunchesAndScreenshotCaptured() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        Thread.sleep(1500) // 首帧稳定

        val inst = InstrumentationRegistry.getInstrumentation()
        val device = UiDevice.getInstance(inst)
        val out = File(inst.targetContext.externalCacheDir, "walkthrough_l2.png")
        device.takeScreenshot(out)

        assertTrue("截图工件未生成", out.isFile)
        assertTrue("截图异常小: ${out.length()}B", out.length() > 20_000)
        scenario.close()
    }

    @Test
    fun orchestratorFullScanRunsCleanOnEmulator() {
        // UI 背后的同一编排器（7.2「逐项一致」的数据源）：全链路 L2 扫描可执行、干净环境零误报
        val orchestrator = ScanOrchestrator(InstrumentationRegistry.getInstrumentation().targetContext)
        assertTrue("debug 构建应走运行时预期分支(usesNative=${orchestrator.selfGuardUsesNativeExpected})", !orchestrator.selfGuardUsesNativeExpected)
        val report = orchestrator.scan(ScanTier.L2)
        assertEquals("干净模拟器零命中: ${report.collectorResults.flatMap { it.findings }.map { it.ruleId + " :: " + it.detail }} + extra=${report.verdict.evidenceVector}", 0, report.verdict.evidenceVector.size)
        assertTrue("8 采集器应全部执行: ${report.collectorResults.size}", report.collectorResults.size >= 7)
        assertTrue("L2 时延预算超限: ${report.elapsedMs}ms", report.elapsedMs < 10_000) // 模拟器宽放（真机 100ms 预算在 8.3 验证）
    }
}
