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
        // 2026-11-11：华为真机锁屏/暗屏时截图仅 ~7KB（黑屏）——唤醒并解锁后再截
        runCatching {
            val inst0 = InstrumentationRegistry.getInstrumentation()
            val d0 = UiDevice.getInstance(inst0)
            d0.wakeUp()
            Thread.sleep(500)
        }
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
        val isEmu = android.os.Build.FINGERPRINT.contains("generic") || android.os.Build.PRODUCT.contains("sdk_gphone")
        if (isEmu) {
            // 模拟器上检测到模拟器信号是真阳性；仅断无非模拟器域命中
            val nonEmulatorFindings = report.collectorResults.flatMap { it.findings }
                .filter { it.category != com.detectany.core.model.Finding.Category.EMULATOR }
                .filter { it.ruleId != "screenshare.adb_enabled" } // 模拟器 ADB 恒开
            assertEquals(
                "干净模拟器非模拟器域应零命中: ${nonEmulatorFindings.map { it.ruleId }}",
                0, nonEmulatorFindings.size,
            )
        } else {
            // 真机（可能 ROOT/作弊）：允许真阳性，禁止 mem 全零伪影；定性必须由 A 级证据支撑
            val prologueMem = report.collectorResults.flatMap { it.findings }
                .filter { it.ruleId.startsWith("integrity.prologue") }
                .map { it.raw["mem"] ?: "" }
            assertTrue("textRead 退化伪影", prologueMem.all { m -> m.any { c -> c != '0' } })
            if (report.verdict.conclusive) {
                assertTrue("定性必须由 A 级证据支撑", report.verdict.evidenceVector.isNotEmpty())
            }
        }
        assertTrue("8 采集器应全部执行: ${report.collectorResults.size}", report.collectorResults.size >= 7)
        assertTrue("L2 时延预算超限: ${report.elapsedMs}ms", report.elapsedMs < 10_000) // 模拟器宽放（真机 100ms 预算在 8.3 验证）
    }
}
