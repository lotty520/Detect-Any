package com.detectany.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.detectany.core.model.ScanTier
import org.junit.Test
import org.junit.runner.RunWith

/** 任务 8.3：时延探针（模拟器参考值；中端真机数据由回归矩阵补测）。 */
@RunWith(AndroidJUnit4::class)
class TimingProbeTest {

    @Test
    fun recordTierTimings() {
        val orchestrator = ScanOrchestrator(InstrumentationRegistry.getInstrumentation().targetContext)
        // 预热（JIT/native 首载）
        orchestrator.scan(ScanTier.L1)
        val l1 = (1..3).map { orchestrator.scan(ScanTier.L1).elapsedMs }
        val l2 = (1..3).map { orchestrator.scan(ScanTier.L2).elapsedMs }
        android.util.Log.i(
            "DetectAnyTiming",
            "L1ms=${l1.joinToString(",")} L2ms=${l2.joinToString(",")}",
        )
        // 模拟器宽放断言（真机 10/100ms 预算见 docs/REGRESSION.md 矩阵）。
        // 2026-11-10 C5 探针下推修复后 L2 回到 969ms（双 manager 场景），
        // 断言从临时宽放 6s 收回 3s（保留 3 倍余量覆盖低端真机）。
        assert(l1.average() < 500) { "L1=${l1}" }
        assert(l2.average() < 3000) { "L2=${l2}" }
    }
}
