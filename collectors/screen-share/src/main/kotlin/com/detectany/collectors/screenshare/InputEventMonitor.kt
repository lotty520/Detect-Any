package com.detectany.collectors.screenshare

import android.view.MotionEvent

/**
 * G6 输入事件行为分析（P2-4，2026-11-11）：滚动窗口统计注入/合成/节律三特征。
 *
 * 挂接模式对齐 ScreenRecordingMonitor：MainActivity.dispatchTouchEvent 转发 →
 * 状态单例累积 → C12 扫描时读快照。冷启动即扫无输入数据时 finding 缺席（可接受，
 * meta 标注 insufficient）。
 *
 * 初版全 C 级（节律/比例的 FP 面——残障辅助注入合法——需真实样本积累后升）。
 * 白名单联动：C11 无障碍白名单命中的服务产生的注入比例高 → 不产出。
 */
object InputEventMonitor {

    private const val WINDOW_SIZE = 200
    private const val WINDOW_MS = 60_000L

    private data class Window(
        val total: Int = 0,
        val accessibilityInjected: Int = 0,
        val virtualDevice: Int = 0,
        val syntheticId: Int = 0,
        val downTimestamps: LongArray = longArrayOf(),
    )

    @Volatile
    private var window: Window = Window()

    /** MainActivity.dispatchTouchEvent 转发入口（主线程）。 */
    fun onMotionEvent(event: MotionEvent) {
        val w = window
        // FLAG_IS_ACCESSIBILITY_EVENT (0x40000000) 是 API 34 常量——minSdk 24 用字面值
        val injected = runCatching { (event.flags and 0x40000000) != 0 }.getOrDefault(false)
        val virtual = runCatching { event.device?.isVirtual == true }.getOrDefault(false)
        val synthetic = event.deviceId == 0
        val downs = if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            w.downTimestamps + event.eventTime
        } else {
            w.downTimestamps
        }
        window = w.copy(
            total = w.total + 1,
            accessibilityInjected = w.accessibilityInjected + if (injected) 1 else 0,
            virtualDevice = w.virtualDevice + if (virtual) 1 else 0,
            syntheticId = w.syntheticId + if (synthetic) 1 else 0,
            downTimestamps = downs,
        )
        trim()
    }

    private fun trim() {
        val w = window
        if (w.total > WINDOW_SIZE || (w.downTimestamps.size > 2 &&
                w.downTimestamps.last() - w.downTimestamps.first() > WINDOW_MS)
        ) {
            window = w.copy(
                total = (w.total / 2).coerceAtLeast(1),
                accessibilityInjected = w.accessibilityInjected / 2,
                virtualDevice = w.virtualDevice / 2,
                syntheticId = w.syntheticId / 2,
                downTimestamps = w.downTimestamps.copyOfRange(w.downTimestamps.size / 2, w.downTimestamps.size),
            )
        }
    }

    /** 扫描快照（C12 消费）。 */
    data class Snapshot(
        val total: Int,
        val accessibilityRatio: Float,
        val virtualRatio: Float,
        val syntheticRatio: Float,
        /** ACTION_DOWN 间隔变异系数：<0.35 = 机器人级低抖动（初版保守不产出，仅 meta） */
        val downIntervalCv: Float?,
    )

    fun snapshot(): Snapshot {
        val w = window
        val cv = if (w.downTimestamps.size >= 8) {
            val gaps = ArrayList<Float>(w.downTimestamps.size - 1)
            for (i in 1 until w.downTimestamps.size) gaps.add((w.downTimestamps[i] - w.downTimestamps[i - 1]).toFloat())
            var mean = 0.0
            for (g in gaps) mean += g
            mean /= gaps.size
            if (mean > 0) {
                var varr = 0.0
                for (g in gaps) varr += (g - mean) * (g - mean)
                varr /= gaps.size
                kotlin.math.sqrt(varr).toFloat() / mean.toFloat()
            } else null
        } else null
        return Snapshot(
            total = w.total,
            accessibilityRatio = if (w.total > 0) w.accessibilityInjected.toFloat() / w.total else 0f,
            virtualRatio = if (w.total > 0) w.virtualDevice.toFloat() / w.total else 0f,
            syntheticRatio = if (w.total > 0) w.syntheticId.toFloat() / w.total else 0f,
            downIntervalCv = cv,
        )
    }

    /** 测试重置。 */
    fun reset() {
        window = Window()
    }
}
