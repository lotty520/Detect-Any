package com.detectany.collectors.screenshare

import java.util.concurrent.Executor

/**
 * 系统级屏幕录制状态监控（G5，API 34+）。
 *
 * WindowManager.addScreenRecordingCallback(Executor, Consumer<Integer>) 上报
 * 「本应用画面是否正被系统级录制」（状态栏录屏指示器语义，OEM 录屏 + 设置了
 * 指示器的 MediaProjection 均覆盖）。需 Activity 可见期间注册（onStart/onStop）；
 * 扫描时读取最近状态。
 *
 * 降级行为：API <34 或未注册期间 stateVisible=null（未知），不产出 Finding。
 */
object ScreenRecordingMonitor {

    /** 最近一次系统上报的「应用可见于录制」状态；null=未知（未注册/未上报）。 */
    @Volatile
    var stateVisible: Boolean? = null
        private set

    /** 最近一次状态变更时间戳（elapsedRealtime），用于证据呈现。 */
    @Volatile
    var lastChangedAtMs: Long = 0L
        private set

    fun update(visible: Boolean) {
        stateVisible = visible
        lastChangedAtMs = android.os.SystemClock.elapsedRealtime()
    }

    /** 测试重置。 */
    fun reset() {
        stateVisible = null
        lastChangedAtMs = 0L
    }

    /**
     * 由 Activity onStart 调用（API 34+）。返回注销句柄（onStop 调用）。
     * API <34 返回 null（能力缺失，静默降级）。
     */
    fun register(activity: android.app.Activity, executor: Executor): AutoCloseable? {
        if (android.os.Build.VERSION.SDK_INT < 34) return null
        return runCatching {
            val cb = java.util.function.Consumer<Int> { state ->
                update(state == android.view.WindowManager.SCREEN_RECORDING_STATE_VISIBLE)
            }
            activity.windowManager.addScreenRecordingCallback(executor, cb)
            AutoCloseable { runCatching { activity.windowManager.removeScreenRecordingCallback(cb) } }
        }.getOrNull()
    }
}
