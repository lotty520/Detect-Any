package com.detectany.collectors.screenshare

import android.app.Activity
import android.os.Build
import android.view.Display

/**
 * 自身所在 Display 追踪（change virtual-display-detect）。
 * application context 取不到自身屏位——由 MainActivity.onResume 注入
 * （对齐 InputEventMonitor/ScreenRecordingMonitor 的 UI 供数惯例）。
 * scrcpy --start-app 在 activity resume 前即完成建屏+落屏，onResume 时序足够。
 */
object SelfDisplayTracker {

    @Volatile
    var displayId: Int = Display.DEFAULT_DISPLAY
        private set

    fun update(activity: Activity) {
        displayId = if (Build.VERSION.SDK_INT >= 30) {
            runCatching { activity.display?.displayId ?: Display.DEFAULT_DISPLAY }.getOrDefault(Display.DEFAULT_DISPLAY)
        } else {
            runCatching {
                @Suppress("DEPRECATION")
                activity.windowManager.defaultDisplay.displayId
            }.getOrDefault(Display.DEFAULT_DISPLAY)
        }
    }
}
