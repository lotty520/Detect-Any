package com.detectany.collectors.behaviorcheck

/**
 * C11 自动化/仪表化纯匹配逻辑（2026-11-16 抽取，主机单测覆盖）。
 * 判据含 2026-11-12/16 真机实证修正（androidx.test 线程名截断形态、组件级标记）。
 */
object AutomationMatching {

    /**
     * 无障碍服务是否为已知自动化：
     * ① 包名命中已知自动化包（contains）
     * ② 完整组件串（pkg/class）命中测试框架标记——uiautomator2 服务寄宿于任意测试包名下，
     * 仅包名匹配会漏（2026-11-12 修正）
     */
    fun isKnownAutomation(
        svc: String,
        knownPackages: Set<String>,
        componentMarkers: Set<String>,
    ): Boolean {
        val svcLower = svc.lowercase()
        val pkg = svc.substringBefore("/").lowercase()
        return knownPackages.any { pkg.contains(it.lowercase()) } ||
            componentMarkers.any { svcLower.contains(it) }
    }

    /**
     * instrumentation 驻留线程名（TASK_COMM_LEN=15 截断形态）：
     * androidx.test 1.5+ 为 "InstrumentationThread" → comm 截断 "Instrumentation"（2026-11-12 Pixel4 实证）；
     * AOSP 老路径为 "Instr: <class>" 前缀。
     */
    fun isInstrumentationThread(comm: String): Boolean =
        comm.startsWith("instr:", ignoreCase = true) || comm.equals("instrumentation", ignoreCase = true)
}
