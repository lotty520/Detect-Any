package com.detectany.compat.platform

/**
 * 平台环境快照：ProbeCap 的全部输入。
 * Android 侧由调用方组装（Build.VERSION.SDK_INT / ApplicationInfo.targetSdkVersion / uname），
 * 本模块保持纯 JVM 以便矩阵单测。
 */
data class PlatformEnv(
    val apiLevel: Int,
    val targetSdk: Int,
    val kernel: KernelVersion?,
)
