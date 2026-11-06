package com.detectany.core.nativeplatform

/**
 * 原生层 syscall 白名单（任务 2.2）：与 raw_syscalls.cpp 中 kAllowedNrs 保持镜像。
 * 双端静态定义是刻意设计（native 层不依赖任何运行时数据）；单测断言集合一致性。
 * 成员 = 三路 diff 最小集 + 显式探针号（reboot/prctl/ptrace/supercall 均为安全探测形态）。
 */
object SyscallAllowlist {

    /** arm64-v8a：openat/close/newfstatat/faccessat + statfs/reboot/prctl/ptrace/supercall(45) */
    val ARM64 = setOf(56L, 57L, 79L, 48L, 43L, 142L, 167L, 117L, 45L)

    /** armeabi-v7a：openat/close/fstatat64/faccessat + statfs64/reboot/prctl/ptrace/supercall(46) */
    val ARM32 = setOf(322L, 6L, 300L, 334L, 266L, 88L, 172L, 26L, 46L)

    /** statx 的 syscall 号（两种架构）——必须永远不在白名单内。 */
    const val STATX_ARM64 = 291L
    const val STATX_ARM32 = 397L

    fun forArch(abi: String?): Set<Long>? = when (abi) {
        "arm64-v8a" -> ARM64
        "armeabi-v7a" -> ARM32
        else -> null
    }
}
