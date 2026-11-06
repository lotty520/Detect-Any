package com.detectany.compat.platform

/**
 * 受版本 × 内核 × targetSdk 门控的探测能力清单。
 * 依据 design.md D7 兼容矩阵；全部采集器 MUST 经 [ProbeCap] 取能力，
 * 禁止散落的 Build.VERSION 判断与「试探再回退」的裸 syscall 模式。
 */
enum class Probe {
    /** /proc/net/unix 读取（Android 7 红利；10+ 对现代 targetSdk EACCES） */
    PROC_NET_UNIX,

    /** statx：一律禁用 —— Android 7 内核(<4.11)不存在，且 9-11 上未列 seccomp 白名单的调用以 SIGSYS 杀进程 */
    STATX,

    /** memfd_create 裸 syscall：需内核 ≥3.17（3.10 机型 ENOSYS 甚至段错误；bionic 包装 API 30） */
    MEMFD_CREATE,

    /** getrandom：裸 syscall 需内核 3.17、bionic 包装 API 28；降级走 arc4random_buf */
    GETRANDOM,

    /** 从应用可写目录 execve 落盘 ELF：targetSdk ≥29 被 W^X 禁止（Termux 钉死 28 佐证） */
    EXEC_FROM_HOME,

    /** 经可写 fd 映射可执行段（W^X）：targetSdk ≥29 禁止 */
    WX_MAPPING,

    /** key attestation API（setAttestationChallenge 自 API 24 存在；可信度分级在 attestation-verify 内处理） */
    KEY_ATTESTATION,
}

/** 门控裁决。 */
enum class ProbeCapability {
    /** 正常执行 */
    ALLOWED,

    /** 可执行但结果受限/需走替代路径（reason 说明） */
    DEGRADED,

    /** 禁止执行；采集器输出降级标记 */
    BLOCKED,
}

/** 门控结果：裁决 + 机器可读原因。 */
data class ProbeStatus(val probe: Probe, val capability: ProbeCapability, val reason: String)
