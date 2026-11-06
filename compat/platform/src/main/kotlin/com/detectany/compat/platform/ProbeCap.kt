package com.detectany.compat.platform

/**
 * 版本 × 内核 × targetSdk 三维门控矩阵（design.md D7 的单一查询入口）。
 *
 * 数据依据（2026-11 调研）：
 * - /proc/net/unix：API ≤8 全体放行；9 起 untrusted_app 按 targetSdk 分域（≤25 豁免、≥26 拒）；
 *   10+ 官方声明 apps cannot access /proc/net。
 * - statx：内核 4.11+ 才存在（Android 7 全系 3.10/3.18/4.4 无）；Android 9-11 seccomp 白名单外 = SIGSYS
 *   杀进程而非 ENOSYS —— 因此本项目无条件禁用，不做任何试探。
 * - memfd_create：内核 3.17+；3.10 机型 ENOSYS 且 ART 记录过旧内核直接段错误的案例，禁止试探回退。
 * - getrandom：bionic 包装 API 28、裸调用需内核 3.17；降级路径 arc4random_buf（全版本可用）。
 * - exec/W^X：targetSdk ≥29（Android 10）禁止 execve 应用 home 目录与可写 fd 映射可执行段。
 * - key attestation：setAttestationChallenge 自 API 24。
 */
object ProbeCap {

    private val KERNEL_MEMFD = KernelVersion(3, 17, 0)
    private val KERNEL_GETRANDOM = KernelVersion(3, 17, 0)

    fun status(probe: Probe, env: PlatformEnv): ProbeStatus = when (probe) {
        Probe.PROC_NET_UNIX -> procNetUnix(env)

        // 无条件禁止：见 Probe.STATX 文档 —— 存在性与 SIGSYS 双重理由，任何环境都不放行
        Probe.STATX -> ProbeStatus(probe, ProbeCapability.BLOCKED, "statx disabled by policy: kernel<4.11 on API24/25 and SIGSYS on 9-11")

        Probe.MEMFD_CREATE -> gateKernel(probe, env, KERNEL_MEMFD, "memfd_create requires kernel>=3.17 (3.10 may crash, never probe-fallback)")

        Probe.GETRANDOM -> when {
            env.apiLevel >= 28 && (env.kernel == null || env.kernel >= KERNEL_GETRANDOM) ->
                ProbeStatus(probe, ProbeCapability.ALLOWED, "bionic getrandom wrapper available")

            else -> ProbeStatus(probe, ProbeCapability.DEGRADED, "fallback to arc4random_buf (full-version available)")
        }

        Probe.EXEC_FROM_HOME -> if (env.targetSdk >= 29) {
            ProbeStatus(probe, ProbeCapability.BLOCKED, "W^X: execve from app home dir blocked for targetSdk>=29")
        } else {
            ProbeStatus(probe, ProbeCapability.ALLOWED, "allowed for legacy targetSdk (not relied upon)")
        }

        Probe.WX_MAPPING -> if (env.targetSdk >= 29) {
            ProbeStatus(probe, ProbeCapability.BLOCKED, "W^X: PROT_EXEC on writable fd blocked for targetSdk>=29")
        } else {
            ProbeStatus(probe, ProbeCapability.ALLOWED, "allowed for legacy targetSdk (not relied upon)")
        }

        Probe.KEY_ATTESTATION -> if (env.apiLevel >= 24) {
            ProbeStatus(probe, ProbeCapability.ALLOWED, "setAttestationChallenge since API 24; trust grading handled downstream")
        } else {
            ProbeStatus(probe, ProbeCapability.BLOCKED, "attestation API requires API 24")
        }
    }

    private fun procNetUnix(env: PlatformEnv): ProbeStatus = when {
        env.apiLevel <= 28 -> ProbeStatus(
            Probe.PROC_NET_UNIX,
            ProbeCapability.ALLOWED,
            "readable on API<=28 (Android 7 dividend)",
        )

        env.apiLevel == 29 && env.targetSdk <= 25 -> ProbeStatus(
            Probe.PROC_NET_UNIX,
            ProbeCapability.ALLOWED,
            "untrusted_app_25 domain exempted on API 29",
        )

        else -> ProbeStatus(
            Probe.PROC_NET_UNIX,
            ProbeCapability.BLOCKED,
            "EACCES on API>=29 for targetSdk>=26 / API>=10; use connect() probing fallback",
        )
    }

    private fun gateKernel(
        probe: Probe,
        env: PlatformEnv,
        min: KernelVersion,
        blockedReason: String,
    ): ProbeStatus {
        val kernel = env.kernel
            ?: return ProbeStatus(probe, ProbeCapability.BLOCKED, "unknown kernel version: conservative block")
        return if (kernel >= min) {
            ProbeStatus(probe, ProbeCapability.ALLOWED, "kernel ${kernel} >= $min")
        } else {
            ProbeStatus(probe, ProbeCapability.BLOCKED, blockedReason)
        }
    }
}
