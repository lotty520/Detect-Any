package com.detectany.compat.platform

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * 任务 1.3 验证单测：矩阵关键格。
 * 覆盖：statx 于 9-11 blocked（及全环境 blocked）、/proc/net/unix 10+ blocked（7 红利 allowed）、
 * memfd 按内核 ≥3.17 门控、getrandom 走 arc4random 回退。
 */
class ProbeCapTest {

    private fun env(api: Int, target: Int = 35, kernel: String? = "4.14.186") =
        PlatformEnv(api, target, kernel?.let(KernelVersion::parse))

    // --- statx：策略性无条件禁用（内核缺失 + 9-11 SIGSYS 双重理由） ---

    @Test
    fun statxBlockedOnAndroid9To11() {
        for (api in 28..30) {
            assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.STATX, env(api)).capability, "api=$api")
        }
    }

    @Test
    fun statxBlockedEverywhereIncludingNewKernels() {
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.STATX, env(24, kernel = "3.10.101")).capability)
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.STATX, env(35, kernel = "6.1.75")).capability)
    }

    // --- /proc/net/unix：Android 7 红利 → 10+ 现代.targetSdk 阻塞 ---

    @Test
    fun procNetUnixReadableOnAndroid7And8() {
        for (api in 24..28) {
            assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.PROC_NET_UNIX, env(api)).capability, "api=$api")
        }
    }

    @Test
    fun procNetUnixBlockedOnAndroid10Plus() {
        for (api in 30..35) {
            assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.PROC_NET_UNIX, env(api)).capability, "api=$api")
        }
    }

    @Test
    fun procNetUnixOnApi29DependsOnTargetSdk() {
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.PROC_NET_UNIX, env(29, target = 25)).capability)
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.PROC_NET_UNIX, env(29, target = 26)).capability)
    }

    // --- memfd_create：内核 ≥3.17 门控（3.10 真空，禁止试探回退） ---

    @Test
    fun memfdGatedByKernelVersion() {
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.MEMFD_CREATE, env(24, kernel = "3.10.101")).capability)
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.MEMFD_CREATE, env(25, kernel = "3.10.84")).capability)
    }

    @Test
    fun memfdAllowedOnModernKernels() {
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.MEMFD_CREATE, env(24, kernel = "3.18.120")).capability)
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.MEMFD_CREATE, env(24, kernel = "4.4.302")).capability)
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.MEMFD_CREATE, env(35, kernel = "6.1.75")).capability)
    }

    @Test
    fun memfdBlockedWhenKernelUnknown() {
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.MEMFD_CREATE, env(35, kernel = null)).capability)
    }

    // --- getrandom：API<28 或老内核 → arc4random 回退 ---

    @Test
    fun getrandomFallsBackToArc4randomOnApi24Kernel310() {
        val s = ProbeCap.status(Probe.GETRANDOM, env(24, kernel = "3.10.101"))
        assertEquals(ProbeCapability.DEGRADED, s.capability)
    }

    @Test
    fun getrandomDegradedOnApi24EvenWithNewKernelBecauseBionicWrapperMissing() {
        // bionic 包装 API 28 才有；24/25 即使内核支持也走 arc4random
        assertEquals(ProbeCapability.DEGRADED, ProbeCap.status(Probe.GETRANDOM, env(25, kernel = "3.18.120")).capability)
    }

    @Test
    fun getrandomAllowedOnApi28PlusWithModernKernel() {
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.GETRANDOM, env(28, kernel = "4.4.302")).capability)
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.GETRANDOM, env(35, kernel = "6.1.75")).capability)
    }

    // --- W^X / exec：targetSdk 29 分界 ---

    @Test
    fun execFromHomeBlockedForModernTargetSdk() {
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.EXEC_FROM_HOME, env(30, target = 29)).capability)
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.EXEC_FROM_HOME, env(28, target = 28)).capability)
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.WX_MAPPING, env(35, target = 35)).capability)
    }

    // --- key attestation：API 24 起 ---

    @Test
    fun keyAttestationAvailableSinceApi24() {
        assertEquals(ProbeCapability.ALLOWED, ProbeCap.status(Probe.KEY_ATTESTATION, env(24)).capability)
        assertEquals(ProbeCapability.BLOCKED, ProbeCap.status(Probe.KEY_ATTESTATION, env(23)).capability)
    }
}
