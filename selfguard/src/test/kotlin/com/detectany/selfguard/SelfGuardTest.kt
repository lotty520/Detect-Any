package com.detectany.selfguard

import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * 任务 6.1-6.3 主机验证：完整性/反调试判定逻辑 + 静默响应（不崩溃、延迟触发）。
 * native 桥（XOR 还原/常数时间比较/调试器探针）在设备冒烟覆盖。
 */
class SelfGuardTest {

    private val sigA = ByteArray(32) { it.toByte() }
    private val sigB = ByteArray(32) { (it + 1).toByte() }

    private fun service(
        sig: ByteArray? = null,
        crc: Long? = null,
        tracer: Long = 0,
        probe: Int = 0,
        expSig: ByteArray = sigA,
        expCrc: Long = 42L,
    ) = SelfGuardService(
        signatureSha256 = { sig },
        dexCrc = { crc },
        tracerPid = { tracer },
        debuggerProbe = { probe },
        expectedSignature = { expSig },
        expectedDexCrc = { expCrc },
        bytesEqual = { a, b -> a.contentEquals(b) },
        probeIntervalMs = 0, // 主机测试：同步模式（无后台线程/缓存语义）
    )

    @Test
    fun signatureMismatchYieldsRepackagedFinding() {
        val f = service(sig = sigB, expSig = sigA).inspect()
        assertEquals("selfguard.repackaged_signature", f.single().ruleId)
        assertEquals(Confidence.A, f.single().confidence)
        assertEquals(Finding.Category.REPACKAGED, f.single().category)
    }

    @Test
    fun dexCrcMismatchYieldsFinding() {
        val f = service(crc = 1234L, expCrc = 5678L).inspect()
        assertEquals("selfguard.dex_crc", f.single().ruleId)
        assertEquals(Confidence.B, f.single().confidence)
    }

    @Test
    fun tracerPidDetected() {
        val f = service(tracer = 90210).inspect()
        val hit = f.first { it.ruleId == "selfguard.tracer_pid" }
        assertTrue(hit.detail.contains("90210"))
    }

    @Test
    fun debuggerProbeDetected() {
        val f = service(probe = 1).inspect()
        assertTrue(f.any { it.ruleId == "selfguard.debugger_attached" })
    }

    @Test
    fun cleanEnvironmentQuiet() {
        assertEquals(0, service(sig = sigA, crc = 42L, expSig = sigA, expCrc = 42L).inspect().size)
    }

    @Test
    fun nullInputsAreSkipped() {
        assertEquals(0, service(sig = null, crc = null).inspect().size)
    }

    @Test
    fun tracerPidParsesStatusText() {
        val status = """
            Name:    com.detectany.app
            State:   S
            TracerPid:	4711
            Threads:	17
        """.trimIndent()
        val pid = status.lineSequence()
            .firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toLongOrNull() ?: -1
        assertEquals(4711L, pid)
    }

    // ---- 6.3 静默响应 ----

    private fun finding() = Finding("x", CollectorId.C7_CODE_INTEGRITY, Confidence.A, Finding.Category.REPACKAGED, null, "t", emptyMap())

    @Test
    fun silentResponseDelaysAndNeverThrows() = runTest {
        var fired = false
        val policy = SilentResponsePolicy(delayMs = 100) { fired = true }
        policy.handle(emptyList())
        assertTrue(!fired, "无发现不应触发")
        policy.handle(listOf(finding()))
        assertTrue(fired, "有发现延迟后触发")
    }

    @Test
    fun silentResponseSwallowsCallbackExceptions() = runTest {
        val policy = SilentResponsePolicy(delayMs = 10) { error("callback exploded") }
        policy.handle(listOf(finding()))
        // 不上抛即通过（不崩溃承诺）
    }
}
