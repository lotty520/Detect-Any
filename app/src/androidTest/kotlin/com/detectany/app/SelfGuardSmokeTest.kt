package com.detectany.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.detectany.core.model.Finding
import com.detectany.selfguard.GuardJni
import com.detectany.selfguard.SelfGuardService
import com.detectany.selfguard.SilentResponsePolicy
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** 任务组 6 设备侧验证：native 完整性桥 / 反调试探针 / 重打包检出 / 静默响应存活。 */
@RunWith(AndroidJUnit4::class)
class SelfGuardSmokeTest {

    private val ctx get() = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun nativeConstantTimeEqualsWorks() {
        val a = SelfGuardService.computeSignatureDigest(ctx)
        assertTrue(GuardJni.constantTimeEquals(a, a))
        val tampered = a.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(GuardJni.constantTimeEquals(a, tampered))
    }

    @Test
    fun nativeExpectedValuesAssemble() {
        assertEquals(32, GuardJni.assembleExpectedSignature().size)
        // 占位常量非全零（机制有效性）
        assertTrue(GuardJni.assembleExpectedSignature().any { it != 0.toByte() })
    }

    @Test
    fun repackagingDetectionMechanism() {
        val actual = SelfGuardService.computeSignatureDigest(ctx)
        // 等效重打包：期望与实际不符 → repackaged Finding（A 级）
        val guard = SelfGuardService(
            signatureSha256 = { actual },
            dexCrc = { null },
            expectedSignature = { actual.copyOf().also { it[3] = (it[3] + 7).toByte() } },
        )
        val findings = guard.inspect()
        assertEquals(listOf("selfguard.repackaged_signature"), findings.map { it.ruleId })
        assertEquals(Finding.Category.REPACKAGED, findings.single().category)
    }

    @Test
    fun cleanEnvironmentNoSelfGuardFindings() {
        val actual = SelfGuardService.computeSignatureDigest(ctx)
        val crc = SelfGuardService.computeDexCrc(ctx)
        val guard = SelfGuardService(
            signatureSha256 = { actual },
            dexCrc = { crc },
            expectedSignature = { actual },
            expectedDexCrc = { crc },
        )
        assertEquals(0, guard.inspect().size)
    }

    @Test
    fun noDebuggerOnTestEnvironment() {
        val guard = SelfGuardService.fromContext(ctx)
        // 模拟器测试进程无调试器：探针 0/无 TracerPid 命中（检出能力由 6.2 单测覆盖）
        assertEquals(0L, SelfGuardService.readTracerPid())
    }

    @Test
    fun silentResponseKeepsProcessAlive() = runBlocking {
        var handled = false
        val policy = SilentResponsePolicy(delayMs = 10) { handled = true }
        policy.handle(listOf(Finding("x", com.detectany.core.model.CollectorId.C7_CODE_INTEGRITY, com.detectany.core.model.Confidence.A, Finding.Category.REPACKAGED, null, "t", emptyMap())))
        assertTrue(handled)
        // 进程存活到断言本身即「不崩溃」验证
    }
}
