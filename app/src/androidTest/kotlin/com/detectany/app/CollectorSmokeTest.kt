package com.detectany.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.detectany.collectors.appfp.AppFingerprintCollector
import com.detectany.collectors.behavior.BehaviorCollector
import com.detectany.collectors.codeintegrity.CodeIntegrityCollector
import com.detectany.collectors.fsprobe.MountCollector
import com.detectany.collectors.fsprobe.PathProbeCollector
import com.detectany.collectors.memmap.MemoryMapCollector
import com.detectany.collectors.props.PropertyCollector
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.ScanInput
import com.detectany.core.model.ScanTier
import com.detectany.collectors.endpoints.EndpointCollector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 干净模拟器上的采集器冒烟（任务组 3 设备侧验证）：
 * 全部 8 个采集器可执行、无 BLOCKED（C4 在 API35 预期 DEGRADED）、
 * 且干净环境零误报（误处置率 <0.1% 验收的最低门槛）。
 */
@RunWith(AndroidJUnit4::class)
class CollectorSmokeTest {

    private fun input() = ScanInput(ScanTier.L2, apiLevel = 35, targetSdk = 35, kernelRelease = "6.1.75", abi = "arm64-v8a")

    private fun run(c: com.detectany.core.model.Collector): CollectorResult = c.collect(input())

    @Test
    fun c1PathProbeCleanNoFalsePositive() {
        val r = run(PathProbeCollector())
        assertEquals(CollectorResult.Status.OK, r.status)
        assertEquals("特征路径在干净环境不应命中: ${r.findings}", 0, r.findings.size)
    }

    @Test
    fun c2MountCollectorClean() {
        val r = run(MountCollector())
        assertTrue(r.status != CollectorResult.Status.BLOCKED)
        assertEquals("挂载分析在干净环境不应命中: ${r.findings}", 0, r.findings.size)
        assertTrue(r.meta.getValue("mounts").toInt() > 10)
    }

    @Test
    fun c3PropertyCollectorClean() {
        val r = run(PropertyCollector())
        assertTrue(r.status != CollectorResult.Status.BLOCKED)
        if (isEmulator()) {
            assertEquals("模拟器应零属性命中: ${r.findings}", 0, r.findings.filter { it.ruleId.startsWith("prop.") }.size)
        } else {
            // 真机（含对抗组 ROOT 设备）：残留属性/verified boot 矛盾属真阳性，不断言零命中；
            // 只排除不可能为真的类别（模拟器属性出现在真机 = 假阳性）
            val fp = r.findings.filter { it.category == com.detectany.core.model.Finding.Category.EMULATOR }
            assertEquals("真机不应出现模拟器类属性命中: ${fp}", 0, fp.size)
        }
        assertTrue(r.meta.getValue("count").toInt() > 100)
    }

    @Test
    fun c4EndpointCollectorDegradedOnApi35() {
        val r = run(EndpointCollector())
        // API 35 + targetSdk 35：/proc/net/unix 门控 BLOCKED → 采集器整体 DEGRADED（透明降级）
        assertEquals(CollectorResult.Status.DEGRADED, r.status)
        assertEquals(0, r.findings.size)
    }

    @Test
    fun c5AppFingerprintClean() {
        val r = run(AppFingerprintCollector.fromContext(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext))
        assertEquals(CollectorResult.Status.OK, r.status)
        if (isEmulator()) {
            assertEquals("干净模拟器必须零命中: ${r.findings.map { it.ruleId }}", 0, r.findings.size)
        } else {
            // 真机可能真实安装 root/作弊管理器（2026-11-06 Pixel 8 实证：APatch manager 命中）
            // —— 命中属真阳性，但必须为合理置信级（内容指纹 B / 包名 C），不得出现异常形态
            assertTrue(
                "命中置信级异常: ${r.findings.map { it.ruleId to it.confidence }}",
                r.findings.all { it.confidence == com.detectany.core.model.Confidence.B || it.confidence == com.detectany.core.model.Confidence.C },
            )
        }
    }

    @Test
    fun c6MemoryMapClean() {
        val r = run(MemoryMapCollector())
        assertTrue(r.status != CollectorResult.Status.BLOCKED)
        assertEquals("内存分析在干净环境不应命中: ${r.findings}", 0, r.findings.size)
        assertTrue(r.meta.getValue("mappings").toInt() > 100)
    }

    @Test
    fun c7CodeIntegrityClean() {
        val ctx = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val r = run(CodeIntegrityCollector(ownLib = { CodeIntegrityCollector.locateOwnLib(ctx) }))
        assertEquals("C7 状态异常: ${r.meta}", CollectorResult.Status.OK, r.status)
        // prologue/GOT 校验必须真实执行过（meta 带基址），而非静默跳过
        assertTrue("C7 未定位到自身库: ${r.meta}", r.meta.containsKey("base"))
        if (isEmulator()) {
            assertEquals("干净模拟器必须零命中: ${r.findings.map { it.ruleId }}", 0, r.findings.size)
        } else {
            // 真机（可能是 ROOT/作弊环境）：命中必须为真阳性（真实补丁字节），不得是全零伪影
            val prologues = r.findings.filter { it.ruleId.startsWith("integrity.prologue") }
            assertNoPrologueArtifacts("C7", prologues.map { it.raw["mem"] ?: "" })
        }
    }

    /** 真阳性 vs 伪影判定（准确为大前提）：prologue 命中的 mem 全零 = 读原语退化（伪影，失败）；真实补丁代码 = 真阳性 */
    internal fun assertNoPrologueArtifacts(tag: String, rawMems: List<String>) {
        val zeros = rawMems.filter { it.isNotEmpty() && it.all { c -> c == '0' } }
        assertTrue("$tag 存在 mem 全零伪影（textRead 退化）: $zeros", zeros.isEmpty())
    }

    internal fun isEmulator(): Boolean = android.os.Build.FINGERPRINT.contains("generic") ||
        android.os.Build.MODEL.contains("Emulator") ||
        android.os.Build.PRODUCT.contains("sdk_gphone") ||
        android.os.Build.PRODUCT.contains("emulator")

    @Test
    fun c8BehaviorProbeCleanNoFalsePositive() {
        val r = run(BehaviorCollector())
        assertEquals(CollectorResult.Status.OK, r.status)
        // 原厂内核：KSU reboot 探针不得产生 fd；APatch HELLO 不返回 magic；SELinux 对照生效
        assertEquals("行为探针在原厂内核不得误报(meta=${r.meta}): ${r.findings.map { it.ruleId to it.detail }}", 0, r.findings.size)
        assertTrue(r.meta.containsKey("ksuRet"))
        assertTrue(r.meta.containsKey("apatchRet"))
        assertTrue(r.meta.containsKey("nativebridgeError"))
    }
}
