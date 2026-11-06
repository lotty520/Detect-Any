package com.detectany.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.detectany.collectors.codeintegrity.CodeIntegrityCollector
import com.detectany.core.nativeplatform.ElfJni
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * CRITICAL#3 修复：C7 内存改写桩检出（等效形态：篡改磁盘副本的 prologue 字节 →
 * 磁盘 vs 内存比对必须命中；真实内存改写受 W^X/SELinux 限制不可注入）。
 */
@RunWith(AndroidJUnit4::class)
class CodeIntegrityMutationTest {

    @Test
    fun mutatedDiskCopyTriggersPrologueFinding() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val loc = CodeIntegrityCollector.locateOwnLib(ctx) ?: error("own lib not located")
        val original = File(loc.diskPath).readBytes()

        // 取一个已知导出符号的 prologue 字节，在副本中翻转首字节（等效内存被 inline hook 改写）
        val sym = "Java_com_detectany_core_nativeplatform_ProbeJni_ksuProbe"
        val vaddr = ElfJni.exportValue(loc.diskPath, sym)
        assertTrue("符号应可解析", vaddr != 0L)
        val prologue = ElfJni.readAtVaddr(loc.diskPath, vaddr, 32)
        assertTrue("prologue 可读", prologue != null && prologue!!.size >= 16)

        val mutated = original.copyOf()
        val idx = indexOf(mutated, prologue!!)
        assertTrue("应在副本中找到 prologue 序列", idx >= 0)
        mutated[idx] = (mutated[idx].toInt() xor 0x5A).toByte()

        val mutatedPath = File(ctx.cacheDir, "libdetectany_native_mutated.so")
        mutatedPath.writeBytes(mutated)

        // 用被篡改的「磁盘事实」对照真实内存 → 必须产出 prologue 不一致 Finding（A 级）
        val findings = com.detectany.collectors.codeintegrity.IntegrityAnalyzer
            .checkPrologues(mutatedPath.absolutePath, loc.base)
        assertTrue("篡改副本必须触发检出: ${findings.map { it.ruleId }}", findings.isNotEmpty())
        assertTrue(findings.any { it.ruleId.startsWith("integrity.prologue") })
        assertEquals(
            com.detectany.core.model.Confidence.A,
            findings.first { it.ruleId.startsWith("integrity.prologue") }.confidence,
        )
        mutatedPath.delete()
    }

    @Test
    fun pristineDiskMatchesMemory() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val loc = CodeIntegrityCollector.locateOwnLib(ctx) ?: error("own lib not located")
        val findings = com.detectany.collectors.codeintegrity.IntegrityAnalyzer
            .checkPrologues(loc.diskPath, loc.base)
        assertEquals("未篡改对照必须零命中: ${findings.map { it.ruleId }}", 0, findings.size)
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
