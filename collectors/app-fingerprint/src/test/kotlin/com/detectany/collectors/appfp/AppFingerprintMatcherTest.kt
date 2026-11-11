package com.detectany.collectors.appfp

import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.SignatureEntries
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** 任务 3.5 验证：包名/证书钉住/内容指纹（spoofed 变体）匹配。 */
class AppFingerprintMatcherTest {

    @Test
    fun spoofedPackageCaughtByDexStringFingerprint() {
        // SukiSU spoofed 构建：包名被随机化，但 DEX 内容探针全命中
        val entry = SignatureEntries.AppEntry(
            id = "app.sukisu",
            packageNames = listOf("com.sukisu.ultra"),
            dexStrings = listOf("sukisu", "KernelSU"),
            framework = "sukisu",
            confidence = Confidence.B,
            category = Finding.Category.ROOT_KERNEL,
        )
        val f = AppFingerprintMatcher.match(entry, "aaaaaa.bbbbbb.cccccc", certSha256Hex = null, presentStrings = setOf("sukisu", "KernelSU", "其他字符串"))
        assertEquals(Confidence.B, f?.confidence)
        assertTrue(f!!.detail.contains("双命中"))  // 2026-11-10 文案修正：包名+内容双命中
    }

    @Test
    fun partialDexProbeNowMatchesUnderAnySemantics() {
        // 2026-11-06 语义修订：高特异词任一命中即 B（包名不进 dex 池，containsAll 导致真机漏检）
        val entry = SignatureEntries.AppEntry(
            id = "x", packageNames = listOf("p"), dexStrings = listOf("a", "b"),
            framework = "m", confidence = Confidence.B, category = Finding.Category.ROOT_USERSPACE,
        )
        val hit = AppFingerprintMatcher.match(entry, "p", null, setOf("a"))
        assertEquals(Confidence.B, hit?.confidence)
        // 2026-11-10 准确性双向修正：内容未命中不再整条漏检（FN 洞），降级 C
        val miss = AppFingerprintMatcher.match(entry, "p", null, emptySet())
        assertEquals(Confidence.C, miss?.confidence)
        assertEquals("false", miss?.raw?.get("contentVerified"))
    }

    @Test
    fun certPinMatchUpgradesAndMismatchExcludes() {
        val entry = SignatureEntries.AppEntry(
            id = "app.magisk", packageNames = listOf("com.topjohnwu.magisk"),
            certPins = listOf("aa".repeat(32)), dexStrings = listOf("libmagisk"),
            framework = "magisk", confidence = Confidence.B, category = Finding.Category.ROOT_USERSPACE,
        )
        val hit = AppFingerprintMatcher.match(entry, "com.topjohnwu.magisk", "AA".repeat(32), emptySet())
        assertEquals(Confidence.B, hit?.confidence)
        // 同包名但证书不符（第三方重打包/仿冒）→ 排除，不出 Finding
        assertNull(AppFingerprintMatcher.match(entry, "com.topjohnwu.magisk", "ff".repeat(32), emptySet()))
    }

    @Test
    fun nameOnlyEntryIsWeak() {
        val entry = SignatureEntries.AppEntry(
            id = "x", packageNames = listOf("com.kingroot"),
            framework = "kingroot", confidence = Confidence.C, category = Finding.Category.ROOT_USERSPACE,
        )
        assertEquals(Confidence.C, AppFingerprintMatcher.match(entry, "com.kingroot", null, emptySet())?.confidence)
    }

    private fun assertTrue(b: Boolean) = kotlin.test.assertTrue(b)
}
