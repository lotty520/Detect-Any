package com.detectany.collectors.instrumentprobe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * C9 加固防线主机单测。fixture 取自 2026-11-16 P8 受控改名实验的真实 /proc 取证
 * （docs/REGRESSION.md 当日节）。
 */
class C9AnalyzerTest {

    // ---- P8 实测：frida-gadget 17.26.2 驻留进程的 5 处无名匿名 rwxp 簇 ----
    private val gadgetRwxMaps = listOf(
        "7856800000-7856807000 rwxp 00000000 00:00 0 ",
        "786c000000-786c007000 rwxp 00000000 00:00 0 ",
        "7893601000-7893608000 rwxp 00000000 00:00 0 ",
        "7893851000-7893852000 rwxp 00000000 00:00 0 ",
        "789385a000-789385b000 rwxp 00000000 00:00 0 ",
    )

    // 干净进程对照：带路径 r-x（apk 库）+ 命名区 + 无 rwxp
    private val cleanMaps = listOf(
        "7046d5b000-7046d5f000 r--p 00000000 fd:00 1234 /data/app/~~xyz/com.detectany.app-Abc/lib/arm64/libdetectany_native.so",
        "7046d60000-7046d64000 r-xp 00004000 fd:00 1234 /data/app/~~xyz/com.detectany.app-Abc/lib/arm64/libdetectany_native.so",
        "7fc8e2a000-7fc8e6b000 rw-p 00000000 00:00 0 [anon:dalvik-jit-code-cache]",
        "7f8a000000-7f8a002000 rw-p 00000000 00:00 0 ",
    )

    @Test
    fun anonRwxCoverage_detectsGadgetClusters() {
        val cov = C9Analyzer.anonRwxCoverage(gadgetRwxMaps)
        assertEquals(5, cov.regions)
        assertEquals(0x7000L * 3 + 0x1000L * 2, cov.bytes) // 3×28KB + 2×4KB = 92KB
        assertTrue(cov.hit, "实测 gadget 簇形态必须命中（5 处 / 92KB）")
    }

    @Test
    fun anonRwxCoverage_cleanProcessZero() {
        val cov = C9Analyzer.anonRwxCoverage(cleanMaps)
        assertEquals(0, cov.regions)
        assertFalse(cov.hit, "干净对照（含命名 jit-cache 与带路径映射）必须零命中")
    }

    @Test
    fun anonRwxCoverage_excludesNamedAndPathedRwx() {
        // 即便出现带路径/命名区的 rwxp（如极端 JIT 形态），不计入无名簇
        val maps = listOf(
            "7f00000000-7f00001000 rwxp 00000000 00:00 0 [anon:dalvik-jit-code-cache]",
            "7f10000000-7f10001000 rwxp 00000000 fd:00 9 /data/app/x/lib/arm64/libexample.so",
        )
        assertFalse(C9Analyzer.anonRwxCoverage(maps).hit)
    }

    @Test
    fun anonRwxCoverage_thresholdBoundaries() {
        // 1 处 4KB：低于双门槛 → 不命中（防孤例 FP）
        assertFalse(C9Analyzer.anonRwxCoverage(listOf("1000-2000 rwxp 00000000 00:00 0 ")).hit)
        // 2 处 4KB：段数门槛命中
        assertTrue(C9Analyzer.anonRwxCoverage(listOf("1000-2000 rwxp 00000000 00:00 0 ", "3000-4000 rwxp 00000000 00:00 0 ")).hit)
        // 1 处 16KB：字节门槛命中
        assertTrue(C9Analyzer.anonRwxCoverage(listOf("1000-5000 rwxp 00000000 00:00 0 ")).hit)
    }

    // ---- 外部路径可执行映射 ----

    @Test
    fun externalExecMapping_detectsGadgetInDataLocalTmp() {
        val maps = cleanMaps + "7a40000000-7a40010000 r-xp 00000000 fd:00 55 /data/local/tmp/fg.so"
        assertEquals("/data/local/tmp/fg.so", C9Analyzer.externalExecMapping(maps))
    }

    @Test
    fun externalExecMapping_sdcardAndStoragePrefixes() {
        assertEquals(
            "/sdcard/Download/evil.so",
            C9Analyzer.externalExecMapping(listOf("7000-8000 r-xp 00000000 00:00 0 /sdcard/Download/evil.so")),
        )
        assertEquals(
            "/storage/emulated/0/x.so",
            C9Analyzer.externalExecMapping(listOf("7000-8000 --xp 00000000 00:00 0 /storage/emulated/0/x.so")),
        )
    }

    @Test
    fun externalExecMapping_ignoresNonExecAndInternalPaths() {
        // 不可执行的外部文件（rw 数据）不算；app 内部路径（apk lib）不算
        assertNull(C9Analyzer.externalExecMapping(listOf("7000-8000 rw-p 00000000 00:00 0 /sdcard/data.bin")))
        assertNull(C9Analyzer.externalExecMapping(cleanMaps))
        // 藏进 app 私有目录（B6 尾巴最坏情况场景）不命中——由 rwx/glib 防线纵深承担
        assertNull(
            C9Analyzer.externalExecMapping(listOf("7000-8000 r-xp 00000000 00:00 0 /data/data/com.detectany.app/code_cache/fg.so")),
        )
    }

    // ---- GLib 线程组合 ----

    @Test
    fun glibPair_presentInRenamedGadgetProcess() {
        // P8 实测（改名 gadget）：xum-js-loop/xrida-gadget/gmain/gdbus 共存
        val threads = listOf("DetectAny-Colle", "xum-js-loop", "xrida-gadget", "gmain", "gdbus", "binder:1_2", "RenderThread")
        assertTrue(C9Analyzer.hasGlibPair(threads))
    }

    @Test
    fun glibPair_absentOnCleanApp() {
        // 干净 app / Chrome 对照实测：0
        assertFalse(C9Analyzer.hasGlibPair(listOf("main", "RenderThread", "binder:1_2", "hwuiTask0")))
        // 单独 gmain（GLib 合法共存形态，calibration #9）不命中
        assertFalse(C9Analyzer.hasGlibPair(listOf("main", "gmain", "RenderThread")))
    }
}
