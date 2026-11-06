package com.detectany.collectors.memmap

import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 3.6 验证：maps/smaps/soinfo 交叉/RWX 自探针分析。 */
class MemoryMapAnalyzerTest {

    @Test
    fun detectsInjectedMemfd() {
        val maps = listOf(
            MapEntry(0x1000, 0x2000, "r-xp", null),
            MapEntry(0x3000, 0x4000, "r-xp", "/memfd:jit-cache-zygisk_lsposed (deleted)"),
        )
        val f = MemoryMapAnalyzer.analyze(maps, emptyMap(), emptyList(), emptyList(), 1)
        assertEquals(1, f.size)
        assertEquals(Confidence.B, f[0].confidence)
        assertEquals(Finding.Category.ZYGISK, f[0].category)
    }

    @Test
    fun detectsKnownHookPaths() {
        val maps = listOf(MapEntry(0x1000, 0x2000, "r-xp", "/data/adb/lspd/liblspd.so"))
        val f = MemoryMapAnalyzer.analyze(maps, emptyMap(), emptyList(), emptyList(), 1)
        assertTrue(f.any { it.ruleId == "mem.known_path" && it.framework == "lsposed" })
    }

    @Test
    fun detectsLibartCowDirty() {
        val maps = listOf(MapEntry(0x5000, 0x6000, "r-xp", "/apex/com.android.art/lib64/libart.so"))
        val f = MemoryMapAnalyzer.analyze(maps, mapOf(0x5000L to 4L), emptyList(), emptyList(), 1)
        assertTrue(f.any { it.ruleId == "mem.libart_cow" && it.detail.contains("4KB") })
    }

    @Test
    fun detectsFdPointingToDataAdb() {
        val f = MemoryMapAnalyzer.analyze(emptyList(), emptyMap(), listOf("/data/adb/modules/zygisksu/x.so"), emptyList(), 1)
        assertEquals("mem.fd_data_adb", f.single().ruleId)
    }

    @Test
    fun detectsHiddenMappingSolistVsMaps() {
        // linker 链表有 libx.so @0x9000，但 maps 中无对应区间
        val maps = listOf(MapEntry(0x1000, 0x2000, "r-xp", "/system/lib64/libc.so"))
        val solist = listOf("/system/lib64/libc.so\t4096", "/data/local/tmp/libx.so\t36864")
        val f = MemoryMapAnalyzer.analyze(maps, emptyMap(), emptyList(), solist, 1)
        assertTrue(f.any { it.ruleId == "mem.hidden_mapping" && it.detail.contains("libx.so") })
    }

    @Test
    fun rwxSelfProbeInvisibleIsStrongFinding() {
        val f = MemoryMapAnalyzer.analyze(emptyList(), emptyMap(), emptyList(), emptyList(), 0)
        val strong = f.single()
        assertEquals("mem.maps_tampered", strong.ruleId)
        assertEquals(Confidence.A, strong.confidence)
    }

    @Test
    fun cleanEnvironmentNoFindings() {
        val maps = listOf(
            MapEntry(0x1000, 0x2000, "r-xp", "/system/lib64/libc.so"),
            MapEntry(0x3000, 0x3400, "rw-p", "[anon:.bss]"),
        )
        val solist = listOf("/system/lib64/libc.so\t4096")
        assertEquals(0, MemoryMapAnalyzer.analyze(maps, emptyMap(), emptyList(), solist, 1).size)
    }
}
