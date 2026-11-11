package com.detectany.collectors.fsprobe

import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.ScanTier
import com.detectany.core.model.SignatureEntries
import com.detectany.core.nativeplatform.StatOutcome
import com.detectany.core.nativeplatform.SyscallBackend
import com.detectany.core.nativeplatform.TriplePathExecutor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 3.1/3.2 验证：C1 三路探测桩测试 + C2 mountinfo 解析/分析。 */
class FsProbeTest {

    private val ok = StatOutcome.Ok(7, 42, 0x8000, 1000, 1000, 123, 1700000000)

    private class FixedBackend(vararg val pair: Pair<String, Pair<StatOutcome, StatOutcome>>) : SyscallBackend {
        override fun statLibc(path: String) = pair.first { it.first == path }.second.second
        override fun statSvc(path: String) = pair.first { it.first == path }.second.first
    }

    private val javaView = TriplePathExecutor.JavaStatView { path ->
        if (path.contains("ramdisk")) ok.copy(dev = -1, ino = -1, uid = -1, gid = -1) else StatOutcome.Errno(2)
    }

    private val input = com.detectany.core.model.ScanInput(ScanTier.L2, 35, 35, "6.1.75", "arm64-v8a")

    @Test
    fun c1_existingPathYieldsEntryFinding() {
        val backend = FixedBackend("/debug_ramdisk/zygisk/monitor.sock" to (ok to ok))
        val collector = PathProbeCollector(
            paths = defaultPathEntries().filter { it.path == "/debug_ramdisk/zygisk/monitor.sock" },
            executor = TriplePathExecutor(backend, javaView),
        )
        val result = collector.collect(input)
        assertEquals(CollectorResult.Status.OK, result.status)
        assertEquals(1, result.findings.size)
        assertEquals("path.zygisk.monitor", result.findings[0].ruleId)
        assertEquals(Confidence.C, result.findings[0].confidence)
        assertEquals("zygisknext", result.findings[0].framework)
    }

    @Test
    fun c1_svcLibcMismatchYieldsStrongHookFinding() {
        // libc 被 hook（size 改 0），svc 真实
        val backend = FixedBackend("/system/bin/su" to (ok to ok.copy(size = 0)))
        val collector = PathProbeCollector(
            paths = defaultPathEntries().filter { it.path == "/system/bin/su" },
            executor = TriplePathExecutor(backend, javaView),
        )
        val result = collector.collect(input)
        val strong = result.findings.first { it.ruleId.startsWith("triple.svc_libc") }
        assertEquals(Confidence.A, strong.confidence)
        assertEquals(FindingCategory.HOOK, strong.category)
    }

    @Test
    fun c1_missingPathNoFindings() {
        val backend = FixedBackend("/system/bin/su" to (StatOutcome.Errno(2) to StatOutcome.Errno(2)))
        val collector = PathProbeCollector(
            paths = defaultPathEntries().filter { it.path == "/system/bin/su" },
            executor = TriplePathExecutor(backend, javaView),
        )
        assertEquals(0, collector.collect(input).findings.size)
    }

    // ---- C2 mountinfo ----

    private val mountLines = listOf(
        "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue",
        "39 38 0:22 / /debug_ramdisk rw,relatime - tmpfs tmpfs rw",
        "40 39 0:23 / /debug_ramdisk/pts rw - devpts devpts rw",
        "41 39 0:24 / /debug_ramdisk/.magisk rw - tmpfs magisk rw",
        "104 30 253:7 / /data rw - ext4 /dev/block/bootdevice/by-name/userdata rw",
        "180 30 0:51 / /mnt/expand rw - tmpfs tmpfs rw",
    )

    @Test
    fun c2_parsesMountInfo() {
        val entries = MountInfoParser.parse(mountLines)
        assertEquals(6, entries.size)
        assertEquals("/mnt2", entries[0].mountPoint)
        assertEquals("ext3", entries[0].fstype)
        assertEquals("rw", entries[0].mountOpts[0])
        assertEquals("tmpfs", entries[1].fstype)
        assertEquals("tmpfs", entries[1].fstype)
    }

    @Test
    fun c2_detectsMagiskResidueAndDebugRamdisk() {
        val findings = MountAnalyzer().analyze(MountInfoParser.parse(mountLines))
        assertTrue(findings.any { it.ruleId == "mount.source_magisk" && it.confidence == Confidence.C })
        assertTrue(findings.any { it.ruleId == "mount.debug_ramdisk" })
    }

    @Test
    fun c2_overlayYieldsBFinding() {
        val lines = listOf("50 30 0:60 / /system/overlay ro - overlay overlay ro,lowerdir=/data/adb/overlay")
        val findings = MountAnalyzer().analyze(MountInfoParser.parse(lines))
        val f = findings.first { it.ruleId.startsWith("mount.overlay") }
        assertEquals(Confidence.B, f.confidence)
    }

    @Test
    fun c2_tooCleanMountsYieldAntiDetect() {
        val analyzer = MountAnalyzer(baselineMountCount = 100)
        val findings = analyzer.analyze(MountInfoParser.parse(mountLines)) // 只有 4 条 << 基线*0.6
        val f = findings.first { it.ruleId == "mount.too_clean" }
        assertEquals(FindingCategory.ANTI_DETECT_PRESENT, f.category)
        assertEquals(Confidence.B, f.confidence)
    }

    @Test
    fun c2_stDevDeviationYieldsFinding() {
        val analyzer = MountAnalyzer(expectedStDev = mapOf("/sys" to 20L))
        val findings = analyzer.analyze(emptyList(), mapOf("/sys" to 21L)) // PayPal 实测形态
        val f = findings.first { it.ruleId == "mount.stdev_deviation./sys" }
        // P2-2（2026-11-11）：降 C——tmpfs 设备号跨重启稳定性未验证
        assertEquals(Confidence.C, f.confidence)
    }

    @Test
    fun c2_cleanEnvironmentNoFindings() {
        val lines = listOf(
            "104 30 253:7 / /data rw - ext4 /dev/block/... rw",
            "32 1 0:21 / / rw - ext4 /dev/block/... ro",
        )
        assertEquals(0, MountAnalyzer().analyze(MountInfoParser.parse(lines)).size)
    }

    // ---- /proc/filesystems 内核注册类型比对（特征库 v7） ----

    private val cleanFsLines = listOf(
        "nodev\tsysfs",
        "nodev\trootfs",
        "nodev\ttmpfs",
        "\text4",
        "nodev\tfunctionfs",
    )

    // 用非采样挂载点（/data 等会触发 statfsSvc native 调用，主机测试不可用）
    private val plainMount = listOf("104 30 253:7 / /mnt/test rw - ext4 /dev/block/... rw")

    @Test
    fun c2_susfsRegisteredYieldsFinding() {
        val collector = MountCollector(
            mountInfoReader = { plainMount },
            filesystemsReader = { cleanFsLines + "nodev\tsusfs" },
            statSampler = { null },
        )
        val result = collector.collect(input)
        val f = result.findings.first { it.ruleId == "fs.susfs" }
        assertEquals(Confidence.B, f.confidence)
        assertEquals("susfs", f.framework)
        assertEquals(FindingCategory.ROOT_KERNEL, f.category)
    }

    @Test
    fun c2_baselineLookupActivatesTooClean() {
        // P2-2 接线：机型命中 deviceBaselines → too_clean 以 mountCountMin 直判
        val baseline = SignatureEntries.DeviceBaselineEntry(model = "TestModel", mountCountMin = 200, stDev = emptyMap())
        val collector = MountCollector(
            mountInfoReader = { plainMount }, // 仅 4 条 << 200
            filesystemsReader = { cleanFsLines },
            baselineLookup = { m -> if (m == "TestModel") baseline else null },
            deviceModel = { "TestModel" },
            statSampler = { null },
        )
        val result = collector.collect(input)
        val f = result.findings.first { it.ruleId == "mount.too_clean" }
        assertEquals(Confidence.B, f.confidence)
    }

    @Test
    fun c2_baselineMissKeepsSilent() {
        // 机型不在基线库 → 信号维持不判（无数据不拍脑袋）
        val collector = MountCollector(
            mountInfoReader = { plainMount },
            filesystemsReader = { cleanFsLines },
            baselineLookup = { null },
            deviceModel = { "UnknownModel" },
            statSampler = { null },
        )
        val result = collector.collect(input)
        assertTrue(result.findings.none { it.ruleId == "mount.too_clean" })
    }

    @Test
    fun c2_cleanProcFilesystemsNoSusfsFinding() {
        val collector = MountCollector(
            mountInfoReader = { plainMount },
            filesystemsReader = { cleanFsLines },
            statSampler = { null },
        )
        val result = collector.collect(input)
        assertTrue(result.findings.none { it.ruleId.startsWith("fs.") })
    }

    @Test
    fun c2_procFilesystemsUnreadableDegradesGracefully() {
        val collector = MountCollector(
            mountInfoReader = { plainMount },
            filesystemsReader = { throw java.io.FileNotFoundException("/proc/filesystems") },
            statSampler = { null },
        )
        val result = collector.collect(input)
        assertTrue(result.findings.none { it.ruleId.startsWith("fs.") })
    }
}

private typealias FindingCategory = com.detectany.core.model.Finding.Category
