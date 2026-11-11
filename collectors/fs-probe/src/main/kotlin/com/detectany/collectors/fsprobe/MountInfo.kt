package com.detectany.collectors.fsprobe

import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.SignatureEntries

/**
 * mountinfo 解析（C2，design.md D2）：纯 Kotlin，主机单测覆盖。
 */
data class MountEntry(
    val mountId: Long,
    val parentId: Long,
    val dev: Long,
    val root: String,
    val mountPoint: String,
    val mountOpts: List<String>,
    val fstype: String,
    val source: String,
    val superOpts: List<String>,
)

object MountInfoParser {

    /** 解析 /proc/self/mountinfo 全部行；无法解析的行跳过。 */
    fun parse(lines: List<String>): List<MountEntry> = lines.mapNotNull { parseLine(it) }

    fun parseLine(line: String): MountEntry? {
        // 格式：36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
        // （"-" 前为可选字段区，之后为 fstype source superopts）
        val dash = line.lastIndexOf(" - ")
        if (dash < 0) return null
        val head = line.substring(0, dash).trim()
        val tail = line.substring(dash + 3).trim()
        val headFields = head.split(Regex("\\s+"))
        if (headFields.size < 6) return null
        val tailFields = tail.split(Regex("\\s+"))
        if (tailFields.size < 3) return null
        val ids = headFields[0].toLongOrNull() ?: return null
        val pid = headFields[1].toLongOrNull() ?: return null
        val devParts = headFields[2].split(":")
        val devMajor = devParts.getOrNull(0)?.toLongOrNull() ?: return null
        val devMinor = devParts.getOrNull(1)?.toLongOrNull() ?: return null
        return MountEntry(
            mountId = ids,
            parentId = pid,
            dev = devMajor shl 20 or devMinor,
            root = headFields[3],
            mountPoint = unescape(headFields[4]),
            mountOpts = headFields[5].split(","),
            fstype = tailFields[0],
            source = unescape(tailFields[1]),
            superOpts = tailFields[2].split(","),
        )
    }

    /** mountinfo 的转义：\040=空格、\011=tab、\134=backslash。 */
    private fun unescape(s: String): String = s
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

/**
 * 挂载分析（C2）：overlay/magic-mount 痕迹 + 「过度干净」异常 + st_dev 采样比对。
 */
class MountAnalyzer(
    private val baselineMountCount: Int? = null,
    private val expectedStDev: Map<String, Long> = emptyMap(),
) {

    fun analyze(
        entries: List<MountEntry>,
        stDevSamples: Map<String, Long> = emptyMap(),
    ): List<Finding> = buildList {
        // 1) overlay 挂载（模块挂载形态，B 级）
        entries.filter { it.fstype == "overlay" }.forEach { e ->
            add(
                Finding(
                    ruleId = "mount.overlay.${e.mountPoint.hashCode().toUInt()}",
                    collector = com.detectany.core.model.CollectorId.C2_MOUNT,
                    confidence = Confidence.B,
                    category = Finding.Category.ROOT_USERSPACE,
                    framework = inferFramework(e),
                    detail = "overlay 挂载: mountPoint=${e.mountPoint} source=${e.source}",
                    raw = mapOf("fstype" to e.fstype, "mountPoint" to e.mountPoint, "source" to e.source),
                ),
            )
        }

        // 2) magic mount 残留（source 含 magisk，C 级弱信号）
        entries.filter { it.source.contains("magisk", ignoreCase = true) }.forEach { e ->
            add(
                Finding(
                    ruleId = "mount.source_magisk",
                    collector = com.detectany.core.model.CollectorId.C2_MOUNT,
                    confidence = Confidence.C,
                    category = Finding.Category.ROOT_USERSPACE,
                    framework = "magisk",
                    detail = "挂载 source 含 magisk: ${e.source} -> ${e.mountPoint}",
                    raw = mapOf("source" to e.source, "mountPoint" to e.mountPoint),
                ),
            )
        }

        // 3) /debug_ramdisk/.magisk* 落脚点（C 级）
        // 2026-11-06 Pixel 8/Android 16 实测：干净设备原生挂载 /debug_ramdisk(tmpfs) 与
        // /debug_ramdisk/pts(devpts) —— 裸 /debug_ramdisk 不是 Magisk 证据，必须收窄到 .magisk 子路径
        entries.filter { it.mountPoint.startsWith("/debug_ramdisk/.magisk") }.forEach { e ->
            add(
                Finding(
                    ruleId = "mount.debug_ramdisk",
                    collector = com.detectany.core.model.CollectorId.C2_MOUNT,
                    confidence = Confidence.C,
                    category = Finding.Category.ROOT_USERSPACE,
                    framework = "magisk",
                    detail = "/debug_ramdisk 挂载: ${e.mountPoint} (${e.fstype})",
                    raw = mapOf("mountPoint" to e.mountPoint, "fstype" to e.fstype),
                ),
            )
        }

        // 4) 「过度干净」（anti_detect_present 独立证据类型）
        baselineMountCount?.let { base ->
            if (entries.size < base * 6 / 10) {
                add(
                    Finding(
                        ruleId = "mount.too_clean",
                        collector = com.detectany.core.model.CollectorId.C2_MOUNT,
                        confidence = Confidence.B,
                        category = Finding.Category.ANTI_DETECT_PRESENT,
                        framework = null,
                        detail = "挂载条目数 ${entries.size} 显著低于同机型基线 $base（隐藏栈嫌疑）",
                        raw = mapOf("count" to entries.size.toString(), "baseline" to base.toString()),
                    ),
                )
            }
        }

        // 5) st_dev 采样与机型基线偏离（PayPal 向量）
        expectedStDev.forEach { (path, expected) ->
            val actual = stDevSamples[path]
            if (actual != null && actual != expected) {
                add(
                    Finding(
                        ruleId = "mount.stdev_deviation.$path",
                        collector = com.detectany.core.model.CollectorId.C2_MOUNT,
                        confidence = Confidence.A,
                        category = Finding.Category.ROOT_USERSPACE,
                        framework = null,
                        detail = "st_dev($path)=$actual 与基线 $expected 不符（启动期 tmpfs 设备号占用痕迹）",
                        raw = mapOf("path" to path, "actual" to actual.toString(), "expected" to expected.toString()),
                    ),
                )
            }
        }
    }

    private fun inferFramework(e: MountEntry): String? = when {
        e.source.contains("magisk", true) || e.superOpts.any { it.contains("magisk", true) } -> "magisk"
        e.mountPoint.contains("/adb/modules", true) -> "ksu"
        else -> null
    }
}

/** 特征路径表（内置基线，Phase 1；任务 4.1 迁入 SignatureEntries 下发）。 */
internal fun defaultPathEntries(): List<SignatureEntries.PathEntry> = listOf(
    // Magisk v31.x：/debug_ramdisk 工件（manager hide 已移除，落脚点重新可见）
    SignatureEntries.PathEntry("path.debug_ramdisk.magisk", "/debug_ramdisk/.magisk/socket", "magisk", Confidence.C, Finding.Category.ROOT_USERSPACE),
    SignatureEntries.PathEntry("path.debug_ramdisk.socket", "/debug_ramdisk/socket", "magisk", Confidence.C, Finding.Category.ROOT_USERSPACE),
    // ZN/ReZygisk socket 路径族（Santander 2025 实测清单）
    SignatureEntries.PathEntry("path.zygisk.monitor", "/debug_ramdisk/zygisk/monitor.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.PathEntry("path.zygisk.zygisk", "/debug_ramdisk/zygisk/zygisk.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.PathEntry("path.zygisk.dev_cp64", "/dev/zygisk/cp64.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.PathEntry("path.zygisk.dev_cp32", "/dev/zygisk/cp32.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.PathEntry("path.rezygisk.dir", "/data/adb/rezygisk", "rezygisk", Confidence.C, Finding.Category.ZYGISK),
    // KSU / APatch daemon 产物
    SignatureEntries.PathEntry("path.ksu.modules", "/data/adb/ksu", "ksu", Confidence.C, Finding.Category.ROOT_KERNEL),
    SignatureEntries.PathEntry("path.apatch.ap", "/data/adb/ap", "apatch", Confidence.C, Finding.Category.ROOT_KERNEL),
    // Riru 遗留（存量命中）
    SignatureEntries.PathEntry("path.riru.dir", "/data/adb/riru", null, Confidence.C, Finding.Category.HOOK),
    // su 二进制存量
    SignatureEntries.PathEntry("path.su.system", "/system/bin/su", null, Confidence.C, Finding.Category.ROOT_USERSPACE),
    SignatureEntries.PathEntry("path.su.system_xbin", "/system/xbin/su", null, Confidence.C, Finding.Category.ROOT_USERSPACE),
    SignatureEntries.PathEntry("path.su.sbin", "/sbin/su", null, Confidence.C, Finding.Category.ROOT_USERSPACE),
)

/** /proc/filesystems 特征类型表（内置基线；特征库 v7 数据化）。 */
internal fun defaultFsEntries(): List<SignatureEntries.FilesystemEntry> = listOf(
    // susfs：register_filesystem("susfs")，非隐藏配置下必现；深隐藏（hide log/mounts 全开）时漏检可接受
    SignatureEntries.FilesystemEntry("fs.susfs", "susfs", "susfs", Confidence.B, Finding.Category.ROOT_KERNEL),
)
