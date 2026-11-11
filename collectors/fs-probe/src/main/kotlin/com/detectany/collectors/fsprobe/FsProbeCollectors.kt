package com.detectany.collectors.fsprobe

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.SignatureEntries
import com.detectany.core.nativeplatform.parseStatArray
import com.detectany.core.nativeplatform.JniSyscallBackend
import com.detectany.core.nativeplatform.SyscallJni
import com.detectany.core.nativeplatform.TriplePathExecutor

/**
 * C1 路径探测（任务 3.1）：特征路径三路探测（Java/libc/svc）+ 失败码分类。
 * svc vs libc 不一致 → A 级 hook 证据；路径存在 → 条目置信级 Finding。
 */
class PathProbeCollector(
    private val paths: List<SignatureEntries.PathEntry> = defaultPathEntries(),
    private val executor: TriplePathExecutor = TriplePathExecutor(JniSyscallBackend),
) : Collector {

    override val id: CollectorId = CollectorId.C1_PATH

    override fun collect(input: ScanInput): CollectorResult {
        // L1 子集化（2026-11-10 时延修复）：仅探测 A/B 级路径——C 级路径
        // （/data/adb 族，对 app 永远 EACCES）在快扫里是纯浪费的 3×syscall
        val effective = if (input.tier == com.detectany.core.model.ScanTier.L1) {
            paths.filter { it.confidence != com.detectany.core.model.Confidence.C }
        } else paths
        val findings = mutableListOf<Finding>()
        var degraded = 0
        for (entry in effective) {
            try {
                val diff = executor.probe(entry.path)
                // 三路 diff：svc vs libc 层间不一致即 hook 证据（A 级物理不变量）
                diff.svcVsLibc?.let { m ->
                    findings.add(
                        Finding(
                            ruleId = "triple.svc_libc.${entry.id}",
                            collector = id,
                            confidence = Confidence.A,
                            category = Finding.Category.HOOK,
                            framework = null,
                            detail = "路径 ${entry.path} 的 libc 与 svc 结果不一致（${m.kind}: ${m.detail}）",
                            raw = mapOf("path" to entry.path, "kind" to m.kind.name, "detail" to m.detail),
                        ),
                    )
                }
                diff.javaVsNative?.let { m ->
                    findings.add(
                        Finding(
                            ruleId = "triple.java_native.${entry.id}",
                            collector = id,
                            confidence = Confidence.B,
                            category = Finding.Category.HOOK,
                            framework = null,
                            detail = "路径 ${entry.path} 的 Java API 与 native 结果不一致（${m.kind}）",
                            raw = mapOf("path" to entry.path, "kind" to m.kind.name),
                        ),
                    )
                }
                // 存在性：以 svc 层（最可信）为准（来自 executor 观测，不直连 JNI）
                val svcExists = diff.svc.exists
                if (svcExists) {
                    findings.add(
                        Finding(
                            ruleId = entry.id,
                            collector = id,
                            confidence = entry.confidence,
                            category = entry.category,
                            framework = entry.framework,
                            detail = "特征路径存在: ${entry.path}",
                            raw = mapOf("path" to entry.path),
                        ),
                    )
                }
            } catch (e: Throwable) {
                degraded++
            }
        }
        return CollectorResult(
            collector = id,
            status = if (degraded == effective.size) CollectorResult.Status.BLOCKED else if (degraded > 0) CollectorResult.Status.DEGRADED else CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf("probed" to effective.size.toString(), "degraded" to degraded.toString()),
        )
    }
}

/**
 * C2 挂载/设备号（任务 3.2）：mountinfo 解析 + st_dev 四路采样 + 基线偏离。
 * statfs f_type 交叉记录进 meta（overlay/tmpfs 判别由 analyzer 消费）；
 * /proc/filesystems 内核注册文件系统类型比对（susfs 非隐藏场景残留，特征库 v7）。
 */
class MountCollector(
    private val mountInfoReader: () -> List<String> = { java.io.File("/proc/self/mountinfo").readLines() },
    private val filesystemsReader: () -> List<String> = { java.io.File("/proc/filesystems").readLines() },
    private val fsEntries: List<SignatureEntries.FilesystemEntry> = defaultFsEntries(),
    // P2-2（2026-11-11）接线：baselineLookup 命中机型（deviceBaselines 数据）时
    // 以真数据构造分析器——too_clean（B）与 st_dev 偏离（C）激活；
    // 未命中机型维持不判（无基线数据不拍脑袋）。默认无 lookup = 原行为。
    private val baselineLookup: (String) -> SignatureEntries.DeviceBaselineEntry? = { null },
    private val analyzer: MountAnalyzer = MountAnalyzer(),
    private val deviceModel: () -> String = { android.os.Build.MODEL ?: "" }, // host 单测 Build.MODEL 返回 null（非异常）——elvis 兜底
    private val stDevPaths: List<String> = listOf("/dev", "/proc", "/sys", "/dev/pts"),
    private val statSampler: (String) -> Long? = { path ->
        runCatching { parseStatArray(SyscallJni.statSvc(path)) as? com.detectany.core.nativeplatform.StatOutcome.Ok }
            .getOrNull()?.dev
    },
) : Collector {

    override val id: CollectorId = CollectorId.C2_MOUNT

    override fun collect(input: ScanInput): CollectorResult = try {
        val entries = MountInfoParser.parse(mountInfoReader())
        val stDevs = stDevPaths.mapNotNull { p -> statSampler(p)?.let { p to it } }.toMap()
        val baseline = baselineLookup(deviceModel())
        val effectiveAnalyzer = baseline?.let {
            MountAnalyzer(baselineMountCount = it.mountCountMin, expectedStDev = it.stDev)
        } ?: analyzer
        val findings = effectiveAnalyzer.analyze(entries, stDevs).toMutableList()

        // statfs f_type 交叉（任务 3.2）：mountinfo 声称的 fstype 与 statfs 实测 f_type 魔数
        // 不一致 = susfs 类挂载伪造形态（overlay 冒充 tmpfs 会被 0x01021997 拆穿）
        val tmpfsCount = entries.count { it.fstype == "tmpfs" }
        for (e in entries) {
            if (e.mountPoint !in FS_CROSS_SAMPLE_POINTS) continue
            val expectedMagic = FSTYPE_MAGIC[e.fstype] ?: continue
            val r = runCatching { SyscallJni.statfsSvc(e.mountPoint) }.getOrNull() ?: continue
            if (r[0] == 0L && r[2] != expectedMagic) {
                findings.add(
                    Finding(
                        ruleId = "mount.fstype_cross.${e.mountPoint.hashCode().toUInt()}",
                        collector = id,
                        confidence = Confidence.B, // A3 降权：susfs v2.x 用户态 umount 一致化
                        category = Finding.Category.ROOT_KERNEL,
                        framework = null,
                        detail = "statfs 交叉不一致: ${e.mountPoint} mountinfo=${e.fstype} 但 statfs f_type=0x${r[2].toString(16)}",
                        raw = mapOf("mountPoint" to e.mountPoint, "claimed" to e.fstype, "f_type" to r[2].toString()),
                    ),
                )
            }
        }

        // /proc/filesystems 内核注册类型比对（v7）：susfs 等以 register_filesystem 注册的
        // 挂载名在非隐藏场景残留；名字由内核持有，无法被用户态改名（深隐藏配置会藏掉 → 漏检可接受）
        findings += checkRegisteredFilesystems()
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf(
                "mounts" to entries.size.toString(),
                "tmpfs" to tmpfsCount.toString(),
                "stdev" to stDevs.entries.joinToString(",") { "${it.key}=${it.value}" },
            ),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    /** /proc/filesystems 行格式：`nodev\tname` 或 `name`；比对特征名（精确匹配）。 */
    private fun checkRegisteredFilesystems(): List<Finding> {
        if (fsEntries.isEmpty()) return emptyList()
        val lines = runCatching { filesystemsReader() }.getOrNull() ?: return emptyList()
        val registered = lines.mapNotNull { it.substringAfterLast('\t').trim().ifEmpty { null } }.toSet()
        return fsEntries.filter { it.fsName in registered }.map { entry ->
            Finding(
                ruleId = entry.id,
                collector = id,
                confidence = entry.confidence,
                category = entry.category,
                framework = entry.framework,
                detail = "内核注册文件系统类型存在: ${entry.fsName}（/proc/filesystems）",
                raw = mapOf("fsName" to entry.fsName),
            )
        }
    }
}

/** statfs 交叉的采样挂载点与 f_type 魔数（Linux 内核 magic.h）。 */
private val FS_CROSS_SAMPLE_POINTS = setOf("/", "/data", "/system", "/vendor", "/product")

private val FSTYPE_MAGIC = mapOf(
    "ext4" to 0xEF53L,
    "f2fs" to 0xF2F52010L,
    "erofs" to 0xE0F5E1E2L,
    "tmpfs" to 0x01021997L,
    "overlay" to 0x794C7630L,
    "vfat" to 0x4D44L,
    "fuse" to 0x65735546L,
)
