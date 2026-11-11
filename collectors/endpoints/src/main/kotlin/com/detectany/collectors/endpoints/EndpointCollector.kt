package com.detectany.collectors.endpoints

import com.detectany.compat.platform.Probe
import com.detectany.compat.platform.ProbeCap
import com.detectany.compat.platform.PlatformEnv
import com.detectany.compat.platform.KernelVersion
import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.SignatureEntries
import com.detectany.core.nativeplatform.JniSyscallBackend
import com.detectany.core.nativeplatform.SyscallJni
import com.detectany.core.nativeplatform.TriplePathExecutor
import com.detectany.core.nativeplatform.parseStatArray

/**
 * C4 网络端点（任务 3.4）：门控下的 /proc/net/unix 匹配 + 文件系统 socket 路径三路探测。
 * Android 10+（现代 targetSdk）/proc/net/unix EACCES → DEGRADED + connect() 路径由规则层后续扩展。
 */
class EndpointCollector(
    private val unixReader: () -> List<String> = { java.io.File("/proc/net/unix").readLines() },
    private val executor: TriplePathExecutor = TriplePathExecutor(JniSyscallBackend),
    private val entries: List<SignatureEntries.SocketEntry> = defaultSocketEntries(),
) : Collector {

    override val id: CollectorId = CollectorId.C4_ENDPOINT

    override fun collect(input: ScanInput): CollectorResult {
        val env = PlatformEnv(input.apiLevel, input.targetSdk, input.kernelRelease?.let(KernelVersion::parse))
        val cap = ProbeCap.status(Probe.PROC_NET_UNIX, env)
        val findings = mutableListOf<Finding>()
        var status = CollectorResult.Status.OK

        if (cap.capability == com.detectany.compat.platform.ProbeCapability.ALLOWED) {
            try {
                findings += EndpointAnalyzer.analyzeUnix(unixReader(), entries)
            } catch (e: Throwable) {
                status = CollectorResult.Status.DEGRADED
            }
        } else {
            // 门控阻塞：透明降级（specs/detection-engine），不失败
            status = CollectorResult.Status.DEGRADED
        }

        // 文件系统 socket 路径（/debug_ramdisk、/dev/zygisk 族）不受 /proc/net 门控影响
        val fsEntries = entries.filter { it.name.startsWith("/") }
        for (entry in fsEntries) {
            try {
                if (parseStatArray(SyscallJni.statSvc(entry.name)).exists) {
                    findings.add(entry.toFinding())
                }
            } catch (_: Throwable) {
            }
        }

        return CollectorResult(
            collector = id,
            status = status,
            findings = findings,
            meta = mapOf("unixGate" to cap.capability.name, "fsProbed" to fsEntries.size.toString()),
        )
    }

    private fun SignatureEntries.SocketEntry.toFinding() = Finding(
        ruleId = id,
        collector = CollectorId.C4_ENDPOINT,
        confidence = confidence,
        category = category,
        framework = framework,
        detail = "socket hit: $name",
        raw = mapOf("name" to name),
    )
}

/** /proc/net/unix 分析（纯 Kotlin）。 */
object EndpointAnalyzer {

    /** 行格式：Num RefCount Protocol Flags Type St Inode Path —— Path 为第 8 列 */
    fun parsePaths(lines: List<String>): List<String> = lines
        .drop(1)
        .map { it.trim().split(Regex("\\s+")) }
        .filter { it.size >= 8 }
        .map { it[7] }

    fun analyzeUnix(lines: List<String>, entries: List<SignatureEntries.SocketEntry>): List<Finding> {
        val paths = parsePaths(lines).toSet()
        return buildList {
            for (entry in entries) {
                val hit = paths.firstOrNull { p ->
                    // 抽象 socket 在 /proc/net/unix 中可能带 @ 前缀或不带；文件 socket 以 / 开头
                    p == entry.name || p == "@${entry.name}" || p.endsWith("/${entry.name}") ||
                        (entry.name.startsWith("/") && p == entry.name)
                }
                if (hit != null) {
                    add(
                        Finding(
                            ruleId = entry.id,
                            collector = CollectorId.C4_ENDPOINT,
                            confidence = entry.confidence,
                            category = entry.category,
                            framework = entry.framework,
                            detail = "/proc/net/unix hit: $hit",
                            raw = mapOf("hit" to hit),
                        ),
                    )
                }
            }
        }
    }
}

internal fun defaultSocketEntries(): List<SignatureEntries.SocketEntry> = listOf(
    // KSU daemon（版本化，特征数据热更新维护）
    SignatureEntries.SocketEntry("sock.ksud", "ksud", "ksu", Confidence.C, Finding.Category.ROOT_KERNEL),
    // ZN/ReZygisk 守护进程
    SignatureEntries.SocketEntry("sock.zygiskd", "zygiskd", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.SocketEntry("sock.zygiskd64", "zygiskd64", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    // LSPosed 族（春秋 Evil Service 清单）
    SignatureEntries.SocketEntry("sock.lsposed", "lsposed", "lsposed", Confidence.C, Finding.Category.HOOK),
    SignatureEntries.SocketEntry("sock.sandhook", "sandhook", null, Confidence.C, Finding.Category.HOOK),
    // 文件系统 socket 路径族（Santander 2025 清单）
    SignatureEntries.SocketEntry("sock.fs.zygisk_monitor", "/debug_ramdisk/zygisk/monitor.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.SocketEntry("sock.fs.zygisk_zygisk", "/debug_ramdisk/zygisk/zygisk.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.SocketEntry("sock.fs.zygisk_cp64", "/dev/zygisk/cp64.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.SocketEntry("sock.fs.zygisk_cp32", "/dev/zygisk/cp32.sock", "zygisknext", Confidence.C, Finding.Category.ZYGISK),
    SignatureEntries.SocketEntry("sock.fs.magisk_socket", "/debug_ramdisk/.magisk/socket", "magisk", Confidence.C, Finding.Category.ROOT_USERSPACE),
)
