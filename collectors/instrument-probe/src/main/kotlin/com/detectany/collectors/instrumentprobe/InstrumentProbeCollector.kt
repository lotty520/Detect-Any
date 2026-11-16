package com.detectany.collectors.instrumentprobe

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * C9: Frida 检测采集器 — 三层防线（字符串 / D-Bus 协议 / RWX 页特征）。
 * 面向 Collector 接口，由 DetectionEngine 并行调度。
 *
 * 校准定级（calibration.md）：
 * - maps 字符串 frida-agent/linjector/gadget → B
 * - 线程名 gum-js-loop + pool-frida → B（gmain 单独不产出）
 * - RWX 连续页 + 大小过滤 → B（需与字符串共振才 A）
 * - D-Bus 协议探测 → B
 *
 * v16.1：maps/线程名读取下沉 native（ProcSelfReads——JVM 层 File hook 失效）；
 * 读取源经构造参数注入（主机单测可注入桩，AppFingerprintCollector 惯例）。
 */
class InstrumentProbeCollector(
    private val mapsLines: () -> List<String> = { com.detectany.core.nativeplatform.ProcSelfReads.readLines("/proc/self/maps") },
    private val threadComms: () -> List<String> = { com.detectany.core.nativeplatform.ProcSelfReads.threadComms() },
) : Collector {

    override val id: CollectorId = CollectorId.C9_INSTRUMENTATION

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        findings += scanMapsForStrings()
        findings += scanThreadNames()
        findings += scanRwxPages()
        findings += scanExternalExecMappings()
        findings += scanGlibThreads()
        findings += probeDbusPorts()
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf(
                "mapsHits" to findings.count { it.ruleId.startsWith("frida.maps") }.toString(),
                "threadHits" to findings.count { it.ruleId.startsWith("frida.thread") }.toString(),
                "rwxHits" to findings.count { it.ruleId.startsWith("frida.rwx") }.toString(),
                "dbusHits" to findings.count { it.ruleId.startsWith("frida.dbus") }.toString(),
            ),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    // ---- L1: maps 字符串扫描 ----

    private val MAPS_KEYWORDS = listOf(
        "frida-agent" to "frida",
        "linjector" to "frida",
        "frida-gadget" to "frida",
        "frida-server" to "frida",
        "libfrida" to "frida",
        "KittyMemory" to "modmenu",
        "libdobby" to "modmenu",
    )

    private fun scanMapsForStrings(): List<Finding> {
        val maps = runCatching { mapsLines() }.getOrDefault(emptyList())
        return MAPS_KEYWORDS.mapNotNull { (keyword, framework) ->
            if (maps.any { it.contains(keyword, ignoreCase = true) }) {
                Finding(
                    ruleId = "frida.maps.$keyword",
                    collector = id,
                    confidence = Confidence.B,
                    category = if (framework == "modmenu") Finding.Category.OVERLAY_INJECTION else Finding.Category.INSTRUMENTATION,
                    framework = framework,
                    detail = "maps contains $keyword mapping",
                    raw = mapOf("keyword" to keyword),
                )
            } else null
        }
    }

    // ---- L2: 线程名扫描 ----

    private val THREAD_NAMES = listOf(
        "gum-js-loop" to "frida",  // Frida 特有
        "pool-frida" to "frida",    // Frida 特有
        // gmain 单独不产出（GLib 合法共用，calibration #9）
    )

    private fun scanThreadNames(): List<Finding> {
        val threads = runCatching { threadComms() }.getOrDefault(emptyList())

        return THREAD_NAMES.mapNotNull { (name, framework) ->
            if (threads.contains(name)) {
                Finding(
                    ruleId = "frida.thread.$name",
                    collector = id,
                    confidence = Confidence.B,
                    category = Finding.Category.INSTRUMENTATION,
                    framework = framework,
                    detail = "Frida thread found in thread list: $name",
                    raw = mapOf("thread" to name),
                )
            } else null
        }
    }

    // ---- L3: RWX 页特征扫描（2026-11-16 P8 实测重校准；逻辑在 C9Analyzer，主机单测覆盖）----
    // 实测（frida-gadget 17.26.2 驻留进程）：RWX 呈**离散小簇**（5 处 4-28KB，共 ~92KB）；
    // 干净进程（app/Chrome 对照）0 处。旧判据（连续≥4 页）有 trailing 段 bug 且对离散簇盲。

    private fun scanRwxPages(): List<Finding> {
        val cov = C9Analyzer.anonRwxCoverage(runCatching { mapsLines() }.getOrDefault(emptyList()))
        return if (cov.hit) {
            listOf(
                Finding(
                    ruleId = "frida.rwx.anon_clusters",
                    collector = id,
                    confidence = Confidence.B,
                    category = Finding.Category.INSTRUMENTATION,
                    framework = null,
                    detail = "${cov.regions} anonymous RWX regions (${cov.bytes / 1024}KB) — runtime code-generation footprint (gum/agent); zero on clean app/Chrome baseline",
                    raw = mapOf("regions" to cov.regions.toString(), "totalKb" to (cov.bytes / 1024).toString()),
                ),
            )
        } else emptyList()
    }

    // ---- L3b: 外部路径可执行映射（2026-11-16 P8 实测新增，改名免疫；逻辑在 C9Analyzer）----
    // 物理不变量：untrusted_app 被 SELinux 禁止执行 /data/local、/storage 路径文件
    //（实测 avc denied execute shell_data_file）；这些位置的 .so 可执行映射 = 注入
    //（gadget/LD_PRELOAD 落点），达成必经 root 改标签——本身就是异常态。so 名字任意。

    private fun scanExternalExecMappings(): List<Finding> {
        val path = C9Analyzer.externalExecMapping(runCatching { mapsLines() }.getOrDefault(emptyList()))
        return if (path != null) {
            listOf(
                Finding(
                    ruleId = "frida.external_mapping",
                    collector = id,
                    confidence = Confidence.B,
                    category = Finding.Category.INSTRUMENTATION,
                    framework = null,
                    detail = "Executable mapping from external storage path (untrusted_app cannot legally load these; injection artifact): $path",
                    raw = mapOf("path" to path.hashCode().toString()),
                ),
            )
        } else emptyList()
    }

    // ---- L2b: GLib 线程组合（2026-11-16 P8 实测新增，改名免疫，C 级起步）----
    // frida/gadget 基于 GLib：驻留进程实测 gmain+gdbus 共存（改名后 xum-js-loop 仍带此二线程）。
    // 干净 app/Chrome 对照 0；但嵌入 GLib 栈的合法 app（gstreamer 系播放器）理论存在——
    // 按 OEM 矩阵原则 C 级起步（weight-only），多机型矩阵后再议 B。
    private fun scanGlibThreads(): List<Finding> {
        val threads = runCatching { threadComms() }.getOrDefault(emptyList())
        return if (C9Analyzer.hasGlibPair(threads)) {
            listOf(
                Finding(
                    ruleId = "frida.glib_threads",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.INSTRUMENTATION,
                    framework = null,
                    detail = "GLib main loop + D-Bus helper threads coexist (gmain+gdbus) — frida/gadget runtime fingerprint; clean baseline zero",
                    raw = mapOf("gmain" to "1", "gdbus" to "1"),
                ),
            )
        } else emptyList()
    }

    // ---- D-Bus 协议探测（限 /proc/net/tcp LISTEN 端口，calibration #7） ----

    private fun probeDbusPorts(): List<Finding> {
        // 解析 /proc/net/tcp 获取本进程可访问的 LISTEN 端口
        val listenPorts = parseListenPorts()
        val findings = mutableListOf<Finding>()

        for (port in listenPorts) {
            if (isFridaDbusEndpoint(port)) {
                findings += Finding(
                    ruleId = "frida.dbus.port$port",
                    collector = id,
                    confidence = Confidence.B,
                    category = Finding.Category.INSTRUMENTATION,
                    framework = "frida",
                    detail = "Port $port responded to Frida D-Bus protocol handshake",
                    raw = mapOf("port" to port.toString()),
                )
                break // 找到一个即可
            }
        }
        return findings
    }

    private fun parseListenPorts(): List<Int> {
        val ports = mutableListOf<Int>()
        // 仅取 /proc/net/tcp 中 LISTEN (0A) 状态的端口。
        // 平台边界（2026-11-10 审计实证）：API 28+ 未特权进程读 /proc/net/tcp 为
        // EACCES → runCatching 吞掉后端口列表为空，探测收敛为 27042 兜底。
        // 改端口 Frida 由 maps/线程名/RWX 三防线兜底（spec 已注明门控）。
        runCatching {
            File("/proc/net/tcp").readLines().drop(1).forEach { line ->
                val fields = line.trim().split(Regex("\\s+"))
                if (fields.size > 3 && fields[3] == "0A") { // TCP_LISTEN
                    val portHex = fields[1].split(":").getOrNull(1)
                    portHex?.toIntOrNull(16)?.let { ports.add(it) }
                }
            }
        }
        // 加上 Frida 默认端口
        if (27042 !in ports) ports.add(27042)
        return ports.filter { it in 1024..65535 }.take(20) // 限制最多 20 个端口（时延控制）
    }

    private fun isFridaDbusEndpoint(port: Int): Boolean = runCatching {
        Socket().use { socket ->
            socket.soTimeout = 5 // 5ms connect timeout（calibration #7）
            socket.connect(InetSocketAddress("127.0.0.1", port), 5)
            // 发送 D-Bus AUTH 握手
            socket.getOutputStream().write(byteArrayOf(0) + "AUTH\r\n".toByteArray())
            socket.getOutputStream().flush()
            // 读取响应——Frida 响应含 "REJECT" 或特定 D-Bus 错误模式
            val buf = ByteArray(64)
            val n = socket.getInputStream().read(buf)
            n > 0 && String(buf, 0, n, Charsets.ISO_8859_1).let {
                it.contains("EXTERNAL") || it.contains("ANONYMOUS") || it.contains("REJECTEXTERNAL")
            }
        }
    }.getOrDefault(false)
}
