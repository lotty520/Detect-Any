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
 */
class InstrumentProbeCollector : Collector {

    override val id: CollectorId = CollectorId.C9_INSTRUMENTATION

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        findings += scanMapsForStrings()
        findings += scanThreadNames()
        findings += scanRwxPages()
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
        val maps = runCatching { File("/proc/self/maps").readLines() }.getOrDefault(emptyList())
        return MAPS_KEYWORDS.mapNotNull { (keyword, framework) ->
            if (maps.any { it.contains(keyword, ignoreCase = true) }) {
                Finding(
                    ruleId = "frida.maps.$keyword",
                    collector = id,
                    confidence = Confidence.B,
                    category = if (framework == "modmenu") Finding.Category.OVERLAY_INJECTION else Finding.Category.INSTRUMENTATION,
                    framework = framework,
                    detail = "maps 中发现 $keyword 映射",
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
        val taskDir = File("/proc/self/task")
        val threads = runCatching { taskDir.listFiles()?.mapNotNull { dir ->
            runCatching { File(dir, "comm").readText().trim() }.getOrNull()
        } ?: emptyList() }.getOrDefault(emptyList())

        return THREAD_NAMES.mapNotNull { (name, framework) ->
            if (threads.contains(name)) {
                Finding(
                    ruleId = "frida.thread.$name",
                    collector = id,
                    confidence = Confidence.B,
                    category = Finding.Category.INSTRUMENTATION,
                    framework = framework,
                    detail = "线程列表中发现 Frida 线程: $name",
                    raw = mapOf("thread" to name),
                )
            } else null
        }
    }

    // ---- L3: RWX 页特征扫描（大小/对齐过滤，calibration #5） ----

    private fun scanRwxPages(): List<Finding> {
        val maps = runCatching { File("/proc/self/maps").readLines() }.getOrDefault(emptyList())
        var consecutiveRwx = 0
        var totalRwxSize = 0L

        for (line in maps) {
            if (line.contains("rwxp")) {
                consecutiveRwx++
                val size = line.split(Regex("\\s+"))[0].split("-").let {
                    (it.getOrNull(1)?.toLongOrNull(16) ?: 0L) - (it.getOrNull(0)?.toLongOrNull(16) ?: 0L)
                }
                totalRwxSize += size
            } else {
                consecutiveRwx = 0
            }
        }

        // Frida agent 典型：≥4 连续 RWX 页 + 总大小 ≥64KB
        // JIT 合法场景通常 ≤2 页且 <32KB（calibration #5 过滤）
        return if (consecutiveRwx >= 4 && totalRwxSize >= 64 * 1024) {
            listOf(
                Finding(
                    ruleId = "frida.rwx.pages",
                    collector = id,
                    confidence = Confidence.B, // B 级；与 maps 字符串共振才 A
                    category = Finding.Category.INSTRUMENTATION,
                    framework = null,
                    detail = "发现 $consecutiveRwx 连续 RWX 页（${totalRwxSize / 1024}KB）—— Frida agent 注入特征",
                    raw = mapOf("consecutive" to consecutiveRwx.toString(), "totalKb" to (totalRwxSize / 1024).toString()),
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
                    detail = "端口 $port 响应 Frida D-Bus 协议握手",
                    raw = mapOf("port" to port.toString()),
                )
                break // 找到一个即可
            }
        }
        return findings
    }

    private fun parseListenPorts(): List<Int> {
        val ports = mutableListOf<Int>()
        // 仅取 /proc/net/tcp 中 LISTEN (0A) 状态的端口
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
