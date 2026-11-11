package com.detectany.collectors.memmap

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.nativeplatform.ProbeJni

/**
 * C6 内存映射（任务 3.6）：maps/smaps/私有脏页/soinfo 链表交叉/RWX 自探针/fd readlink。
 * （ART class_loaders_ 链表计数为 native 深遍历项，独立迭代中——本采集器不含，见任务 8.2 回归项。）
 */
class MemoryMapCollector(
    private val mapsReader: () -> List<String> = { java.io.File("/proc/self/maps").readLines() },
    private val smapsReader: () -> List<String> = { java.io.File("/proc/self/smaps").readLines() },
    private val fdNames: () -> List<String> = { ProbeJni.fdNames().toList() },
    private val solist: () -> List<String> = { ProbeJni.solist().toList() },
    private val rwxProbe: () -> Int = { ProbeJni.rwxSelfProbe() },
) : Collector {

    override val id: CollectorId = CollectorId.C6_MEMORY_MAP

    override fun collect(input: ScanInput): CollectorResult = try {
        val maps = MapsParser.parse(mapsReader())
        // 时延优化：smaps 体积大（数 MB），仅当 maps 有可疑路径才解析
        val mapsSuspicious = maps.any { m ->
            val p = m.path ?: return@any false
            p.contains("memfd:") || p.contains("lspd") || p.contains("zygisk") ||
                p.contains("riru") || p.contains("XposedBridge") || p.contains("edxp")
        }
        val smaps = if (mapsSuspicious) MapsParser.parseSmapsPrivateDirty(smapsReader()) else emptyMap()
        val findings = MemoryMapAnalyzer.analyze(maps, smaps, fdNames(), solist(), rwxProbe())
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf(
                "mappings" to maps.size.toString(),
                "execAnon" to maps.count { it.executable && it.path == null }.toString(),
            ),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }
}

/** maps 解析（纯 Kotlin）。 */
data class MapEntry(val start: Long, val end: Long, val perms: String, val path: String?) {
    val executable: Boolean get() = perms.contains("x")
    val writable: Boolean get() = perms.contains("w")
}

object MapsParser {

    fun parse(lines: List<String>): List<MapEntry> = lines.mapNotNull { line ->
        val addr = line.substringBefore(' ').trim()
        if (!addr.contains('-')) return@mapNotNull null
        val s = addr.substringBefore('-').toLongOrNull(16) ?: return@mapNotNull null
        val e = addr.substringAfter('-').toLongOrNull(16) ?: return@mapNotNull null
        val perms = line.split(Regex("\\s+")).getOrNull(1) ?: return@mapNotNull null
        val path = line.trim().split(Regex("\\s+")).lastOrNull { it.startsWith("/") }
        MapEntry(s, e, perms, path)
    }

    /** smaps → (映射起始地址, Private_Dirty KB)。 */
    fun parseSmapsPrivateDirty(lines: List<String>): Map<Long, Long> {
        val out = mutableMapOf<Long, Long>()
        var current: Long? = null
        for (line in lines) {
            val addr = line.substringBefore(' ').trim()
            if (addr.contains('-')) {
                current = addr.substringBefore('-').toLongOrNull(16)
            } else if (line.startsWith("Private_Dirty:")) {
                val kb = line.split(Regex("\\s+")).getOrNull(1)?.toLongOrNull()
                val c = current
                if (c != null && kb != null) out[c] = kb
            }
        }
        return out
    }
}

/** 内存映射分析（纯 Kotlin，主机单测）。 */
object MemoryMapAnalyzer {

    fun analyze(
        maps: List<MapEntry>,
        privateDirty: Map<Long, Long>,
        fdNames: List<String>,
        solist: List<String>,
        rwxProbeResult: Int,
    ): List<Finding> = buildList {
        // 1) memfd / 匿名映射显示名含注入框架特征（Santander/Hunter 实测向量）
        maps.filter { m ->
            val p = m.path ?: return@filter false
            p.contains("memfd:") && (p.contains("zygisk") || p.contains("lsposed") || p.contains("jit-cache-zygisk"))
        }.forEach { m ->
            add(
                Finding(
                    ruleId = "mem.injected_memfd",
                    collector = CollectorId.C6_MEMORY_MAP,
                    confidence = Confidence.B,
                    category = Finding.Category.ZYGISK,
                    framework = if (m.path!!.contains("lsposed")) "lsposed" else "zygisknext",
                    detail = "memfd mapping: ${m.path}",
                    raw = mapOf("path" to m.path!!),
                ),
            )
        }

        // 2) 已知路径字符串（lspd/riru/XposedBridge.jar/libzygisk）
        maps.filter { m ->
            val p = m.path ?: return@filter false
            listOf("lspd", "riru", "XposedBridge.jar", "libzygisk", "edxp").any { p.contains(it, ignoreCase = true) }
        }.forEach { m ->
            add(
                Finding(
                    ruleId = "mem.known_path",
                    collector = CollectorId.C6_MEMORY_MAP,
                    confidence = Confidence.C,
                    category = Finding.Category.HOOK,
                    framework = if (m.path!!.contains("lspd", true)) "lsposed" else null,
                    detail = "Suspicious mapping path: ${m.path}",
                    raw = mapOf("path" to m.path!!),
                ),
            )
        }

        // 3) libart 可执行段 Private_Dirty COW 脏页（Zygisk patch 痕迹）
        privateDirty.forEach { (start, kb) ->
            val entry = maps.firstOrNull { it.start == start }
            if (entry?.path?.contains("libart") == true && kb > 0 && entry.executable) {
                add(
                    Finding(
                        ruleId = "mem.libart_cow",
                        collector = CollectorId.C6_MEMORY_MAP,
                        confidence = Confidence.B,
                        category = Finding.Category.ZYGISK,
                        framework = null,
                        detail = "libart exec segment has ${kb}KB Private_Dirty COW pages (runtime patching trace)",
                        raw = mapOf("start" to start.toString(), "kb" to kb.toString()),
                    ),
                )
            }
        }

        // 4) fd readlink → /data/adb 路径（注入载体关联）
        fdNames.filter { it.startsWith("/data/adb") }.forEach { fd ->
            add(
                Finding(
                    ruleId = "mem.fd_data_adb",
                    collector = CollectorId.C6_MEMORY_MAP,
                    confidence = Confidence.B,
                    category = Finding.Category.HOOK,
                    framework = null,
                    detail = "fd points into /data/adb: $fd",
                    raw = mapOf("fd" to fd.hashCode().toString(), "prefix" to "/data/adb"),
                ),
            )
        }

        // 5) soinfo 链表 vs maps 交叉：linker 权威列表中存在而 maps 不可见 = 隐藏映射
        for (line in solist) {
            val name = line.substringBefore('\t')
            val bias = line.substringAfter('\t').toLongOrNull() ?: continue
            if (name == "[anon-linker]") continue
            val covered = maps.any { m -> bias >= m.start && bias < m.end }
            if (!covered && name.isNotBlank()) {
                add(
                    Finding(
                        ruleId = "mem.hidden_mapping",
                        collector = CollectorId.C6_MEMORY_MAP,
                        confidence = Confidence.B,
                        category = Finding.Category.ZYGISK,
                        framework = null,
                        detail = "In linker list but invisible in maps: $name @0x${bias.toString(16)} (maps erasure trace)",
                        raw = mapOf("name" to name, "bias" to bias.toString()),
                    ),
                )
            }
        }

        // 6) RWX 自探针：maps 读取本身被 hook（A 级，物理不变量）
        if (rwxProbeResult == 0) {
            add(
                Finding(
                    ruleId = "mem.maps_tampered",
                    collector = CollectorId.C6_MEMORY_MAP,
                    confidence = Confidence.A,
                    category = Finding.Category.HOOK,
                    framework = null,
                    detail = "RWX self-probe mapping invisible in maps — maps reading is hooked/tampered",
                    raw = mapOf("rwxProbe" to "0"),
                ),
            )
        }
    }
}
