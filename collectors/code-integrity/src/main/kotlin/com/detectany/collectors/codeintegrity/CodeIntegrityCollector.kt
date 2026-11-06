package com.detectany.collectors.codeintegrity

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import android.content.Context
import com.detectany.core.model.ScanInput
import com.detectany.core.nativeplatform.ElfJni
import com.detectany.core.nativeplatform.NativePlatform
import com.detectany.core.nativeplatform.ProbeJni
import com.detectany.collectors.memmap.MapsParser
import java.util.zip.ZipFile

/**
 * C7 指令完整性（任务 3.7）：
 * 1) 自身 native 库全部导出入口 prologue 的磁盘 vs 内存字节比对（校验清单=采集器入口）；
 * 2) 自身 GOT 槽位解析地址 vs 目标库磁盘 st_value+基址（无 dlsym 依赖）。
 */
class CodeIntegrityCollector(
    private val ownLib: () -> OwnLibPath? = { locateOwnLib() },
    private val mapsReader: () -> List<String> = { java.io.File("/proc/self/maps").readLines() },
) : Collector {

    /** 自身库定位：磁盘路径（ELF 解析用）+ 进程内加载基址。 */
    data class OwnLibPath(val diskPath: String, val base: Long)

    override val id: CollectorId = CollectorId.C7_CODE_INTEGRITY

    override fun collect(input: ScanInput): CollectorResult {
        return try {
            val loc = ownLib()
                ?: return CollectorResult(collector = id, status = CollectorResult.Status.DEGRADED, meta = mapOf("reason" to "own lib not located"))
            val maps = MapsParser.parse(mapsReader())
            val findings = IntegrityAnalyzer.checkPrologues(loc.diskPath, loc.base) +
                IntegrityAnalyzer.checkGot(loc.diskPath, loc.base, maps)
            CollectorResult(
                collector = id,
                status = CollectorResult.Status.OK,
                findings = findings,
                meta = mapOf("lib" to loc.diskPath, "base" to loc.base.toString()),
            )
        } catch (e: Throwable) {
            CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
        }
    }

    companion object {
        internal const val LIB_NAME = "libdetectany_native.so"

        /**
         * 定位自身库（两种打包形态）：
         * 1) extractNativeLibs=true：maps 中有 .../lib/arm64/libdetectany_native.so —— 磁盘=映射路径；
         * 2) extractNativeLibs=false（AGP 默认）：库直接从 APK 内加载，maps 只见 base.apk ——
         *    基址取 dl_iterate_phdr（linker 权威表），磁盘副本从 APK zip 抽出（useLegacyPackaging=false 时 so 未压缩，
         *    抽取即原字节，vaddr 布局与内存一致）。
         */
        fun locateOwnLib(context: Context? = null): OwnLibPath? {
            NativePlatform.ensureLoaded()
            val maps = MapsParser.parse(java.io.File("/proc/self/maps").readLines())
            maps.firstOrNull { it.path?.endsWith(LIB_NAME) == true }?.let {
                return OwnLibPath(it.path!!, it.start)
            }
            // 形态 2：solist 求基址
            val entry = ProbeJni.solist().firstOrNull { it.substringBefore('\t').endsWith(LIB_NAME) } ?: return null
            val base = entry.substringAfter('\t').toLongOrNull() ?: return null
            val disk = context?.let { extractFromApk(it) } ?: guessDiskPath(maps)
            return disk?.let { OwnLibPath(it, base) }
        }

        private fun guessDiskPath(maps: List<com.detectany.collectors.memmap.MapEntry>): String? =
            maps.firstNotNullOfOrNull { m -> m.path?.takeIf { it.endsWith("/base.apk") } }

        private fun extractFromApk(context: Context): String? = runCatching {
            val ai = context.applicationInfo
            val existing = java.io.File(ai.nativeLibraryDir, LIB_NAME)
            if (existing.isFile) return existing.absolutePath
            val out = java.io.File(context.cacheDir, LIB_NAME)
            if (!out.isFile) {
                ZipFile(ai.sourceDir).use { zip ->
                    val entry = zip.entries().asSequence().firstOrNull { it.name.endsWith(LIB_NAME) } ?: return null
                    zip.getInputStream(entry).use { input ->
                        java.io.FileOutputStream(out).use { input.copyTo(it) }
                    }
                }
            }
            out.absolutePath
        }.getOrNull()
    }
}

/** 完整性分析（比对逻辑纯 Kotlin，主机单测）。 */
object IntegrityAnalyzer {

    /** 自身导出符号（= JNI 入口 = 采集器入口，任务要求校验清单覆盖采集器自身入口）。 */
    private val OWN_ENTRY_SYMBOLS = listOf(
        "Java_com_detectany_core_nativeplatform_SyscallJni_statSvc",
        "Java_com_detectany_core_nativeplatform_SyscallJni_statLibc",
        "Java_com_detectany_core_nativeplatform_ElfJni_exportValue",
        "Java_com_detectany_core_nativeplatform_ProbeJni_ksuProbe",
        "Java_com_detectany_core_nativeplatform_PropJni_propList",
    )

    /**
     * GOT 槽位检查的导入符号样本（libc 关键路径）。
     * MUST 排除 IFUNC 族（memcpy/memset/memmove/strlen...）：运行时解析到 SIMD/MTE 变体实现，
     * 本来就不等于磁盘 st_value（API 35 实测 memcpy 偏移差 ~0x71098）。
     */
    private val GOT_SAMPLE_SYMBOLS = setOf("openat", "close", "read", "write", "mmap", "mprotect")

    /**
     * prologue 磁盘 vs 内存：任一符号字节不一致 = inline hook（A 级）。
     */
    fun checkPrologues(libPath: String, base: Long): List<Finding> {
        val findings = mutableListOf<Finding>()
        for (sym in OWN_ENTRY_SYMBOLS) {
            val vaddr = runCatching { ElfJni.exportValue(libPath, sym) }.getOrDefault(0L)
            if (vaddr == 0L) continue
            val disk = runCatching { ElfJni.readAtVaddr(libPath, vaddr, 32) }.getOrNull() ?: continue
            val mem = runCatching { ProbeJni.memRead(base + vaddr, 32) }.getOrNull() ?: continue
            if (!disk.contentEquals(mem)) {
                findings.add(
                    Finding(
                        ruleId = "integrity.prologue.$sym",
                        collector = CollectorId.C7_CODE_INTEGRITY,
                        confidence = Confidence.A,
                        category = Finding.Category.HOOK,
                        framework = null,
                        detail = "采集器入口 prologue 被改写: $sym（内存字节 != 磁盘字节）",
                        raw = mapOf("symbol" to sym, "vaddr" to vaddr.toString()),
                    ),
                )
            }
        }
        return findings
    }

    /**
     * GOT 槽位：解析地址必须落在某映射库内，且 == 该库磁盘 st_value + 基址（自洽校验，不用 dlsym）。
     */
    fun checkGot(libPath: String, base: Long, maps: List<com.detectany.collectors.memmap.MapEntry>): List<Finding> {
        val findings = mutableListOf<Finding>()
        val relocs = runCatching { ElfJni.relocations(libPath) }.getOrDefault(emptyArray())
        for (line in relocs) {
            val sym = line.substringBefore('\t')
            if (sym !in GOT_SAMPLE_SYMBOLS) continue
            val gotVaddr = line.substringAfter('\t').toLongOrNull() ?: continue
            val slotBytes = runCatching { ProbeJni.memRead(base + gotVaddr, 8) }.getOrNull() ?: continue
            val resolved = bytesToLong(slotBytes)
            if (resolved == 0L) continue
            val target = maps.firstOrNull { resolved >= it.start && resolved < it.end }
            if (target?.path == null) {
                // 解析地址不在任何已知映射（指向匿名区 = inline hook 蹦床特征）
                findings.add(
                    Finding(
                        ruleId = "integrity.got_anon.$sym",
                        collector = CollectorId.C7_CODE_INTEGRITY,
                        confidence = Confidence.A,
                        category = Finding.Category.HOOK,
                        framework = null,
                        detail = "GOT[$sym] 解析到匿名区 0x${resolved.toString(16)}（蹦床特征）",
                        raw = mapOf("symbol" to sym, "resolved" to resolved.toString(16)),
                    ),
                )
                continue
            }
            val expected = runCatching { ElfJni.exportValue(target.path!!, sym) }.getOrDefault(0L)
            val targetBase = maps.firstOrNull { it.path == target.path }?.start ?: 0L
            if (expected != 0L && resolved != targetBase + expected) {
                findings.add(
                    Finding(
                        ruleId = "integrity.got_hooked.$sym",
                        collector = CollectorId.C7_CODE_INTEGRITY,
                        confidence = Confidence.A,
                        category = Finding.Category.HOOK,
                        framework = null,
                        detail = "GOT[$sym] 指向 0x${resolved.toString(16)}，与磁盘期望 0x${(targetBase + expected).toString(16)} 不符",
                        raw = mapOf("symbol" to sym, "resolved" to resolved.toString(16), "expected" to (targetBase + expected).toString(16)),
                    ),
                )
            }
        }
        return findings
    }

    internal fun bytesToLong(b: ByteArray): Long {
        var v = 0L
        for (i in b.indices.reversed()) {
            v = (v shl 8) or (b[i].toLong() and 0xFF)
        }
        return v
    }
}
