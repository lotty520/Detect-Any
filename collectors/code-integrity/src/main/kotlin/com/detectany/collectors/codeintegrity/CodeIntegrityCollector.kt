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
         *    磁盘副本从 APK zip 抽出，**基址用自校验投票**：在 base.apk 的各映射段起点找 ELF 魔数，
         *    再以已知符号「磁盘 vs 内存」字节比对确认。
         *
         * 2026-11-06 Pixel 8 实测教训：dl_iterate_phdr 的 dlpi_addr 对 APK 内嵌库在主 app 进程
         * 返回错误 bias（androidTest 进程恰好正确，掩盖缺陷）—— memRead 落零页、prologue 全部
         * 假阳性（mem=全零 而非蹦床指令）。故 dlpi_addr 仅作最后兜底。
         */
        fun locateOwnLib(context: Context? = null): OwnLibPath? {
            NativePlatform.ensureLoaded()
            val maps = MapsParser.parse(java.io.File("/proc/self/maps").readLines())

            // 路径 1（最可靠）：maps 中直接有 libdetectany_native.so
            maps.firstOrNull { it.path?.endsWith(LIB_NAME) == true }?.let {
                return OwnLibPath(it.path!!, it.start)
            }

            // 路径 2：solist（linker 权威 load bias）+ 符号字节验证
            // 注：phdr 投票在模拟器和真机上均产生假阳性（2026-11-09），
            //     因为多个 APK 内嵌 so 可能通过魔数+phdr 双检查 → 已移除。
            //     solist 是 linker 维护的权威地址，用已知符号字节做最终验证。
            val disk = context?.let { extractFromApk(it) } ?: guessDiskPath(maps) ?: return null
            val diskBytes = runCatching { java.io.File(disk).readBytes() }.getOrNull() ?: return null

            val solistEntry = ProbeJni.solist().firstOrNull { it.substringBefore('\t').endsWith(LIB_NAME) }
            val solistBase = solistEntry?.substringAfter('\t')?.toLongOrNull()
            if (solistBase == null || solistBase <= 0) return null

            // 验证：读一个已知符号的 prologue 字节（disk vs memory）
            // 用 textRead（mprotect 方式，处理 execute-only 页）
            val verifySym = "Java_com_detectany_core_nativeplatform_SyscallJni_statSvc"
            val verifyVaddr = runCatching { ElfJni.exportValue(disk, verifySym) }.getOrDefault(0L)
            if (verifyVaddr == 0L) return null
            val verifyDisk = runCatching { ElfJni.readAtVaddr(disk, verifyVaddr, 16) }.getOrNull() ?: return null
            val verifyMem = runCatching { ProbeJni.textRead(solistBase + verifyVaddr, 16) }.getOrNull()

            return if (verifyMem != null && verifyMem.contentEquals(verifyDisk)) {
                OwnLibPath(disk, solistBase) // 字节匹配 = base 正确
            } else {
                android.util.Log.w("C7", "locateOwnLib 符号验证失败 disk=$disk solistBase=$solistBase memNull=${verifyMem == null}")
                null // 不匹配 = solist 有误或被 hook → 宁可不检出也不假阳性
            }
        }

        private fun leInt(b: ByteArray, off: Int): Long {
            var v = 0L
            for (i in 3 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
            return v
        }

        private fun leLong(b: ByteArray, off: Int): Long {
            var v = 0L
            for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
            return v
        }

        private fun guessDiskPath(maps: List<com.detectany.collectors.memmap.MapEntry>): String? =
            maps.firstNotNullOfOrNull { m -> m.path?.takeIf { it.endsWith("/base.apk") } }

        private fun extractFromApk(context: Context): String? = runCatching {
            val ai = context.applicationInfo
            val existing = java.io.File(ai.nativeLibraryDir, LIB_NAME)
            if (existing.isFile) return existing.absolutePath
            // 缓存副本必须与 APK 内条目尺寸一致——install -r 跨构建保留 cache，
            // 旧字节会让 solist 符号验证静默失败（2026-11-10 回归发现的陈旧缓存类故障）
            val out = java.io.File(context.cacheDir, LIB_NAME)
            ZipFile(ai.sourceDir).use { zip ->
                val entry = zip.entries().asSequence().firstOrNull { it.name.endsWith(LIB_NAME) } ?: return null
                if (!out.isFile || out.length() != entry.size) {
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
            // execute-only 文本段：PVM 读零（Pixel 8/A16 实测），必须走 mprotect 临时放行的 textRead
            val mem = runCatching { ProbeJni.textRead(base + vaddr, 32) }.getOrNull() ?: continue
            if (!disk.contentEquals(mem)) {
                findings.add(
                    Finding(
                        ruleId = "integrity.prologue.$sym",
                        collector = CollectorId.C7_CODE_INTEGRITY,
                        confidence = Confidence.A,
                        category = Finding.Category.HOOK,
                        framework = null,
                        detail = "Collector entry prologue rewritten: $sym (memory bytes != disk bytes)",
                        raw = mapOf(
                            "symbol" to sym,
                            "vaddr" to vaddr.toString(16),
                            "disk" to disk.take(12).joinToString("") { "%02x".format(it) },
                            "mem" to mem.take(12).joinToString("") { "%02x".format(it) },
                        ),
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
            val slotBytes = runCatching { ProbeJni.textRead(base + gotVaddr, 8) }.getOrNull() ?: continue
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
                        detail = "GOT[$sym] resolves into anonymous region 0x${resolved.toString(16)} (trampoline signature)",
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
                        detail = "GOT[$sym] resolves to 0x${resolved.toString(16)}, expected 0x${(targetBase + expected).toString(16)} per disk (target ${target.path})",
                        raw = mapOf("symbol" to sym, "resolved" to resolved.toString(16), "expected" to (targetBase + expected).toString(16), "targetLib" to (target.path ?: "")),
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
