package com.detectany.collectors.instrumentprobe

/**
 * C9 纯分析逻辑（2026-11-16 对抗加固配套抽取，主机单测覆盖——properties 教训：可测性内建）。
 * 判据全部来自 P8 受控改名实验取证（docs/REGRESSION.md 2026-11-16 节）。
 */
object C9Analyzer {

    /** 外部路径前缀：untrusted_app 被 SELinux 物理禁止加载的可执行文件位置。 */
    val EXTERNAL_PREFIXES = listOf("/data/local/", "/sdcard/", "/storage/")

    /** 无名匿名 RWX 簇覆盖度。hit 判据：≥2 处或 ≥16KB（实测 gadget 5 簇 ~92KB；干净 0）。 */
    data class RwxCoverage(val regions: Int, val bytes: Long) {
        val hit: Boolean get() = regions >= 2 || bytes >= 16 * 1024
    }

    /** maps 行 → 无名匿名 rwxp 簇统计（带路径/命名区[...]不计）。 */
    fun anonRwxCoverage(mapsLines: List<String>): RwxCoverage {
        var regions = 0
        var bytes = 0L
        for (line in mapsLines) {
            if (!line.contains("rwxp")) continue
            val path = line.trim().substringAfterLast(' ', "")
            if (path.startsWith("/") || path.startsWith("[")) continue
            regions++
            bytes += line.split(Regex("\\s+"))[0].split("-").let {
                (it.getOrNull(1)?.toLongOrNull(16) ?: 0L) - (it.getOrNull(0)?.toLongOrNull(16) ?: 0L)
            }
        }
        return RwxCoverage(regions, bytes)
    }

    /** 可执行外部路径映射：返回命中的 path（一条即证），无则 null。 */
    fun externalExecMapping(mapsLines: List<String>, prefixes: List<String> = EXTERNAL_PREFIXES): String? {
        for (line in mapsLines) {
            val perms = line.split(Regex("\\s+")).getOrNull(1) ?: continue
            if (!perms.contains('x')) continue
            val path = line.trim().substringAfterLast(' ', "")
            if (prefixes.any { path.startsWith(it) }) return path
        }
        return null
    }

    /** GLib 运行时指纹：gmain 与 gdbus 线程共存。 */
    fun hasGlibPair(threadComms: List<String>): Boolean =
        threadComms.any { it == "gmain" } && threadComms.any { it == "gdbus" }
}
