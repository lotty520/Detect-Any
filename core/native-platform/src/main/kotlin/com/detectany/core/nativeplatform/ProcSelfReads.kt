package com.detectany.core.nativeplatform

/**
 * /proc/self 读取门面（v16.1 native 下沉）：native 优先，JVM File 降级。
 *
 * 动机：java.io.File/BufferedReader 可被 Frida Java hook / Xposed 一行拦截（隐藏
 * Instrumentation 线程、抹除 maps 关键行）；native 侧读取不经 JVM。降级路径仅在
 * native 库不可用（加载失败等良性场景）时启用，保住「collect 永不致盲」。
 *
 * 注意：本门面只负责「读取」下沉；匹配逻辑仍在 Kotlin 采集器侧（主机可测惯例）。
 */
object ProcSelfReads {

    /** /proc/self/maps 上限（重进程 ~1-2MB 文本，8MB 冗余上限）。 */
    private const val MAX_FILE = 8 * 1024 * 1024

    /** 全量线程 comm（trim 后）。native 不可用时降级 JVM 枚举。 */
    fun threadComms(): List<String> =
        runCatching { ProbeJni.threadComms()?.toList() }.getOrNull()
            ?: runCatching {
                java.io.File("/proc/self/task").listFiles()
                    ?.mapNotNull { dir -> runCatching { java.io.File(dir, "comm").readText().trim() }.getOrNull() }
                    .orEmpty()
            }.getOrDefault(emptyList())

    /** 读 /proc/self 下文件原始字节；失败返回 null。 */
    fun readBytes(path: String, maxLen: Int = MAX_FILE): ByteArray? =
        runCatching { ProbeJni.readSelfFile(path, maxLen) }.getOrNull()
            ?: runCatching {
                val f = java.io.File(path)
                if (!f.isFile) return@runCatching null
                f.readBytes().takeIf { it.size <= maxLen } ?: f.readBytes().copyOf(maxLen)
            }.getOrNull()

    /** 读 /proc/self 下文件并按行拆分；失败返回空列表。 */
    fun readLines(path: String): List<String> =
        readBytes(path)?.toString(Charsets.ISO_8859_1)?.lines() ?: emptyList()

    /** argv0（cmdline 首个 NUL 结束段；进程名/nice-name）。失败返回空串。 */
    fun argv0(): String =
        readBytes("/proc/self/cmdline", 4096)
            ?.toString(Charsets.ISO_8859_1)
            ?.substringBefore('\u0000')
            .orEmpty()
}
