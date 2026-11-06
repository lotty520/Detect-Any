package com.detectany.core.nativeplatform

/**
 * ELF 自解析桥（任务 2.3）：从磁盘解析 .dynsym 得符号 st_value，
 * 与 /proc/self/maps 基址相加 = 期望运行时地址，与 dlsym 实测交叉验证（C7 亦复用）。
 */
object ElfJni {
    init { NativePlatform.ensureLoaded() }

    /** 磁盘 .dynsym 中符号的 st_value（vaddr）；0 = 未命中/失败。 */
    external fun exportValue(path: String, symbol: String): Long

    /** 该库文件在本进程 maps 中的加载基址；0 = 未映射。 */
    external fun mappedBase(path: String): Long

    /**
     * dlsym(RTLD_DEFAULT, symbol) 实测地址。仅用于验证：磁盘自解析期望地址 vs 运行时地址交叉
     * （任务 2.3）。生产判定路径不使用 dlsym（可被 hook）。
     */
    external fun dlsymAddress(symbol: String): Long

    /** 读磁盘 ELF 中 [vaddr, vaddr+len) 的原始字节（C7 prologue 比对）；null = 失败。 */
    external fun readAtVaddr(path: String, vaddr: Long, len: Int): ByteArray?

    /** 动态重定位表："symbolName\tgotVaddr"（C7 GOT 完整性）。 */
    external fun relocations(path: String): Array<String>
}

/** 组合视图：期望运行时地址 = 基址 + st_value。 */
class ElfInspector {
    fun expectedRuntimeAddress(path: String, symbol: String): Long? {
        val value = ElfJni.exportValue(path, symbol)
        val base = ElfJni.mappedBase(path)
        return if (value != 0L && base != 0L) base + value else null
    }
}
