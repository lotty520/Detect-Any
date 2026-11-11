package com.detectany.data.signature

import kotlinx.serialization.Serializable

/**
 * 特征数据库（任务 4.1）：唯一高频变化层（design.md D5）。
 * 全部字段可 JSON 化；条目带 since/until 框架版本区间与置信级别，失效走数据更新不发版。
 */
@Serializable
data class SignatureDb(
    val version: Long,
    val paths: List<PathEntry> = emptyList(),
    val apps: List<AppEntry> = emptyList(),
    val sockets: List<SocketEntry> = emptyList(),
    val properties: List<PropertyEntry> = emptyList(),
    val supercalls: List<SupercallEntry> = emptyList(),
    val filesystems: List<FilesystemEntry> = emptyList(),
    val keyboxBlacklist: List<KeyboxEntry> = emptyList(),
    val deviceBaselines: List<DeviceBaseline> = emptyList(),
) {
    @Serializable
    data class PathEntry(
        val id: String,
        val path: String,
        val framework: String? = null,
        /** A/B/C（对齐 core.model.Confidence） */
        val confidence: String,
        val category: String,
        val since: String? = null,
        val until: String? = null,
    )

    @Serializable
    data class AppEntry(
        val id: String,
        val packageNames: List<String>,
        val certPins: List<String> = emptyList(),
        val dexStrings: List<String> = emptyList(),
        val framework: String,
        val confidence: String,
        val category: String,
        val since: String? = null,
        val until: String? = null,
    )

    @Serializable
    data class SocketEntry(
        val id: String,
        val name: String,
        val framework: String? = null,
        val confidence: String,
        val category: String,
        val since: String? = null,
        val until: String? = null,
    )

    @Serializable
    data class PropertyEntry(
        val id: String,
        val keyPrefix: String,
        val framework: String? = null,
        val confidence: String,
        val category: String,
        val valueContains: String? = null,
        val since: String? = null,
        val until: String? = null,
    )

    /** supercall 族（KSU 系 reboot 双魔数 / APatch syscall45 / 旧 prctl）——magic 全部数据化 */
    @Serializable
    data class SupercallEntry(
        val family: String,
        val magic1Hex: String? = null,
        val magic2Hex: String? = null,
        val superkey: String? = null,
        val helloCmdHex: String? = null,
        val helloMagicHex: String? = null,
        val framework: String,
        val since: String? = null,
        val until: String? = null,
    )

    /** 内核注册文件系统类型（/proc/filesystems 挂载名比对；susfs 等非隐藏场景残留） */
    @Serializable
    data class FilesystemEntry(
        val id: String,
        /** /proc/filesystems 行内文件系统名（nodev 前缀已剥离） */
        val fsName: String,
        val framework: String?,
        val confidence: String,
        val category: String,
        val since: String? = null,
        val until: String? = null,
    )

    /** keybox 证书序列号黑名单（hex 小写；来源官方 CRL + 实测流通清单） */
    @Serializable
    data class KeyboxEntry(
        val serialHex: String,
        val reason: String? = null,
        val since: String? = null,
    )

    /** 机型基线（挂载数下限 / st_dev 预期 / 属性组合） */
    @Serializable
    data class DeviceBaseline(
        val model: String,
        val mountCountMin: Int? = null,
        val stDev: Map<String, Long> = emptyMap(),
    )
}
