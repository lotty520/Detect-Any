package com.detectany.core.model

/**
 * 内置/可下发的特征条目（Phase 1 子集；完整 schema 在任务 4.1 落地）。
 * 采集器按条目 ID 匹配原始观测产出 Finding。
 */
data class SignatureEntries(
    val paths: List<PathEntry> = emptyList(),
    val sockets: List<SocketEntry> = emptyList(),
    val properties: List<PropertyEntry> = emptyList(),
    val apps: List<AppEntry> = emptyList(),
    val filesystems: List<FilesystemEntry> = emptyList(),
    val deviceBaselines: List<DeviceBaselineEntry> = emptyList(),
) {
    data class PathEntry(
        val id: String,
        val path: String,
        val framework: String?,
        val confidence: Confidence,
        val category: Finding.Category,
    )

    data class SocketEntry(
        val id: String,
        /** /proc/net/unix 中的名字（抽象名或文件路径） */
        val name: String,
        val framework: String?,
        val confidence: Confidence,
        val category: Finding.Category,
    )

    data class PropertyEntry(
        val id: String,
        /** 属性名，支持前缀匹配（如 init.svc.magisk） */
        val keyPrefix: String,
        val framework: String?,
        val confidence: Confidence,
        val category: Finding.Category,
        /** 值条件：非 null 时值必须包含该子串才命中（如 native.bridge 必须含 loader 名，排除全机型默认值 "0"） */
        val valueContains: String? = null,
    )

    /** 机型挂载基线（P2-2：too_clean/st_dev 消费侧接线，2026-11-11） */
    data class DeviceBaselineEntry(
        val model: String,
        /** 挂载数下限观测（同机型实测最小值；低于此 = too_clean 门槛） */
        val mountCountMin: Int,
        /** 关键路径 st_dev 期望（tmpfs 设备号；跨重启稳定性未验证 → 消费侧 C 级） */
        val stDev: Map<String, Long> = emptyMap(),
    )

    data class FilesystemEntry(
        val id: String,
        /** /proc/filesystems 行内文件系统名（nodev 前缀已剥离） */
        val fsName: String,
        val framework: String?,
        val confidence: Confidence,
        val category: Finding.Category,
    )

    data class AppEntry(
        val id: String,
        /** 候选包名（含官方 spoofed 变体） */
        val packageNames: List<String>,
        /** 签名证书 sha256/xxx 钉住（可选，命中包名后强校验） */
        val certPins: List<String> = emptyList(),
        /** DEX 内容探针字符串（内容指纹：spoofed 包名的兜底路径） */
        val dexStrings: List<String> = emptyList(),
        val framework: String,
        val confidence: Confidence,
        val category: Finding.Category,
    )
}
