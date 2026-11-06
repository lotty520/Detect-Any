package com.detectany.core.model

/**
 * 采集器 SPI：C1-C8 的统一入口（specs/signal-collection）。
 * 采集器只输出取证观测（Finding）——框架无关、无判定逻辑；
 * 规则与评分在引擎侧（core:engine + core:rules）完成。
 */
interface Collector {
    val id: CollectorId

    /**
     * 执行采集。能力被兼容矩阵阻塞时返回 status=BLOCKED 的降级结果，
     * MUST NOT 抛异常中断整体扫描（specs/detection-engine「采集能力降级透明」）。
     */
    fun collect(input: ScanInput): CollectorResult
}

/** 采集器编号（对齐 design.md D2）。 */
enum class CollectorId {
    C1_PATH,
    C2_MOUNT,
    C3_PROPERTY,
    C4_ENDPOINT,
    C5_APP_FINGERPRINT,
    C6_MEMORY_MAP,
    C7_CODE_INTEGRITY,
    C8_BEHAVIOR,
}

/** 扫描输入：环境快照 + 档位。 */
data class ScanInput(
    val tier: ScanTier,
    val apiLevel: Int,
    val targetSdk: Int,
    val kernelRelease: String?,
    val abi: String?,
)

/** 采集结果：状态 + 观测（Finding）列表 + 元信息。 */
data class CollectorResult(
    val collector: CollectorId,
    val status: Status,
    val findings: List<Finding> = emptyList(),
    val meta: Map<String, String> = emptyMap(),
) {
    enum class Status { OK, DEGRADED, BLOCKED }
}

/** 单条取证观测。 */
data class Finding(
    /** 特征条目 ID（内置或热更新下发，如 "path.debug_ramdisk_zygisk"） */
    val ruleId: String,
    val collector: CollectorId,
    val confidence: Confidence,
    /** 分类标签（specs/detection-engine 的 7 类） */
    val category: Category,
    /** 命中框架（magisk/ksu/apatch/lsposed/...；泛 hook 类可为 null） */
    val framework: String?,
    /** 证据回放用：人可读的原始观测描述 */
    val detail: String,
    /** 结构化原始观测（出端必须脱敏） */
    val raw: Map<String, String> = emptyMap(),
) {
    enum class Category {
        ROOT_KERNEL,
        ROOT_USERSPACE,
        HOOK,
        ZYGISK,
        ATTESTATION_SPOOF,
        REPACKAGED,
        ANTI_DETECT_PRESENT,
    }
}
