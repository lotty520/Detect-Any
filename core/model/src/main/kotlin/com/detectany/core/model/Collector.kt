package com.detectany.core.model

/**
 * 采集器 SPI：C1-C12 的统一入口（specs/signal-collection）。
 * 采集器只输出取证观测（Finding）——框架无关、无判定逻辑；
 * 规则与评分在引擎侧（core:engine + core:rules）完成。
 *
 * 架构约束（面向接口编程）：
 * - 全部采集器 MUST 实现 [Collector] 接口
 * - 全部检测项 MUST 经 DetectionEngine 并行调度，无特殊路径
 * - 特征常量 MUST 来自 SignatureDb（可热更新），采集器零硬编码框架逻辑
 */
interface Collector {
    val id: CollectorId

    /**
     * 执行采集。能力被兼容矩阵阻塞时返回 status=BLOCKED 的降级结果，
     * MUST NOT 抛异常中断整体扫描（specs/detection-engine「采集能力降级透明」）。
     */
    fun collect(input: ScanInput): CollectorResult
}

/** 采集器编号。C1-C8 既有，C9-C12 新增（close-detection-gaps）。 */
enum class CollectorId {
    // ---- 既有（root/hook/injection 域） ----
    C1_PATH,
    C2_MOUNT,
    C3_PROPERTY,
    C4_ENDPOINT,
    C5_APP_FINGERPRINT,
    C6_MEMORY_MAP,
    C7_CODE_INTEGRITY,
    C8_BEHAVIOR,

    // ---- 新增（instrumentation/virtual-env/behavioral/screen-share 域） ----
    /** C9: Frida 检测（D-Bus 探测、线程名、RWX 页特征） */
    C9_INSTRUMENTATION,
    /** C10: 虚拟环境/模拟器（传感器、GL、容器、CPU 架构） */
    C10_VIRTUAL_ENV,
    /** C11: 行为异常（VPN、代理、无障碍、时钟、GPS） */
    C11_BEHAVIORAL,
    /** C12: 屏幕共享/远程控制（scrcpy、ADB、overlay、输入注入） */
    C12_SCREEN_SHARE,

    /** P2-1（2026-11-11）：硬件证明域（L3 档专用，Keymaster 异步 + 超时治理） */
    C13_ATTESTATION,
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
    /** 分类标签 */
    val category: Category,
    /** 命中框架（magisk/ksu/frida/scrcpy/...；泛 hook 类可为 null） */
    val framework: String?,
    /** 证据回放用：人可读的原始观测描述 */
    val detail: String,
    /** 结构化原始观测（出端必须脱敏） */
    val raw: Map<String, String> = emptyMap(),
) {
    enum class Category {
        // ---- 既有 ----
        ROOT_KERNEL,
        ROOT_USERSPACE,
        HOOK,
        ZYGISK,
        ATTESTATION_SPOOF,
        REPACKAGED,
        ANTI_DETECT_PRESENT,

        // ---- 新增（close-detection-gaps） ----
        /** Frida / objection / 动态插桩 */
        INSTRUMENTATION,
        /** 虚拟机 / 沙箱容器 */
        VIRTUAL_ENV,
        /** 模拟器 */
        EMULATOR,
        /** VPN / 代理 / MITM */
        NETWORK_MITM,
        /** 自动化脚本 / 输入注入 */
        AUTOMATION,
        /** 速度篡改 */
        SPEED_HACK,
        /** GPS 伪造 */
        GPS_SPOOF,
        /** 摄像头伪造（虚拟摄像头 / 换脸注入） */
        CAMERA_SPOOF,
        /** 设备身份伪造（IMEI/Android ID/序列号伪造工具） */
        DEVICE_SPOOF,
        /** SIM 卡状态异常（矛盾态/缺失态） */
        SIM_ANOMALY,
        /** 屏幕共享 / 投屏 */
        SCREEN_SHARE,
        /** 远程控制 */
        REMOTE_CONTROL,
        /** 悬浮窗 / tapjacking */
        OVERLAY_INJECTION,
    }
}
