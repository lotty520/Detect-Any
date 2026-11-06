package com.detectany.core.model

/**
 * 扫描档位（对齐 specs/detection-engine：L1 ≤10ms 快信号、L2 ≤100ms 全量、L3 异步含证明）。
 */
enum class ScanTier {
    /** 快通道：仅弱级快信号布尔结果 */
    L1,

    /** 标准：全量采集 + 评分 + 证据向量 */
    L2,

    /** 完整：L2 + 硬件证明发起（异步部分不计入时延预算） */
    L3,
}
