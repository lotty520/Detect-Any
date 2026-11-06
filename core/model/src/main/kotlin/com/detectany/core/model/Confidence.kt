package com.detectany.core.model

/**
 * 证据置信级别（对齐 design.md D4 / specs/detection-engine 判定权限）。
 */
enum class Confidence(val weight: Int) {
    /** 强：物理不变量，单信号即可推高风险分 */
    A(40),

    /** 中：行为/状态差异，需两条及以上共振参与定性 */
    B(15),

    /** 弱：静态痕迹，仅加权，不单独触发处置级结论 */
    C(5),
}
