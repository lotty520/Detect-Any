package com.detectany.collectors.virtualenv

/**
 * C10 模拟器构建形态纯匹配（2026-11-16 抽取，主机单测覆盖——含华为 bootimage 模板形态 FP 边界）。
 */
object EmulatorMatching {

    val BUILD_PATTERNS = listOf(
        "generic", "google_sdk", "sdk_gphone", "vbox86", "nox", "ttVM", "ldplayer", "goldfish", "ranchu",
    )

    /**
     * Cuttlefish（crosvm，Google CI/ACloud 官方无头虚拟设备）低置信模式——C 级：
     * 无实机矩阵证据（按 OEM 矩阵原则不许 B）；avd_name 属性向量已覆盖 cvd 的 B 面。
     * "cutf"/"cutf_cvd" 用 contains（独特串）；"cvd" 过短易撞——仅对 product/device 全等匹配。
     */
    val CUTTLEFISH_CONTAINS = listOf("cutf")
    val CUTTLEFISH_EXACT = listOf("cvd")

    /** Build 四字段命中的全部模式（多命中 = 多条 B 级共振，保留旧循环语义）。 */
    fun buildPatternHits(
        fingerprint: String,
        model: String,
        product: String,
        hardware: String,
        patterns: List<String> = BUILD_PATTERNS,
    ): List<String> = patterns.filter { p ->
        fingerprint.contains(p, true) || model.contains(p, true) ||
            product.contains(p, true) || hardware.contains(p, true)
    }

    /** Cuttlefish 形态命中（C 级面）：contains 串或 product/device 全等。 */
    fun cuttlefishHit(product: String, device: String): Boolean =
        CUTTLEFISH_CONTAINS.any { product.contains(it, true) || device.contains(it, true) } ||
            product.equals("cvd", true) || device.equals("cvd", true)
}
