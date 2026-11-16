package com.detectany.collectors.virtualenv

/**
 * C10 模拟器构建形态纯匹配（2026-11-16 抽取，主机单测覆盖——含华为 bootimage 模板形态 FP 边界）。
 */
object EmulatorMatching {

    val BUILD_PATTERNS = listOf(
        "generic", "google_sdk", "sdk_gphone", "vbox86", "nox", "ttVM", "ldplayer", "goldfish", "ranchu",
    )

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
}
