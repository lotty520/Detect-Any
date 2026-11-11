package com.detectany.core.engine

import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.rules.RuleHit

/**
 * 扫描结论（specs/detection-engine「证据向量输出」）。
 */
data class ScanVerdict(
    val riskScore: Int,
    val conclusive: Boolean,
    val categories: Set<Finding.Category>,
    /** 框架命中分（framework -> 累计权重） */
    val frameworkScores: Map<String, Int>,
    val evidenceVector: List<String>,
    val antiDetectPresent: Boolean,
)

/**
 * 评分模型（任务 4.4，对齐 design.md D4 判定权限）：
 * - 强（A）：单条即可定性（conclusive）
 * - 中（B）：同框架（或同 category 的 hook/zygisk 域）两条 B、或一 B 一 C 共振才定性
 * - 弱（C）：仅加权，永不定性
 * - anti_detect_present 权重高于普通 root
 */
class ScoreModel(
    private val conclusiveThreshold: Int = 50,
) {

    /**
     * 云手机合围信号集（2026-11-10 第四批）：单条全为 C 级（各自存在合法场景），
     * 但真实硬件同时满足 ≥3 项近乎不可能——容器/云手机在 SIM/电池/传感器三个
     * 独立子系统上同时呈现虚拟形态才能凑齐。
     * 注意：no_telephony 与 sim.all_absent 已在采集器侧用 FEATURE_TELEPHONY 门控，
     * WiFi 平板场景（无电话+无传感器）最多凑 2 项，不触发。
     */
    internal val cloudPhoneSignals = setOf(
        "sim.all_absent",
        "battery.framework_only",
        "battery.zero_temperature",
        "battery.level_without_voltage",
        "emulator.sensors_absent",
    )

    fun score(findings: List<Finding>, hits: List<RuleHit>): ScanVerdict {
        val aFindings = findings.filter { it.confidence == Confidence.A }
        val bByDomain = findings.filter { it.confidence == Confidence.B }.groupBy { it.framework ?: it.category.name }
        val cByDomain = findings.filter { it.confidence == Confidence.C }.groupBy { it.framework ?: it.category.name }

        val categories = findings.map { it.category }.toSet()
        val antiDetect = Finding.Category.ANTI_DETECT_PRESENT in categories

        // 框架/域得分：A=40（含 anti_detect ×1.5）、B=15、C=5 + 规则权重加成
        val domainScores = mutableMapOf<String, Int>()
        findings.forEach { f ->
            val domain = f.framework ?: f.category.name
            val base = when (f.confidence) {
                Confidence.A -> 40
                Confidence.B -> 15
                Confidence.C -> 5
            }
            val multiplier = if (f.category == Finding.Category.ANTI_DETECT_PRESENT) 1.5 else 1.0
            domainScores.merge(domain, (base * multiplier).toInt(), Int::plus)
        }
        hits.forEach { h ->
            val domain = h.rule.framework ?: h.rule.category ?: "generic"
            domainScores.merge(domain, h.rule.weight, Int::plus)
        }

        // 定性判定（判定权限矩阵）
        // 2026-11-06 校准：B 共振放宽为「任意域两条 B」——B 为高伪装成本信号
        // （内容指纹/行为探针级），跨域双 B 在干净设备上近乎不可能；原同域限制导致
        // 真机「APatch 管理器(B) + zygiskdetect(B)」误判未达定性（rooted 设备漏定性）。
        // B+C 共振仍要求同域（C 级噪声高，需域内佐证）。
        val conclusive = run {
            if (aFindings.isNotEmpty()) return@run true
            val allB = findings.filter { it.confidence == Confidence.B }
            if (allB.size >= 2) return@run true
            bByDomain.forEach { (domain, bs) ->
                if (bs.size == 1 && (cByDomain[domain]?.size ?: 0) >= 1) return@run true
            }
            // C 级合围共振（云手机形态）：三个独立子系统的虚拟形态同时出现
            if (findings.count { it.ruleId in cloudPhoneSignals } >= 3) return@run true
            false
        }

        // 总分：各域得分开方和（多域共振抬升但不线性爆炸）封顶 100
        val raw = domainScores.values.sumOf { kotlin.math.sqrt(it.toDouble()) }.toInt() * 2
        val score = raw.coerceAtLeast(0).coerceAtMost(100)
        val conclusiveScore = if (conclusive) score.coerceAtLeast(conclusiveThreshold) else score.coerceAtMost(conclusiveThreshold - 1)

        return ScanVerdict(
            riskScore = conclusiveScore,
            conclusive = conclusive,
            categories = categories,
            frameworkScores = domainScores,
            evidenceVector = findings.map { it.ruleId }.distinct(),
            antiDetectPresent = antiDetect,
        )
    }
}
