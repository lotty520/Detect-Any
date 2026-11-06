package com.detectany.core.rules

import com.detectany.core.model.Finding
import kotlinx.serialization.Serializable

/** 规则定义（任务 4.3/4.5）：Finding 前缀匹配 → 框架/分类命中与权重。 */
@Serializable
data class RuleSet(
    val version: Long,
    val rules: List<RuleDef> = emptyList(),
) {
    @Serializable
    data class RuleDef(
        val id: String,
        val framework: String? = null,
        val category: String? = null,
        /** 命中的 Finding.ruleId 前缀 */
        val matchRuleIdPrefixes: List<String>,
        val weight: Int = 10,
    )
}

/** 规则命中。 */
data class RuleHit(
    val rule: RuleSet.RuleDef,
    val matchedFindingRuleIds: List<String>,
)

/**
 * 规则引擎：采集器 Finding × 规则 → RuleHit。
 * 纯逻辑（specs/signal-collection：采集器框架无关，判定全部在规则层）。
 */
class RulesEngine(private val ruleSet: RuleSet) {

    fun evaluate(findings: List<Finding>): List<RuleHit> {
        val hits = mutableListOf<RuleHit>()
        for (rule in ruleSet.rules) {
            val matched = findings.filter { f -> rule.matchRuleIdPrefixes.any { f.ruleId.startsWith(it) } }
                .map { it.ruleId }
                .distinct()
            if (matched.isNotEmpty()) {
                hits.add(RuleHit(rule, matched))
            }
        }
        return hits
    }
}

/** 规则库初始版（任务 4.5，对齐 design.md D9 每框架主信号映射）。 */
object BundledRuleSet {

    val ruleSet = RuleSet(
        version = 1,
        rules = listOf(
            // ---- Magisk（v31.x：包名复活 + /debug_ramdisk 工件 + st_dev/SELinux 强信号） ----
            RuleSet.RuleDef("rule.magisk", framework = "magisk", matchRuleIdPrefixes = listOf("app.magisk", "mount.source_magisk", "mount.debug_ramdisk", "path.debug_ramdisk", "sock.fs.magisk_socket", "prop.init_svc_magisk", "mount.stdev_deviation", "behavior.selinux_label.magisk"), weight = 12),
            // ---- KSU 系（reboot supercall 为主信号） ----
            RuleSet.RuleDef("rule.ksu", framework = "ksu", matchRuleIdPrefixes = listOf("behavior.ksu_supercall", "app.ksu", "path.ksu", "sock.ksud", "behavior.legacy_prctl", "behavior.selinux_label.ksu_file"), weight = 14),
            RuleSet.RuleDef("rule.ksunext", framework = "ksunext", matchRuleIdPrefixes = listOf("app.ksunext"), weight = 12),
            RuleSet.RuleDef("rule.sukisu", framework = "sukisu", matchRuleIdPrefixes = listOf("app.sukisu"), weight = 12),
            // ---- APatch（syscall45 + 包名） ----
            RuleSet.RuleDef("rule.apatch", framework = "apatch", matchRuleIdPrefixes = listOf("behavior.apatch_supercall", "app.apatch", "path.apatch"), weight = 14),
            // ---- LSPosed ----
            RuleSet.RuleDef("rule.lsposed", framework = "lsposed", matchRuleIdPrefixes = listOf("sock.lsposed", "mem.known_path", "behavior.selinux_label.lsposed", "path.riru", "prop.riru_bridge"), weight = 12),
            // ---- ZN/ReZygisk（NativeBridge + ptrace 残留 + socket 族） ----
            RuleSet.RuleDef("rule.zygisknext", framework = "zygisknext", matchRuleIdPrefixes = listOf("behavior.nativebridge_sticky", "behavior.ptrace_residue", "path.zygisk", "sock.zygiskd", "sock.fs.zygisk", "path.rezygisk", "mem.injected_memfd"), weight = 12),
            RuleSet.RuleDef("rule.rezygisk", framework = "rezygisk", matchRuleIdPrefixes = listOf("path.rezygisk"), weight = 12),
            // ---- 通用 hook（三路 diff / 完整性 / maps 篡改：强信号不定框架） ----
            RuleSet.RuleDef("rule.hook", category = "HOOK", matchRuleIdPrefixes = listOf("triple.svc_libc", "triple.java_native", "behavior.triple_diff", "integrity.prologue", "integrity.got_", "mem.maps_tampered", "mem.hidden_mapping", "mem.fd_data_adb"), weight = 15),
            // ---- 隐藏栈本身（anti_detect_present） ----
            RuleSet.RuleDef("rule.anti_detect", category = "ANTI_DETECT_PRESENT", matchRuleIdPrefixes = listOf("mount.too_clean", "prop.area_anomaly", "mount.fstype_cross"), weight = 16),
            // ---- su 存量 ----
            RuleSet.RuleDef("rule.su_binary", category = "ROOT_USERSPACE", matchRuleIdPrefixes = listOf("path.su."), weight = 8),

            // ==== 任务 8.1 扩展 ====

            // ---- LSPatch / 任意重打包（自保护签名钉住 + DEX CRC 是 LSPatch 对目标 app 的主判定） ----
            RuleSet.RuleDef("rule.repackaged", category = "REPACKAGED", matchRuleIdPrefixes = listOf("selfguard.repackaged_signature", "selfguard.dex_crc", "mem.known_path"), weight = 18),

            // ---- TrickyStore（证明链异常交叉：吊销/字段矛盾/软件链——设计 D9 中唯一全服务端兜底域） ----
            RuleSet.RuleDef("rule.trickystore", framework = "trickystore", matchRuleIdPrefixes = listOf("attest.keybox_revoked", "attest.cross.", "attest.software_backed"), weight = 18),

            // ---- susfs（三路统计发散：mountinfo 声称的 fstype 与 statfs f_type 魔数不一致） ----
            RuleSet.RuleDef("rule.susfs", framework = "susfs", matchRuleIdPrefixes = listOf("mount.fstype_cross"), weight = 16),

            // ---- PIF 属性伪装（成对属性偏离） ----
            RuleSet.RuleDef("rule.pif", framework = "pif", matchRuleIdPrefixes = listOf("prop.build_pair."), weight = 12),
        ),
    )
}
