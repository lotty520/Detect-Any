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

    /**
     * 规则求值（2026-11-10 审计修复：单一归因语义）。
     * 历史 bug：一条 finding 的 ruleId 前缀可同时命中多条规则（app.ksunext
     * → rule.ksu + rule.ksunext；path.rezygisk.* → rule.zygisknext +
     * rule.rezygisk；mount.fstype_cross.* → rule.anti_detect + rule.susfs），
     * 一个证据被重复归因到两个域 → 分数虚增、威胁页双分组。
     * 修复：每条 finding 只归因「匹配前缀最长」的一条规则（同长取声明序），
     * 一条规则仍可聚合多条 finding。
     */
    fun evaluate(findings: List<Finding>): List<RuleHit> {
        // finding → 最佳规则（最长前缀）
        val bestRuleByFinding = findings.associate { f ->
            // 最长前缀优先；同长时框架特异规则（framework 非空）优于泛化类别规则
            // （fstype_cross → rule.susfs 而非 rule.anti_detect——框架归因优先），
            // 仍平则先声明者
            var bestLen = -1
            var best: RuleSet.RuleDef? = null
            ruleSet.rules.forEachIndexed { idx, rule ->
                val len = rule.matchRuleIdPrefixes.filter { f.ruleId.startsWith(it) }.maxOfOrNull { it.length } ?: return@forEachIndexed
                val better = when {
                    best == null -> true
                    len > bestLen -> true
                    // 同长：框架特异规则优先（fstype_cross → susfs 而非泛化 anti_detect）
                    len == bestLen && rule.framework != null && best!!.framework == null -> true
                    else -> false
                }
                if (better) { bestLen = len; best = rule }
            }
            f.ruleId to best
        }
        val hits = mutableListOf<RuleHit>()
        for (rule in ruleSet.rules) {
            val matched = findings.filter { f -> bestRuleByFinding[f.ruleId] === rule }
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
            RuleSet.RuleDef("rule.magisk", framework = "magisk", matchRuleIdPrefixes = listOf("app.magisk", "mount.source_magisk", "mount.debug_ramdisk", "path.debug_ramdisk", "sock.fs.magisk_socket", "prop.init_svc_magisk", "prop.magisk_version", "mount.stdev_deviation", "behavior.selinux_label.magisk"), weight = 12),
            // ---- KSU 系（reboot supercall 为主信号） ----
            RuleSet.RuleDef("rule.ksu", framework = "ksu", matchRuleIdPrefixes = listOf("behavior.ksu_supercall", "app.ksu", "path.ksu", "sock.ksud", "behavior.legacy_prctl", "behavior.selinux_label.ksu_file"), weight = 14),
            RuleSet.RuleDef("rule.ksunext", framework = "ksunext", matchRuleIdPrefixes = listOf("app.ksunext"), weight = 12),
            RuleSet.RuleDef("rule.sukisu", framework = "sukisu", matchRuleIdPrefixes = listOf("app.sukisu"), weight = 12),
            // ---- APatch（syscall45 + 包名） ----
            RuleSet.RuleDef("rule.apatch", framework = "apatch", matchRuleIdPrefixes = listOf("behavior.apatch_supercall", "app.apatch", "path.apatch"), weight = 14),
            // ---- LSPosed ----
            RuleSet.RuleDef("rule.lsposed", framework = "lsposed", matchRuleIdPrefixes = listOf("sock.lsposed", "mem.known_path", "behavior.selinux_label.lsposed", "path.riru", "prop.riru_bridge", "path.lsposed"), weight = 12),
            // ---- ZN/ReZygisk（NativeBridge + ptrace 残留 + socket 族） ----
            RuleSet.RuleDef("rule.zygisknext", framework = "zygisknext", matchRuleIdPrefixes = listOf("behavior.nativebridge_sticky", "behavior.ptrace_residue", "path.zygisk", "sock.zygiskd", "sock.fs.zygisk", "path.rezygisk", "mem.injected_memfd", "prop.zygisk_denylists"), weight = 12),
            RuleSet.RuleDef("rule.rezygisk", framework = "rezygisk", matchRuleIdPrefixes = listOf("path.rezygisk"), weight = 12),
            // ---- 通用 hook（三路 diff / 完整性 / maps 篡改：强信号不定框架） ----
            RuleSet.RuleDef("rule.hook", category = "HOOK", matchRuleIdPrefixes = listOf("triple.svc_libc", "triple.java_native", "behavior.triple_diff", "integrity.prologue", "integrity.got_", "mem.maps_tampered", "mem.hidden_mapping", "mem.fd_data_adb"), weight = 15),
            // ---- 隐藏栈本身（anti_detect_present） ----
            RuleSet.RuleDef("rule.anti_detect", category = "ANTI_DETECT_PRESENT", matchRuleIdPrefixes = listOf("mount.too_clean", "prop.area_anomaly", "mount.fstype_cross", "path.shamiko"), weight = 16),
            // ---- su 存量 ----
            RuleSet.RuleDef("rule.su_binary", category = "ROOT_USERSPACE", matchRuleIdPrefixes = listOf("path.su."), weight = 8),

            // ==== 任务 8.1 扩展 ====

            // ---- LSPatch / 任意重打包（自保护签名钉住 + DEX CRC 是 LSPatch 对目标 app 的主判定） ----
            RuleSet.RuleDef("rule.repackaged", category = "REPACKAGED", matchRuleIdPrefixes = listOf("selfguard.repackaged_signature", "selfguard.dex_crc", "mem.known_path", "app.lspatch"), weight = 18),

            // ---- 证明域 info 级（P2-1：降级/超时标注归并；异常证据仍归 rule.trickystore） ----
            RuleSet.RuleDef("rule.attestation_info", category = "ATTESTATION_SPOOF", matchRuleIdPrefixes = listOf("attest.degraded", "attest.rejected"), weight = 6),

            // ---- TrickyStore（证明链异常交叉：吊销/字段矛盾/软件链——设计 D9 中唯一全服务端兜底域） ----
            RuleSet.RuleDef("rule.trickystore", framework = "trickystore", matchRuleIdPrefixes = listOf("attest.keybox_revoked", "attest.cross.", "attest.software_backed", "path.trickystore"), weight = 18),

            // ---- susfs（mountinfo/statfs 交叉 + /proc/filesystems 内核注册类型残留） ----
            RuleSet.RuleDef("rule.susfs", framework = "susfs", matchRuleIdPrefixes = listOf("mount.fstype_cross", "fs.susfs"), weight = 16),

            // ---- 作弊工具族（2026-11-06 真机实证补录） ----
            RuleSet.RuleDef("rule.trustmealready", framework = "trustmealready", matchRuleIdPrefixes = listOf("app.trustmealready"), weight = 12),
            RuleSet.RuleDef("rule.zygiskdetect", framework = "zygiskdetect", matchRuleIdPrefixes = listOf("app.zygiskdetect"), weight = 10),
            RuleSet.RuleDef("rule.vector", framework = "vector", matchRuleIdPrefixes = listOf("app.vector"), weight = 12),
            RuleSet.RuleDef("rule.neozygisk", framework = "neozygisk", matchRuleIdPrefixes = listOf("app.neozygisk"), weight = 12),
            RuleSet.RuleDef("rule.nyazygisk", framework = "nyazygisk", matchRuleIdPrefixes = listOf("app.nyazygisk"), weight = 12),

            // ---- 新域（close-detection-gaps） ----
            RuleSet.RuleDef("rule.frida", category = "INSTRUMENTATION", matchRuleIdPrefixes = listOf("frida.", "path.frida."), weight = 16),
            RuleSet.RuleDef("rule.emulator", category = "EMULATOR", matchRuleIdPrefixes = listOf("emulator.", "battery."), weight = 14),
            RuleSet.RuleDef("rule.virtual_env", category = "VIRTUAL_ENV", matchRuleIdPrefixes = listOf("virtual."), weight = 14),
            RuleSet.RuleDef("rule.network_mitm", category = "NETWORK_MITM", matchRuleIdPrefixes = listOf("network.vpn", "network.proxy", "network.global_proxy"), weight = 8), // network.vpn_owner 被 network.vpn 前缀覆盖

            // ---- SIM 卡状态异常（矛盾态，C 级） ----
            RuleSet.RuleDef("rule.sim_anomaly", category = "SIM_ANOMALY", matchRuleIdPrefixes = listOf("sim.", "geo."), weight = 8),
            RuleSet.RuleDef("rule.automation", category = "AUTOMATION", matchRuleIdPrefixes = listOf("automation."), weight = 12),
            RuleSet.RuleDef("rule.screenshare", category = "SCREEN_SHARE", matchRuleIdPrefixes = listOf("screenshare.", "app.screenrecorder"), weight = 14),

            // ---- GPS 伪造（G4：伪造定位应用在装） ----
            RuleSet.RuleDef("rule.fakegps", category = "GPS_SPOOF", matchRuleIdPrefixes = listOf("app.fakegps"), weight = 10),

            // ---- 摄像头伪造（KYC 换脸注入：虚拟摄像头应用/模块在装） ----
            RuleSet.RuleDef("rule.fakecamera", category = "CAMERA_SPOOF", matchRuleIdPrefixes = listOf("app.fakecamera"), weight = 12),

            // ---- 设备身份伪造（IMEI/Android ID 伪造 + 网络身份伪造工具在装） ----
            RuleSet.RuleDef("rule.deviceidchanger", category = "DEVICE_SPOOF", matchRuleIdPrefixes = listOf("app.deviceidchanger", "app.virtualnet"), weight = 10),

            // ---- PIF 属性伪装（成对属性偏离 + 模块/配置残留路径） ----
            RuleSet.RuleDef("rule.pif", framework = "pif", matchRuleIdPrefixes = listOf("prop.build_pair.", "path.pif"), weight = 12),
        ),
    )
}
