package com.detectany.app.ui

import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.feature.report.ReportModel

/**
 * 产品级信息架构（2026-11-06 重构）：
 * - 结果按「威胁」组织（用户心智：我中了什么、多严重、证据是什么）
 * - 模块按「检测能力域」组织（用户不感知 C1-C8 工程件）
 */

// ---------------------------------------------------------------------------
// 威胁注册表（结果分组）
// ---------------------------------------------------------------------------

data class ThreatMeta(
    val key: String,
    val name: String,
    val desc: String,
    /** 威胁类别着色 */
    val category: Finding.Category,
)

val THREATS: Map<String, ThreatMeta> = listOf(
    ThreatMeta("magisk", "Magisk", "Userspace root framework", Finding.Category.ROOT_USERSPACE),
    ThreatMeta("ksu", "KernelSU", "Kernel-space root (supercall)", Finding.Category.ROOT_KERNEL),
    ThreatMeta("ksunext", "KernelSU-Next", "KSU superset (built-in susfs)", Finding.Category.ROOT_KERNEL),
    ThreatMeta("sukisu", "SukiSU-Ultra", "KSU superset (high hiding)", Finding.Category.ROOT_KERNEL),
    ThreatMeta("apatch", "APatch", "Kernel root (KP + KPM)", Finding.Category.ROOT_KERNEL),
    ThreatMeta("lsposed", "LSPosed", "Hook injection framework", Finding.Category.HOOK),
    ThreatMeta("zygisknext", "Zygisk Next", "Zygisk injection layer", Finding.Category.ZYGISK),
    ThreatMeta("rezygisk", "ReZygisk", "Zygisk injection layer (open fork)", Finding.Category.ZYGISK),
    ThreatMeta("trickystore", "TrickyStore", "Hardware attestation forgery (keybox)", Finding.Category.ATTESTATION_SPOOF),
    ThreatMeta("susfs", "susfs", "Kernel-level hiding capability", Finding.Category.ROOT_KERNEL),
    ThreatMeta("pif", "PIF", "Play Integrity fingerprint spoofing", Finding.Category.ATTESTATION_SPOOF),
    ThreatMeta("trustmealready", "TrustMeAlready", "Certificate validation bypass module", Finding.Category.HOOK),
    ThreatMeta("zygiskdetect", "Zygisk Detector", "Injection-detection tool installed", Finding.Category.ZYGISK),
    ThreatMeta("frida", "Frida", "Dynamic instrumentation framework", Finding.Category.INSTRUMENTATION),
    ThreatMeta("scrcpy", "scrcpy", "Screen mirroring / remote control", Finding.Category.SCREEN_SHARE),
    ThreatMeta("qemu", "QEMU Emulator", "Android emulator", Finding.Category.EMULATOR),
    ThreatMeta("vbox", "VirtualBox", "Emulator virtualization layer", Finding.Category.EMULATOR),
    ThreatMeta("bluestacks", "BlueStacks", "Android emulator", Finding.Category.EMULATOR),
    ThreatMeta("anydesk", "AnyDesk", "Remote desktop", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("teamviewer", "TeamViewer", "Remote desktop", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("airdroid", "AirDroid", "Remote management", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("airmirror", "AirMirror", "Remote control", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("vysor", "Vysor", "Screen mirroring", Finding.Category.SCREEN_SHARE),
    ThreatMeta("fakegps", "GPS Spoofer", "Location-spoofing app installed", Finding.Category.GPS_SPOOF),
    ThreatMeta("fakecamera", "Virtual Camera", "Camera-spoofing tool installed (KYC risk)", Finding.Category.CAMERA_SPOOF),
    ThreatMeta("deviceidchanger", "Device ID Spoofer", "IMEI/Android ID forging tool installed", Finding.Category.DEVICE_SPOOF),
    ThreatMeta("virtualnet", "Network Identity Spoofer", "Wi-Fi/cellular identity forgery module", Finding.Category.DEVICE_SPOOF),
    ThreatMeta("appenv", "Device Spoofing Tool", "Per-app device-info forgery module (appenv family)", Finding.Category.DEVICE_SPOOF),
    ThreatMeta("screenrecorder", "Screen Recorder", "Third-party screen-recording app installed", Finding.Category.SCREEN_SHARE),
    ThreatMeta("modmenu", "Mod Menu", "Game modification overlay", Finding.Category.OVERLAY_INJECTION),
).associateBy { it.key }

/** 未具名框架时按类别归组。 */
private val CATEGORY_FALLBACK = mapOf(
    "HOOK" to "Hook Injection",
    "ROOT_KERNEL" to "Kernel Root",
    "ROOT_USERSPACE" to "Userspace Root",
    "ZYGISK" to "Zygisk Injection",
    "ATTESTATION_SPOOF" to "Attestation Spoofing",
    "REPACKAGED" to "Repackaged",
    "ANTI_DETECT_PRESENT" to "Hiding Stack / Anti-Detection",
    "GPS_SPOOF" to "GPS Spoofing",
    "CAMERA_SPOOF" to "Camera Spoofing",
    "DEVICE_SPOOF" to "Device Identity Spoofing",
    "SIM_ANOMALY" to "SIM Anomaly",
    "SCREEN_SHARE" to "Screen Sharing",
    "REMOTE_CONTROL" to "Remote Control / RAT",
    // 2026-11-10 审计：7 个类别缺兜底——framework=null 的 finding 在 UI
    // 显示裸枚举名（P8 实见 "AUTOMATION"），补齐 20 类全覆盖
    "INSTRUMENTATION" to "Dynamic Instrumentation",
    "VIRTUAL_ENV" to "Virtual Environment",
    "EMULATOR" to "Emulator",
    "NETWORK_MITM" to "Network MITM",
    "AUTOMATION" to "Automation Tools",
    "SPEED_HACK" to "Speed Hack",
    "OVERLAY_INJECTION" to "Overlay Injection",
)

data class ThreatGroup(
    val key: String,
    val name: String,
    val desc: String,
    val category: Finding.Category,
    val findings: List<ReportModel.FindingView>,
    val worst: Confidence,
)

/** 按威胁分组（强证据优先排序）。 */
fun groupByThreat(findings: List<ReportModel.FindingView>): List<ThreatGroup> {
    return findings
        .groupBy { f -> f.framework ?: CATEGORY_FALLBACK[f.category] ?: f.category }
        .map { (key, fs) ->
            val meta = THREATS[key]
            val worst = fs.minOf { confRank(it.confidenceLabel) }  // min = 最强信号
            ThreatGroup(
                key = key,
                name = meta?.name ?: key,
                desc = meta?.desc ?: (CATEGORY_FALLBACK[fs.first().category] ?: ""),
                category = meta?.category ?: fs.first().let { Finding.Category.valueOf(it.category) },
                findings = fs,
                worst = CONF_RANKS[worst] ?: Confidence.C,
            )
        }
        .sortedWith(compareBy<ThreatGroup> { confRankLabel(it.worst) }.thenByDescending { it.findings.size })
}

private fun confRank(label: String): Int = when (label) { "STRONG" -> 0; "MED" -> 1; else -> 2 }
private fun confRankLabel(c: Confidence): Int = when (c) { Confidence.A -> 0; Confidence.B -> 1; else -> 2 }
private val CONF_RANKS = listOf(Confidence.A, Confidence.B, Confidence.C)  // rank 0=强→A

// ---------------------------------------------------------------------------
// 检测能力域（模块分组）
// ---------------------------------------------------------------------------

enum class CapabilityDomain(val title: String, val desc: String, val members: List<CollectorId>) {
    ENVIRONMENT("Filesystem & Mounts", "Signature paths, mount forensics, statfs/st_dev cross-checks", listOf(CollectorId.C1_PATH, CollectorId.C2_MOUNT)),
    PROPERTIES("Property Consistency", "Full property snapshot, area gaps, paired-prop deviation", listOf(CollectorId.C3_PROPERTY)),
    ENDPOINTS("Network Endpoints", "Unix domain sockets, file socket paths (gated)", listOf(CollectorId.C4_ENDPOINT)),
    APPS("App Fingerprints", "Declarative enumeration, cert pinning, DEX content probes", listOf(CollectorId.C5_APP_FINGERPRINT)),
    MEMORY("Memory & Injection Traces", "maps/smaps/solist cross-checks, RWX self-probe, fd linkage", listOf(CollectorId.C6_MEMORY_MAP)),
    INTEGRITY("Integrity & Self-Protection", "prologue/GOT verification, signature digest, anti-debug", listOf(CollectorId.C7_CODE_INTEGRITY)),
    ATTEST("Hardware Attestation (L3)", "Keymaster chain, CRL, field cross-checks", listOf(CollectorId.C13_ATTESTATION)),
    KERNEL("Kernel Interface Behavior", "supercall probes, SELinux errno semantics, triple-path diff", listOf(CollectorId.C8_BEHAVIOR)),
    INSTRUMENTATION("Instrumentation Detection", "Frida defenses: strings / D-Bus protocol / RWX pages", listOf(CollectorId.C9_INSTRUMENTATION)),
    VIRTUAL_ENV("Virtual Environment", "4-dimension emulator cross: props/hardware/sensors/GL", listOf(CollectorId.C10_VIRTUAL_ENV)),
    BEHAVIORAL("Behavioral Anomalies", "VPN/proxy/accessibility automation/clock consistency", listOf(CollectorId.C11_BEHAVIORAL)),
    SCREEN_SHARE("Screen Share Detection", "scrcpy sockets/HID, ADB session, remote desktop, overlay", listOf(CollectorId.C12_SCREEN_SHARE)),
}

/** 采集器短名（能力域成员行 / 证据来源行，无 C 编号）。 */
val CollectorId.shortName: String
    get() = when (this) {
        CollectorId.C1_PATH -> "Path Probing"
        CollectorId.C2_MOUNT -> "Mount & Device IDs"
        CollectorId.C3_PROPERTY -> "Property Enumeration"
        CollectorId.C4_ENDPOINT -> "Endpoint Probing"
        CollectorId.C5_APP_FINGERPRINT -> "App Fingerprints"
        CollectorId.C6_MEMORY_MAP -> "Memory Maps"
        CollectorId.C7_CODE_INTEGRITY -> "Integrity Check"
        CollectorId.C8_BEHAVIOR -> "Behavior Probes"
        CollectorId.C9_INSTRUMENTATION -> "Instrumentation Probes"
        CollectorId.C10_VIRTUAL_ENV -> "Virtual Environment"
        CollectorId.C11_BEHAVIORAL -> "Behavioral Detection"
        CollectorId.C12_SCREEN_SHARE -> "Screen Share"
        CollectorId.C13_ATTESTATION -> "Hardware Attestation"
    }
