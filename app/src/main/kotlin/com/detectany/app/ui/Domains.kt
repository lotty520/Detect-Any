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
    ThreatMeta("magisk", "Magisk", "用户态 Root 框架", Finding.Category.ROOT_USERSPACE),
    ThreatMeta("ksu", "KernelSU", "内核态 Root（supercall）", Finding.Category.ROOT_KERNEL),
    ThreatMeta("ksunext", "KernelSU-Next", "KSU 超集（内置 susfs）", Finding.Category.ROOT_KERNEL),
    ThreatMeta("sukisu", "SukiSU-Ultra", "KSU 超集（高隐藏）", Finding.Category.ROOT_KERNEL),
    ThreatMeta("apatch", "APatch", "内核 Root（KP + KPM）", Finding.Category.ROOT_KERNEL),
    ThreatMeta("lsposed", "LSPosed", "Hook 注入框架", Finding.Category.HOOK),
    ThreatMeta("zygisknext", "Zygisk Next", "Zygisk 注入层", Finding.Category.ZYGISK),
    ThreatMeta("rezygisk", "ReZygisk", "Zygisk 注入层（开源分支）", Finding.Category.ZYGISK),
    ThreatMeta("trickystore", "TrickyStore", "硬件证明伪造（keybox）", Finding.Category.ATTESTATION_SPOOF),
    ThreatMeta("susfs", "susfs", "内核级隐藏能力", Finding.Category.ROOT_KERNEL),
    ThreatMeta("pif", "PIF", "Play Integrity 指纹伪装", Finding.Category.ATTESTATION_SPOOF),
    ThreatMeta("trustmealready", "TrustMeAlready", "证书校验绕过模块", Finding.Category.HOOK),
    ThreatMeta("zygiskdetect", "Zygisk 检测工具", "注入环境探测工具在装", Finding.Category.ZYGISK),
    ThreatMeta("frida", "Frida", "动态插桩框架", Finding.Category.INSTRUMENTATION),
    ThreatMeta("scrcpy", "scrcpy", "屏幕镜像/远程控制", Finding.Category.SCREEN_SHARE),
    ThreatMeta("qemu", "QEMU 模拟器", "Android 模拟器", Finding.Category.EMULATOR),
    ThreatMeta("vbox", "VirtualBox", "模拟器虚拟化层", Finding.Category.EMULATOR),
    ThreatMeta("bluestacks", "BlueStacks", "Android 模拟器", Finding.Category.EMULATOR),
    ThreatMeta("anydesk", "AnyDesk", "远程桌面", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("teamviewer", "TeamViewer", "远程桌面", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("airdroid", "AirDroid", "远程管理", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("airmirror", "AirMirror", "远程控制", Finding.Category.REMOTE_CONTROL),
    ThreatMeta("vysor", "Vysor", "屏幕镜像", Finding.Category.SCREEN_SHARE),
    ThreatMeta("fakegps", "GPS 伪造工具", "伪造定位应用在装", Finding.Category.GPS_SPOOF),
    ThreatMeta("fakecamera", "虚拟摄像头", "摄像头伪造工具在装（KYC 风险）", Finding.Category.CAMERA_SPOOF),
    ThreatMeta("deviceidchanger", "设备身份伪造", "IMEI/Android ID 伪造工具在装", Finding.Category.DEVICE_SPOOF),
    ThreatMeta("virtualnet", "网络身份伪造", "WiFi/蜂窝身份伪造模块在装", Finding.Category.DEVICE_SPOOF),
    ThreatMeta("appenv", "改机工具", "应用变量类改机模块在装（per-app 伪造设备信息）", Finding.Category.DEVICE_SPOOF),
    ThreatMeta("screenrecorder", "第三方录屏", "屏幕录制应用在装", Finding.Category.SCREEN_SHARE),
    ThreatMeta("modmenu", "Mod Menu", "游戏修改菜单", Finding.Category.OVERLAY_INJECTION),
).associateBy { it.key }

/** 未具名框架时按类别归组。 */
private val CATEGORY_FALLBACK = mapOf(
    "HOOK" to "通用 Hook 注入",
    "ROOT_KERNEL" to "内核 Root",
    "ROOT_USERSPACE" to "用户态 Root",
    "ZYGISK" to "Zygisk 注入",
    "ATTESTATION_SPOOF" to "证明伪造",
    "REPACKAGED" to "重打包",
    "ANTI_DETECT_PRESENT" to "隐藏栈 / 反检测",
    "GPS_SPOOF" to "GPS 伪造",
    "CAMERA_SPOOF" to "摄像头伪造",
    "DEVICE_SPOOF" to "设备身份伪造",
    "SIM_ANOMALY" to "SIM 状态异常",
    "SCREEN_SHARE" to "屏幕共享",
    "REMOTE_CONTROL" to "远程控制 / RAT",
    // 2026-11-10 审计：7 个类别缺兜底——framework=null 的 finding 在 UI
    // 显示裸枚举名（P8 实见 "AUTOMATION"），补齐 20 类全覆盖
    "INSTRUMENTATION" to "动态插桩",
    "VIRTUAL_ENV" to "虚拟环境",
    "EMULATOR" to "模拟器",
    "NETWORK_MITM" to "网络劫持",
    "AUTOMATION" to "自动化工具",
    "SPEED_HACK" to "速度篡改",
    "OVERLAY_INJECTION" to "悬浮窗注入",
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

private fun confRank(label: String): Int = when (label) { "强" -> 0; "中" -> 1; else -> 2 }
private fun confRankLabel(c: Confidence): Int = when (c) { Confidence.A -> 0; Confidence.B -> 1; else -> 2 }
private val CONF_RANKS = listOf(Confidence.A, Confidence.B, Confidence.C)  // rank 0=强→A

// ---------------------------------------------------------------------------
// 检测能力域（模块分组）
// ---------------------------------------------------------------------------

enum class CapabilityDomain(val title: String, val desc: String, val members: List<CollectorId>) {
    ENVIRONMENT("文件与挂载环境", "特征路径、挂载取证、statfs/st_dev 交叉", listOf(CollectorId.C1_PATH, CollectorId.C2_MOUNT)),
    PROPERTIES("系统属性一致性", "属性全量快照、属性区空洞、成对属性偏离", listOf(CollectorId.C3_PROPERTY)),
    ENDPOINTS("网络与端点", "Unix 域套接字、文件 socket 路径族（门控降级）", listOf(CollectorId.C4_ENDPOINT)),
    APPS("应用与包指纹", "声明式枚举、签名钉住、DEX 内容指纹（spoofed 兜底）", listOf(CollectorId.C5_APP_FINGERPRINT)),
    MEMORY("内存与注入痕迹", "maps/smaps/soinfo 链表交叉、RWX 自探针、fd 关联", listOf(CollectorId.C6_MEMORY_MAP)),
    INTEGRITY("完整性与自保护", "prologue/GOT 校验、签名摘要、反调试", listOf(CollectorId.C7_CODE_INTEGRITY)),
    KERNEL("内核接口行为", "supercall 探针、SELinux errno 语义、三路 diff", listOf(CollectorId.C8_BEHAVIOR)),
    INSTRUMENTATION("动态插桩检测", "Frida 三层防线：字符串/D-Bus 协议/RWX 页特征", listOf(CollectorId.C9_INSTRUMENTATION)),
    VIRTUAL_ENV("虚拟环境检测", "模拟器属性/硬件/传感器/容器/GL 渲染器四维交叉", listOf(CollectorId.C10_VIRTUAL_ENV)),
    BEHAVIORAL("行为异常检测", "VPN/代理/无障碍自动化/时钟一致性", listOf(CollectorId.C11_BEHAVIORAL)),
    SCREEN_SHARE("屏幕共享检测", "scrcpy 套接字/HID、ADB 会话、远程桌面、悬浮窗", listOf(CollectorId.C12_SCREEN_SHARE)),
}

/** 采集器短名（能力域成员行 / 证据来源行，无 C 编号）。 */
val CollectorId.shortName: String
    get() = when (this) {
        CollectorId.C1_PATH -> "特征路径探测"
        CollectorId.C2_MOUNT -> "挂载与设备号"
        CollectorId.C3_PROPERTY -> "属性枚举"
        CollectorId.C4_ENDPOINT -> "端点探测"
        CollectorId.C5_APP_FINGERPRINT -> "应用指纹"
        CollectorId.C6_MEMORY_MAP -> "内存映射"
        CollectorId.C7_CODE_INTEGRITY -> "完整性校验"
        CollectorId.C8_BEHAVIOR -> "行为探针"
        CollectorId.C9_INSTRUMENTATION -> "插桩探针"
        CollectorId.C10_VIRTUAL_ENV -> "虚拟环境"
        CollectorId.C11_BEHAVIORAL -> "行为检测"
        CollectorId.C12_SCREEN_SHARE -> "屏幕共享"
    }
