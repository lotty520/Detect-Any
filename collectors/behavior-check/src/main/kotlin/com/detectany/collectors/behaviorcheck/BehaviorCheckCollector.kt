package com.detectany.collectors.behaviorcheck

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput

/**
 * C11: 行为异常检测 — VPN / 代理 / 无障碍 / 时钟 / GPS。
 * 面向 Collector 接口，由 DetectionEngine 并行调度。
 *
 * 校准定级（calibration.md）：
 * - VPN 存在 → C（企业/隐私 VPN 常态；calibration #1）
 * - http.proxyHost 非空 → C（企业代理合法）
 * - 无障碍已知自动化 → B；未知 → C 不参与定性（calibration #3 白名单）
 * - 时钟差 >100ms（BOOTTIME vs MONOTONIC）→ B（异步后台执行）
 */
class BehaviorCheckCollector(
    private val context: Context,
) : Collector {

    override val id: CollectorId = CollectorId.C11_BEHAVIORAL

    /** 已知自动化工具包名（特征库可热更新扩展） */
    private val knownAutomationPackages = setOf(
        "org.autojs.autojs", "org.autojs.autoxjs.v6",
        "com.stardust.autojs", "io.github.autojs",
        "com.arlosoft.macrodroid",
        "net.dinglisch.android.taskerm",
        "com.touchsprite.android", "com.lrappsoft.lanren",
        "com.example.easyclick", "ieasyclick.app",
    )

    /** 无障碍白名单（系统/OEM/密码管理器/辅助工具，calibration #3） */
    private val accessibilityWhitelist = setOf(
        "com.google.android.marvin", // TalkBack
        "com.google.android.accessibility", // Select to Speak
        "com.android.accessibilityservice",
        "com.android.settings", // 系统设置
        "com.lastpass.lpandroid", "com.agilebits.onepassword",
        "com.bitwarden", "com.dashlane",
        "com.samsung.android.accessibility",
    )

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        findings += checkVpn()
        findings += checkProxy()
        findings += checkAccessibility()
        findings += checkClockConsistency()
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf(
                "vpn" to isVpnActive().toString(),
                "proxyHost" to (System.getProperty("http.proxyHost") ?: "null"),
                "clockDriftMs" to lastClockDriftMs.toString(),
            ),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    // ---- VPN 检测（C 级，calibration #1） ----

    private fun isVpnActive(): Boolean = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }.getOrDefault(false)

    private fun checkVpn(): List<Finding> {
        return if (isVpnActive()) {
            listOf(
                Finding(
                    ruleId = "network.vpn_active",
                    collector = id,
                    confidence = Confidence.C, // C 级：企业/隐私 VPN 合法常态
                    category = Finding.Category.NETWORK_MITM,
                    framework = null,
                    detail = "VPN 传输层活跃（可能为 HTTP Toolkit/Packet Capture/PCAPdroid，也可能为企业 VPN）",
                    raw = mapOf("vpn" to "true"),
                ),
            )
        } else emptyList()
    }

    // ---- 代理检测（C 级） ----

    private fun checkProxy(): List<Finding> {
        val host = System.getProperty("http.proxyHost")
        return if (!host.isNullOrBlank()) {
            listOf(
                Finding(
                    ruleId = "network.proxy_set",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.NETWORK_MITM,
                    framework = null,
                    detail = "HTTP 代理已配置: $host（可能为 Charles/Burp，也可能为企业代理）",
                    raw = mapOf("hostHash" to host.hashCode().toString()),
                ),
            )
        } else emptyList()
    }

    // ---- 无障碍服务枚举（白名单制，calibration #3） ----

    private fun checkAccessibility(): List<Finding> = buildList {
        val enabledServices = runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        }.getOrDefault("")

        if (enabledServices.isBlank()) return@buildList

        val services = enabledServices.split(":").filter { it.isNotBlank() }

        for (svc in services) {
            val pkg = svc.substringBefore("/").lowercase()

            // 白名单检查：系统/密码管理器/辅助工具 → 不产出
            if (accessibilityWhitelist.any { pkg.startsWith(it.lowercase()) }) continue

            // 已知自动化工具 → B 级
            val isKnownAutomation = knownAutomationPackages.any { pkg.contains(it.lowercase()) }
            add(
                Finding(
                    ruleId = if (isKnownAutomation) "automation.known.$pkg" else "automation.unknown.$pkg",
                    collector = id,
                    confidence = if (isKnownAutomation) Confidence.B else Confidence.C,
                    category = Finding.Category.AUTOMATION,
                    framework = if (isKnownAutomation) pkg.substringAfterLast(".") else null,
                    detail = if (isKnownAutomation) {
                        "已知自动化工具无障碍服务已启用: $pkg"
                    } else {
                        "非白名单无障碍服务: $pkg（C 级，不参与定性）"
                    },
                    raw = mapOf("pkgHash" to pkg.hashCode().toString(), "known" to isKnownAutomation.toString()),
                ),
            )
        }
    }

    // ---- G1: 多时钟一致性检测（speed hack, calibration #8） ----
    // 比较 CLOCK_BOOTTIME (elapsedRealtimeNanos) vs CLOCK_MONOTONIC (nanoTime)
    // 速度篡改 hook 只能改一个时钟源；差值 >100ms = B 级
    // 校准决策：排除 currentTimeMillis（受 NTP/用户调整影响）；500ms 测量窗口

    private var lastClockDriftMs: Long = 0

    private fun checkClockConsistency(): List<Finding> {
        val windowMs = 500L // 测量窗口（并行引擎下不阻塞其他采集器）
        val boottimeStart = android.os.SystemClock.elapsedRealtimeNanos()
        val monotonicStart = System.nanoTime()

        // 自旋等待窗口结束（保持 CPU 活跃，防 DOZE 干扰）
        while (System.nanoTime() - monotonicStart < windowMs * 1_000_000) {
            // busy-wait
        }

        val boottimeElapsed = android.os.SystemClock.elapsedRealtimeNanos() - boottimeStart
        val monotonicElapsed = System.nanoTime() - monotonicStart
        val driftNs = boottimeElapsed - monotonicElapsed
        lastClockDriftMs = driftNs / 1_000_000

        // 正常漂移 <5ms；阈值 100ms（10x 余量，calibration #8）
        return if (kotlin.math.abs(lastClockDriftMs) > 100) {
            listOf(
                Finding(
                    ruleId = "speedhack.clock_drift",
                    collector = id,
                    confidence = Confidence.B,
                    category = Finding.Category.SPEED_HACK,
                    framework = null,
                    detail = "时钟源不一致: BOOTTIME 漂移 ${lastClockDriftMs}ms（>100ms 阈值）—— 速度篡改特征",
                    raw = mapOf(
                        "boottimeMs" to (boottimeElapsed / 1_000_000).toString(),
                        "monotonicMs" to (monotonicElapsed / 1_000_000).toString(),
                        "driftMs" to lastClockDriftMs.toString(),
                    ),
                ),
            )
        } else emptyList()
    }

}
