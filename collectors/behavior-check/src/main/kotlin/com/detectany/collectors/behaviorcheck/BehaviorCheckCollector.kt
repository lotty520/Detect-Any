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

    /**
     * 测试框架组件标记：匹配完整 component 字符串（pkg/class）。
     * uiautomator2 的无障碍服务寄宿在任意测试包名下（class 才是稳定特征：
     * androidx.test.uiautomator.* / Appium server 服务）——仅按包名匹配会漏检。
     */
    private val automationComponentMarkers = setOf(
        "uiautomator", // androidx.test.uiautomator 服务类 + io.appium.uiautomator2.server
        "appium",
    )

    /** 无障碍白名单（系统/OEM/密码管理器/辅助工具，calibration #3） */
    private val accessibilityWhitelist = setOf(
        "com.google.android.marvin", // TalkBack
        "com.google.android.accessibility", // Select to Speak / Switch Access / Sound Amplifier
        "com.android.accessibilityservice",
        "com.android.settings", // 系统设置
        "com.android.systemui", // 无障碍菜单（AccessibilityMenuService，无图标系统服务）
        "com.lastpass.lpandroid", "com.agilebits.onepassword",
        "com.bitwarden", "com.dashlane",
        "com.samsung.android.accessibility",
        "com.miui.accessibility", "com.vivo.accessibility", // OEM 无障碍服务（无图标系统服务）
        "com.oplus.accessibility", "com.huawei.accessibility",
        // 2026-11-11 华为真机实证：分布式剪贴板拖拽服务（EMUI 系统功能）误入未知名单
        "com.huawei.distributedpasteboard", "com.huawei.screenreader",
        "com.coloros.accessibility", "com.heytap.accessibility",
        // 2026-11-12 小米 Android 16 真机实证：CarWith 车联聚焦服务
        // （/product/app/CarWith + SYSTEM 标志——OEM 系统功能，非用户装自动化）
        "com.miui.carlink",
    )

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        findings += checkVpn()
        findings += checkVpnOwner()
        findings += checkProxy()
        findings += checkGlobalProxy()
        findings += checkAccessibility()
        findings += checkInstrumentationPosture()
        findings += checkClockConsistency()
        findings += checkSimStatus()
        findings += checkBatteryIntegrity()
        findings += checkGeoConsistency()
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf(
                "vpn" to isVpnActive().toString(),
                "proxyHost" to (System.getProperty("http.proxyHost") ?: "null"),
                "clockDriftMs" to lastClockDriftMs.toString(),
                "simState" to (lastSimStates.joinToString(",")).ifEmpty { "n/a" },
                "battery" to (lastBatterySummary ?: "n/a"),
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
                    detail = "VPN transport active (possibly HTTP Toolkit/Packet Capture/PCAPdroid, possibly corporate VPN)",
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
                    detail = "HTTP proxy configured: $host (possibly Charles/Burp, possibly corporate proxy)",
                    raw = mapOf("hostHash" to host.hashCode().toString()),
                ),
            )
        } else emptyList()
    }

    // ---- 全局代理（系统级 HTTP 代理，独立于 JVM 属性——改机工具常漏改此处形成矛盾面） ----

    private fun checkGlobalProxy(): List<Finding> {
        // 值形态："host:port"（或带 ~ 排除列表）；未设置时为 null 或 "none"
        val gp = runCatching {
            Settings.Global.getString(context.contentResolver, Settings.Global.HTTP_PROXY)
        }.getOrNull()?.trim().orEmpty()
        if (gp.isEmpty() || gp == "none" || gp == ":0") return emptyList()
        return listOf(
            Finding(
                ruleId = "network.global_proxy_set",
                collector = id,
                confidence = Confidence.C, // 合法场景：企业策略/家长控制
                category = Finding.Category.NETWORK_MITM,
                framework = null,
                detail = "System-wide HTTP proxy configured: $gp (device-wide interception surface, MITM tool signature)",
                raw = mapOf("proxyHash" to gp.hashCode().toString()),
            ),
        )
    }

    // ---- 无障碍服务枚举（白名单制，calibration #3） ----
    // RAT 形态探测（无障碍+隐藏图标+非系统三特征，BTMOB 类）已论证不可行：
    // 已启用的无障碍服务包对未声明 queries 的应用并不可见（2026-11-10 模拟器
    // 实证——服务真绑定后 getPackageInfo 仍 NameNotFoundException；TalkBack 可见
    // 属特例不可泛化），图标状态无从查询；破局需 QUERY_ALL_PACKAGES，与 specs
    // 「不申报全量枚举」冲突 → 列为已知边界（见 COVERAGE_ANALYSIS）。

    private fun checkAccessibility(): List<Finding> = buildList {
        val enabledServices = runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        }.getOrDefault("")

        if (enabledServices.isBlank()) return@buildList

        val services = enabledServices.split(":").filter { it.isNotBlank() }

        for (svc in services) {
            val svcLower = svc.lowercase()
            val pkg = svc.substringBefore("/").lowercase()

            // 白名单检查：系统/密码管理器/辅助工具 → 不产出
            if (accessibilityWhitelist.any { pkg.startsWith(it.lowercase()) }) continue

            // 已知自动化工具（包名）或测试框架组件标记（完整 component 匹配）→ B 级
            val isKnownAutomation = knownAutomationPackages.any { pkg.contains(it.lowercase()) } ||
                automationComponentMarkers.any { svcLower.contains(it) }
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

    // ---- Instrumentation 运行姿态（am instrument 驱动：Espresso/AndroidJUnitRunner/Appium server 等） ----
    // 证据 1（线程命名，2026-11-12 Pixel 4/API 33/androidx.test 1.6.2 实证）：
    //   androidx.test 1.5+ 的 runner 创建 "InstrumentationThread"（comm 受 TASK_COMM_LEN=15
    //   截断显示为 "Instrumentation"）；AOSP 老路径 InstrumentationThread 名为
    //   "Instr: <class>"（前缀保留）。正常 app 无此二形态线程命名。
    //   实证补充：现代 argv0/cmdline=包名（无 Instr: 前缀），进程命名向量仅老版本有效，保留兼容。
    // 证据 2（反射 best-effort）：ActivityThread.mInstrumentation 实例类非基类
    //   （runner 子类替换，如 androidx.test.runner.AndroidJUnitRunner）。
    //   targetSdk 28+ hidden-API enforcement 拦截时 runCatching 静默降级，不单独作为依据。

    private fun checkInstrumentationPosture(): List<Finding> = buildList {
        val argv0 = readSelfArgv0()
        val instrThread = readSelfThreadComms().firstOrNull {
            it.startsWith("instr:", true) || it.equals("instrumentation", true)
        }
        val argvHit = argv0.startsWith("instr:", true)
        val instrClass = readInstrumentationClass()

        if (instrThread == null && !argvHit && instrClass == null) return@buildList
        add(
            Finding(
                ruleId = "automation.instrumented",
                collector = id,
                confidence = Confidence.B,
                category = Finding.Category.AUTOMATION,
                framework = "instrumentation",
                detail = "Process running under test instrumentation" +
                    (instrThread?.let { " (thread comm: \"$it\")" } ?: "") +
                    (if (argvHit) " (argv0: \"${argv0.take(40)}\")" else "") +
                    (instrClass?.let { " (instrumentation class: $it)" } ?: ""),
                raw = buildMap {
                    instrThread?.let { put("thread", it) }
                    if (argvHit) put("argv0", argv0.take(40))
                    instrClass?.let { put("class", it) }
                },
            ),
        )
    }

    // v16.1：读取下沉 native（ProcSelfReads——JVM 层 File hook 失效，native 库不可用时其内部降级）
    private fun readSelfArgv0(): String =
        com.detectany.core.nativeplatform.ProcSelfReads.argv0()

    private fun readSelfThreadComms(): List<String> =
        com.detectany.core.nativeplatform.ProcSelfReads.threadComms()

    private fun readInstrumentationClass(): String? = runCatching {
        val at = Class.forName("android.app.ActivityThread").getMethod("currentActivityThread").invoke(null)
            ?: return@runCatching null
        val field = at.javaClass.getDeclaredField("mInstrumentation")
        field.isAccessible = true
        (field.get(at) as? android.app.Instrumentation)?.javaClass?.name
    }.getOrNull()?.takeIf { it != "android.app.Instrumentation" } // 基类实例=正常冷启动，非信号

    // ---- VPN owner 识别（always-on VPN 的归属包名，best-effort 非公开键） ----

    private fun checkVpnOwner(): List<Finding> {
        // Settings.Secure 非公开键；部分版本可读出 always-on VPN 的包名（读取本身无需权限）
        val owner = runCatching {
            Settings.Secure.getString(context.contentResolver, "always_on_vpn_app")
        }.getOrNull()?.trim().orEmpty()
        if (owner.isEmpty() || owner == context.packageName) return emptyList()
        return listOf(
            Finding(
                ruleId = "network.vpn_owner",
                collector = id,
                confidence = Confidence.C, // always-on VPN 合法（企业）；归属包名供风控归因
                category = Finding.Category.NETWORK_MITM,
                framework = null,
                detail = "Always-on VPN owner app: $owner (full-traffic tunnel; possibly corporate VPN or a capture/split tool)",
                raw = mapOf("pkgHash" to owner.hashCode().toString()),
            ),
        )
    }

    // ---- SIM 卡状态感知（全部 C 级：只报矛盾态，不报常态——无 SIM 存在大量合法场景） ----
    // 无权限信号集（API 权威确认免 READ_PHONE_STATE）：
    // getSimState(slot) / getSimCountryIso / getNetworkCountryIso / getSimOperator / getActiveModemCount

    private var lastSimStates: List<String> = emptyList()

    /** SIM_STATE_LOADED（API 26+）不在公开常量表——用数值常量（框架内部一致）。 */
    private val SIM_STATE_LOADED_VAL = 10

    private fun checkSimStatus(): List<Finding> = buildList {
        val tm = runCatching { context.getSystemService(android.telephony.TelephonyManager::class.java) }.getOrNull()
            ?: return@buildList
        // 无电话能力的设备（WiFi-only 平板）跳过——SIM 缺失不是异常
        val hasTelephony = runCatching {
            context.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_TELEPHONY)
        }.getOrDefault(false)
        if (!hasTelephony) return@buildList

        val modemCount = runCatching {
            if (android.os.Build.VERSION.SDK_INT >= 30) tm.activeModemCount else @Suppress("DEPRECATION") tm.phoneCount
        }.getOrDefault(0)
        if (modemCount <= 0) return@buildList

        val states = (0 until modemCount).map { slot ->
            runCatching { tm.getSimState(slot) }.getOrDefault(android.telephony.TelephonyManager.SIM_STATE_UNKNOWN)
        }
        lastSimStates = states.map { simStateName(it) }

        // 矛盾 1：SIM 声称 LOADED 但运营商/国家码全空（软件伪造 SIM 状态特征）
        val loaded = states.any { it == SIM_STATE_LOADED_VAL }
        if (loaded) {
            val simIso = runCatching { tm.simCountryIso }.getOrNull().orEmpty()
            val simOp = runCatching { tm.simOperator }.getOrNull().orEmpty()
            val netIso = runCatching { tm.networkCountryIso }.getOrNull().orEmpty()
            if (simIso.isBlank() && simOp.isBlank() && netIso.isBlank()) {
                add(
                    Finding(
                        ruleId = "sim.loaded_but_blank",
                        collector = id,
                        confidence = Confidence.C,
                        category = Finding.Category.SIM_ANOMALY,
                        framework = null,
                        detail = "SIM state LOADED but operator/country all blank — contradictory (software-faked SIM or virtual modem)",
                        raw = mapOf("modems" to modemCount.toString(), "states" to lastSimStates.joinToString(",")),
                    ),
                )
            } else if (simIso.isNotBlank() && netIso.isNotBlank() && simIso != netIso) {
                // 线索（合法漫游常见，仅记录）
                add(
                    Finding(
                        ruleId = "sim.iso_mismatch",
                        collector = id,
                        confidence = Confidence.C,
                        category = Finding.Category.SIM_ANOMALY,
                        framework = null,
                        detail = "SIM country ($simIso) differs from registered network country ($netIso) (legal while roaming; cross with GPS/timezone to indicate spoofing)",
                        raw = mapOf("simIso" to simIso, "netIso" to netIso),
                    ),
                )
            }
        }

        // 矛盾 2：有 modem 有电话能力但全槽 ABSENT（云手机/群控设备常见形态；备机/双卡空槽合法）→ 仅记录
        val allAbsent = states.isNotEmpty() && states.all { it == android.telephony.TelephonyManager.SIM_STATE_ABSENT }
        if (allAbsent) {
            add(
                Finding(
                    ruleId = "sim.all_absent",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.SIM_ANOMALY,
                    framework = null,
                    detail = "Device has cellular capability but all SIM slots ABSENT (common on cloud phones/device farms; backup devices legal — C-grade, not conclusive)",
                    raw = mapOf("modems" to modemCount.toString()),
                ),
            )
        }
    }

    // ---- 地理一致性（三方合议：时区区域 + locale 国别 vs SIM 国码；ICU API 24+ 免权限） ----
    // 单看时区 vs SIM 的不一致在国际旅行场景大量合法（2026-11-10 模拟器实证：
    // 宿主时区 CN + 虚拟 SIM US 即触发）。收紧为三方合议：时区与 SIM 不一致
    // 且 locale 国别也与 SIM 不一致才产出——旅行者（locale 通常随原属地）不触发；
    // 改机/GPS 伪造常出现三方拼凑不自洽。

    private fun checkGeoConsistency(): List<Finding> {
        val tm = runCatching { context.getSystemService(android.telephony.TelephonyManager::class.java) }.getOrNull()
            ?: return emptyList()
        val simIso = runCatching { tm.simCountryIso }.getOrNull()?.uppercase().orEmpty()
        if (simIso.isBlank()) return emptyList()

        val tzId = java.util.TimeZone.getDefault().id
        val tzRegion = runCatching { android.icu.util.TimeZone.getRegion(tzId) }.getOrNull()?.uppercase().orEmpty()
        if (tzRegion.isBlank() || tzRegion == "001") return emptyList() // 001=无区域时区（UTC/GMT）
        if (tzRegion == simIso) return emptyList() // 时区与 SIM 一致 → 无信号

        // 三方合议第二票：locale 国别（用户可改，但旅行者通常保留原属地）
        val localeCountry = java.util.Locale.getDefault().country.uppercase()
        return if (localeCountry.isNotEmpty() && localeCountry != simIso) {
            listOf(
                Finding(
                    ruleId = "geo.tz_sim_mismatch",
                    collector = id,
                    confidence = Confidence.C, // 跨国旅行/双卡合法；与 GPS/网络交叉可判改机
                    category = Finding.Category.SIM_ANOMALY,
                    framework = null,
                    detail = "Geo tripartite inconsistency: timezone region ($tzRegion) and locale ($localeCountry) both differ from SIM country ($simIso) (tz=$tzId) — device/GPS spoofing signature",
                    raw = mapOf("tzRegion" to tzRegion, "simIso" to simIso, "locale" to localeCountry, "tz" to tzId),
                ),
            )
        } else emptyList()
    }

    private fun simStateName(s: Int): String = when (s) {
        android.telephony.TelephonyManager.SIM_STATE_ABSENT -> "ABSENT"
        android.telephony.TelephonyManager.SIM_STATE_PIN_REQUIRED -> "PIN"
        android.telephony.TelephonyManager.SIM_STATE_PUK_REQUIRED -> "PUK"
        android.telephony.TelephonyManager.SIM_STATE_NETWORK_LOCKED -> "NET_LOCK"
        android.telephony.TelephonyManager.SIM_STATE_READY -> "READY"
        android.telephony.TelephonyManager.SIM_STATE_NOT_READY -> "NOT_READY"
        android.telephony.TelephonyManager.SIM_STATE_PERM_DISABLED -> "PERM_DIS"
        android.telephony.TelephonyManager.SIM_STATE_CARD_IO_ERROR -> "IO_ERR"
        android.telephony.TelephonyManager.SIM_STATE_CARD_RESTRICTED -> "RESTRICTED"
        SIM_STATE_LOADED_VAL -> "LOADED"
        else -> "UNKNOWN"
    }

    // ---- 电池完整性（云手机假电池：跨层矛盾 + 物理矛盾，全部 C 级——OEM 兼容性差异大） ----
    // 层 1：Java 框架（ACTION_BATTERY_CHANGED 粘性广播）
    // 层 2：内核（/sys/class/power_supply/<name>/ 存在性）
    // 云手机/容器在框架层伪造电池，内核层往往无真实 power_supply 节点 → 跨层矛盾

    private var lastBatterySummary: String? = null

    private fun checkBatteryIntegrity(): List<Finding> = buildList {
        val intent = runCatching {
            context.registerReceiver(null, android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED))
        }.getOrNull() ?: return@buildList

        val present = runCatching { intent.getBooleanExtra(android.os.BatteryManager.EXTRA_PRESENT, true) }.getOrDefault(true)
        val level = runCatching { intent.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1) }.getOrDefault(-1)
        val voltage = runCatching { intent.getIntExtra(android.os.BatteryManager.EXTRA_VOLTAGE, -1) }.getOrDefault(-1) // mV
        val temp = runCatching { intent.getIntExtra(android.os.BatteryManager.EXTRA_TEMPERATURE, -1) }.getOrDefault(-1) // 0.1°C
        val status = runCatching { intent.getIntExtra(android.os.BatteryManager.EXTRA_STATUS, -1) }.getOrDefault(-1)
        lastBatterySummary = "present=$present level=$level v=$voltage t=$temp status=$status"

        if (!present) return@buildList

        // 矛盾 1：声称有电池 + 有电量，但电压为 0（真实电池有电压才有电量——物理矛盾）
        if (level > 5 && voltage == 0) {
            add(
                Finding(
                    ruleId = "battery.level_without_voltage",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.VIRTUAL_ENV,
                    framework = null,
                    detail = "Battery level $level% but voltage 0mV — charge-without-voltage physical contradiction (virtual battery; some kernels legitimately omit voltage)",
                    raw = mapOf("level" to level.toString(), "voltage" to voltage.toString()),
                ),
            )
        }

        // 矛盾 2：声称有电池 + 电量 >5%，但温度为 0.0°C（273K 以下真机极罕见；热敏电阻缺失/虚拟电池默认值）
        if (level > 5 && temp == 0) {
            add(
                Finding(
                    ruleId = "battery.zero_temperature",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.VIRTUAL_ENV,
                    framework = null,
                    detail = "Battery temperature 0.0°C (sub-freezing sustained operation physically implausible — virtual-battery default)",
                    raw = mapOf("temp" to "0"),
                ),
            )
        }

        // 矛盾 3（跨层）：框架层有电池，但内核无任何标准 power_supply 节点
        // OEM 命名不统一（battery/bms/maxfg/…），此处用目录枚举：/sys/class/power_supply/ 空 = 内核零电池
        val psDir = java.io.File("/sys/class/power_supply")
        if (psDir.isDirectory) {
            val supplies = runCatching { psDir.list()?.toList() }.getOrNull()
            if (supplies != null && supplies.isEmpty()) {
                add(
                    Finding(
                        ruleId = "battery.framework_only",
                        collector = id,
                        confidence = Confidence.C,
                        category = Finding.Category.VIRTUAL_ENV,
                        framework = null,
                        detail = "Framework reports battery (level=$level%) but /sys/class/power_supply empty — no kernel power supplies (cloud-phone/container cross-layer contradiction)",
                        raw = mapOf("level" to level.toString(), "powerSupplies" to "0"),
                    ),
                )
            }
        }
        // 目录不可读（SELinux 常态）→ 静默跳过，不作为信号
    }
    // 比较 CLOCK_BOOTTIME (elapsedRealtimeNanos) vs CLOCK_MONOTONIC (nanoTime)
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
                    detail = "Clock-source inconsistency: BOOTTIME drift ${lastClockDriftMs}ms (>100ms threshold) — speed-hack signature",
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
