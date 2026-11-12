package com.detectany.collectors.screenshare

import android.content.Context
import android.hardware.input.InputManager
import android.os.BatteryManager
import android.provider.Settings
import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import java.io.File

/**
 * C12: 屏幕共享/远程控制检测 — scrcpy / ADB / 远程桌面 / overlay。
 * 面向 Collector 接口，由 DetectionEngine 并行调度。
 *
 * 校准定级（calibration.md）：
 * - scrcpy unix socket → A（专属特征）
 * - InputDevice 名含 scrcpy → A（专属）
 * - ADB + USB + 应用前台 → B（三条件组合）
 * - ADB 单独 → C（开发者常用）
 * - 远程桌面 + 无障碍启用 → B；仅安装 → C
 * - overlay + canDrawOverlays → C（过滤器合法）；+ 触摸遮蔽共振 → B
 */
class ScreenShareCollector(
    private val context: Context,
) : Collector {

    override val id: CollectorId = CollectorId.C12_SCREEN_SHARE

    /** 已知远程桌面包名 */
    private val remoteDesktopPackages = mapOf(
        "com.anydesk.anydeskandroid" to "anydesk",
        "com.teamviewer.quicksupport.market" to "teamviewer",
        "com.teamviewer.host.market" to "teamviewer",
        "com.teamviewer.teamviewer.market.mobile" to "teamviewer",
        "com.sand.airdroid" to "airdroid",
        "com.sand.airmirror" to "airmirror",
        "com.koushikdutta.vysor" to "vysor",
        "com.google.chromeremotedesktop" to "chromeremote",
    )

    /** 已知过滤器/辅助工具 overlay 白名单（calibration #15） */
    private val overlayWhitelist = setOf(
        "com.urbandroid.lux", // Twilight
        "com.justgetflux.flux", // f.lux
        "net.dinglisch.android.taskerm", // Tasker (overlay)
    )

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        findings += checkScrcpySockets()
        findings += checkInputDevices()
        findings += checkAdbSession()
        findings += checkRemoteDesktop()
        findings += checkOverlay()
        findings += checkScreenRecordingState()
        findings += checkInputBehavior()
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf(
                "scrcpySockets" to findings.count { it.ruleId.startsWith("screenshare.scrcpy") }.toString(),
                "adbEnabled" to isAdbEnabled().toString(),
                "remoteDesktopApps" to findRemoteDesktopApps().size.toString(),
                "screenRecording" to (ScreenRecordingMonitor.stateVisible?.toString() ?: "unknown"),
                "inputEvents" to InputEventMonitor.snapshot().total.toString(),
            ),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    // ---- G6 输入行为（P2-4）：注入/合成比例（滚动窗口快照，初版全 C——节律 FP 面待样本） ----

    private fun checkInputBehavior(): List<Finding> {
        val snap = InputEventMonitor.snapshot()
        if (snap.total < 30) return emptyList() // 样本不足（冷启动即扫）——meta 见下
        val findings = mutableListOf<Finding>()
        if (snap.accessibilityRatio > 0.3f) {
            findings.add(
                Finding(
                    ruleId = "input.accessibility_ratio",
                    collector = id,
                    confidence = Confidence.C, // 残障辅助服务合法注入——白名单联动前不升
                    category = Finding.Category.AUTOMATION,
                    framework = null,
                    detail = "Input events: ${(snap.accessibilityRatio * 100).toInt()}% accessibility-injected over last ${snap.total} events (auto-clicker / remote-control signature; also legitimate for accessibility users)",
                    raw = mapOf("ratio" to snap.accessibilityRatio.toString(), "total" to snap.total.toString()),
                ),
            )
        }
        if (snap.syntheticRatio > 0.5f || snap.virtualRatio > 0.5f) {
            findings.add(
                Finding(
                    ruleId = "input.synthetic_ratio",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.AUTOMATION,
                    framework = null,
                    detail = "Input events: synthetic/virtual-device source ${(maxOf(snap.syntheticRatio, snap.virtualRatio) * 100).toInt()}% (Instrumentation/adb injection or virtual HID)",
                    raw = mapOf("synthetic" to snap.syntheticRatio.toString(), "virtual" to snap.virtualRatio.toString()),
                ),
            )
        }
        return findings
    }

    // ---- 系统级录制状态（G5，API 34+；状态由 ScreenRecordingMonitor 持有） ----

    private fun checkScreenRecordingState(): List<Finding> {
        // null=未知（未注册/能力缺失）→ 不产出；true=系统确认本应用画面正被录制
        val visible = ScreenRecordingMonitor.stateVisible ?: return emptyList()
        return if (visible) {
            listOf(
                Finding(
                    ruleId = "screenshare.recording_active",
                    collector = id,
                    confidence = Confidence.B, // 系统上报的物理状态，非启发式
                    category = Finding.Category.SCREEN_SHARE,
                    framework = null,
                    detail = "Screen-recording callback confirms this app is being recorded (status-bar recording indicator semantics, API 34+)",
                    raw = mapOf(
                        "stateVisible" to "true",
                        "lastChangedAtMs" to ScreenRecordingMonitor.lastChangedAtMs.toString(),
                    ),
                ),
            )
        } else emptyList()
    }

    // ---- scrcpy unix socket 检测（A 级） ----

    private fun checkScrcpySockets(): List<Finding> {
        val unix = runCatching { File("/proc/net/unix").readLines() }.getOrDefault(emptyList())
        return if (unix.any { it.contains("scrcpy_", true) }) {
            listOf(
                Finding(
                    ruleId = "screenshare.scrcpy_socket",
                    collector = id,
                    confidence = Confidence.A,
                    category = Finding.Category.SCREEN_SHARE,
                    framework = "scrcpy",
                    detail = "scrcpy abstract socket found (screen mirroring active)",
                    raw = mapOf("socket" to "scrcpy_"),
                ),
            )
        } else emptyList()
    }

    // ---- InputDevice 枚举（scrcpy HID / 虚拟设备） ----

    private fun checkInputDevices(): List<Finding> = buildList {
        runCatching {
            val im = context.getSystemService(Context.INPUT_SERVICE) as? InputManager ?: return@runCatching
            @Suppress("DEPRECATION")
            val ids = im.inputDeviceIds
            for (devId in ids) {
                val device = im.getInputDevice(devId) ?: continue
                val name = device.name ?: continue
                if (name.contains("scrcpy", true)) {
                    add(
                        Finding(
                            ruleId = "screenshare.scrcpy_hid",
                            collector = id,
                            confidence = Confidence.A,
                            category = Finding.Category.REMOTE_CONTROL,
                            framework = "scrcpy",
                            detail = "scrcpy HID virtual input device found: $name",
                            raw = mapOf("device" to name.hashCode().toString()),
                        ),
                    )
                }
                if (device.isVirtual && !name.contains("virtual", true)) {
                    add(
                        Finding(
                            ruleId = "screenshare.virtual_input",
                            collector = id,
                            confidence = Confidence.B,
                            category = Finding.Category.AUTOMATION,
                            framework = null,
                            detail = "Virtual input device (not physical hardware): $name",
                            raw = mapOf("device" to name.hashCode().toString()),
                        ),
                    )
                }
            }
        }
    }

    // ---- ADB 会话检测（三条件分级） ----

    private fun isAdbEnabled(): Boolean = runCatching {
        Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    }.getOrDefault(false)

    private fun isUsbPlugged(): Boolean = runCatching {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager ?: return false
        bm.isCharging && bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_STATUS) == BatteryManager.BATTERY_STATUS_CHARGING
    }.getOrDefault(false)

    private fun isAppInForeground(): Boolean = runCatching {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? android.app.ActivityManager
        val pid = android.os.Process.myPid()
        am?.runningAppProcesses?.firstOrNull { it.pid == pid }?.importance ==
            android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
    }.getOrDefault(false)

    private fun checkAdbSession(): List<Finding> = buildList {
        val adb = isAdbEnabled()
        if (!adb) return@buildList

        val usb = isUsbPlugged()
        val fg = isAppInForeground()

        // 2026-11-12 语义修正：ADB 是设备状态因子，不构成远控判定基础。
        // - adb_session 原判 B 级挂 REMOTE_CONTROL：B 可与跨域 B 共振定性——
        //   「开着 USB 调试用真机」被推到定性边缘，语义过强。真 scrcpy 会话由
        //   socket/HID（A 级）直接判定，无需 B 级替身。
        // - 终态：两条均 C 级，adb_session 降类别为 NETWORK_MITM 之外的独立姿态
        //   描述（复用 REMOTE_CONTROL 展示会误导）——改挂 SCREEN_SHARE 也不对；
        //   引入 AUTOMATION 亦牵强。正确落点：这是「调试面开放」状态，挂
        //   REMOTE_CONTROL 仅作归组展示、但 C 级永不参与定性（模型保证）。
        if (adb && usb && fg) {
            add(
                Finding(
                    ruleId = "screenshare.adb_session",
                    collector = id,
                    confidence = Confidence.C, // B→C：状态因子，非会话判定
                    category = Finding.Category.REMOTE_CONTROL,
                    framework = null,
                    detail = "Debug surface open: ADB + USB + foreground (possible scrcpy session; direct verdict comes from socket/HID A-grade probes)",
                    raw = mapOf("adb" to "1", "usb" to "1", "foreground" to "1"),
                ),
            )
        } else {
            add(
                Finding(
                    ruleId = "screenshare.adb_enabled",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.REMOTE_CONTROL,
                    framework = null,
                    detail = "ADB debugging enabled (device posture factor, not a remote-control verdict basis)",
                    raw = mapOf("adb" to "1", "usb" to usb.toString()),
                ),
            )
        }
    }

    // ---- 远程桌面包指纹 ----

    private fun findRemoteDesktopApps(): List<Pair<String, String>> {
        return remoteDesktopPackages.mapNotNull { (pkg, name) ->
            runCatching {
                context.packageManager.getPackageInfo(pkg, 0)
                pkg to name
            }.getOrNull()
        }
    }

    private fun checkRemoteDesktop(): List<Finding> = buildList {
        val installed = findRemoteDesktopApps()
        if (installed.isEmpty()) return@buildList

        // 检查是否有对应的无障碍服务启用
        val enabledServices = runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        }.getOrDefault("")

        for ((pkg, name) in installed) {
            val accessibilityActive = enabledServices.contains(pkg, true)
            add(
                Finding(
                    ruleId = "screenshare.remote_desktop.$name",
                    collector = id,
                    confidence = if (accessibilityActive) Confidence.B else Confidence.C,
                    category = Finding.Category.REMOTE_CONTROL,
                    framework = name,
                    detail = if (accessibilityActive) {
                        "$name 已安装且无障碍服务已启用（远程控制活跃）"
                    } else {
                        "$name 已安装（合法远程协助可能；无障碍未启用 = C 级）"
                    },
                    raw = mapOf("pkg" to pkg, "accessibility" to accessibilityActive.toString()),
                ),
            )
        }
    }

    // ---- Overlay 权限检测（白名单制） ----

    private fun checkOverlay(): List<Finding> = buildList {
        val canDraw = Settings.canDrawOverlays(context)
        if (!canDraw) return@buildList

        // 检查是否有白名单外的应用持有 overlay 权限
        // canDrawOverlays 只检查调用者自身——检测其他应用需枚举
        // 简化实现：如果本应用有 overlay 权限，检查是否在白名单
        val selfPkg = context.packageName
        val isWhitelisted = overlayWhitelist.any { selfPkg.startsWith(it) }

        if (!isWhitelisted) {
            add(
                Finding(
                    ruleId = "screenshare.overlay_permission",
                    collector = id,
                    confidence = Confidence.C, // C 级：过滤器/悬浮球合法（calibration #15）
                    category = Finding.Category.OVERLAY_INJECTION,
                    framework = null,
                    detail = "An app holds overlay permission (possibly GameGuardian/Mod Menu, possibly a legitimate filter)",
                    raw = mapOf("canDrawOverlays" to "true"),
                ),
            )
        }
    }
}
