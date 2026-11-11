package com.detectany.collectors.virtualenv

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.SensorManager
import android.opengl.GLES20
import android.os.Build
import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import java.io.File

/**
 * C10: 虚拟环境/模拟器检测 — 四维交叉（构建属性 / 硬件痕迹 / 容器特征 / GL 渲染器）。
 * 面向 Collector 接口，由 DetectionEngine 并行调度。
 *
 * 校准定级（calibration.md）：
 * - ro.kernel.qemu=1 → A（不可伪装）
 * - /dev/qemu_pipe, /dev/vboxguest → A（硬件设备节点）
 * - Build.CPU_ABI=ARM + cpuinfo=x86 → A（架构声明不一致）
 * - Build.FINGERPRINT 含 generic/goldfish → B
 * - 传感器/基带缺失 → C（需共振，低端设备合法缺失）
 * - SwiftShader GL → C（Android Go 低端设备合法）
 * - 容器路径 user≥10 → 不产出（Work Profile 合法）
 */
class VirtualEnvCollector(
    private val context: Context,
) : Collector {

    override val id: CollectorId = CollectorId.C10_VIRTUAL_ENV

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        findings += checkBuildProperties()
        findings += checkHardwareArtifacts()
        findings += checkCpuArchitecture(input)
        findings += checkSensors()
        findings += checkContainer()
        findings += checkGlRenderer()
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf(
                "fingerprint" to Build.FINGERPRINT.takeLast(30),
                "cpuAbi" to (Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"),
            ),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    // ---- 构建属性检测 ----

    private val EMULATOR_BUILD_PATTERNS = listOf(
        "generic" to "generic",
        "google_sdk" to "google_sdk",
        "sdk_gphone" to "sdk_gphone",
        "vbox86" to "vbox",
        "nox" to "nox",
        "ttVM" to "tencent",
        "ldplayer" to "ldplayer",
        "goldfish" to "goldfish",
        "ranchu" to "ranchu",
    )

    private fun checkBuildProperties(): List<Finding> = buildList {
        for ((pattern, name) in EMULATOR_BUILD_PATTERNS) {
            if (Build.FINGERPRINT.contains(pattern, true) || Build.MODEL.contains(pattern, true) ||
                Build.PRODUCT.contains(pattern, true) || Build.HARDWARE.contains(pattern, true)
            ) {
                add(
                    Finding(
                        ruleId = "emulator.build.$name",
                        collector = id,
                        confidence = Confidence.B,
                        category = Finding.Category.EMULATOR,
                        framework = name,
                        detail = "Build 属性含模拟器特征: $pattern",
                        raw = mapOf("pattern" to pattern),
                    ),
                )
            }
        }

        // A 级：ro.kernel.qemu = 1（不可伪装）
        val qemu = System.getProperty("ro.kernel.qemu") ?: runCatching {
            val pi = Class.forName("android.os.SystemProperties")
            val get = pi.getMethod("get", String::class.java)
            get.invoke(null, "ro.kernel.qemu") as? String
        }.getOrNull()
        if (qemu == "1") {
            add(
                Finding(
                    ruleId = "emulator.qemu",
                    collector = id,
                    confidence = Confidence.A,
                    category = Finding.Category.EMULATOR,
                    framework = "qemu",
                    detail = "ro.kernel.qemu=1（不可伪装的模拟器标志）",
                    raw = mapOf("qemu" to qemu),
                ),
            )
        }
    }

    // ---- 硬件痕迹检测 ----

    private fun checkHardwareArtifacts(): List<Finding> = buildList {
        val paths = listOf(
            "/dev/qemu_pipe" to "qemu",
            "/dev/socket/qemud" to "qemu",
            "/dev/vboxguest" to "vbox",
            "/proc/irq/9/vboxguest" to "vbox",
            "/data/bluestacks.prop" to "bluestacks",
            "/xbin/bstk" to "bluestacks",
        )
        for ((path, name) in paths) {
            if (File(path).exists()) {
                add(
                    Finding(
                        ruleId = "emulator.hw.$name",
                        collector = id,
                        confidence = Confidence.A, // 硬件设备节点不可软件伪造
                        category = Finding.Category.EMULATOR,
                        framework = name,
                        detail = "模拟器硬件痕迹: $path",
                        raw = mapOf("path" to path),
                    ),
                )
            }
        }
    }

    // ---- CPU 架构交叉验证 ----

    private fun checkCpuArchitecture(input: ScanInput): List<Finding> {
        val declaredAbi = Build.SUPPORTED_ABIS.firstOrNull() ?: return emptyList()
        val cpuInfo = runCatching { File("/proc/cpuinfo").readText() }.getOrDefault("")

        val isX86 = cpuInfo.contains("x86", true) || cpuInfo.contains("Intel", true) || cpuInfo.contains("AMD", true)
        val isArm = cpuInfo.contains("ARM", true) || cpuInfo.contains("Cortex", true)

        return if (isX86 && declaredAbi.startsWith("arm")) {
            // A 级：声明 ARM 但实际 x86 = 架构不一致 = 模拟器
            listOf(
                Finding(
                    ruleId = "emulator.cpu_mismatch",
                    collector = id,
                    confidence = Confidence.A,
                    category = Finding.Category.EMULATOR,
                    framework = null,
                    detail = "CPU 架构不一致: Build.CPU_ABI=$declaredAbi 但 /proc/cpuinfo 显示 x86",
                    raw = mapOf("declaredAbi" to declaredAbi, "cpuX86" to "true"),
                ),
            )
        } else if (isX86 && declaredAbi.startsWith("x86")) {
            // CPU_ABI 本来就声明 x86 → 合法 x86 设备（Chromebook 等），不产出
            emptyList()
        } else {
            emptyList()
        }
    }

    // ---- 传感器检测（C 级，需共振）+ 传感器节律（恒定值 = 虚拟传感器物理特征） ----

    private fun checkSensors(): List<Finding> = buildList {
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return@buildList
        val hasAccelerometer = sm.getDefaultSensor(android.hardware.Sensor.TYPE_ACCELEROMETER) != null
        val hasGyroscope = sm.getDefaultSensor(android.hardware.Sensor.TYPE_GYROSCOPE) != null

        if (!hasAccelerometer && !hasGyroscope) {
            // 传感器全缺失 → C 级（低端设备合法缺失，需与其他维度共振）
            add(
                Finding(
                    ruleId = "emulator.sensors_absent",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.EMULATOR,
                    framework = null,
                    detail = "加速度计和陀螺仪均缺失（低端设备合法；需与其他模拟器信号共振）",
                    raw = mapOf("accel" to "absent", "gyro" to "absent"),
                ),
            )
        } else {
            // 节律检测：真实 MEMS 有热噪声，长时间完全恒定 = 虚拟传感器（云手机/部分模拟器）
            addAll(checkSensorRhythm(sm))
        }

        // 基带检测（C 级）
        val hasTelephony = context.packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
        if (!hasTelephony) {
            add(
                Finding(
                    ruleId = "emulator.no_telephony",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.EMULATOR,
                    framework = null,
                    detail = "无电话硬件（WiFi-only 平板合法；需共振）",
                    raw = mapOf("telephony" to "absent"),
                ),
            )
        }
    }

    /**
     * 传感器节律（恒定值检测）：真实加速度计静止时仍有 LSB 级热噪声抖动；
     * 足量样本内逐字节完全恒定 = 物理不可能 → 虚拟传感器（B 级）。
     * 判定门槛保守：≥16 样本 + 跨度 ≥100ms 全等才产出，规避低端量化噪声极端情形。
     * 采样窗口 ~150ms，不主导扫描时延。
     */
    private fun checkSensorRhythm(sm: SensorManager): List<Finding> {
        val accel = sm.getDefaultSensor(android.hardware.Sensor.TYPE_ACCELEROMETER) ?: return emptyList()
        val samples = java.util.concurrent.ConcurrentLinkedQueue<FloatArray>()
        val latch = java.util.concurrent.CountDownLatch(1)
        var startTime = 0L

        // registerListener 需要带 Looper 的线程；用一次性 HandlerThread
        val thread = android.os.HandlerThread("sensor-rhythm").apply { start() }
        var collected = false
        try {
            val listener = object : android.hardware.SensorEventListener {
                override fun onSensorChanged(e: android.hardware.SensorEvent) {
                    if (startTime == 0L) startTime = android.os.SystemClock.elapsedRealtime()
                    samples.add(floatArrayOf(e.values[0], e.values[1], e.values[2]))
                    // 跨度 >120ms 且样本够即收工
                    if (samples.size >= 24 ||
                        (samples.size >= 16 && android.os.SystemClock.elapsedRealtime() - startTime >= 120)
                    ) {
                        collected = true
                        latch.countDown()
                    }
                }

                override fun onAccuracyChanged(s: android.hardware.Sensor?, a: Int) {}
            }
            val handler = android.os.Handler(thread.looper)
            val registered = runCatching {
                sm.registerListener(listener, accel, android.hardware.SensorManager.SENSOR_DELAY_FASTEST, handler)
            }.isSuccess
            if (!registered) return emptyList()

            latch.await(300, java.util.concurrent.TimeUnit.MILLISECONDS)
            runCatching { sm.unregisterListener(listener) }

            if (!collected || samples.size < 16 || startTime == 0L) return emptyList()
            val spanMs = android.os.SystemClock.elapsedRealtime() - startTime
            if (spanMs < 100) return emptyList()

            val first = samples.first()
            val allConstant = samples.all { it[0] == first[0] && it[1] == first[1] && it[2] == first[2] }
            return if (allConstant) {
                listOf(
                    Finding(
                        ruleId = "emulator.sensor_constant",
                        collector = id,
                        confidence = Confidence.B,
                        category = Finding.Category.EMULATOR,
                        framework = null,
                        detail = "加速度计 ${samples.size} 样本/${spanMs}ms 内逐值完全恒定——真实 MEMS 热噪声下物理不可能（虚拟传感器：云手机/模拟器特征）",
                        raw = mapOf(
                            "samples" to samples.size.toString(),
                            "spanMs" to spanMs.toString(),
                            "value" to "${first[0]},${first[1]},${first[2]}",
                        ),
                    ),
                )
            } else emptyList()
        } finally {
            thread.quitSafely()
        }
    }

    // ---- 容器检测（排除 Work Profile） ----

    private fun checkContainer(): List<Finding> = buildList {
        // 仅在主用户（userId=0）下检测；user≥10 = Work Profile / 副用户，不产出
        val userId = android.os.Process.myUserHandle().hashCode()
        if (userId != 0) return@buildList

        val expectedPath = "/data/data/${context.packageName}"
        val actualPath = context.filesDir?.parentFile?.absolutePath ?: return@buildList

        if (actualPath != expectedPath && !actualPath.contains(context.packageName)) {
            add(
                Finding(
                    ruleId = "virtual.container.path",
                    collector = id,
                    confidence = Confidence.B,
                    category = Finding.Category.VIRTUAL_ENV,
                    framework = null,
                    detail = "数据目录路径异常: 期望 $expectedPath 实际 $actualPath（容器特征）",
                    raw = mapOf("expected" to expectedPath.hashCode().toString(), "actual" to actualPath.hashCode().toString()),
                ),
            )
        }
    }

    // ---- G2: GL 渲染器指纹（calibration #6） ----
    // 模拟器特有的 GL_RENDERER/GL_VENDOR 字符串
    // SwiftShader → C 级（Android Go 低端设备合法使用）
    // Translator/VBox/Bluestacks/ttVM → B 级（仅模拟器出现）

    private data class GlInfo(val renderer: String?, val vendor: String?)

    private fun queryGlInfo(): GlInfo = runCatching {
        val eglDisplay = android.opengl.EGL14.eglGetDisplay(android.opengl.EGL14.EGL_DEFAULT_DISPLAY)
        if (eglDisplay == android.opengl.EGL14.EGL_NO_DISPLAY) return@runCatching GlInfo(null, null)
        val ver = IntArray(2)
        if (!android.opengl.EGL14.eglInitialize(eglDisplay, ver, 0, ver, 1)) return@runCatching GlInfo(null, null)

        val attribs = intArrayOf(android.opengl.EGL14.EGL_RED_SIZE, 8, android.opengl.EGL14.EGL_GREEN_SIZE, 8, android.opengl.EGL14.EGL_BLUE_SIZE, 8, android.opengl.EGL14.EGL_SURFACE_TYPE, android.opengl.EGL14.EGL_PBUFFER_BIT, android.opengl.EGL14.EGL_NONE)
        var numConfigs = IntArray(1)
        val configs = arrayOfNulls<android.opengl.EGLConfig>(1)
        if (!android.opengl.EGL14.eglChooseConfig(eglDisplay, attribs, 0, configs, 0, 1, numConfigs, 0) || numConfigs[0] == 0) {
            android.opengl.EGL14.eglTerminate(eglDisplay)
            return@runCatching GlInfo(null, null)
        }

        val pbufferAttribs = intArrayOf(android.opengl.EGL14.EGL_WIDTH, 1, android.opengl.EGL14.EGL_HEIGHT, 1, android.opengl.EGL14.EGL_NONE)
        val surface = android.opengl.EGL14.eglCreatePbufferSurface(eglDisplay, configs[0], pbufferAttribs, 0)
        val ctxAttribs = intArrayOf(android.opengl.EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, android.opengl.EGL14.EGL_NONE)
        val context = android.opengl.EGL14.eglCreateContext(eglDisplay, configs[0], android.opengl.EGL14.EGL_NO_CONTEXT, ctxAttribs, 0)

        android.opengl.EGL14.eglMakeCurrent(eglDisplay, surface, surface, context)
        val renderer = android.opengl.GLES20.glGetString(android.opengl.GLES20.GL_RENDERER)
        val vendor = android.opengl.GLES20.glGetString(android.opengl.GLES20.GL_VENDOR)

        android.opengl.EGL14.eglMakeCurrent(eglDisplay, android.opengl.EGL14.EGL_NO_SURFACE, android.opengl.EGL14.EGL_NO_SURFACE, android.opengl.EGL14.EGL_NO_CONTEXT)
        android.opengl.EGL14.eglDestroySurface(eglDisplay, surface)
        android.opengl.EGL14.eglDestroyContext(eglDisplay, context)
        android.opengl.EGL14.eglTerminate(eglDisplay)
        GlInfo(renderer, vendor)
    }.getOrDefault(GlInfo(null, null))

    private fun checkGlRenderer(): List<Finding> = buildList {
        val gl = queryGlInfo() ?: return@buildList
        val renderer = gl.renderer ?: return@buildList

        // B 级：仅模拟器出现的字符串
        val emulatorGlPatterns = mapOf(
            "Translator" to "emulator_translator",
            "Bluestacks" to "bluestacks",
            "ttVM" to "tencent_gameloop",
            "VBox" to "vbox",
            "Android Emulator" to "avd",
        )
        for ((pattern, name) in emulatorGlPatterns) {
            if (renderer.contains(pattern, true)) {
                add(
                    Finding(
                        ruleId = "emulator.gl.$name",
                        collector = id,
                        confidence = Confidence.B,
                        category = Finding.Category.EMULATOR,
                        framework = name,
                        detail = "GL 渲染器含模拟器特征: $pattern",
                        raw = mapOf("rendererHash" to renderer.hashCode().toString()),
                    ),
                )
            }
        }

        // C 级：SwiftShader（低端设备合法，calibration #6）
        if (renderer.contains("SwiftShader", true)) {
            add(
                Finding(
                    ruleId = "emulator.gl.swiftshader",
                    collector = id,
                    confidence = Confidence.C,
                    category = Finding.Category.EMULATOR,
                    framework = "swiftshader",
                    detail = "GL 渲染器为 SwiftShader 软件渲染（低端设备合法；需共振）",
                    raw = mapOf("rendererHash" to renderer.hashCode().toString()),
                ),
            )
        }
    }

}
