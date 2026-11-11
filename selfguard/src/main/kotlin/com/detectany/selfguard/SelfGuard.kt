package com.detectany.selfguard

import android.content.Context
import android.content.pm.PackageManager
import com.detectany.core.model.CollectorId
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * 自保护服务（任务 6.1-6.3）：签名摘要 + DEX CRC + 反调试 → Finding 列表（引擎聚合）。
 * 全程静默：不崩溃、不弹窗、可延迟响应（specs/self-protection）。
 */
class SelfGuardService(
    private val signatureSha256: () -> ByteArray?,
    private val dexCrc: () -> Long?,
    private val tracerPid: () -> Long = { readTracerPid() },
    private val debuggerProbe: () -> Int = { GuardJni.debuggerProbe() },
    /** 预期值默认来自 native XOR 分散常量；主机测试注入桩 */
    private val expectedSignature: () -> ByteArray = { GuardJni.assembleExpectedSignature() },
    private val expectedDexCrc: () -> Long = { GuardJni.assembleExpectedDexCrc() },
    /** 生产走 native 常数时间比较；主机测试注入 contentEquals */
    private val bytesEqual: (ByteArray, ByteArray) -> Boolean = { a, b -> GuardJni.constantTimeEquals(a, b) },
    /** 反调试探测周期（后台定时 fork；0 = 每次 inspect 同步 fork——主机测试/旧行为兼容） */
    private val probeIntervalMs: Long = 30_000L,
    /** P3 占位门覆盖：null=native 探测（设备）；false=跳过占位门（host 测试注入桩时） */
    private val signaturePlaceholderOverride: Boolean? = null,
) {
    @Volatile internal var lastDebuggerProbe: Int = 0

    @Volatile internal var lastProbeAtMs: Long = 0L

    private val probeScheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "DetectAny-GuardProbe").apply { isDaemon = true }
    }

    init {
        if (probeIntervalMs > 0) {
            // 2026-11-10 L1 时延修复：fork 子进程在现代大进程上一次 80-118ms（P8 实测），
            // 每次 inspect 同步 fork 拖垮快扫。改为后台定时探测 + inspect 读缓存快照；
            // 缓存超过 3 周期未刷新（探测线程死亡等）则视为无信号（FN 方向，安全）。
            probeScheduler.scheduleAtFixedRate({
                runCatching {
                    lastDebuggerProbe = debuggerProbe()
                    lastProbeAtMs = System.currentTimeMillis()
                }
            }, 0L, probeIntervalMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        }
    }


    /** 巡检（幂等、无副作用、永不抛出）。 */
    fun inspect(): List<Finding> = buildList {
        // 6.1 签名摘要（repackaged 强证据：重打包必换签名）
        // P3（2026-11-11）：native 常量仍是发布占位时跳过（release 未装配真值时
        // 用占位比对必然误报 repackaged(A)——占位检测属发布装配工序，见 RUNBOOK）
        val placeholderSig = signaturePlaceholderOverride
            ?: runCatching { GuardJni.signatureIsPlaceholder() }.getOrDefault(true)
        val actualSig = if (placeholderSig) null else signatureSha256()
        if (actualSig != null) {
            val expected = expectedSignature()
            if (!bytesEqual(actualSig, expected)) {
                add(
                    Finding(
                        ruleId = "selfguard.repackaged_signature",
                        collector = CollectorId.C7_CODE_INTEGRITY,
                        confidence = Confidence.A,
                        category = Finding.Category.REPACKAGED,
                        framework = null,
                        detail = "APK signature digest mismatch (repackaged)",
                        raw = emptyMap(),
                    ),
                )
            }
        }

        // 6.1 DEX CRC（关键代码被改的快信号）——同占位门
        val crcPlaceholder = signaturePlaceholderOverride
            ?: runCatching { GuardJni.crcIsPlaceholder() }.getOrDefault(true)
        val actualCrc = if (crcPlaceholder) null else dexCrc()
        if (actualCrc != null) {
            val expected = expectedDexCrc()
            if (actualCrc != expected) {
                add(
                    Finding(
                        ruleId = "selfguard.dex_crc",
                        collector = CollectorId.C7_CODE_INTEGRITY,
                        confidence = Confidence.B,
                        category = Finding.Category.REPACKAGED,
                        framework = null,
                        detail = "classes.dex CRC32 mismatch (code tampering/injection)",
                        raw = emptyMap(),
                    ),
                )
            }
        }

        // 6.2 TracerPid 轮询
        val tp = tracerPid()
        if (tp > 0) {
            add(
                Finding(
                    ruleId = "selfguard.tracer_pid",
                    collector = CollectorId.C7_CODE_INTEGRITY,
                    confidence = Confidence.B,
                    category = Finding.Category.HOOK,
                    framework = null,
                    detail = "TracerPid=$tp (process is being traced)",
                    raw = mapOf("tracerPid" to tp.toString()),
                ),
            )
        }

        // 6.2 子进程 ATTACH 反查（调试器独占 ptrace → EPERM）
        // 后台定时模式读缓存快照（新鲜度 3 周期内）；同步模式（probeIntervalMs=0）保留旧行为
        val probe = if (probeIntervalMs > 0) {
            if (System.currentTimeMillis() - lastProbeAtMs <= probeIntervalMs * 3) lastDebuggerProbe else 0
        } else {
            debuggerProbe()
        }
        if (probe == 1) {
            add(
                Finding(
                    ruleId = "selfguard.debugger_attached",
                    collector = CollectorId.C7_CODE_INTEGRITY,
                    confidence = Confidence.B,
                    category = Finding.Category.HOOK,
                    framework = null,
                    detail = "Child PTRACE_ATTACH to parent returned EPERM (debugger attached)",
                    raw = emptyMap(),
                ),
            )
        }
    }

    companion object {
        fun fromContext(context: Context) = SelfGuardService(
            signatureSha256 = { runCatching { computeSignatureDigest(context) }.getOrNull() },
            dexCrc = { runCatching { computeDexCrc(context) }.getOrNull() },
        )

        fun computeSignatureDigest(context: Context): ByteArray {
            val pm = context.packageManager
            val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            val cert = info.signatures?.firstOrNull() ?: error("no signature")
            return MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
        }

        fun computeDexCrc(context: Context): Long {
            val apk = context.applicationInfo.sourceDir ?: error("no sourceDir")
            ZipFile(apk).use { zip ->
                val entry = zip.getEntry("classes.dex") ?: error("no classes.dex")
                return entry.crc
            }
        }

        fun readTracerPid(): Long {
            val status = runCatching { java.io.File("/proc/self/status").readText() }.getOrNull() ?: return -1
            return status.lineSequence()
                .firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(':')?.trim()?.toLongOrNull() ?: -1
        }
    }
}

/**
 * 静默延迟响应（任务 6.3）：集成面 API——spec 要求「静默记分并可延迟响应」，
 * 静默记分由 findings 并入评分满足（生产无崩溃无弹窗）；延迟回调能力在此提供，
 * 响应动作（如何处置）由集成方接线（app 自身不消费属预期，2026-11-10 审计注记）。
 * MUST NOT 即时崩溃/弹窗；检出后延迟回调（默认 5s），
 * 攻击者无法从即时反馈定位检测点。可在任意作用域调用（coroutine）。
 */
class SilentResponsePolicy(
    private val delayMs: Long = 5_000,
    private val onDetected: suspend (List<Finding>) -> Unit,
) {
    suspend fun handle(findings: List<Finding>) {
        // 静默：任何异常吞掉，绝不上抛（不崩溃承诺）
        runCatching {
            if (findings.isNotEmpty()) {
                kotlinx.coroutines.delay(delayMs)
                onDetected(findings)
            }
        }
    }
}
