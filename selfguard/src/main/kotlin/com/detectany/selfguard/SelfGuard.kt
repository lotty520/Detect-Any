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
) {
    /** 巡检（幂等、无副作用、永不抛出）。 */
    fun inspect(): List<Finding> = buildList {
        // 6.1 签名摘要（repackaged 强证据：重打包必换签名）
        val actualSig = signatureSha256()
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
                        detail = "APK 签名摘要与预期不符（重打包）",
                        raw = emptyMap(),
                    ),
                )
            }
        }

        // 6.1 DEX CRC（关键代码被改的快信号）
        val actualCrc = dexCrc()
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
                        detail = "classes.dex CRC32 与预期不符（代码篡改/注入）",
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
                    detail = "TracerPid=$tp（进程被跟踪）",
                    raw = mapOf("tracerPid" to tp.toString()),
                ),
            )
        }

        // 6.2 子进程 ATTACH 反查（调试器独占 ptrace → EPERM）
        val probe = debuggerProbe()
        if (probe == 1) {
            add(
                Finding(
                    ruleId = "selfguard.debugger_attached",
                    collector = CollectorId.C7_CODE_INTEGRITY,
                    confidence = Confidence.B,
                    category = Finding.Category.HOOK,
                    framework = null,
                    detail = "子进程 PTRACE_ATTACH 父进程返回 EPERM（调试器已附加）",
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
 * 静默延迟响应（任务 6.3）：MUST NOT 即时崩溃/弹窗；检出后延迟回调（默认 5s），
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
