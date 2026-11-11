package com.detectany.collectors.appfp

import android.content.Context
import android.content.pm.PackageManager
import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.SignatureEntries
import java.security.MessageDigest

/**
 * C5 应用指纹（任务 3.5）：<queries> 声明式枚举 + 签名证书钉住 + DEX 内容探针。
 * spoofed 包名变体靠 dexStrings 内容指纹兜底（KSU-Next/SukiSU 官方随机化包名/类名/so 名）。
 */
class AppFingerprintCollector(
    private val packageQuery: (String) -> PackageHit? = { null },
    private val apkStringProbe: (String, List<String>) -> Set<String> = { _, _ -> emptySet() },
    private val entries: List<SignatureEntries.AppEntry> = defaultAppEntries(),
) : Collector {

    /** 单包观测：安装与否 + 证书摘要 + base.apk 路径。 */
    data class PackageHit(val installed: Boolean, val certSha256Hex: String?, val baseApkPath: String?)

    override val id: CollectorId = CollectorId.C5_APP_FINGERPRINT

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        for (entry in entries) {
            // 两步策略（时延优化 2026-11-06）：先查包名（~0ms），命中才读 APK 内容
            val hit = entry.packageNames.asSequence()
                .mapNotNull { name -> packageQuery(name)?.takeIf { it.installed }?.let { name to it } }
                .firstOrNull() ?: continue
            // 分层：pins→签名比对（快）；dexStrings→内容扫描（仅该条目探针 + 命中即停）；
            // 都无→包名 C 级（零扫描）。2026-11-10 性能修复：探针按条目下推，
            // 双 manager 场景 3.2s → 亚秒（原全框架超集扫描纯属浪费）
            val present = if (entry.certPins.isEmpty() && entry.dexStrings.isNotEmpty()) {
                apkStringProbe(hit.second.baseApkPath ?: "", entry.dexStrings)
            } else {
                emptySet()
            }
            AppFingerprintMatcher.match(entry, hit.first, hit.second.certSha256Hex, present)
                ?.let { findings.add(it) }
        }
        CollectorResult(collector = id, status = CollectorResult.Status.OK, findings = findings)
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    companion object {
        /** 生产环境工厂：PackageManager 取包 + 读 base.apk 字节做字符串探针（特征条目可注入）。 */
        fun fromContext(
            context: Context,
            entries: List<SignatureEntries.AppEntry> = defaultAppEntries(),
        ): AppFingerprintCollector {
            val pm = context.packageManager
            val query: (String) -> PackageHit? = { name ->
                runCatching {
                    // API 28+：GET_SIGNING_CERTIFICATES（签名轮替/密钥升级场景下
                    // 废弃路径可能返回旧签名）；低版本回退 GET_SIGNATURES
                    val info = if (android.os.Build.VERSION.SDK_INT >= 28) {
                        pm.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES)
                    } else {
                        @Suppress("DEPRECATION") pm.getPackageInfo(name, PackageManager.GET_SIGNATURES)
                    }
                    val cert = info.signingInfo?.apkContentsSigners?.firstOrNull()
                        ?: @Suppress("DEPRECATION") info.signatures?.firstOrNull()
                    PackageHit(
                        installed = true,
                        certSha256Hex = cert?.let { sig ->
                            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
                        },
                        baseApkPath = info.applicationInfo?.sourceDir,
                    )
                }.getOrNull()
            }
            val probe: (String, List<String>) -> Set<String> = { apkPath, probes ->
                // 流式分块扫描（64KB 块 + 跨块 overlap）：大 APK（Magisk 30MB+）不整读，
                // 内存 O(块) 且全部探针命中即停——C5 时延/内存双修（2026-11-06）；
                // 探针由调用方按条目传入（2026-11-10：早退实际生效——条目自身
                // 探针在其 APK 内真实存在，不再被无关框架探针拖完全量）
                scanApkStrings(apkPath, probes)
            }
            return AppFingerprintCollector(query, probe, entries)
        }

        /** APK 内搜索的探针字符串超集（各框架条目从中取子集）。 */
        private const val CHUNK = 64 * 1024

        /** 流式扫描 APK 字节：命中即记录，全部命中提前终止；跨块边界以 overlap 保护。 */
        internal fun scanApkStrings(apkPath: String, probes: List<String>): Set<String> = runCatching {
            val f = java.io.File(apkPath)
            if (!f.isFile || probes.isEmpty()) return@runCatching emptySet<String>()
            val maxLen = probes.maxOf { it.length }
            val found = mutableSetOf<String>()
            java.io.BufferedInputStream(java.io.FileInputStream(f), CHUNK).use { input ->
                var tail = ByteArray(0)
                val buf = ByteArray(CHUNK)
                while (found.size < probes.size) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    // window = 上块尾部 + 本块（ISO-8859-1 单字节映射，无损）
                    val window = tail + buf.copyOf(n)
                    val wtxt = String(window, Charsets.ISO_8859_1)
                    for (p in probes) {
                        if (p !in found && wtxt.contains(p)) found += p
                    }
                    tail = window.copyOfRange(maxOf(0, window.size - (maxLen - 1)), window.size)
                }
            }
            found
        }.getOrDefault(emptySet())
    }
}

/** 匹配逻辑（纯 Kotlin，主机单测覆盖 spoofed 变体）。 */
object AppFingerprintMatcher {

    fun match(
        entry: SignatureEntries.AppEntry,
        packageName: String,
        certSha256Hex: String?,
        presentStrings: Set<String>,
    ): Finding? {
        // 证书钉住优先：命中包名后证书必须匹配；不匹配 → 排除误报（同名包非官方重打包）
        if (entry.certPins.isNotEmpty()) {
            if (certSha256Hex != null && entry.certPins.any { it.equals(certSha256Hex, ignoreCase = true) }) {
                return Finding(
                    ruleId = entry.id,
                    collector = CollectorId.C5_APP_FINGERPRINT,
                    confidence = Confidence.B,
                    category = entry.category,
                    framework = entry.framework,
                    detail = "Manager package hit (cert-pinned): $packageName",
                    raw = mapOf("package" to packageName, "pinned" to "true"),
                )
            }
            return null
        }
        // 内容指纹 = 包名命中的二次验证（Luckin Coffee 教训：防同名无关 app 假阳性）。
        // 2026-11-06 语义修正：any 命中（containsAll 曾致整条漏检）。
        // 2026-11-10 准确性双向修正：内容未命中不再 return null（官方 manager 全压缩
        // 构建时整条漏检 = FN 洞），降级 C——精确域名式包名的撞名风险极低
        // （撞名者本身即仿冒），接受为 C 级 weight-only；内容命中保持 B。
        if (entry.dexStrings.isNotEmpty()) {
            if (entry.dexStrings.any { it in presentStrings }) {
                return Finding(
                    ruleId = entry.id,
                    collector = CollectorId.C5_APP_FINGERPRINT,
                    confidence = Confidence.B,
                    category = entry.category,
                    framework = entry.framework,
                    detail = "Package + content fingerprint double hit: $packageName (any probe present: ${entry.dexStrings.joinToString("+")})",
                    raw = mapOf("package" to packageName, "probes" to entry.dexStrings.joinToString(",")),
                )
            }
            return Finding(
                ruleId = entry.id,
                collector = CollectorId.C5_APP_FINGERPRINT,
                confidence = Confidence.C,
                category = entry.category,
                framework = entry.framework,
                detail = "Exact package hit but content probes missed: $packageName (fully-compressed APK or impersonating name — C-grade, not conclusive)",
                raw = mapOf("package" to packageName, "contentVerified" to "false"),
            )
        }
        // 无 pins 无探针 → 仅包名（弱）
        return Finding(
            ruleId = entry.id,
            collector = CollectorId.C5_APP_FINGERPRINT,
            confidence = Confidence.C,
            category = entry.category,
            framework = entry.framework,
            detail = "Package name hit: $packageName",
            raw = mapOf("package" to packageName),
        )
    }
}

internal fun defaultAppEntries(): List<SignatureEntries.AppEntry> = listOf(
    // Magisk v31.1 已移除 hide/repackage → 官方包名重新有效
    SignatureEntries.AppEntry(
        id = "app.magisk",
        packageNames = listOf("com.topjohnwu.magisk"),
        dexStrings = listOf("com.topjohnwu.magisk", "libmagisk"),
        framework = "magisk",
        confidence = Confidence.B,
        category = Finding.Category.ROOT_USERSPACE,
    ),
    // KSU 主线（包名可经 gradle 重命名 → 内容指纹兜底）
    SignatureEntries.AppEntry(
        id = "app.ksu",
        packageNames = listOf("me.weishu.kernelsu", "me.weishu.kernelsu.pr"),
        dexStrings = listOf("me.weishu.kernelsu", "ksu_driver"),
        framework = "ksu",
        confidence = Confidence.B,
        category = Finding.Category.ROOT_KERNEL,
    ),
    // KSU-Next（spoofed 变体：包名随机 6 字母三段 → 只能内容指纹）
    SignatureEntries.AppEntry(
        id = "app.ksunext",
        packageNames = listOf("com.rifsxd.ksunext"),
        dexStrings = listOf("com.rifsxd.ksunext", "KernelSU"),
        framework = "ksunext",
        confidence = Confidence.B,
        category = Finding.Category.ROOT_KERNEL,
    ),
    // SukiSU（spoofed 构建随机化包名/类名/so 名 → 内容指纹）
    SignatureEntries.AppEntry(
        id = "app.sukisu",
        packageNames = listOf("com.sukisu.ultra", "io.sukisu.ultra", "com.sukisu.zako"),
        dexStrings = listOf("sukisu", "KernelSU"),
        framework = "sukisu",
        confidence = Confidence.B,
        category = Finding.Category.ROOT_KERNEL,
    ),
    // APatch（hide manager 已移除，官方包名有效）
    SignatureEntries.AppEntry(
        id = "app.apatch",
        packageNames = listOf("me.bmax.apatch"),
        dexStrings = listOf("me.bmax.apatch", "superkey"),
        framework = "apatch",
        confidence = Confidence.B,
        category = Finding.Category.ROOT_KERNEL,
    ),
)
