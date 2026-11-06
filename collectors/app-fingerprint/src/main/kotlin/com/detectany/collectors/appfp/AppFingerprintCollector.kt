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
    private val apkStringProbe: (String) -> Set<String> = { emptySet() },
    private val entries: List<SignatureEntries.AppEntry> = defaultAppEntries(),
) : Collector {

    /** 单包观测：安装与否 + 证书摘要 + base.apk 路径。 */
    data class PackageHit(val installed: Boolean, val certSha256Hex: String?, val baseApkPath: String?)

    override val id: CollectorId = CollectorId.C5_APP_FINGERPRINT

    override fun collect(input: ScanInput): CollectorResult = try {
        val findings = mutableListOf<Finding>()
        for (entry in entries) {
            val hit = entry.packageNames.asSequence()
                .mapNotNull { name -> packageQuery(name)?.takeIf { it.installed }?.let { name to it } }
                .firstOrNull() ?: continue
            AppFingerprintMatcher.match(entry, hit.first, hit.second.certSha256Hex, apkStringProbe(hit.second.baseApkPath ?: ""))
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
                    val info = pm.getPackageInfo(name, PackageManager.GET_SIGNATURES)
                    val cert = info.signatures?.firstOrNull()
                    PackageHit(
                        installed = true,
                        certSha256Hex = cert?.let { sig ->
                            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
                        },
                        baseApkPath = info.applicationInfo?.sourceDir,
                    )
                }.getOrNull()
            }
            val probe: (String) -> Set<String> = { apkPath ->
                runCatching {
                    val f = java.io.File(apkPath)
                    if (!f.isFile) return@runCatching emptySet<String>()
                    val text = String(f.readBytes(), Charsets.ISO_8859_1)
                    DEFAULT_PROBE_STRINGS.filterTo(mutableSetOf()) { text.contains(it) }
                }.getOrDefault(emptySet())
            }
            return AppFingerprintCollector(query, probe, entries)
        }

        /** APK 内搜索的探针字符串超集（各框架条目从中取子集）。 */
        val DEFAULT_PROBE_STRINGS = listOf(
            "me.weishu.kernelsu", "KernelSU", "ksu_driver",
            "me.bmax.apatch", "APatch", "superkey",
            "com.topjohnwu.magisk", "libmagisk", "magiskinit",
            "lspd", "XposedBridge", "edxp",
            "zygisk", "com.rifsxd.ksunext", "sukisu",
        )
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
                    detail = "管理器包命中(证书钉住): $packageName",
                    raw = mapOf("package" to packageName, "pinned" to "true"),
                )
            }
            return null
        }
        // 内容指纹：DEX 探针字符串全命中 → B（spoofed 包名兜底路径）
        if (entry.dexStrings.isNotEmpty()) {
            if (presentStrings.containsAll(entry.dexStrings)) {
                return Finding(
                    ruleId = entry.id,
                    collector = CollectorId.C5_APP_FINGERPRINT,
                    confidence = Confidence.B,
                    category = entry.category,
                    framework = entry.framework,
                    detail = "内容指纹命中(spoofed 变体): 探针 ${entry.dexStrings.joinToString("+")} 全部存在",
                    raw = mapOf("probes" to entry.dexStrings.joinToString(",")),
                )
            }
            return null
        }
        // 无 pins 无探针 → 仅包名（弱）
        return Finding(
            ruleId = entry.id,
            collector = CollectorId.C5_APP_FINGERPRINT,
            confidence = Confidence.C,
            category = entry.category,
            framework = entry.framework,
            detail = "包名命中: $packageName",
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
