package com.detectany.collectors.props

import com.detectany.core.model.Collector
import com.detectany.core.model.CollectorId
import com.detectany.core.model.CollectorResult
import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.ScanInput
import com.detectany.core.model.SignatureEntries
import com.detectany.core.nativeplatform.SystemPropertiesBridge

/**
 * C3 属性快照（任务 3.3）：全量 KV + 特征前缀匹配 + 属性区空洞扫描。
 */
class PropertyCollector(
    private val props: () -> Map<String, String> = { SystemPropertiesBridge().list() },
    private val areaScanner: () -> List<PropertyAreaFile> = { scanPropertyArea() },
    private val entries: List<SignatureEntries.PropertyEntry> = defaultPropertyEntries(),
) : Collector {

    override val id: CollectorId = CollectorId.C3_PROPERTY

    /** /dev/__properties__/ 下文件观测（空洞扫描输入）。 */
    data class PropertyAreaFile(val name: String, val size: Long, val readable: Boolean, val ownerUid: Int?)

    override fun collect(input: ScanInput): CollectorResult = try {
        val map = props()
        val findings = PropertyAnalyzer.analyze(map, entries) + PropertyAnalyzer.analyzeArea(areaScanner())
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf("count" to map.size.toString()),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    companion object {
        /** 属性区（resetprop 痕迹：春秋「Property Modified」向量）。ownerUid 预留（Phase 2 经 native 填充）。 */
        internal fun scanPropertyArea(): List<PropertyAreaFile> {
            val dir = java.io.File("/dev/__properties__")
            val files = dir.listFiles() ?: return emptyList()
            return files.map { f ->
                PropertyAreaFile(name = f.name, size = f.length(), readable = f.canRead(), ownerUid = null)
            }
        }
    }
}

/** 属性分析（纯 Kotlin，主机单测）。 */
object PropertyAnalyzer {

    /** Build 侧 vs 镜像侧的成对属性（PIF 伪装的物理残差） */
    internal val PIF_PAIRS = listOf(
        Triple("prop.build_pair.fingerprint", "ro.build.fingerprint", "ro.bootimage.build.fingerprint"),
        Triple("prop.build_pair.incremental", "ro.build.version.incremental", "ro.vendor.build.version.incremental"),
        Triple("prop.build_pair.tags", "ro.build.tags", "ro.bootimage.build.tags"),
    )


    fun analyze(map: Map<String, String>, entries: List<SignatureEntries.PropertyEntry>): List<Finding> = buildList {
        for (entry in entries) {
            // 前缀匹配（init.svc.magisk 命中 init.svc.magiskd / init.svc.magisk_p92d 等整族）+ 值条件
            val valueCond = entry.valueContains
            // valueContains=null → 属性存在即命中（如 ro.zygisk.denylists 残留检测）
            val hit = map.entries.firstOrNull {
                it.key.startsWith(entry.keyPrefix) &&
                    (valueCond == null || it.value.contains(valueCond))
            }
            // 对于 ro. 前缀的残留检测：值无关，存在即信号
            if (hit == null && entry.keyPrefix.startsWith("ro.") && valueCond == null) {
                // 精确匹配（非前缀）的 ro. 属性，存在即命中
                val exact = map[entry.keyPrefix]
                if (exact != null) {
                    add(
                        Finding(
                            ruleId = entry.id,
                            collector = CollectorId.C3_PROPERTY,
                            confidence = entry.confidence,
                            category = entry.category,
                            framework = entry.framework,
                            detail = "残留属性存在: ${entry.keyPrefix}=$exact（root 框架残留痕迹）",
                            raw = mapOf("key" to entry.keyPrefix.hashCode().toString()),
                        ),
                    )
                    continue
                }
            }
            if (hit != null) {
                add(
                    Finding(
                        ruleId = entry.id,
                        collector = CollectorId.C3_PROPERTY,
                        confidence = entry.confidence,
                        category = entry.category,
                        framework = entry.framework,
                        detail = "属性命中 ${hit.key}=${hit.value}",
                        raw = mapOf("key" to hit.key, "valueHash" to hit.value.hashCode().toString()),
                    ),
                )
            }
        }

        // PIF 系属性伪装（任务 8.1）：改 Build.* 但改不了 bootimage/vendor 侧镜像值
        // —— 成对属性不一致即基线偏离（PIF 只 hook ro.build.* 读取路径）
        for ((id, mainKey, mirrorKey) in PIF_PAIRS) {
            val main = map[mainKey]
            val mirror = map[mirrorKey]
            if (!main.isNullOrEmpty() && !mirror.isNullOrEmpty() && main != mirror) {
                add(
                    Finding(
                        ruleId = id,
                        collector = CollectorId.C3_PROPERTY,
                        confidence = Confidence.B,
                        category = Finding.Category.ATTESTATION_SPOOF,
                        framework = "pif",
                        detail = "成对属性不一致: $mainKey != $mirrorKey（Build 伪装痕迹）",
                        raw = mapOf("mainHash" to main.hashCode().toString(), "mirrorHash" to mirror.hashCode().toString()),
                    ),
                )
            }
        }

        // 通用强信号：ro.debuggable / test-keys
        if (map["ro.debuggable"] == "1") {
            add(
                Finding(
                    ruleId = "prop.debuggable",
                    collector = CollectorId.C3_PROPERTY,
                    confidence = Confidence.C,
                    category = Finding.Category.ROOT_USERSPACE,
                    framework = null,
                    detail = "ro.debuggable=1（工程构建/调试 ROM 特征）",
                    raw = mapOf("key" to "ro.debuggable", "valueHash" to "1".hashCode().toString()),
                ),
            )
        }
        if ((map["ro.build.tags"] ?: "").contains("test-keys")) {
            add(
                Finding(
                    ruleId = "prop.test_keys",
                    collector = CollectorId.C3_PROPERTY,
                    confidence = Confidence.C,
                    category = Finding.Category.ROOT_USERSPACE,
                    framework = null,
                    detail = "ro.build.tags 含 test-keys（自编构建特征）",
                    raw = mapOf("key" to "ro.build.tags", "valueHash" to (map["ro.build.tags"] ?: "").hashCode().toString()),
                ),
            )
        }
    }

    /**
     * 属性区空洞（resetprop 改值后元数据留痕）：
     * - 文件存在但不可读（正常属性文件 0444 全局可读）
     * - size 为 0 的空洞文件
     */
    fun analyzeArea(files: List<PropertyCollector.PropertyAreaFile>): List<Finding> = buildList {
        files.filter { !it.readable || it.size == 0L }.forEach { f ->
            add(
                Finding(
                    ruleId = "prop.area_anomaly.${f.name.hashCode().toUInt()}",
                    collector = CollectorId.C3_PROPERTY,
                    confidence = Confidence.B,
                    category = Finding.Category.ANTI_DETECT_PRESENT,
                    framework = null,
                    detail = "属性区文件异常: ${f.name} readable=${f.readable} size=${f.size}（resetprop 痕迹形态）",
                    raw = mapOf("name" to f.name, "readable" to f.readable.toString(), "size" to f.size.toString()),
                ),
            )
        }
    }
}

internal fun defaultPropertyEntries(): List<SignatureEntries.PropertyEntry> = listOf(
    // Magisk 服务属性族（DroidGuard 2026 仍在探测）
    SignatureEntries.PropertyEntry("prop.init_svc_magisk", "init.svc.magisk", "magisk", Confidence.C, Finding.Category.ROOT_USERSPACE),
    SignatureEntries.PropertyEntry("prop.magisk_version", "magisk.version", "magisk", Confidence.C, Finding.Category.ROOT_USERSPACE),
    SignatureEntries.PropertyEntry("prop.persist_magisk_hide", "persist.magisk.hide", "magisk", Confidence.C, Finding.Category.ROOT_USERSPACE),
    // Riru 遗留（值必须含 loader 名——全机型默认值 "0" 不算命中）
    SignatureEntries.PropertyEntry("prop.riru_bridge", "ro.dalvik.vm.native.bridge", null, Confidence.C, Finding.Category.HOOK, valueContains = "libriruloader"),
)
