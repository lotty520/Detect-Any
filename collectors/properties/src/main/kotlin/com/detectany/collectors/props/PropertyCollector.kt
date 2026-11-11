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
    private val signatureEntries: List<SignatureEntries.PropertyEntry> = defaultPropertyEntries(),
) : Collector {

    override val id: CollectorId = CollectorId.C3_PROPERTY

    /** 设备侧直读通道（host 测试注入 stub，不触达此路径）。 */
    private fun nativePropGet(key: String): String? =
        runCatching { com.detectany.core.nativeplatform.PropJni.propGet(key) }.getOrNull()

    /** /dev/__properties__/ 下文件观测（空洞扫描输入）。 */
    data class PropertyAreaFile(val name: String, val size: Long, val readable: Boolean, val ownerUid: Int?)

    override fun collect(input: ScanInput): CollectorResult = try {
        // L1 快路径（2026-11-10 时延修复）：免 800+ 全量枚举与属性区扫描，
        // 仅直读关键键（特征库 keyPrefix 的精确键 + 成对属性两侧）——P8 实测
        // L1 19-20ms 主因即全量枚举回调。L2/L3 维持全量语义。
        val map = if (input.tier == com.detectany.core.model.ScanTier.L1) {
            l1DirectReadMap()
        } else {
            props()
        }
        val areaFindings = if (input.tier == com.detectany.core.model.ScanTier.L1) {
            emptyList()
        } else {
            PropertyAnalyzer.analyzeArea(areaScanner())
        }
        val findings = PropertyAnalyzer.analyze(map, signatureEntries, directRead = ::nativePropGet) + areaFindings
        CollectorResult(
            collector = id,
            status = CollectorResult.Status.OK,
            findings = findings,
            meta = mapOf("count" to map.size.toString()),
        )
    } catch (e: Throwable) {
        CollectorResult(collector = id, status = CollectorResult.Status.BLOCKED, meta = mapOf("error" to (e.message ?: e.javaClass.simpleName)))
    }

    /** L1 直读键集：特征条目精确键 + 成对属性两侧 + verified boot 键。 */
    private fun l1DirectReadMap(): Map<String, String> = buildMap {
        val directKeys = mutableSetOf("ro.boot.verifiedbootstate")
        signatureEntries.forEach { e ->
            if (!e.keyPrefix.startsWith("init.svc.")) directKeys.add(e.keyPrefix)
        }
        PropertyAnalyzer.PIF_PAIRS.forEach { (_, main, mirror) ->
            directKeys.add(main); directKeys.add(mirror)
        }
        directKeys.forEach { k -> nativePropGet(k)?.let { put(k, it) } }
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

    /** 成对属性（Build 侧 vs 镜像侧，PIF/改机伪装残差）：Triple(id, main, mirror) + 置信级 */
    // 2026-11-11 干净华为真机回归实证：全部六对在 OEM 出厂态存在合法不一致——
    // 华为 TAS-AL00（未 root/locked/green）：bootimage.build.tags=dev-keys vs 主指纹
    // release-keys、bootimage fingerprint 为 generic_a15 模板、incremental 语义不同
    // （日期串 vs 版本号）、vendor.product.* 全空。老三对当年仅在 Pixel 验证维持 B
    // 属验证面不足。按准确性原则六对全部 C 级（weight-only），PIF 定性改由
    // verified_boot_lie（A）与 vendor 交叉族承担。
    internal val PIF_PAIRS: List<Triple<String, String, String>> = listOf(
        Triple("prop.build_pair.fingerprint", "ro.build.fingerprint", "ro.bootimage.build.fingerprint"),
        Triple("prop.build_pair.incremental", "ro.build.version.incremental", "ro.vendor.build.version.incremental"),
        Triple("prop.build_pair.tags", "ro.build.tags", "ro.bootimage.build.tags"),
        Triple("prop.build_pair.model", "ro.product.model", "ro.vendor.product.model"),
        Triple("prop.build_pair.device", "ro.product.device", "ro.vendor.product.device"),
        Triple("prop.build_pair.brand", "ro.product.brand", "ro.vendor.product.brand"),
    )

    /** C 级成对（OEM 出厂合法不一致实证，华为 2026-11-11）：全部降为 weight-only。 */
    internal val PIF_PAIRS_C_GRADE = setOf(
        "prop.build_pair.model", "prop.build_pair.device", "prop.build_pair.brand",
        "prop.build_pair.fingerprint", "prop.build_pair.incremental", "prop.build_pair.tags",
    )


    /**
     * @param directRead 直读通道（__system_property_find）：ro.boot.* 不在 foreach 枚举中，
     * 需按名直读。注入式设计保持分析器主机可测（v6 曾直接内联 PropJni 导致 5 个主机
     * 单测 UnsatisfiedLinkError——2026-11-10 审计修复）。
     */
    fun analyze(
        map: Map<String, String>,
        entries: List<SignatureEntries.PropertyEntry>,
        directRead: (String) -> String? = { null },
    ): List<Finding> = buildList {
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
                            detail = "Residual property present: ${entry.keyPrefix}=$exact (root-framework residue)",
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
                        detail = "Property hit ${hit.key}=${hit.value}",
                        raw = mapOf("key" to hit.key, "valueHash" to hit.value.hashCode().toString()),
                    ),
                )
            }
        }

        // PIF 系属性伪装（任务 8.1）：改 Build.* 但改不了 bootimage/vendor 侧镜像值
        // —— 成对属性不一致即基线偏离（PIF 只 hook ro.build.* 读取路径）
        for ((id, mainKey, mirrorKey) in PIF_PAIRS) {
            // 2026-11-11 华为真机审计修复：ro.bootimage.* 族不在 __system_property_foreach
            // 枚举结果中（与 ro.boot.* 同族盲区，shell 可读但 app 枚举拿不到）→
            // fingerprint/tags 两对的 bootimage 侧结构性缺失，生产从未生效。
            // mirror 侧枚举缺失时 directRead 兜底。
            val main = map[mainKey] ?: directRead(mainKey)
            val mirror = map[mirrorKey] ?: directRead(mirrorKey)
            if (!main.isNullOrEmpty() && !mirror.isNullOrEmpty() && main != mirror) {
                add(
                    Finding(
                        ruleId = id,
                        collector = CollectorId.C3_PROPERTY,
                        confidence = if (id in PIF_PAIRS_C_GRADE) Confidence.C else Confidence.B,
                        category = Finding.Category.ATTESTATION_SPOOF,
                        framework = "pif",
                        detail = "Paired property mismatch: $mainKey != $mirrorKey (Build spoofing trace)",
                        raw = mapOf("mainHash" to main.hashCode().toString(), "mirrorHash" to mirror.hashCode().toString()),
                    ),
                )
            }
        }

        // verified boot 交叉：声称 green 但设备有任何 root 历史痕迹 = 矛盾
        // 用 propGet 直读（ro.boot.* 可能不在 foreach 枚举结果中）
        val vbs = directRead("ro.boot.verifiedbootstate") ?: map["ro.boot.verifiedbootstate"]
        if (vbs == "green") {
            val zygiskResidual = map.keys.any { it.startsWith("ro.zygisk.") }
            val magiskResidual = map.keys.any { it.startsWith("ro.magisk.") || it.startsWith("init.svc.magisk") }
            if (zygiskResidual || magiskResidual) {
                add(
                    Finding(
                        ruleId = "prop.verified_boot_lie",
                        collector = CollectorId.C3_PROPERTY,
                        confidence = Confidence.A, // 物理矛盾：verified boot green + root 残留 = 属性被伪造
                        category = Finding.Category.ANTI_DETECT_PRESENT,
                        framework = null,
                        detail = "Verified boot claims green but root-framework residual properties exist — properties forged (deep-hiding signature)",
                        raw = mapOf("vbs" to vbs.hashCode().toString()),
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
                    detail = "ro.debuggable=1 (engineering/debug build signature)",
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
                    detail = "ro.build.tags contains test-keys (self-built ROM signature)",
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
                    detail = "Property-area file anomaly: ${f.name} readable=${f.readable} size=${f.size} (resetprop trace pattern)",
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
