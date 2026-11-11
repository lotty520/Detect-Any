package com.detectany.app

import android.content.Context
import com.detectany.collectors.appfp.AppFingerprintCollector
import com.detectany.collectors.behavior.BehaviorCollector
import com.detectany.collectors.codeintegrity.CodeIntegrityCollector
import com.detectany.collectors.endpoints.EndpointCollector
import com.detectany.collectors.fsprobe.MountCollector
import com.detectany.collectors.fsprobe.PathProbeCollector
import com.detectany.collectors.memmap.MemoryMapCollector
import com.detectany.collectors.props.PropertyCollector
import com.detectany.core.engine.DetectionEngine
import com.detectany.core.model.Collector
import com.detectany.core.model.ScanInput
import com.detectany.core.model.ScanTier
import com.detectany.core.rules.BundledRuleSet
import com.detectany.core.rules.RulesEngine
import com.detectany.data.signature.BundledSignatureDb
import com.detectany.data.signature.SignatureStore
import com.detectany.selfguard.SelfGuardService

/**
 * APP 装配层：特征数据驱动装配全部采集器（specs/signal-collection：新框架只改数据）。
 */
class ScanOrchestrator(context: Context) {

    private val appContext = context.applicationContext
    private val signatureStore = SignatureStore() // 内置基线；更新通道装配后注入 verifier
    // 自保护：release 走 native XOR 分散常量（发布装配替换真值）；
    // debug 构建占位常量必然不匹配 → 以当前构建实测值为预期（机制由 SelfGuardSmokeTest 专项覆盖）
    private val selfGuard: SelfGuardService =
        if (BuildConfig.DEBUG) {
            SelfGuardService(
                signatureSha256 = { runCatching { SelfGuardService.computeSignatureDigest(appContext) }.getOrNull() },
                dexCrc = { runCatching { SelfGuardService.computeDexCrc(appContext) }.getOrNull() },
                expectedSignature = { runCatching { SelfGuardService.computeSignatureDigest(appContext) }.getOrNull() ?: ByteArray(32) },
                expectedDexCrc = { runCatching { SelfGuardService.computeDexCrc(appContext) }.getOrNull() ?: -1L },
            )
        } else {
            SelfGuardService.fromContext(appContext)
        }

    private val entries get() = BundledSignatureDb.toEntries(signatureStore.current())

    /** P2-1（2026-11-11）：C13 硬件证明采集器（L3 专用）。
     *  锚点：真机双根未装配前 AttestationVerifier 空锚 → Rejected 降级路径（不误报，
     *  AttestationDeviceSmokeTest 契约）；CRL 离线快照兜底；first_api_level 走 PropJni。 */
    private val attestationCollector = com.detectany.feature.attestation.AttestationCollector(
        service = com.detectany.feature.attestation.AttestationService(
            verifier = com.detectany.feature.attestation.AttestationVerifier(emptyList()),
            crl = com.detectany.feature.attestation.CrlStore(fetcher = { error("online channel pending P2-3") }),
            firstApiLevel = {
                runCatching {
                    com.detectany.core.nativeplatform.PropJni.propGet("ro.product.first_api_level")?.toIntOrNull()
                }.getOrNull()
            },
            ownPackageName = appContext.packageName,
            crossInput = com.detectany.feature.attestation.AttestationVerifier.CrossInput(claimedModel = android.os.Build.MODEL),
        ),
    )

    @Volatile
    private var engine: DetectionEngine = DetectionEngine(
        collectors = buildCollectors(),
        rules = RulesEngine(BundledRuleSet.ruleSet),
        attestationCollector = attestationCollector,
    )

    /** 特征文件导入（specs：装载即生效——导入后原位重建引擎与采集器）。 */
    fun importSignatureUpdate(jsonText: String): String {
        val r = com.detectany.feature.report.SignatureImport(signatureStore).import(jsonText)
        if (r is com.detectany.feature.report.SignatureImport.Result.Applied) {
            engine = DetectionEngine(collectors = buildCollectors(), rules = RulesEngine(BundledRuleSet.ruleSet), attestationCollector = attestationCollector)
            return "Signatures updated to v${r.version} (effective immediately)"
        }
        return "Import rejected: ${(r as com.detectany.feature.report.SignatureImport.Result.Rejected).reason}"
    }

    private fun buildCollectors(): List<Collector> = listOf(
        PathProbeCollector(paths = entries.paths),
        MountCollector(fsEntries = entries.filesystems, baselineLookup = { model ->
                entries.deviceBaselines.firstOrNull { it.model == model }
            }),
        PropertyCollector(signatureEntries = entries.properties),
        EndpointCollector(entries = entries.sockets),
        AppFingerprintCollector.fromContext(appContext, entries.apps),
        MemoryMapCollector(),
        CodeIntegrityCollector(ownLib = { CodeIntegrityCollector.locateOwnLib(appContext) }),
        BehaviorCollector(BundledSignatureDb.toSupercallSpecs(signatureStore.current())),
        com.detectany.collectors.instrumentprobe.InstrumentProbeCollector(),
        com.detectany.collectors.virtualenv.VirtualEnvCollector(appContext),
        com.detectany.collectors.behaviorcheck.BehaviorCheckCollector(appContext),
        com.detectany.collectors.screenshare.ScreenShareCollector(appContext),
    )

    /** 诊断暴露：debug 构建应使用运行时预期而非 native 占位常量。 */
    val selfGuardUsesNativeExpected: Boolean get() = !BuildConfig.DEBUG

    fun scan(tier: ScanTier): DetectionEngine.ScanReport {
        val input = ScanInput(
            tier = tier,
            apiLevel = android.os.Build.VERSION.SDK_INT,
            targetSdk = appContext.applicationInfo.targetSdkVersion,
            kernelRelease = System.getProperty("os.version"),
            abi = android.os.Build.SUPPORTED_ABIS.firstOrNull(),
        )
        // 自保护 Finding 并入整体评分（任务 6.3）
        return engine.scan(input, tier, extraFindings = selfGuard.inspect())
    }
}
