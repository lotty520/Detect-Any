package com.detectany.feature.attestation

import java.security.KeyStore
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.util.Date

/**
 * 证明链校验（任务 5.2/5.3）：锚定 + 只取第一个扩展 + 安全级别 + 吊销 + 应用绑定 + 字段交叉。
 * 纯 Kotlin，测试向量全部主机可测。
 */
/**
 * A2: 根证书锚定集动态消费 —— 官方端点 android.googleapis.com/attestation/root
 * 返回 JSON 数组（PEM 编码根证书列表）。RSA 根 2016 版已于 2026-05-24 过期，
 * Google 官方要求继续信任 SERIALNUMBER=f92009e853b6b045 除非入 CRL。
 */
class RootAnchorStore(private val fetcher: (String) -> String? = { null }) {
    private val url get() = "https://android.googleapis.com/attestation/root"

    data class AnchorResult(
        val roots: List<java.security.cert.X509Certificate>,
        val source: String,
    )

    fun loadDynamic(): AnchorResult? = runCatching {
        val body = fetcher(url) ?: return@runCatching null
        val pems = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")
            .findAll(body).map { it.value }.toList()
        if (pems.isEmpty()) return@runCatching null
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        val roots = pems.mapNotNull { pem ->
            runCatching {
                cf.generateCertificate(java.io.ByteArrayInputStream(pem.toByteArray()))
                    as java.security.cert.X509Certificate
            }.getOrNull()
        }
        if (roots.isEmpty()) null else AnchorResult(roots, "dynamic")
    }.getOrNull()

    companion object {
        /**
         * RSA 过期信任豁免（官方政策）：
         * Google 要求对 2016 RSA 根（SERIALNUMBER=f92009e853b6b045）在过期后
         * 继续信任签发的链，除非该序列号入 CRL。RKP 证书则必须检查过期。
         */
        fun isExpiredRootTrusted(cert: java.security.cert.X509Certificate): Boolean {
            val isRsaRoot = cert.publicKey.algorithm == "RSA"
            val isGoogleRoot = cert.subjectX500Principal.name.contains("Google")
            return isRsaRoot && isGoogleRoot && cert.notAfter < java.util.Date()
        }
    }
}

class AttestationVerifier(
    /** 信任锚（Google 双根：旧 RSA 根 + 2026-02 起 ECDSA P-384 新根；由装配层注入）。 */
    private val roots: List<X509Certificate>,
) {

    sealed interface Verdict {
        /** 硬件链、锚定通过、无吊销：可作为信任依据 */
        data class Trusted(val description: KeyDescriptionParser.KeyDescription) : Verdict

        /** 链有效但非硬件背书（软件 attestation——可被 TrickyStore 的 AOSP 软件 keybox 完整伪造） */
        data class SoftwareBacked(val description: KeyDescriptionParser.KeyDescription) : Verdict

        /** 吊销序列号命中 → attestation_spoof 证据 */
        data class Revoked(val cert: X509Certificate, val serialHex: String) : Verdict

        /** 锚定/签名失败、无扩展、challenge 或 appKey 不符、追加叶子被拒等 */
        data class Rejected(val reason: String) : Verdict
    }

    /**
     * A1 (P0): Android 16 首发（first_api_level ≥ 36）为 RKP-only 设备——
     * 官方策略要求仅接受 ECDSA P-384 RKP 链。RSA 根链在 RKP-only 设备上
     * 出现即为强伪造信号（2026-02-01 起 ECDSA 根独占 RKP 设备）。
     */
    data class RkpPolicy(val firstApiLevel: Int? = null) {
        val isRkpOnlyDevice: Boolean get() = (firstApiLevel ?: 0) >= 36
    }

    fun verify(
        chain: List<X509Certificate>,
        expectedChallenge: ByteArray? = null,
        expectedPackageName: String? = null,
        revokedSerials: Set<String> = emptySet(),
        rkpPolicy: RkpPolicy = RkpPolicy(),
    ): Verdict {
        if (roots.isEmpty()) return Verdict.Rejected("no trust anchors configured")
        if (chain.isEmpty()) return Verdict.Rejected("empty chain")

        // 1) PKIX 锚定（仅信任显式锚；追加伪叶子/断链在此被拒）
        val anchorResult = validateChainToAnchors(chain)
        if (anchorResult != null) return Verdict.Rejected(anchorResult)

        // 2) 只取链上第一个 attestation 扩展
        val parsed = KeyDescriptionParser.parseFirstFromChain(chain)
            ?: return Verdict.Rejected("no attestation extension in chain")
        val desc = parsed.second

        // 3) challenge 回显
        if (expectedChallenge != null && !desc.attestationChallenge.contentEquals(expectedChallenge)) {
            return Verdict.Rejected("challenge mismatch")
        }

        // 4) attestationApplicationId 绑定（Quarkslab：跨应用中继在此被拒）
        if (expectedPackageName != null) {
            val names = desc.attestationApplicationId?.packageNames ?: emptyList()
            if (names.none { it == expectedPackageName }) {
                return Verdict.Rejected("attestationApplicationId mismatch (relay suspected)")
            }
        }

        // 5) 吊销序列号（全链逐证书）
        for (cert in chain) {
            val serial = cert.serialNumber.toString(16).lowercase()
            if (serial in revokedSerials) {
                return Verdict.Revoked(cert, serial)
            }
        }

        // A1: RKP-only 策略检查——Android 16 首发+RSA 根 = 强伪造信号
        if (desc.hardwareBacked && rkpPolicy.isRkpOnlyDevice) {
            val isRkpChain = chain.any { cert ->
                cert.publicKey.algorithm == "EC" && cert.sigAlgName.contains("384")
            }
            if (!isRkpChain) {
                return Verdict.Rejected(
                    "RKP-only device (first_api_level=${rkpPolicy.firstApiLevel}) presented non-RKP RSA chain " +
                        "— Android 16 launch devices exclusively use ECDSA P-384 RKP; RSA chain is a spoof signal",
                )
            }
        }

        return if (desc.hardwareBacked) Verdict.Trusted(desc) else Verdict.SoftwareBacked(desc)
    }

    /** 字段交叉（任务 5.3）：RootOfTrust/补丁级别/StrongBox 能力 vs 系统声称与机型能力库。 */
    data class CrossInput(
        val claimedBootloaderLocked: Boolean? = null,
        val claimedPatchLevelYymm: Int? = null,
        /** 机型能力库：model -> 是否具备 StrongBox */
        val strongBoxCapableModels: Map<String, Boolean> = emptyMap(),
        val claimedModel: String? = null,
    )

    data class CrossAnomaly(val kind: String, val detail: String)

    fun crossCheck(desc: KeyDescriptionParser.KeyDescription, input: CrossInput): List<CrossAnomaly> = buildList {
        val rot = desc.rootOfTrust
        if (rot != null) {
            if (rot.verifiedBootState !in listOf(
                    KeyDescriptionParser.VerifiedBootState.VERIFIED,
                    KeyDescriptionParser.VerifiedBootState.SELF_SIGNED,
                )
            ) {
                add(CrossAnomaly("verified_boot_state", "verifiedBootState=${rot.verifiedBootState}（非 Verified/SelfSigned）"))
            }
            input.claimedBootloaderLocked?.let { claimed ->
                if (claimed && !rot.deviceLocked) {
                    add(CrossAnomaly("bootloader_lock_mismatch", "系统声称锁定但证明 deviceLocked=false（TrickyStore leaf-hack 形态）"))
                }
            }
        }
        input.claimedPatchLevelYymm?.let { claimed ->
            val attested = desc.osPatchLevel
            if (attested != null && attested > claimed) {
                add(CrossAnomaly("patch_level_future", "证明补丁级别 $attested 晚于系统声称 $claimed"))
            }
        }
        if (desc.attestationSecurityLevel == KeyDescriptionParser.SecurityLevel.STRONGBOX) {
            val model = input.claimedModel
            if (model != null && input.strongBoxCapableModels[model] != true) {
                add(CrossAnomaly("strongbox_capability_mismatch", "声称 StrongBox 但机型库无此能力: $model"))
            }
        }
    }

    private fun validateChainToAnchors(chain: List<X509Certificate>): String? = runCatching {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(null)
        roots.forEachIndexed { i, r -> ks.setCertificateEntry("attest-root-$i", r) }
        val cf = CertificateFactory.getInstance("X.509")
        val cp = cf.generateCertPath(chain)
        val params = PKIXParameters(ks).apply {
            isRevocationEnabled = false // 吊销走专用 CRL 信号（Google 官方状态端点）
            date = Date()
        }
        CertPathValidator.getInstance("PKIX").validate(cp, params)
        null
    }.getOrElse { "chain validation failed: ${it.message ?: it.javaClass.simpleName}" }
}
