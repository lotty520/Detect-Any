package com.detectany.feature.attestation

import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject

/**
 * Key attestation 扩展解析（任务 5.1）。
 * OID 1.3.6.1.4.1.11129.2.1.17；KeyDescription ASN.1（AOSP keymaster attestation record）。
 * AuthorizationList 记录 tag 空间：703 keySize / 724 rootOfTrust / 725 osVersion /
 * 726 osPatchLevel / 727 attestationApplicationId / 736 vendorPatchLevel / 737 bootPatchLevel。
 */
object KeyDescriptionParser {

    const val EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

    enum class SecurityLevel { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX }

    enum class VerifiedBootState { VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED }

    data class RootOfTrust(
        val verifiedBootKey: ByteArray,
        val deviceLocked: Boolean,
        val verifiedBootState: VerifiedBootState,
        val verifiedBootHash: ByteArray,
    )

    data class ApplicationId(
        val packageNames: List<String>,
        val signatureDigests: List<ByteArray>,
    )

    data class KeyDescription(
        val attestationVersion: Int,
        val attestationSecurityLevel: SecurityLevel,
        val keymasterVersion: Int,
        val attestationChallenge: ByteArray,
        val rootOfTrust: RootOfTrust?,
        val osVersion: Int?,
        val osPatchLevel: Int?,
        val vendorPatchLevel: Int?,
        val bootPatchLevel: Int?,
        val keySize: Int?,
        val attestationApplicationId: ApplicationId?,
    ) {
        val hardwareBacked: Boolean
            get() = attestationSecurityLevel != SecurityLevel.SOFTWARE
    }

    /** 从证书链解析「第一个」出现的 attestation 扩展（specs/attestation-verify：只信第一个）。 */
    fun parseFirstFromChain(chain: List<X509Certificate>): Pair<X509Certificate, KeyDescription>? {
        for (cert in chain) {
            val ext = cert.getExtensionValue(EXTENSION_OID) ?: continue
            val octets = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(ext)).octets
            return cert to parse(octets)
        }
        return null
    }

    fun parse(bytes: ByteArray): KeyDescription {
        val seq = ASN1Sequence.getInstance(bytes)
        var i = 0
        val attestationVersion = ASN1Integer.getInstance(seq.getObjectAt(i++)).intValueExact()
        val attestationSecurityLevel = level(ASN1Enumerated.getInstance(seq.getObjectAt(i++)).intValueExact())
        val keymasterVersion = ASN1Integer.getInstance(seq.getObjectAt(i++)).intValueExact()
        // keymasterSecurityLevel（ENUMERATED）——不参与本层判定，跳过
        i++
        val challenge = ASN1OctetString.getInstance(seq.getObjectAt(i++)).octets
        // uniqueId
        i++
        val softwareEnforced = ASN1Sequence.getInstance(seq.getObjectAt(i++))
        val teeEnforced = ASN1Sequence.getInstance(seq.getObjectAt(i))
        val holder = mutableMapOf<Int, org.bouncycastle.asn1.ASN1TaggedObject>()

        fun scan(list: ASN1Sequence, into: MutableMap<Int, org.bouncycastle.asn1.ASN1TaggedObject>) {
            for (el in list) {
                val tagged = el as? org.bouncycastle.asn1.ASN1TaggedObject ?: continue
                into[tagged.tagNo] = tagged
            }
        }
        scan(softwareEnforced, holder)
        scan(teeEnforced, holder)

        val rot = holder[724]?.let { runCatching { parseRootOfRootGuard(it) }.getOrNull() }
        val app = holder[727]?.let { runCatching { parseApplicationId(ASN1Sequence.getInstance(it, true)) }.getOrNull() }

        return KeyDescription(
            attestationVersion = attestationVersion,
            attestationSecurityLevel = attestationSecurityLevel,
            keymasterVersion = keymasterVersion,
            attestationChallenge = challenge,
            rootOfTrust = rot,
            osVersion = taggedInt(holder, 725),
            osPatchLevel = taggedInt(holder, 726),
            vendorPatchLevel = taggedInt(holder, 736),
            bootPatchLevel = taggedInt(holder, 737),
            keySize = taggedInt(holder, 703),
            attestationApplicationId = app,
        )
    }

    /**
     * 真实 schema（AOSP）：deviceLocked 为 BOOLEAN；verifiedBootState 为 ENUMERATED。
     * 2026-11-06 Pixel 8/Android 16 实测：旧解析按 ENUMERATED 读 deviceLocked 直接崩溃。
     * 逐字段防御式解析：任一字段形态不符 → 整体返回 null（不崩、不采信），绝不抛出。
     */
    private fun parseRootOfRootGuard(tagged: org.bouncycastle.asn1.ASN1TaggedObject): RootOfTrust? =
        parseRootOfTrust(ASN1Sequence.getInstance(tagged, true))

    private fun parseRootOfTrust(seq: ASN1Sequence): RootOfTrust? = runCatching {
        val lockedObj = seq.getObjectAt(1)
        val deviceLocked = when (lockedObj) {
            is org.bouncycastle.asn1.ASN1Boolean -> lockedObj.isTrue
            else -> ASN1Enumerated.getInstance(lockedObj).intValueExact() != 0 // 兼容旧合成向量
        }
        RootOfTrust(
            verifiedBootKey = ASN1OctetString.getInstance(seq.getObjectAt(0)).octets,
            deviceLocked = deviceLocked,
            verifiedBootState = VerifiedBootState.entries[ASN1Enumerated.getInstance(seq.getObjectAt(2)).intValueExact()],
            verifiedBootHash = ASN1OctetString.getInstance(seq.getObjectAt(3)).octets,
        )
    }.getOrNull()

    /** tagged 字段防御读取：形态不符返回 null（真实厂商链形态多样）。 */
    internal fun taggedInt(holder: Map<Int, org.bouncycastle.asn1.ASN1TaggedObject>, tag: Int): Int? =
        holder[tag]?.let { t -> runCatching { ASN1Integer.getInstance(t, true).value.toInt() }.getOrNull() }

    private fun parseApplicationId(seq: ASN1Sequence): ApplicationId {
        val packageInfos = ASN1Sequence.getInstance(seq.getObjectAt(0))
        val sigDigests = ASN1Sequence.getInstance(seq.getObjectAt(1))
        val names = buildList {
            for (el in packageInfos) {
                val info = ASN1Sequence.getInstance(el)
                add(String(ASN1OctetString.getInstance(info.getObjectAt(0)).octets, Charsets.UTF_8))
            }
        }
        val digests = buildList {
            for (el in sigDigests) add(ASN1OctetString.getInstance(el).octets)
        }
        return ApplicationId(names, digests)
    }

    private fun level(v: Int): SecurityLevel = when (v) {
        0 -> SecurityLevel.SOFTWARE
        1 -> SecurityLevel.TRUSTED_ENVIRONMENT
        2 -> SecurityLevel.STRONGBOX
        else -> throw IllegalArgumentException("unknown security level $v")
    }

    // ---- 测试向量构造（暴露给单测与回放工具） ----

    fun buildTestExtension(
        challenge: ByteArray,
        securityLevel: SecurityLevel,
        deviceLocked: Boolean,
        bootState: VerifiedBootState,
        packageName: String? = null,
        osPatchLevel: Int? = null,
    ): ByteArray {
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(300))          // attestationVersion (Keymaster 3+)
        v.add(ASN1Enumerated(securityLevel.ordinal))
        v.add(ASN1Integer(300))          // keymasterVersion
        v.add(ASN1Enumerated(securityLevel.ordinal)) // keymasterSecurityLevel
        v.add(DEROctetString(challenge))
        v.add(DEROctetString(byteArrayOf()))         // uniqueId
        v.add(DERSequence())             // softwareEnforced: empty

        val tee = ASN1EncodableVector()
        tee.add(DERTaggedObject(703, ASN1Integer(256)))
        val rot = ASN1EncodableVector()
        rot.add(DEROctetString("vbkey".toByteArray()))
        rot.add(if (deviceLocked) org.bouncycastle.asn1.ASN1Boolean.TRUE else org.bouncycastle.asn1.ASN1Boolean.FALSE)
        rot.add(ASN1Enumerated(bootState.ordinal))
        rot.add(DEROctetString("vbhash".toByteArray()))
        tee.add(DERTaggedObject(724, DERSequence(rot)))
        osPatchLevel?.let { tee.add(DERTaggedObject(726, ASN1Integer(it.toLong()))) }
        if (packageName != null) {
            val pkg = ASN1EncodableVector()
            val pkgInfo = ASN1EncodableVector()
            pkgInfo.add(DEROctetString(packageName.toByteArray(Charsets.UTF_8)))
            pkgInfo.add(ASN1Integer(1))
            pkg.add(DERSequence(pkgInfo))
            val sigs = ASN1EncodableVector()
            sigs.add(DEROctetString(byteArrayOf(1, 2, 3)))
            val appId = ASN1EncodableVector()
            appId.add(DERSequence(pkg))
            appId.add(DERSequence(sigs))
            tee.add(DERTaggedObject(727, DERSequence(appId)))
        }
        v.add(DERSequence(tee))
        return DERSequence(v).encoded
    }
}
