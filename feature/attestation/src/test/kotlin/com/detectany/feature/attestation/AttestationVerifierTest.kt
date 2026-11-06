package com.detectany.feature.attestation

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * 任务 5.1/5.2/5.3 验证：合成链测试向量（合法/吊销/软件链/追加伪叶子/中继/challenge）。
 */
class AttestationVerifierTest {

    private val verifier = AttestationVerifier(listOf(genCa().first))

    // ---- 测试链工厂 ----

    private class Ca(cert: X509Certificate, key: java.security.PrivateKey) {
        val cert = cert
        val key = key
    }

    private fun genCa(): Pair<X509Certificate, java.security.PrivateKey> {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()
        val now = Date()
        val b = JcaX509v3CertificateBuilder(
            X500Name("CN=attest-test-root"), BigInteger(64, SecureRandom()), now, Date(now.time + 3600_000L),
            X500Name("CN=attest-test-root"), kp.public,
        )
        b.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        return JcaX509CertificateConverter().getCertificate(b.build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private))) to kp.private
    }

    private fun genLeaf(
        issuer: X509Certificate,
        issuerKey: java.security.PrivateKey,
        serial: BigInteger = BigInteger(64, SecureRandom()),
        extension: ByteArray? = null,
        subject: String = "CN=attested-key",
        ca: Boolean = false,
    ): X509Certificate {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()
        val now = Date()
        val b = JcaX509v3CertificateBuilder(
            X500Name(issuer.subjectX500Principal.name), serial, now, Date(now.time + 3600_000L),
            X500Name(subject), kp.public,
        )
        b.addExtension(
            Extension.subjectAlternativeName, false,
            GeneralNames(arrayOf(GeneralName(GeneralName.dNSName, "localhost"))),
        )
        if (ca) b.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        extension?.let { b.addExtension(org.bouncycastle.asn1.x509.Extension(org.bouncycastle.asn1.ASN1ObjectIdentifier(KeyDescriptionParser.EXTENSION_OID), false, org.bouncycastle.asn1.DEROctetString(it))) }
        return JcaX509CertificateConverter().getCertificate(b.build(JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)))
    }

    private val hwExt = KeyDescriptionParser.buildTestExtension(
        challenge = "nonce-123".toByteArray(),
        securityLevel = KeyDescriptionParser.SecurityLevel.TRUSTED_ENVIRONMENT,
        deviceLocked = true,
        bootState = KeyDescriptionParser.VerifiedBootState.VERIFIED,
        packageName = "com.detectany.app",
        osPatchLevel = 202610,
    )

    // ---- 5.1 解析 ----

    @Test
    fun parsesKeyDescriptionFields() {
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val leaf = genLeaf(root, rootKey, extension = hwExt)
        val r = v.verify(listOf(leaf, root), expectedChallenge = "nonce-123".toByteArray(), expectedPackageName = "com.detectany.app")
        assertTrue(r is AttestationVerifier.Verdict.Trusted, r.toString())
        val d = (r as AttestationVerifier.Verdict.Trusted).description
        assertEquals(KeyDescriptionParser.SecurityLevel.TRUSTED_ENVIRONMENT, d.attestationSecurityLevel)
        assertTrue(d.rootOfTrust!!.deviceLocked)
        assertEquals(KeyDescriptionParser.VerifiedBootState.VERIFIED, d.rootOfTrust.verifiedBootState)
        assertEquals(202610, d.osPatchLevel)
        assertEquals(listOf("com.detectany.app"), d.attestationApplicationId!!.packageNames)
    }

    // ---- 5.2 三类测试向量 ----

    @Test
    fun revokedSerialVector() {
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val serial = BigInteger("aabbccdd", 16)
        val leaf = genLeaf(root, rootKey, serial = serial, extension = hwExt)
        val r = v.verify(listOf(leaf, root), revokedSerials = setOf(serial.toString(16)))
        assertTrue(r is AttestationVerifier.Verdict.Revoked, r.toString())
        assertEquals("aabbccdd", (r as AttestationVerifier.Verdict.Revoked).serialHex)
    }

    @Test
    fun softwareChainVector() {
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val swExt = KeyDescriptionParser.buildTestExtension(
            challenge = "n".toByteArray(), securityLevel = KeyDescriptionParser.SecurityLevel.SOFTWARE,
            deviceLocked = true, bootState = KeyDescriptionParser.VerifiedBootState.VERIFIED,
        )
        val leaf = genLeaf(root, rootKey, extension = swExt)
        val r = v.verify(listOf(leaf, root))
        assertTrue(r is AttestationVerifier.Verdict.SoftwareBacked, r.toString())
    }

    @Test
    fun appendedLeafVector() {
        // 攻击者在合法链尾部追加自签伪叶子（带伪造扩展）：PKIX 锚定必须拒绝
        val (root, rootKey) = genCa()
        val attackerCa = genCa()
        val v = AttestationVerifier(listOf(root))
        val legit = genLeaf(root, rootKey, extension = hwExt)
        val fakeExt = KeyDescriptionParser.buildTestExtension(
            challenge = "evil".toByteArray(), securityLevel = KeyDescriptionParser.SecurityLevel.TRUSTED_ENVIRONMENT,
            deviceLocked = true, bootState = KeyDescriptionParser.VerifiedBootState.VERIFIED,
        )
        val appended = genLeaf(attackerCa.first, attackerCa.second, extension = fakeExt)
        val r = v.verify(listOf(appended, legit, root))
        assertTrue(r is AttestationVerifier.Verdict.Rejected, "追加伪叶子必须被拒: $r")
    }

    @Test
    fun firstExtensionOnlyIsUsed() {
        // 链上多处扩展：leaf（第一个）与中间 CA（第二个）都带扩展 → 只取 leaf 的
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val otherExt = KeyDescriptionParser.buildTestExtension(
            challenge = "other".toByteArray(), securityLevel = KeyDescriptionParser.SecurityLevel.SOFTWARE,
            deviceLocked = false, bootState = KeyDescriptionParser.VerifiedBootState.FAILED,
        )
        // 中间 CA：自带密钥对、由根签发、携带第二个（伪造形态）扩展
        val interKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()
        val now = Date()
        val interBuilder = JcaX509v3CertificateBuilder(
            X500Name(root.subjectX500Principal.name), BigInteger(64, SecureRandom()), now, Date(now.time + 3600_000L),
            X500Name("CN=attest-inter"), interKp.public,
        )
        interBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        interBuilder.addExtension(
            org.bouncycastle.asn1.x509.Extension(
                org.bouncycastle.asn1.ASN1ObjectIdentifier(KeyDescriptionParser.EXTENSION_OID), false,
                org.bouncycastle.asn1.DEROctetString(otherExt),
            ),
        )
        val inter = JcaX509CertificateConverter().getCertificate(
            interBuilder.build(JcaContentSignerBuilder("SHA256withRSA").build(rootKey)),
        )
        // leaf 由中间 CA 签发、带真实扩展（第一个）
        val leaf = genLeaf(inter, interKp.private, extension = hwExt)
        val r = v.verify(listOf(leaf, inter, root), expectedChallenge = "nonce-123".toByteArray())
        assertTrue(r is AttestationVerifier.Verdict.Trusted, "应以第一个（leaf）扩展为准: $r")
    }

    @Test
    fun challengeMismatchRejected() {
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val leaf = genLeaf(root, rootKey, extension = hwExt)
        val r = v.verify(listOf(leaf, root), expectedChallenge = "wrong".toByteArray())
        assertTrue(r is AttestationVerifier.Verdict.Rejected && r.reason.contains("challenge"), r.toString())
    }

    @Test
    fun relayAppIdMismatchRejected() {
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val leaf = genLeaf(root, rootKey, extension = hwExt)
        val r = v.verify(listOf(leaf, root), expectedChallenge = "nonce-123".toByteArray(), expectedPackageName = "com.other.app")
        assertTrue(r is AttestationVerifier.Verdict.Rejected && r.reason.contains("relay"), r.toString())
    }

    // ---- 5.3 字段交叉 + 降级 ----

    @Test
    fun crossCheckDetectsBootloaderLie() {
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val unlockedExt = KeyDescriptionParser.buildTestExtension(
            challenge = "n".toByteArray(), securityLevel = KeyDescriptionParser.SecurityLevel.TRUSTED_ENVIRONMENT,
            deviceLocked = false, bootState = KeyDescriptionParser.VerifiedBootState.UNVERIFIED,
        )
        val leaf = genLeaf(root, rootKey, extension = unlockedExt)
        val r = v.verify(listOf(leaf, root))
        val d = (r as AttestationVerifier.Verdict.Trusted).description
        val anomalies = v.crossCheck(d, AttestationVerifier.CrossInput(claimedBootloaderLocked = true))
        assertTrue(anomalies.any { it.kind == "bootloader_lock_mismatch" || it.kind == "verified_boot_state" })
    }

    @Test
    fun strongBoxCapabilityMismatch() {
        val (root, rootKey) = genCa()
        val v = AttestationVerifier(listOf(root))
        val sbExt = KeyDescriptionParser.buildTestExtension(
            challenge = "n".toByteArray(), securityLevel = KeyDescriptionParser.SecurityLevel.STRONGBOX,
            deviceLocked = true, bootState = KeyDescriptionParser.VerifiedBootState.VERIFIED,
        )
        val leaf = genLeaf(root, rootKey, extension = sbExt)
        val d = (v.verify(listOf(leaf, root)) as AttestationVerifier.Verdict.Trusted).description
        val anomalies = v.crossCheck(
            d,
            AttestationVerifier.CrossInput(strongBoxCapableModels = mapOf("Pixel 8" to true), claimedModel = "Pixel 4a"),
        )
        assertTrue(anomalies.any { it.kind == "strongbox_capability_mismatch" })
    }

    @Test
    fun noAnchorsIsRejected() {
        val v = AttestationVerifier(emptyList())
        assertTrue(v.verify(listOf(genCa().first)) is AttestationVerifier.Verdict.Rejected)
    }
}
