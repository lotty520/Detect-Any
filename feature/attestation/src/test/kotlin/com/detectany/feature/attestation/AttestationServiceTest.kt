package com.detectany.feature.attestation

import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertTrue

/** 任务 5.3 验证：first_api_level 降级路径（specs/attestation-verify「设备等级降级」）。 */
class AttestationServiceTest {

    private class FakeSource(val result: AttestationSource.Result?) : AttestationSource {
        override fun attest(): AttestationSource.Result? = result
        override fun cleanup() {}
    }

    private fun cert(): X509Certificate {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()
        val now = Date()
        val b = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            org.bouncycastle.asn1.x500.X500Name("CN=x"), java.math.BigInteger.valueOf(7), now, Date(now.time + 3600_000L),
            org.bouncycastle.asn1.x500.X500Name("CN=x"), kp.public,
        )
        return org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
            b.build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(kp.private)),
        )
    }

    private fun crl() = CrlStore(fetcher = { error("unused") })

    @Test
    fun firstApiLevelBelow26IsDegraded() {
        val service = AttestationService(
            client = FakeSource(AttestationSource.Result("n".toByteArray(), listOf(cert()))),
            verifier = AttestationVerifier(emptyList()),
            crl = crl(),
            firstApiLevel = { 24 },
        )
        val out = service.run()
        assertTrue(out is AttestationService.Outcome.Degraded, out.toString())
        assertTrue((out as AttestationService.Outcome.Degraded).reason.contains("first_api_level"))
    }

    @Test
    fun unavailableAttestationIsDegraded() {
        val service = AttestationService(
            client = FakeSource(null),
            verifier = AttestationVerifier(emptyList()),
            crl = crl(),
            firstApiLevel = { 33 },
        )
        val out = service.run()
        assertTrue(out is AttestationService.Outcome.Degraded && out.reason.contains("unavailable"), out.toString())
    }

    @Test
    fun noAnchorsOnModernDeviceIsDegradedNotSpoof() {
        // 无锚配置（真实 Google 根未装配时）：降级为 Rejected-Degraded，绝不误报 Spoof
        val service = AttestationService(
            client = FakeSource(AttestationSource.Result("n".toByteArray(), listOf(cert()))),
            verifier = AttestationVerifier(emptyList()),
            crl = crl(),
            firstApiLevel = { 33 },
        )
        val out = service.run()
        assertTrue(out is AttestationService.Outcome.Degraded, "应降级而非误报: $out")
    }
}
