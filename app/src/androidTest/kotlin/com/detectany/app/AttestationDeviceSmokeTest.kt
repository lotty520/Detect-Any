package com.detectany.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.detectany.feature.attestation.AttestationClient
import com.detectany.feature.attestation.AttestationService
import com.detectany.feature.attestation.AttestationVerifier
import com.detectany.feature.attestation.CrlStore
import com.detectany.feature.attestation.KeyDescriptionParser
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * WARNING#9 修复：C9 证明发起的设备冒烟（此前仅合成链验证）。
 * 模拟器预期：attestation 可发起（Google APIs 镜像带 keymaster/remote provisioning）；
 * 锚未装配 → Service 走 Degraded（不误报 Spoof）。
 */
@RunWith(AndroidJUnit4::class)
class AttestationDeviceSmokeTest {

    @Test
    fun realAttestationInitiatesAndChainParses() {
        val client = AttestationClient()
        try {
            val result = client.attest()
            assertNotNull("模拟器应能发起 attestation", result)
            val parsed = KeyDescriptionParser.parseFirstFromChain(result!!.chain)
            assertNotNull("真实链应含 attestation 扩展且可解析", parsed)
            assertTrue(
                "challenge 回显一致",
                parsed!!.second.attestationChallenge.contentEquals(result.challenge),
            )
        } finally {
            client.cleanup()
        }
    }

    @Test
    fun serviceEndToEndGraciousWithoutAnchors() {
        val service = AttestationService(
            verifier = AttestationVerifier(emptyList()), // 真实双根未装配
            crl = CrlStore(fetcher = { error("offline") }),
            firstApiLevel = { 35 }, // 模拟器首发 API ≥26 → 走发起路径
        )
        val out = service.run()
        // 无锚必须 Degraded（Rejected 路径），绝不误报 SpoofSuspected
        assertTrue("应优雅降级而非误报: $out", out is AttestationService.Outcome.Degraded)
        assertTrue(
            (out as AttestationService.Outcome.Degraded).reason.contains("anchors") ||
                out.reason.contains("unavailable") ||
                out.reason.contains("rejected"),
        )
    }
}
