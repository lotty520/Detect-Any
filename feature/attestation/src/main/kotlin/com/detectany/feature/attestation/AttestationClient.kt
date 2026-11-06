package com.detectany.feature.attestation

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * 证明发起（任务 5.1，设备侧）：AndroidKeyStore EC P-256 + setAttestationChallenge（API 24+）。
 */
interface AttestationSource {
    data class Result(val challenge: ByteArray, val chain: List<X509Certificate>)
    fun attest(): Result?
    fun cleanup()
}

class AttestationClient(
    private val alias: String = "detectany_attest_${System.nanoTime()}",
) : AttestationSource {

    /** 发起一次 attestation；失败（无 Keymaster/不可用）返回 null（上层走降级）。 */
    override fun attest(): AttestationSource.Result? = runCatching {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(spec)
        kpg.generateKeyPair()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val chain = ks.getCertificateChain(alias)?.toList()?.filterIsInstance<X509Certificate>() ?: return null
        if (chain.isEmpty()) return null
        AttestationSource.Result(challenge, chain)
    }.getOrNull()

    override fun cleanup() {
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ks.deleteEntry(alias)
        }
    }
}
