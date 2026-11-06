package com.detectany.data.signature

import kotlinx.serialization.encodeToString
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 4.1/4.2 验证：schema 装载 + ed25519 验签 + 增量合并 + 拒绝路径。 */
class SignatureStoreTest {

    private fun keyPair(): Pair<String, java.security.PrivateKey> {
        val kp = KeyPairGenerator.getInstance("Ed25519").genKeyPair()
        val pubB64 = Base64.getEncoder().encodeToString(kp.public.encoded)
        return pubB64 to kp.private
    }

    private fun sign(priv: java.security.PrivateKey, payload: SignatureDb): String {
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(priv)
        sig.update(UpdateCodec.payloadBytes(payload))
        return Base64.getEncoder().encodeToString(sig.sign())
    }

    @Test
    fun bundledBaselineLoadsAndParses() {
        val db = BundledSignatureDb.db
        assertEquals(3L, db.version)
        assertTrue(db.paths.size >= 10)
        assertTrue(db.apps.any { it.id == "app.sukisu" && it.dexStrings.isNotEmpty() })
        assertTrue(db.supercalls.any { it.family == "ksu_reboot" && it.magic1Hex == "deadbeef" })
        // 采集器视图转换
        val entries = BundledSignatureDb.toEntries()
        assertTrue(entries.apps.size == db.apps.size)
        assertTrue(entries.paths.first().confidence == com.detectany.core.model.Confidence.C)
    }

    @Test
    fun jsonRoundTrip() {
        val text = UpdateCodec.json.encodeToString(SignatureDb.serializer(), BundledSignatureDb.db)
        val back = UpdateCodec.json.decodeFromString(SignatureDb.serializer(), text)
        assertEquals(BundledSignatureDb.db, back)
    }

    @Test
    fun goodUpdateAppliesImmediately() {
        val (pub, priv) = keyPair()
        val store = SignatureStore(verifier = SignatureVerifier(pub))
        val newDb = store.current().copy(version = 5)
        val update = SignedUpdate(version = 5, payload = newDb, signatureBase64 = sign(priv, newDb))
        val r = store.apply(update)
        assertTrue(r is ApplyResult.Applied)
        assertEquals(5L, store.current().version) // 装载即生效
    }

    @Test
    fun badSignatureRejectedKeepsOld() {
        val (pub, _) = keyPair()
        val (_, otherPriv) = keyPair()
        val store = SignatureStore(verifier = SignatureVerifier(pub))
        val newDb = store.current().copy(version = 5)
        val forged = SignedUpdate(version = 5, payload = newDb, signatureBase64 = sign(otherPriv, newDb))
        val r = store.apply(forged)
        assertTrue(r is ApplyResult.Rejected && r.reason.contains("signature"))
        assertEquals(3L, store.current().version) // 旧版保留
    }

    @Test
    fun versionRegressionRejected() {
        val (pub, priv) = keyPair()
        val store = SignatureStore(verifier = SignatureVerifier(pub))
        val newDb = store.current().copy(version = 1)
        val update = SignedUpdate(version = 1, payload = newDb, signatureBase64 = sign(priv, newDb))
        assertTrue(store.apply(update) is ApplyResult.Rejected)
    }

    @Test
    fun deltaMergeByIdAndBlacklist() {
        val (pub, priv) = keyPair()
        val store = SignatureStore(verifier = SignatureVerifier(pub))
        val delta = SignatureDb(
            version = 4,
            paths = listOf(SignatureDb.PathEntry("path.new_marker", "/data/adb/newthing", "sukisu", "C", "ROOT_KERNEL")),
            keyboxBlacklist = listOf(SignatureDb.KeyboxEntry("aabbcc", "leaked")),
        )
        val update = SignedUpdate(version = 4, baseVersion = 3, payload = delta, signatureBase64 = sign(priv, delta))
        val r = store.apply(update)
        assertTrue(r is ApplyResult.Applied, r.toString())
        val db = store.current()
        assertTrue(db.paths.any { it.id == "path.new_marker" })
        assertTrue(db.paths.any { it.id == "path.su.system" }) // 旧条目保留
        assertTrue(db.keyboxBlacklist.any { it.serialHex == "aabbcc" })
    }

    @Test
    fun deltaBaseMismatchRejected() {
        val (pub, priv) = keyPair()
        val store = SignatureStore(verifier = SignatureVerifier(pub))
        val delta = SignatureDb(version = 9)
        val update = SignedUpdate(version = 9, baseVersion = 7, payload = delta, signatureBase64 = sign(priv, delta))
        val r = store.apply(update)
        assertTrue(r is ApplyResult.Rejected && r.reason.contains("base mismatch"))
    }

    @Test
    fun oversizedPayloadRejected() {
        val (pub, priv) = keyPair()
        val store = SignatureStore(verifier = SignatureVerifier(pub), maxDeltaBytes = 256)
        val big = store.current().let { db ->
            db.copy(paths = (0 until 64).map { SignatureDb.PathEntry("p$it", "/x/$it", null, "C", "ROOT_USERSPACE") })
        }
        val update = SignedUpdate(version = 5, payload = big, signatureBase64 = sign(priv, big))
        val r = store.apply(update)
        assertTrue(r is ApplyResult.Rejected && r.reason.contains("exceeds"))
    }
}
