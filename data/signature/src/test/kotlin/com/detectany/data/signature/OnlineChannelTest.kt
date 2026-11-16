package com.detectany.data.signature

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * P2-3 在线通道 host 测试：HttpServer 服务一个**真实签名**的更新信封，
 * OnlineChannel 拉取 → SignatureStore.apply 装载——在线轮询与手动导入共用同一验签管线。
 */
class OnlineChannelTest {

    private lateinit var server: HttpServer
    private var port: Int = 0

    @BeforeTest
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        port = server.address.port
        server.start()
    }

    @AfterTest
    fun stop() {
        server.stop(0)
    }

    private fun signedEnvelope(): String {
        val kp = KeyPairGenerator.getInstance("Ed25519").genKeyPair()
        val db = BundledSignatureDb.db.copy(version = BundledSignatureDb.db.version + 1)
        val sig = Signature.getInstance("Ed25519").apply {
            initSign(kp.private)
            update(UpdateCodec.payloadBytes(db))
        }
        val envelope = SignedUpdate(
            version = db.version,
            payload = db,
            signatureBase64 = Base64.getEncoder().encodeToString(sig.sign()),
        )
        // 顺带把公钥挂到上下文供测试装配 store
        pubB64 = Base64.getEncoder().encodeToString(kp.public.encoded)
        return kotlinx.serialization.json.Json.encodeToString(SignedUpdate.serializer(), envelope)
    }

    private var pubB64: String = ""

    @Test
    fun onlineFetchFeedsExistingVerifyPipeline() {
        val envelope = signedEnvelope()
        server.createContext("/update") { ex ->
            val bytes = envelope.toByteArray()
            ex.sendResponseHeaders(200, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
            ex.close()
        }
        val text = OnlineChannel.fetchUpdate("http://127.0.0.1:$port/update")
        val store = SignatureStore(verifier = SignatureVerifier(pubB64))
        val update = kotlinx.serialization.json.Json.decodeFromString(SignedUpdate.serializer(), text)
        val result = store.apply(update)
        assertTrue(result is ApplyResult.Applied, "在线拉取的信封应经既有验签管线装载: $result")
        assertEquals(BundledSignatureDb.db.version + 1, store.current().version)
    }

    @Test
    fun non2xxThrowsForCallerDegrade() {
        server.createContext("/gone") { ex ->
            ex.sendResponseHeaders(500, -1)
            ex.close()
        }
        assertFailsWith<IllegalArgumentException> {
            OnlineChannel.fetchUpdate("http://127.0.0.1:$port/gone")
        }
    }

    @Test
    fun oversizedEnvelopeRejected() {
        server.createContext("/big") { ex ->
            val bytes = ByteArray(OnlineChannel.MAX_ENVELOPE_BYTES + 1)
            ex.sendResponseHeaders(200, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
            ex.close()
        }
        assertFailsWith<IllegalArgumentException> {
            OnlineChannel.fetchUpdate("http://127.0.0.1:$port/big")
        }
    }
}
