package com.detectany.compat.platform.net

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import okhttp3.Request
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.OutputStream
import java.math.BigInteger
import java.net.InetSocketAddress
import java.net.URL
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * 任务 1.4 主机侧验证：TLS 1.3 握手 + 自有信任锚 + SPKI pinning 的通道逻辑。
 * Android 7 设备侧验证（Conscrypt 在真机/模拟器上）见任务 1.4 勾选说明——本测试证明
 * 通道的锚定/pinning/协议协商逻辑在 provider 无关层面成立。
 */
class SecureChannelTest {

    private lateinit var server: HttpsServer
    private lateinit var serverCert: X509Certificate
    private lateinit var caCert: X509Certificate
    private lateinit var otherCaCert: X509Certificate
    private var port: Int = 0

    @BeforeTest
    fun startTls13OnlyServer() {
        val (caCertX, caKey) = genCa("CN=detectany-test-ca")
        val (otherCa, _) = genCa("CN=detectany-other-ca")
        val (serverCertX, serverKey) = genServerCert(caCertX, caKey)
        caCert = caCertX
        otherCaCert = otherCa
        serverCert = serverCertX

        val kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm())
        val ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType())
        ks.load(null)
        ks.setKeyEntry("server", serverKey, charArrayOf(), arrayOf(serverCertX, caCertX))
        kmf.init(ks, charArrayOf())

        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)

        server = HttpsServer.create(InetSocketAddress("localhost", 0), 0)
        server.httpsConfigurator = object : HttpsConfigurator(ctx) {
            override fun configure(params: com.sun.net.httpserver.HttpsParameters) {
                // 仅放行 TLS 1.3：客户端必须以 TLS 1.3 完成协商
                params.protocols = arrayOf("TLSv1.3")
            }
        }
        server.createContext("/") { exchange ->
            val body = "pong".toByteArray()
            exchange.sendResponseHeaders(200, body.size.toLong())
            (exchange.responseBody as OutputStream).use { it.write(body) }
        }
        server.executor = null
        server.start()
        port = server.address.port
    }

    @AfterTest
    fun stopServer() {
        server.stop(0)
    }

    @Test
    fun negotiatesTls13() {
        val channel = SecureChannel(trustAnchors = listOf(caCert), pins = mapOf("localhost" to listOf(SpkiPins.of(serverCert))))
        assertEquals("TLSv1.3", channel.negotiate("localhost", port))
    }

    @Test
    fun pinnedGetOverTls13Succeeds() {
        val channel = SecureChannel(trustAnchors = listOf(caCert), pins = mapOf("localhost" to listOf(SpkiPins.of(serverCert))))
        val response = channel.newClient().newCall(Request.Builder().url(URL("https://localhost:$port/")).build()).execute()
        response.use {
            assertEquals(200, it.code)
            assertEquals("pong", it.body!!.string())
        }
    }

    @Test
    fun wrongPinIsRejected() {
        // 锚正确但 pin 不匹配：证书链验证通过、pinning 失败
        val wrongPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val channel = SecureChannel(trustAnchors = listOf(caCert), pins = mapOf("localhost" to listOf(wrongPin)))
        val ex = assertFailsWith<Exception> {
            channel.newClient().newCall(Request.Builder().url(URL("https://localhost:$port/")).build()).execute()
        }
        // OkHttp 将 pin 失败包装为 SSLPeerUnverifiedException（或其包装）
        var cause: Throwable? = ex
        var matched = ex is SSLPeerUnverifiedException
        while (cause != null && !matched) {
            cause = cause.cause
            matched = cause is SSLPeerUnverifiedException
        }
        assertTrue(matched, "expected SSLPeerUnverifiedException in cause chain, got $ex")
    }

    @Test
    fun foreignAnchorIsRejected() {
        // 服务器证书由 detectany-test-ca 签发，客户端只信 other-ca：握手必须失败
        val channel = SecureChannel(trustAnchors = listOf(otherCaCert))
        assertFailsWith<Exception> {
            channel.negotiate("localhost", port)
        }
    }

    // --- 证书生成（仅测试） ---

    private fun genCa(subject: String): Pair<X509Certificate, PrivateKey> {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()
        val now = Date()
        val holder = JcaX509v3CertificateBuilder(
            X500Name(subject),
            BigInteger(64, SecureRandom()),
            now,
            Date(now.time + 3600_000L),
            X500Name(subject),
            kp.public,
        )
        holder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        holder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        val cert = JcaX509CertificateConverter().getCertificate(
            holder.build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private)),
        )
        return cert to kp.private
    }

    private fun genServerCert(caCert: X509Certificate, caKey: PrivateKey): Pair<X509Certificate, PrivateKey> {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()
        val now = Date()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(caCert.subjectX500Principal.name),
            BigInteger(64, SecureRandom()),
            now,
            Date(now.time + 3600_000L),
            X500Name("CN=localhost"),
            kp.public,
        )
        builder.addExtension(
            Extension.subjectAlternativeName,
            false,
            GeneralNames(arrayOf(GeneralName(GeneralName.dNSName, "localhost"), GeneralName(GeneralName.iPAddress, "127.0.0.1"))),
        )
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withRSA").build(caKey)),
        )
        return cert to kp.private
    }
}
