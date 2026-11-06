package com.detectany.compat.platform.net

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import java.net.InetSocketAddress
import java.net.URL
import java.security.Provider
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * 安全网络通道（design.md D7 / 任务 1.4）：
 * - 自有信任锚（仅信任显式提供的证书，不使用系统信任库）
 * - SPKI pinning（按主机钉住公钥摘要）
 * - 可注入 TLS Provider（Android 侧由 app 注入 Conscrypt，为 Android 7 带来 TLS 1.3；
 *   JVM/测试侧可用默认 provider）
 *
 * 本类保持纯 JVM：Provider 的选择与安装是宿主(app)的责任。
 */
class SecureChannel(
    trustAnchors: List<X509Certificate>,
    pins: Map<String, List<String>> = emptyMap(),
    private val provider: Provider? = null,
    private val connectTimeoutMs: Long = 10_000,
    private val readTimeoutMs: Long = 15_000,
) {
    val trustManager: X509TrustManager
    val sslSocketFactory: SSLSocketFactory

    init {
        require(trustAnchors.isNotEmpty()) { "至少提供一个信任锚" }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(SpkiPins.anchorKeyStore(trustAnchors))
        trustManager = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        val ctx = if (provider != null) SSLContext.getInstance("TLS", provider) else SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trustManager), SecureRandom())
        sslSocketFactory = ctx.socketFactory
    }

    private val certificatePinner: CertificatePinner = pins.entries.fold(CertificatePinner.Builder()) { b, (host, hostPins) ->
        hostPins.fold(b) { bb, pin -> bb.add(host, pin) }
    }.build()

    fun newClient(): OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustManager)
        .certificatePinner(certificatePinner)
        .connectTimeout(connectTimeoutMs, TimeUnit.MILLISECONDS)
        .readTimeout(readTimeoutMs, TimeUnit.MILLISECONDS)
        .build()

    /**
     * 原生 SSLSocket 协商探测：返回协商出的协议名（如 "TLSv1.3"）。
     * 用于在目标设备上直接验证 TLS 1.3 能力（Android 7 验证用）。
     */
    fun negotiate(host: String, port: Int, timeoutMs: Int = connectTimeoutMs.toInt()): String {
        val raw = sslSocketFactory.createSocket()
        require(raw is SSLSocket) { "factory 未产出 SSLSocket" }
        raw.use { socket ->
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            socket.startHandshake()
            return socket.session.protocol
        }
    }

    /** 便捷重载。 */
    fun negotiate(url: URL): String = negotiate(url.host, url.port.takeIf { it != -1 } ?: url.defaultPort)
}
