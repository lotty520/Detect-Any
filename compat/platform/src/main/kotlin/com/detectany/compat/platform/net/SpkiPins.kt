package com.detectany.compat.platform.net

import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * SPKI pin 工具：计算/承载证书公钥的 sha256/BASE64 pin（OkHttp CertificatePinner 语法）。
 */
object SpkiPins {

    /** 计算证书 SubjectPublicKeyInfo 的 sha256/xxx pin。 */
    fun of(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded)
        return "sha256/" + Base64.getEncoder().encodeToString(digest)
    }

    /** 由锚证书集合构造仅信任这些锚的 KeyStore（忽略系统信任库）。 */
    fun anchorKeyStore(anchors: List<X509Certificate>): KeyStore {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(null)
        anchors.forEachIndexed { index, cert ->
            ks.setCertificateEntry("detectany-anchor-$index", cert)
        }
        return ks
    }
}
