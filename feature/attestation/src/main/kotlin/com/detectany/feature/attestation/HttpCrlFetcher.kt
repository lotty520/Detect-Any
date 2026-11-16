package com.detectany.feature.attestation

import java.net.HttpURLConnection
import java.net.URL

/**
 * P2-3 在线通道（2026-11-16 落地）：CRL 真实拉取器。
 * 纯 JVM HttpURLConnection（无新依赖）；失败抛异常由 CrlStore 降级（快照兜底/空集），
 * 绝不阻断扫描。max-age 解析 Cache-Control（含 s-maxage 优先）。
 */
object HttpCrlFetcher {

    private const val CONNECT_TIMEOUT_MS = 5_000
    private const val READ_TIMEOUT_MS = 10_000
    private const val MAX_BODY_BYTES = 1 shl 20 // 1MB 上限（CRL status JSON 实际 <200KB）

    /** 返回 (body, cacheControlMaxAgeSeconds?)；非 2xx / 超时 / 超限 → 异常（调用方降级）。 */
    fun fetch(url: String): Pair<String, Long?> {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        conn.setRequestProperty("Accept", "application/json")
        try {
            val code = conn.responseCode
            require(code in 200..299) { "HTTP $code" }
            val bytes = conn.inputStream.use { it.readNBytes(MAX_BODY_BYTES + 1) }
            require(bytes.size <= MAX_BODY_BYTES) { "body exceeds ${MAX_BODY_BYTES / 1024}KB cap" }
            return String(bytes, Charsets.UTF_8) to parseMaxAge(conn.getHeaderField("Cache-Control"))
        } finally {
            conn.disconnect()
        }
    }

    /** "max-age=3600" / "public, s-maxage=86400, max-age=600" → 86400（s-maxage 优先）。 */
    internal fun parseMaxAge(header: String?): Long? {
        if (header.isNullOrBlank()) return null
        val directives = header.split(',').map { it.trim().lowercase() }
        val pick = { key: String ->
            directives.firstOrNull { it.startsWith("$key=") }?.substringAfter('=')?.toLongOrNull()
        }
        return pick("s-maxage") ?: pick("max-age")
    }
}
