package com.detectany.data.signature

import java.net.HttpURLConnection
import java.net.URL

/**
 * P2-3 在线通道（2026-11-16）：签名热更新的在线拉取器。
 * 仅负责「取文本」；验签/装载沿用 SignedUpdate + SignatureStore.apply 与手动导入同一管线。
 * 失败抛异常（调用方决定降级提示），信封 ≤200KB（SignedUpdate 契约上限）。
 */
object OnlineChannel {

    private const val CONNECT_TIMEOUT_MS = 5_000
    private const val READ_TIMEOUT_MS = 10_000
    const val MAX_ENVELOPE_BYTES: Int = 200 * 1024

    /** 拉取更新信封文本；非 2xx / 超时 / 超 200KB → 异常。 */
    fun fetchUpdate(url: String): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        conn.setRequestProperty("Accept", "application/json")
        try {
            val code = conn.responseCode
            require(code in 200..299) { "HTTP $code" }
            val bytes = conn.inputStream.use { it.readNBytes(MAX_ENVELOPE_BYTES + 1) }
            require(bytes.size <= MAX_ENVELOPE_BYTES) { "envelope exceeds ${MAX_ENVELOPE_BYTES / 1024}KB cap" }
            return String(bytes, Charsets.UTF_8)
        } finally {
            conn.disconnect()
        }
    }
}
