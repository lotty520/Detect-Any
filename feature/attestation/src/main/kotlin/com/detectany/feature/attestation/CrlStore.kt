package com.detectany.feature.attestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Google 官方 keybox 吊销状态消费（任务 5.2）：
 * 端点 https://android.googleapis.com/attestation/status（公开 JSON），
 * 按 Cache-Control max-age 节流拉取，离线快照兜底。
 */
class CrlStore(
    /** fetcher: url -> (body, cacheControlMaxAgeSeconds?) */
    private val fetcher: (String) -> Pair<String, Long?> = { error("no fetcher wired") },
    private val snapshotStore: SnapshotStore = NoopSnapshotStore(),
    private val url: String = "https://android.googleapis.com/attestation/status",
) {
    interface SnapshotStore {
        fun load(): String?
        fun save(body: String)
    }

    class NoopSnapshotStore : SnapshotStore {
        override fun load(): String? = null
        override fun save(body: String) {}
    }

    @Serializable
    data class StatusResponse(val entries: Map<String, StatusEntry> = emptyMap(), val validUntil: String? = null) {
        @Serializable
        data class StatusEntry(val status: String? = null, val reason: String? = null)
    }

    @Volatile
    private var cached: StatusResponse? = null

    @Volatile
    private var lastFetchAtMs: Long = 0

    @Volatile
    private var cachedMaxAgeSec: Long = DEFAULT_MAX_AGE_SEC

    /** 当前吊销序列号集合（小写 hex）。force = 忽略节流。 */
    fun revokedSerials(nowMs: Long = System.currentTimeMillis(), force: Boolean = false): Set<String> {
        val fresh = cached != null && nowMs - lastFetchAtMs < cachedMaxAgeSec * 1000
        if (!force && fresh) return current().entries.filter { it.value.status == "REVOKED" }.keys

        val (body, maxAge) = runCatching { fetcher(url) }.getOrElse {
            // 离线：快照兜底
            val snap = snapshotStore.load()
            if (snap != null) {
                cached = parse(snap)
            }
            return current().entries.filter { it.value.status == "REVOKED" }.keys
        }
        maxAge?.let { cachedMaxAgeSec = it }
        val parsed = parse(body)
        cached = parsed
        lastFetchAtMs = nowMs
        snapshotStore.save(body)
        return parsed.entries.filter { it.value.status == "REVOKED" }.keys
    }

    fun current(): StatusResponse = cached ?: (snapshotStore.load()?.let { parse(it) } ?: StatusResponse())

    internal fun parse(body: String): StatusResponse =
        Json { ignoreUnknownKeys = true }.decodeFromString(StatusResponse.serializer(), body)

    companion object {
        const val DEFAULT_MAX_AGE_SEC = 3600L
    }
}
