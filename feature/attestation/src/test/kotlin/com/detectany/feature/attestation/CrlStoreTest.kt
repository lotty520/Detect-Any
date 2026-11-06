package com.detectany.feature.attestation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 5.2：CRL 解析/节流/离线快照。 */
class CrlStoreTest {

    private val body = """
        {"entries": {"aabbcc": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}, "112233": {"status": "SUSPENDED"}}, "validUntil": "2026-12-01"}
    """.trimIndent()

    @Test
    fun parsesAndFiltersRevoked() {
        var fetched = 0
        val store = CrlStore(fetcher = { fetched++; body to 60L })
        val revoked = store.revokedSerials(nowMs = 1000L)
        assertEquals(setOf("aabbcc"), revoked)
        assertEquals(1, fetched)
        // 节流：窗口内第二次调用不再拉取
        store.revokedSerials(nowMs = 2000L)
        assertEquals(1, fetched)
        // force 越过节流
        store.revokedSerials(nowMs = 2000L, force = true)
        assertEquals(2, fetched)
    }

    @Test
    fun offlineFallsBackToSnapshot() {
        var online = true
        val snap = object : CrlStore.SnapshotStore {
            var saved: String? = null
            override fun load(): String? = saved
            override fun save(b: String) { saved = b }
        }
        val store = CrlStore(fetcher = { if (online) body to 60L else error("offline") }, snapshotStore = snap)
        // 第一次在线：成功并保存快照
        assertEquals(setOf("aabbcc"), store.revokedSerials(nowMs = 1000L))
        assertTrue(snap.saved != null)
        // 窗口过期后离线：快照兜底
        online = false
        assertEquals(setOf("aabbcc"), store.revokedSerials(nowMs = 999_999_999L))
    }
}
