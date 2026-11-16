package com.detectany.feature.attestation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * HttpCrlFetcher 纯解析面测试。
 * 注：HTTP 回环（body/状态码/上限）不在本模块测——Android library 的 unit test 编译
 * 对 android.jar 的 com.sun.net.httpserver 桩（方法缺失）；同款回环由纯 JVM 模块
 * data/signature 的 OnlineChannelTest 覆盖（同一拉取模式）。
 */
class HttpCrlFetcherTest {

    @Test
    fun maxAgeParsing() {
        assertNull(HttpCrlFetcher.parseMaxAge(null))
        assertNull(HttpCrlFetcher.parseMaxAge(""))
        assertNull(HttpCrlFetcher.parseMaxAge("no-store"))
        assertEquals(3600L, HttpCrlFetcher.parseMaxAge("public, max-age=3600"))
        assertEquals(86400L, HttpCrlFetcher.parseMaxAge("max-age=600, s-maxage=86400"))
        assertEquals(0L, HttpCrlFetcher.parseMaxAge("max-age=0"))
        assertTrue(HttpCrlFetcher.parseMaxAge("max-age=abc") == null, "垃圾值忽略而非崩溃")
    }
}
