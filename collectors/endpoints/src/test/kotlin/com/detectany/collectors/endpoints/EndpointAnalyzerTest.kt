package com.detectany.collectors.endpoints

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 任务 3.4 验证：/proc/net/unix 解析与 socket 匹配。 */
class EndpointAnalyzerTest {

    private val unixLines = listOf(
        "Num       RefCount Protocol Flags    Type St Inode Path",
        "00000000: 00000002 00000000 00010000 0001 01 1234 @zygiskd",
        "00000000: 00000002 00000000 00010000 0001 01 1235 /debug_ramdisk/.magisk/socket",
        "00000000: 00000002 00000000 00010000 0001 01 1236 @ksud",
        "00000000: 00000002 00000000 00010000 0001 01 1237 @com.google.android.gms.common",
    )

    @Test
    fun parsesPaths() {
        val paths = EndpointAnalyzer.parsePaths(unixLines)
        assertEquals(4, paths.size)
        assertTrue(paths.contains("@zygiskd"))
    }

    @Test
    fun matchesAbstractAndFileSockets() {
        val findings = EndpointAnalyzer.analyzeUnix(unixLines, defaultSocketEntries())
        assertTrue(findings.any { it.ruleId == "sock.zygiskd" && it.framework == "zygisknext" })
        assertTrue(findings.any { it.ruleId == "sock.ksud" && it.framework == "ksu" })
        assertTrue(findings.any { it.ruleId == "sock.fs.magisk_socket" && it.framework == "magisk" })
    }

    @Test
    fun cleanEnvironmentNoFindings() {
        val clean = listOf(
            "Num       RefCount Protocol Flags    Type St Inode Path",
            "00000000: 00000002 00000000 00010000 0001 01 1237 @com.google.android.gms.common",
        )
        assertEquals(0, EndpointAnalyzer.analyzeUnix(clean, defaultSocketEntries()).size)
    }
}
