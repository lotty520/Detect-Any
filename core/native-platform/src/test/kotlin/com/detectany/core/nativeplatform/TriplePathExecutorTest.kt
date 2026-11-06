package com.detectany.core.nativeplatform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 任务 2.1 单测（host JVM，桩后端）：三路一致性 / hook 桩注入下的差异检出。
 */
class TriplePathExecutorTest {

    private val ok = StatOutcome.Ok(dev = 7, ino = 42, mode = 0x8000, uid = 1000, gid = 1000, size = 123, mtimeSec = 1700000000)

    private class FixedBackend(var svc: StatOutcome, var libc: StatOutcome) : SyscallBackend {
        override fun statLibc(path: String): StatOutcome = libc
        override fun statSvc(path: String): StatOutcome = svc
    }

    private class FixedJavaView(var result: StatOutcome) : TriplePathExecutor.JavaStatView {
        override fun stat(path: String): StatOutcome = result
    }

    private fun executor(svc: StatOutcome, libc: StatOutcome, java: StatOutcome): TriplePathExecutor =
        TriplePathExecutor(FixedBackend(svc, libc), FixedJavaView(java))

    @Test
    fun consistentTripleIsClean() {
        val javaOk = ok.copy(dev = -1, ino = -1, uid = -1, gid = -1)
        val diff = executor(ok, ok, javaOk).probe("/system/lib64/libc.so")
        assertTrue(diff.clean)
        assertNull(diff.svcVsLibc)
        assertNull(diff.javaVsNative)
    }

    @Test
    fun svcLibcFieldMismatchIsDetected() {
        // hook 桩：libc 路被篡改（size/ino 被改）
        val hookedLibc = ok.copy(size = 0, ino = 7)
        val diff = executor(ok, hookedLibc, ok.copy(dev = -1, ino = -1, uid = -1, gid = -1)).probe("/x")
        val m = diff.svcVsLibc
        assertTrue(m != null && m.kind == TriplePathExecutor.MismatchKind.SVC_LIBC_FIELDS)
        assertTrue("ino" in m.detail && "size" in m.detail)
    }

    @Test
    fun svcLibcExistenceMismatchIsDetected() {
        // 桩：libc 谎报不存在（susfs 隐藏形态）
        val diff = executor(ok, StatOutcome.Errno(2), ok.copy(dev = -1, ino = -1, uid = -1, gid = -1)).probe("/hidden")
        assertEquals(TriplePathExecutor.MismatchKind.SVC_LIBC_EXISTENCE, diff.svcVsLibc?.kind)
    }

    @Test
    fun differentErrnoIsMismatch() {
        val diff = executor(StatOutcome.Errno(13), StatOutcome.Errno(2), StatOutcome.Errno(13)).probe("/data/adb")
        assertEquals(TriplePathExecutor.MismatchKind.SVC_LIBC_ERRNO, diff.svcVsLibc?.kind)
    }

    @Test
    fun javaNativeExistenceMismatchIsDetected() {
        // Java 层 hook 桩：Java API 谎报文件存在
        val diff = executor(StatOutcome.Errno(2), StatOutcome.Errno(2), ok.copy(dev = -1, ino = -1, uid = -1, gid = -1)).probe("/ghost")
        assertEquals(TriplePathExecutor.MismatchKind.JAVA_NATIVE_EXISTENCE, diff.javaVsNative?.kind)
    }

    @Test
    fun javaNativeSizeMismatchIsDetected() {
        val javaOk = ok.copy(dev = -1, ino = -1, uid = -1, gid = -1, size = 999)
        val diff = executor(ok, ok, javaOk).probe("/file")
        assertEquals(TriplePathExecutor.MismatchKind.JAVA_NATIVE_SIZE, diff.javaVsNative?.kind)
    }

    @Test
    fun sameErrnoBothSidesIsClean() {
        val diff = executor(StatOutcome.Errno(13), StatOutcome.Errno(13), StatOutcome.Errno(13)).probe("/data/adb/x")
        assertTrue(diff.clean)
    }

    @Test
    fun statArrayParsingRoundTrip() {
        val arr = longArrayOf(0, 0, 7, 42, 0x8000, 1000, 1000, 123, 1700000000)
        assertEquals(ok, parseStatArray(arr))
        assertEquals(StatOutcome.Errno(13), parseStatArray(longArrayOf(1, 13, 0, 0, 0, 0, 0, 0, 0)))
    }
}
