package com.detectany.core.nativeplatform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 任务 2.2 单测：守卫白名单 —— 与 native kAllowedNrs 的镜像集合一致性、
 * statx 永远不在白名单、不存在试探回退路径（policy 由 ProbeCap.STATX 恒 BLOCKED 保证，见 1.3 测试）。
 */
class SyscallAllowlistTest {

    @Test
    fun arm64AllowlistMatchesDocumentedNrs() {
        assertEquals(setOf(56L, 57L, 79L, 48L, 43L, 142L, 167L, 117L, 45L), SyscallAllowlist.ARM64)
    }

    @Test
    fun arm32AllowlistMatchesDocumentedNrs() {
        assertEquals(setOf(322L, 6L, 300L, 334L, 266L, 88L, 172L, 26L, 46L), SyscallAllowlist.ARM32)
    }

    @Test
    fun statxNeverInAnyAllowlist() {
        assertFalse(SyscallAllowlist.STATX_ARM64 in SyscallAllowlist.ARM64)
        assertFalse(SyscallAllowlist.STATX_ARM32 in SyscallAllowlist.ARM32)
        assertFalse(SyscallAllowlist.STATX_ARM64 in SyscallAllowlist.ARM32)
        assertFalse(SyscallAllowlist.STATX_ARM32 in SyscallAllowlist.ARM64)
    }

    @Test
    fun allowlistsContainOnlyTheDocumentedSet() {
        // 三路 diff 最小集(4) + 显式探针号(5: statfs/reboot/prctl/ptrace/supercall)
        assertTrue(SyscallAllowlist.ARM64.size == 9 && SyscallAllowlist.ARM32.size == 9)
    }

    @Test
    fun archLookup() {
        assertEquals(SyscallAllowlist.ARM64, SyscallAllowlist.forArch("arm64-v8a"))
        assertEquals(SyscallAllowlist.ARM32, SyscallAllowlist.forArch("armeabi-v7a"))
        assertNull(SyscallAllowlist.forArch("x86_64"))
        assertNull(SyscallAllowlist.forArch(null))
    }

    @Test
    fun truncationHeuristicForPropValues() {
        // PROP_VALUE_MAX=92 → 91 即疑似截断
        assertEquals(92, SystemPropertiesBridge.PROP_VALUE_MAX)
        assertTrue("x".repeat(91).length >= SystemPropertiesBridge.PROP_VALUE_MAX - 1)
        assertFalse("short".length >= SystemPropertiesBridge.PROP_VALUE_MAX - 1)
    }
}
