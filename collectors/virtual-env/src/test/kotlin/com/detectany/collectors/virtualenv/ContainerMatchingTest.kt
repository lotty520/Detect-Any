package com.detectany.collectors.virtualenv

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** 多开/容器判定纯逻辑测试（2026-11-17 多开识别）。 */
class ContainerMatchingTest {

    @Test
    fun userContextClassification() {
        // 主用户 / 常见进程 userId 形态（myUserHandle().hashCode() 对 0..9 返回原值）
        assertEquals(ContainerMatching.UserContext.MAIN, ContainerMatching.classifyUser(0))
        // 数值兜底：999 = MIUI 等老双开形态（原生 CLONE 实测分到 10——见 classifyProfile 主判据）
        assertEquals(ContainerMatching.UserContext.CLONE, ContainerMatching.classifyUser(999))
        // work profile / 副用户（10+，合法豁免）
        assertEquals(ContainerMatching.UserContext.PROFILE_OR_SECONDARY, ContainerMatching.classifyUser(10))
        assertEquals(ContainerMatching.UserContext.PROFILE_OR_SECONDARY, ContainerMatching.classifyUser(11))
        assertEquals(ContainerMatching.UserContext.PROFILE_OR_SECONDARY, ContainerMatching.classifyUser(150))
    }

    @Test
    fun profileTypeClassification() {
        // P8 实证形态：Type=CLONE、userId=10——主判据按 user-type 命中
        assertEquals(ContainerMatching.UserContext.CLONE, ContainerMatching.classifyProfile(isProfile = true, isManagedProfile = false))
        // work profile（managed）→ 合法豁免
        assertEquals(ContainerMatching.UserContext.PROFILE_OR_SECONDARY, ContainerMatching.classifyProfile(isProfile = true, isManagedProfile = true))
        // 非 profile（主/副用户）→ 交数值兜底
        assertEquals(null, ContainerMatching.classifyProfile(isProfile = false, isManagedProfile = false))
        // 查询不可用 → 交数值兜底
        assertEquals(null, ContainerMatching.classifyProfile(isProfile = null, isManagedProfile = false))
        assertEquals(null, ContainerMatching.classifyProfile(isProfile = true, isManagedProfile = null))
    }

    @Test
    fun cgroupUidMismatchDetectsContainer() {
        // 容器内：cgroup uid_ 段是宿主 uid，与自身 myUid 不一致
        val cgroupInContainer = "10:cpu:/uid_10261/pid_12345\n0::/\n"
        assertTrue(ContainerMatching.cgroupUidMismatch(cgroupInContainer, myUid = 10295))
        // 正常：一致
        val cgroupNormal = "10:cpu:/uid_10295/pid_1\n"
        assertFalse(ContainerMatching.cgroupUidMismatch(cgroupNormal, myUid = 10295))
        // cgroup v2 无 uid_ 段（部分设备）→ 无证据不产出
        assertFalse(ContainerMatching.cgroupUidMismatch("0::/\n", myUid = 10295))
        // 空文本
        assertFalse(ContainerMatching.cgroupUidMismatch("", myUid = 10295))
        // 首个 uid_ 段优先（多段形态）
        assertTrue(ContainerMatching.cgroupUidMismatch("2:memory:/uid_10261\n0::/uid_99999\n", myUid = 10295))
    }
}
