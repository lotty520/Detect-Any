package com.detectany.collectors.virtualenv

/**
 * 多开/容器纯匹配逻辑（2026-11-17 多开识别配套，主机单测覆盖）。
 */
object ContainerMatching {

    /** clone user 标准 id（OEM 双开/分身/原生 clone profile）。 */
    const val CLONE_USER_ID = 999

    /** userId/user-type 语义分类（替代一刀切豁免）。 */
    enum class UserContext { MAIN, CLONE, PROFILE_OR_SECONDARY }

    /**
     * API 30+ 主判据（P8 实证 2026-11-17：原生 CLONE profile 的 userId 走普通序列分配到 10，
     * **999 非原生标准**——数值判据只配做兜底）。isProfile 且非 managed → CLONE 类 profile。
     */
    fun classifyProfile(isProfile: Boolean?, isManagedProfile: Boolean?): UserContext? = when {
        isProfile == null || isManagedProfile == null -> null // 查询不可用 → 数值兜底
        isProfile && !isManagedProfile -> UserContext.CLONE
        isProfile -> UserContext.PROFILE_OR_SECONDARY // managed（work）→ 合法
        else -> null // 非 profile（主用户/副用户）→ 数值兜底
    }

    /** 数值兜底（API<30 / 查询失败）：999=MIUI 等老双开形态；10+=profile/副用户豁免。 */
    fun classifyUser(userId: Int): UserContext = when {
        userId == CLONE_USER_ID -> UserContext.CLONE
        userId >= 10 -> UserContext.PROFILE_OR_SECONDARY
        else -> UserContext.MAIN
    }

    /**
     * /proc/self/cgroup 的 uid_ 段与 myUid 是否错位（容器第二证据）。
     * cgroup v2 无 uid_ 段 → false（无证据不产出）。
     */
    fun cgroupUidMismatch(cgroupText: String, myUid: Int): Boolean {
        val m = Regex("uid_(\\d+)").find(cgroupText) ?: return false
        return m.groupValues[1].toIntOrNull()?.let { it != myUid } ?: false
    }
}
