package com.detectany.collectors.screenshare

/**
 * 虚拟显示器分类器（change virtual-display-detect）。
 * 纯 Kotlin 无 Android 依赖——主机可测；Android 采集面由 ScreenShareCollector 组装快照注入
 * （对齐 IntegrityAnalyzer/Analyzer 拆分惯例，防 propGet 内联毁 host 可测的旧教训）。
 *
 * Ground truth: docs/calibration/virtual-displays.md（2026-11-18 API35 实验室取证）。
 * 分类顺序＝特征专属性（专属名称 > 路由巧合）：名称直命中优先于投屏路由互证，
 * 防止「cast 会话在场掩蔽并存的 shell 建屏」（design D2 / 审计 F3）。
 *
 * 定级纪律（spec）：单信号全 C；唯一 B 路径是复合——自身位于 shell-owned 屏 且 ADB 姿态共现
 * （两族独立信号，均由 C12 采集，就地合成一条 B；定性复用 ScoreModel 既有同域 B+C 共振）。
 */
object VirtualDisplayClassifier {

    /** 分类特征表版本：新增形态（OEM 副屏/投屏白名单/容器建屏）只改下方数据表并 bump（spec R5） */
    const val CALIBRATION_VERSION = 1

    /** shell 身份建屏的 Display 名称（真值：name="scrcpy", uniqueId=virtual:com.android.shell,2000,…） */
    private val SHELL_DISPLAY_NAMES = listOf("scrcpy")

    /** 多开/虚拟化引擎建屏形态——待容器实测入库（当前留空 → 落 unknown，不入未实证特征） */
    private val CONTAINER_DISPLAY_PATTERNS: List<Regex> = emptyList()

    /** 合法投屏/DeX/OEM 副屏白名单——fp_certify 多厂商矩阵核验前留空（全部落 unknown，C 级） */
    private val LEGIT_CAST_PATTERNS: List<Regex> = emptyList()

    /** 开发者模拟屏（真值：name="Overlay #1", uniqueId=overlay:1） */
    private val DEV_SIMULATE_NAME = Regex("^Overlay #\\d+$")

    enum class DisplayClass { SHELL_OWNED, CONTAINER_APP, LEGIT_CAST_OEM, DEV_SIMULATE, UNKNOWN }

    /** 单块显示器的采集快照（Android 面由 collector 组装；flags 为 Display.getFlags() 原始 int） */
    data class DisplaySnapshot(
        val displayId: Int,
        val name: String?,
        val flags: Int,
        val isSelf: Boolean,
    )

    /** 横向分类上下文（与单屏无关的共现信号） */
    data class ClassifyContext(
        val overlaySimulateSetting: String?,       // Settings.Global "overlay_display_devices"（hidden 常量→字符串键读）
        val adbPresent: Boolean,                   // 同 scan ADB 姿态在场
        val castRouteNames: Set<String> = emptySet(), // MediaRouter 活跃路由名
    )

    data class Classification(
        val cls: DisplayClass,
        val chain: List<String>,
    )

    /**
     * 逐屏独立分类。pattern 参数带生产默认值，测试可注入样例特征
     * （CONTAINER/LEGIT 生产表为空——按「不入未实证特征」纪律，测试样本不算实证）。
     */
    fun classify(
        snapshot: DisplaySnapshot,
        ctx: ClassifyContext,
        shellNames: List<String> = SHELL_DISPLAY_NAMES,
        containerPatterns: List<Regex> = CONTAINER_DISPLAY_PATTERNS,
        legitPatterns: List<Regex> = LEGIT_CAST_PATTERNS,
    ): Classification {
        val chain = mutableListOf<String>()
        val n = snapshot.name.orEmpty()

        // 1) shell-owned：名称直命中（scrcpy vhd 建屏名硬编码，未提供改名面）
        if (shellNames.any { n.equals(it, ignoreCase = true) }) {
            chain += "name='$n' ∈ SHELL_DISPLAY_NAMES"
            return Classification(DisplayClass.SHELL_OWNED, chain)
        }
        // 2) container-app：容器建屏特征
        containerPatterns.firstOrNull { it.containsMatchIn(n) }?.let {
            chain += "name='$n' ~ CONTAINER_DISPLAY_PATTERNS"
            return Classification(DisplayClass.CONTAINER_APP, chain)
        }
        // 3) legit-cast-oem：白名单特征 或 活跃投屏路由名与屏名互证
        if (legitPatterns.any { it.containsMatchIn(n) } || ctx.castRouteNames.any { it.equals(n, ignoreCase = true) }) {
            chain += "name='$n' ∈ LEGIT_CAST_PATTERNS/routes(${ctx.castRouteNames.joinToString("|")})"
            return Classification(DisplayClass.LEGIT_CAST_OEM, chain)
        }
        // 4) dev-simulate：Overlay #N 名称（设置键互证情况记入判定链）
        if (DEV_SIMULATE_NAME.matches(n)) {
            val corrob = !ctx.overlaySimulateSetting.isNullOrBlank()
            chain += "name='$n' ~ Overlay#N" +
                (if (corrob) " + overlay_display_devices='${ctx.overlaySimulateSetting}'（双证）" else "（设置键未开，名称单证）")
            return Classification(DisplayClass.DEV_SIMULATE, chain)
        }
        // 5) unknown 兜底：flags 原始值入链供回放；adb 共现只记旁证不单独归因
        chain += "name='$n' flags=0x${snapshot.flags.toString(16)} displayId=${snapshot.displayId} 无特征命中"
        if (ctx.adbPresent) chain += "adb 姿态在场（shell 建屏旁证，不据此归因）"
        return Classification(DisplayClass.UNKNOWN, chain)
    }

    /** 复合 B 判定：自身位于 shell-owned 屏 且 ADB 姿态在场（spec R3 唯一例外路径） */
    fun compositeShellControl(selfClass: DisplayClass?, adbPresent: Boolean): Boolean =
        selfClass == DisplayClass.SHELL_OWNED && adbPresent
}
