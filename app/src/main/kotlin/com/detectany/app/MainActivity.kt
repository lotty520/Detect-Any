package com.detectany.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.ViewModule
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.detectany.app.ui.EvidenceScreen
import com.detectany.app.ui.theme.DetectAnyTheme
import com.detectany.app.ui.ModulesScreen
import com.detectany.app.ui.ScanController
import com.detectany.app.ui.ScanScreen
import com.detectany.app.ui.SettingsScreen

class MainActivity : ComponentActivity() {

    /** API 34+ 系统录屏回调注销句柄（onStart 注册 / onStop 注销，状态留存于 Monitor）。 */
    private var screenRecordingHandle: AutoCloseable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 2026-11-11 华为修复：EMUI(API 31) 沉浸式下系统栏覆盖内容。
        // 显式 edge-to-edge + 让 M3 Scaffold/TopAppBar/NavigationBar 各自消费 insets
        // （跨版本一致行为：模拟器 35 与华为 31 均正常）
        this.enableEdgeToEdge()
        val orchestrator = ScanOrchestrator(applicationContext)
        setContent {
            DetectAnyTheme {
                Surface {
                    AppShell(orchestrator)
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        // mainExecutor 需 API 28；register 内部门控 API 34+，<34 直接返回 null
        // 不触达 executor——但为满足 minSdk 24 静态契约，改用等价构建
        val executor = if (android.os.Build.VERSION.SDK_INT >= 28) mainExecutor
        else java.util.concurrent.Executors.newSingleThreadExecutor()
        screenRecordingHandle = com.detectany.collectors.screenshare.ScreenRecordingMonitor
            .register(this, executor)
    }

    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        runCatching { com.detectany.collectors.screenshare.InputEventMonitor.onMotionEvent(ev) }
        return super.dispatchTouchEvent(ev)
    }

    override fun onStop() {
        screenRecordingHandle?.close()
        screenRecordingHandle = null
        super.onStop()
    }
}

private data class Tab(val route: String, val labelRes: Int, val icon: ImageVector)

private val TABS = listOf(
    Tab("scan", R.string.tab_scan, Icons.Filled.Radar),
    Tab("evidence", R.string.tab_threats, Icons.Filled.BugReport),
    Tab("modules", R.string.tab_capabilities, Icons.Filled.ViewModule),
    Tab("settings", R.string.tab_settings, Icons.Filled.Settings),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppShell(orchestrator: ScanOrchestrator) {
    val nav = rememberNavController()
    val controller = remember { ScanController(orchestrator) }
    val currentRoute = nav.currentBackStackEntryAsState().value?.destination?.route
    val snackbar = remember { androidx.compose.material3.SnackbarHostState() }

    androidx.compose.runtime.LaunchedEffect(controller.statusLine) {
        controller.statusLine?.let {
            snackbar.showSnackbar(it)
            controller.statusLine = null
        }
    }

    Scaffold(
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    // v18：按页标题（当前 tab 名）；品牌名留驻 About
                    val titleRes = TABS.firstOrNull { it.route == currentRoute }?.labelRes
                    Text(
                        titleRes?.let { stringResource(it) } ?: stringResource(R.string.app_name),
                        style = MaterialTheme.typography.titleLarge,
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
        bottomBar = {
            NavigationBar {
                TABS.forEach { tab ->
                    val selected = currentRoute == tab.route
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            if (selected) return@NavigationBarItem
                            // 先尝试弹栈返回（对已在返回栈中的目的地立即生效，含按钮入口的栈形态）；
                            // 失败（仅在 saved state 中）再走统一导航恢复
                            if (!nav.popBackStack(tab.route, inclusive = false)) {
                                navigateTab(nav, tab.route)
                            }
                        },
                        icon = {
                            if (tab.route == "evidence" && controller.hasFindings) {
                                BadgedBox(badge = { Badge { Text("${controller.reportModel?.findings?.size ?: 0}") } }) {
                                    TabIcon(tab, selected)
                                }
                            } else {
                                TabIcon(tab, selected)
                            }
                        },
                        label = { Text(stringResource(tab.labelRes)) },
                    )
                }
            }
        },
    ) { inner ->
        AppNavHost(nav, controller, Modifier.padding(inner))
    }

}

@Composable
private fun TabIcon(tab: Tab, selected: Boolean) {
    val label = stringResource(tab.labelRes)
    Icon(
        tab.icon,
        contentDescription = label,
        // v18：未选中色走主题 token（原 Color.Gray 死值在深色下偏暗）
        tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/**
 * 统一 tab 导航：popUpTo 起点 + saveState + singleTop + restoreState。
 * 「查看证据」按钮与底部 tab 必须共用——2026-11-06 实证：plain navigate
 * 产生 [scan, evidence] 栈形态后，tab 点击的 popUpTo+restoreState 组合静默失效。
 */
fun navigateTab(nav: NavHostController, route: String) {
    nav.navigate(route) {
        popUpTo(nav.graph.startDestinationId) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

@Composable
private fun AppNavHost(nav: NavHostController, controller: ScanController, modifier: Modifier) {
    NavHost(navController = nav, startDestination = "scan", modifier = modifier) {
        composable(
            "scan",
        ) { ScanScreen(controller, onOpenEvidence = { threat ->
            nav.navigate("evidence" + (threat?.let { "?threat=$it" } ?: "")) {
                popUpTo(nav.graph.startDestinationId) { saveState = true }
                launchSingleTop = true
                restoreState = true
            }
        }, onOpenCapabilities = { navigateTab(nav, "modules") }) }
        composable("evidence" + "?threat={threat}", arguments = listOf(androidx.navigation.navArgument("threat") { nullable = true; defaultValue = null })) { entry ->
            EvidenceScreen(controller, scrollToThreat = entry.arguments?.getString("threat"))
        }
        composable("modules") { ModulesScreen(controller) }
        composable("settings") { SettingsScreen(controller) }
    }
}
