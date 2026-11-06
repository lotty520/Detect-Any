package com.detectany.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.detectany.app.ui.EvidenceScreen
import com.detectany.app.ui.ModulesScreen
import com.detectany.app.ui.ScanController
import com.detectany.app.ui.ScanScreen
import com.detectany.app.ui.SettingsScreen

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val orchestrator = ScanOrchestrator(applicationContext)
        setContent {
            MaterialTheme {
                Surface {
                    AppShell(orchestrator)
                }
            }
        }
    }
}

private data class Tab(val route: String, val label: String, val icon: ImageVector)

private val TABS = listOf(
    Tab("scan", "扫描", Icons.Filled.Radar),
    Tab("evidence", "证据", Icons.Filled.BugReport),
    Tab("modules", "模块", Icons.Filled.ViewModule),
    Tab("settings", "设置", Icons.Filled.Settings),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppShell(orchestrator: ScanOrchestrator) {
    val nav = rememberNavController()
    val controller = remember { ScanController(orchestrator) }
    val currentRoute = nav.currentBackStackEntryAsState().value?.destination?.route

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    val risk = controller.reportModel?.riskScore
                    Text(
                        "Detect-Any",
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    if (risk != null) {
                        Text(
                            "  ·  $risk",
                            color = com.detectany.app.ui.scoreColor(risk),
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            style = MaterialTheme.typography.titleLarge,
                        )
                    }
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
                            nav.navigate(tab.route) {
                                popUpTo(nav.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
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
                        label = { Text(tab.label) },
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
    Icon(
        tab.icon,
        contentDescription = tab.label,
        tint = if (selected) MaterialTheme.colorScheme.primary else Color.Gray,
    )
}

@Composable
private fun AppNavHost(nav: NavHostController, controller: ScanController, modifier: Modifier) {
    NavHost(navController = nav, startDestination = "scan", modifier = modifier) {
        composable("scan") { ScanScreen(controller, onOpenEvidence = { nav.navigate("evidence") }) }
        composable("evidence") { EvidenceScreen(controller) }
        composable("modules") { ModulesScreen(controller) }
        composable("settings") { SettingsScreen(controller) }
    }
}
