package com.detectany.app.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.detectany.app.BuildConfig
import com.detectany.app.R

/** 设置页：导出/导入、能力边界、版本。 */
@Composable
fun SettingsScreen(controller: ScanController) {
    val context = LocalContext.current
    var feedback by remember { mutableStateOf<String?>(null) }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            feedback = context.getString(R.string.import_cancelled)
        } else {
            runCatching {
                context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
            }.getOrNull()?.let { text ->
                controller.importSignature(text)
                feedback = controller.statusLine
            } ?: run { feedback = context.getString(R.string.import_failed) }
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        SettingsCard(stringResource(R.string.settings_data)) {
            OutlinedButton(
                onClick = { feedback = controller.exportReport(context) },
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.medium,
            ) {
                Text(stringResource(R.string.settings_export))
            }
            OutlinedButton(
                onClick = {
                    feedback = context.getString(R.string.import_selecting)
                    importLauncher.launch(arrayOf("application/json", "text/*", "*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.medium,
            ) {
                Text(stringResource(R.string.settings_import))
            }
        }

        SettingsCard(stringResource(R.string.settings_boundaries)) {
            BoundaryRow(stringResource(R.string.boundary_kpm), stringResource(R.string.boundary_kpm_desc))
            BoundaryRow(stringResource(R.string.boundary_susfs), stringResource(R.string.boundary_susfs_desc))
            BoundaryRow(stringResource(R.string.boundary_prob), stringResource(R.string.boundary_prob_desc))
            BoundaryRow(stringResource(R.string.boundary_api24), stringResource(R.string.boundary_api24_desc))
        }

        SettingsCard(stringResource(R.string.settings_about)) {
            // 版本号读 BuildConfig（v0.2.0 bump 后不再手改此处——2026-11-12 审计发现曾滞留 0.1.0）
            Text(
                "Detect-Any ${BuildConfig.VERSION_NAME}",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(
                    R.string.settings_versions,
                    com.detectany.data.signature.BundledSignatureDb.db.version,
                    com.detectany.core.rules.BundledRuleSet.ruleSet.version,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                stringResource(R.string.settings_targets),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        feedback?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    InfoCard(elevation = 1.dp) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            content()
        }
    }
}

@Composable
private fun BoundaryRow(k: String, v: String) {
    ListItem(
        headlineContent = { Text(k, style = MaterialTheme.typography.bodyMedium) },
        supportingContent = { Text(v, style = MaterialTheme.typography.bodySmall) },
    )
}
