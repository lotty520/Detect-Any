package com.detectany.app.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ListItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

/** 设置页：导出/导入、能力边界、版本。 */
@Composable
fun SettingsScreen(controller: ScanController) {
    val context = LocalContext.current
    var feedback by remember { mutableStateOf<String?>(null) }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            feedback = "Import cancelled"
        } else {
            runCatching {
                context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
            }.getOrNull()?.let { text ->
                controller.importSignature(text)
                feedback = controller.statusLine
            } ?: run { feedback = "Import failed: cannot read file" }
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        SettingsCard("Data") {
            OutlinedButton(onClick = { feedback = controller.exportReport(context) }, modifier = Modifier.fillMaxWidth()) {
                Text("Export structured report (redacted JSON)")
            }
            OutlinedButton(
                onClick = {
                    feedback = "Select signature file…"
                    importLauncher.launch(arrayOf("application/json", "text/*", "*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Import signature update (ed25519-signed, instant)")
            }
        }

        SettingsCard("Capability Boundaries (public commitments)") {
            BoundaryRow("KPM (Kernel Patch Module)", "Not detectable from userspace — no detection promise, hardware attestation as backstop")
            BoundaryRow("Full susfs configuration", "Some static traces not promised; accepted via adversarial-combo capture rate")
            BoundaryRow("Probabilistic detection", "Verdicts anchor to evidence combinations (STRONG/MED/WEAK resonance), not single-point absolutes")
            BoundaryRow("Android 7 attestation", "Collect-but-dont-trust when hardware chain unassured; local signals as backstop")
        }

        SettingsCard("About") {
            Text("Detect-Any 0.1.0", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
            Text(
                "Signature DB v${com.detectany.data.signature.BundledSignatureDb.db.version} · Rules v${com.detectany.core.rules.BundledRuleSet.ruleSet.version} · online channel pending",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "25+ targets: Magisk / KernelSU family / APatch / ZN / ReZygisk / LSPosed / LSPatch / TrickyStore / susfs / Shamiko / PIF / Frida / emulators / spoofing tools",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        feedback?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        }
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    Card(
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
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
