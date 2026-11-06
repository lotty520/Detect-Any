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
            feedback = "已取消导入"
        } else {
            runCatching {
                context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
            }.getOrNull()?.let { text ->
                controller.importSignature(text)
                feedback = controller.statusLine
            } ?: run { feedback = "导入失败：无法读取文件" }
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("设置与运维", style = MaterialTheme.typography.headlineSmall)

        SettingsCard("数据") {
            OutlinedButton(onClick = { feedback = controller.exportReport(context) }, modifier = Modifier.fillMaxWidth()) {
                Text("导出结构化报告（脱敏 JSON）")
            }
            OutlinedButton(
                onClick = {
                    feedback = "选择特征文件…"
                    importLauncher.launch(arrayOf("application/json", "text/*", "*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("导入特征更新（ed25519 签名，即时生效）")
            }
        }

        SettingsCard("能力边界（对外承诺口径）") {
            BoundaryRow("KPM 内核补丁模块", "用户态不可检——不做检出承诺，硬件证明兜底")
            BoundaryRow("susfs 完整配置", "部分静态痕迹不承诺，按对抗组合捕获率验收")
            BoundaryRow("检测概率性", "结论锚定证据组合（强/中/弱共振），非单点绝对判定")
            BoundaryRow("Android 7 证明", "硬件链不保证时只采集不采信，本地信号兜底")
        }

        SettingsCard("关于") {
            Text("Detect-Any 0.1.0", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
            Text(
                "特征库 v${com.detectany.data.signature.BundledSignatureDb.db.version} · 规则库 v${com.detectany.core.rules.BundledRuleSet.ruleSet.version} · 更新通道未装配",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "覆盖 13 项目标：Magisk / KernelSU 系 / APatch / ZN / ReZygisk / LSPosed / LSPatch / TrickyStore / susfs / Shamiko / PIF 系",
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
    Column {
        Text(k, style = MaterialTheme.typography.bodyMedium)
        Text(v, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
