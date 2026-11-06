# 验证后修复记录（2026-11-06）

对应《验证报告》issue 编号：

| Issue | 处置 | 证据 |
|---|---|---|
| WARNING#7 supercall magic 数据化 | ✅ 修复：`SupercallSpec`(core:model) + `BundledSignatureDb.toSupercallSpecs` + `BehaviorCollector(supercalls)` 工厂 + `ScanOrchestrator` 全量接线 | 编译绿 + behavior-probe 测试绿 |
| CRITICAL#3 改写桩测试 | ✅ 修复：`CodeIntegrityMutationTest`（篡改磁盘副本 prologue → A 级命中；未篡改对照零命中） | 设备 21/21 |
| WARNING#9 证明设备冒烟 | ✅ 修复：`AttestationDeviceSmokeTest`（真实链发起+解析+challenge 回显；无锚优雅降级不误报） | 设备 21/21 |
| SUGGESTION#12 导出/导入 UI 入口 | ✅ 修复：`导出报告`/`导入特征` 按钮 + OpenDocument 选择器 + 导入即重建引擎（装载即生效） | GUI T5：文件落盘+JSON 结构核验 |
| SUGGESTION#11 默认条目内嵌 | 未处置（SUGGESTION 级；生产装配已走 SignatureDb，默认值仅测试兜底） | — |
| CRITICAL 1.4/8.2/8.3、3.6/3.7 其余 | 环境依赖（真机/NEON），维持挂账 | docs/REGRESSION.md |
