# Proposal

## Why

2026 年的 Root/Hook 框架生态已结构性变化：KSU 家族（KernelSU/KernelSU-Next/SukiSU-Ultra）新增使用量约为 Magisk 的 2.3 倍，supercall 接口在 2025-11 整体重写（prctl → reboot 双魔数 + ioctl），spoofed 包名成为官方发行标配，susfs+Shamiko+TrickyStore 构成的隐藏栈可对抗绝大多数静态特征。开源检测器（RootBeer/RootBeerFresh 等）停留在 2023 前时代，商业 SDK 闭源且更新节奏跟不上对抗工具中位 2 天一更的现实。本项目要在 Detect-Any 仓库上构建一个**工业级、模块化、特征数据可热更新**的 Root/Hook 框架检测识别 APP，最低兼容 Android 7（API 24）。前置全网调研（2026-11-04）已完成：修正旧需求规格中 4 项失效假设（prctl 探测、Magisk hide、TrickyStore 渠道误读、attestation API 等级），并新增 8 项 2025-2026 实战验证过的强信号（st_dev 设备号采样、SELinux errno 语义、ptrace 注入残留、class_loaders_ 计数等）。

## What Changes

- **新建 Android APP**（Kotlin + Compose UI，minSdk 24，arm64-v8a/armeabi-v7a 双 ABI，16KB 页对齐）：扫描、报告、证据回放、导出
- **模块化分层架构**：UI 壳 / 检测引擎 / 采集器（C1-C8，框架无关纯取证）/ 规则引擎（JSON 可热更新）/ 特征数据层 / 硬件证明 / 兼容层 / 自保护
- **检测目标 13 项**：Magisk、KernelSU、KernelSU-Next、SukiSU-Ultra、APatch、ZygiskNext、ReZygisk、LSPosed、LSPatch、TrickyStore、susfs、Shamiko、PIF 系
- **弱/中/强三级置信分级**：强=物理不变量（单信号可定性）、中=行为/状态差异（需共振）、弱=静态痕迹（仅加权）；输出 `risk_score + evidence_vector + 分类标签`，禁止裸布尔
- **特征数据热更新**：路径表/包名与 APK 内容指纹/supercall magic 表/socket 名表/keybox 黑名单/机型基线全部服务端下发、签名验证（对抗工具中位 2 天一更，写死特征半衰期以周计）
- **硬件证明（C9）**：key attestation 发起与证书链校验（Google 双根并存 + 官方 CRL + attestationApplicationId 绑定），按 `ro.product.first_api_level` 分级降级
- **Android 7 兼容门控**：版本 × 内核 × targetSdk 三维修度矩阵（statx 禁用、memfd 内核门控、/proc/net/unix 版本门控、linker namespace 全静态链接、TLS 内置 Conscrypt）
- **证据回放/对照视图**（建议默认，待确认）：逐项解释命中原因，支撑 FP 治理与用户信任
- **分叉生态特征条目**（建议默认，待确认）：TeeSimulator、TS-OSS、Vector、NeoZygisk 并入特征库跟踪清单
- **服务端组件为 Phase 2 可选层**（建议默认，待确认）：首版离线优先，Play Integrity 解码与 keybox 复用图谱留待服务端

## Capabilities

### New Capabilities

- `detection-engine`: 扫描编排、弱/中/强置信分级、加权评分、证据向量输出与 L1（≤10ms）/L2（≤100ms）/L3（异步）三档延迟预算
- `signal-collection`: C1-C8 采集器（路径/挂载/属性/网络端点/应用指纹/内存映射/指令完整性/接口行为），框架无关纯取证，按兼容矩阵降级
- `signature-data`: 特征数据的格式、内置基线、增量下发与签名验证、失效条目的版本化管理
- `attestation-verify`: key attestation 证书链校验（双根、CRL、应用绑定、StrongBox 能力交叉）、Play Integrity 集成与 Android 7 降级路径
- `evidence-report`: 报告呈现、证据回放（逐命中项解释）、导出与 FP 申诉样本结构
- `self-protection`: 自身完整性校验（签名/prologue）、反调试、采集与判定的分体混淆、静默记分与延迟响应

### Modified Capabilities

（无——绿地项目，当前 `openspec/specs/` 为空）

## Impact

- **代码**：Detect-Any 仓库当前为空仓库，本 change 建立全部工程结构（Gradle 多模块 + native JNI 层）
- **依赖**：NDK r27+/r28（16KB 对齐）、Conscrypt（Android 7 TLS）、Jetpack Compose；Phase 2 可选服务端（Play Integrity 解码、特征下发通道、复用图谱）
- **能力边界（必须写入对外材料）**：KPM 存在性、susfs 完整配置下部分场景不做客户端检出承诺，由硬件证明与服务端兜底并明示
- **合规**：应用枚举遵守 `<queries>` 声明式方案（QUERY_ALL_PACKAGES 仅按需申报）；出端数据最小化并哈希脱敏
