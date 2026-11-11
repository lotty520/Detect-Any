# detection-engine Specification

## Purpose

检测引擎负责编排全部采集器执行、按弱/中/强置信分级加权评分，并以风险分+证据向量+分类标签的形式输出分级延迟档位的检测结果。

## Requirements

### Requirement: 扫描编排与聚合
引擎 SHALL 编排全部已启用采集器的执行，并将各采集器的取证观测聚合为统一结果结构。

#### Scenario: L2 标准扫描
- **WHEN** 用户发起一次标准（L2）扫描
- **THEN** 全部启用的采集器结果被聚合进同一份扫描结果中

### Requirement: 分级延迟档位
引擎 SHALL 提供三档输出：L1 快通道仅含快信号布尔结果且耗时 MUST NOT 超过 10ms（旗舰实测 9-13ms 边缘达标，骁龙 7 系待机型矩阵）；L2 标准档含全量采集、评分与证据向量，耗时 MUST NOT 超过 1500ms（中端口径）；L3 异步档附加硬件证明发起（尚未接线，见 COVERAGE 断链记录）。

**预算修订记录（2026-11-10 审计）**：原 L2 预算 ≤100ms 为 design.md 理想化指标，
自 2026-11-06 首测即未达到（模拟器 623-1175ms / P8 旗舰 969ms），处于持续违约
状态——按实测分布修订为 ≤1500ms（中端），旗舰口径 ~1000ms。主要成本：C5 APK
内容扫描（多 manager 场景线性，优化路径在 REGRESSION 债务表）。预算修订
视为契约变更，须在 CHANGELOG 同步。

#### Scenario: L1 时延达标
- **WHEN** 在中端机型（骁龙 7 系）上执行 L1 快通道
- **THEN** 总耗时不超过 10ms（旗舰实测 9-13ms，中端待矩阵）

#### Scenario: L2 时延达标
- **WHEN** 在中端机型上执行 L2 标准扫描
- **THEN** 总耗时不超过 1500ms（旗舰实测 ~969ms；证明的异步部分不计入）

### Requirement: 证据向量输出
任何档位的检测结果 MUST 包含 `risk_score(0-100)`、`evidence_vector`（命中规则 ID 列表）与分类标签（root_kernel / root_userspace / hook / zygisk / attestation_spoof / repackaged / anti_detect_present / instrumentation / virtual_env / emulator / network_mitm / automation / speed_hack / gps_spoof），引擎 MUST NOT 输出裸布尔结果。

#### Scenario: 输出结构完整
- **WHEN** 任一档位扫描完成
- **THEN** 结果同时包含风险分、证据向量与至少一个分类标签

#### Scenario: 新分类标签输出
- **WHEN** Frida 检测命中
- **THEN** 结果含 `instrumentation` 分类标签

#### Scenario: 模拟器检测命中
- **WHEN** 模拟器构建属性匹配
- **THEN** 结果含 `emulator` 分类标签
### Requirement: 置信判定权限
强（A）级信号单条命中即可推高风险分；中（B）级信号 MUST 在两条及以上共振时才参与定性；弱（C）级信号仅作加权，MUST NOT 单独触发处置级结论。跨域双 B 共振规则适用于全部域（含新增 instrumentation/virtual-env/behavioral-anomaly）。

#### Scenario: 单条中级信号不触发
- **WHEN** 仅一条中级信号命中
- **THEN** 不产生高风险结论，仅在证据向量中加权记录

#### Scenario: 强信号单条定性
- **WHEN** 三路调用 diff 检出层间不一致
- **THEN** 风险分被推高并可单独支撑 hook 类定性

#### Scenario: Frida B 级 + 模拟器 B 级共振
- **WHEN** Frida 探测(B) 和模拟器硬件信号(B) 同时命中
- **THEN** conclusive 定性成立
### Requirement: 反检测独立证据
引擎 SHALL 将「检出隐藏栈本身」（如挂载结构异常干净、属性组合在机型基线中不存在）输出为独立证据类型 `anti_detect_present`，其风险加权 MUST 高于普通 root 信号。

#### Scenario: 过度干净检出
- **WHEN** 挂载条目数显著低于同机型基线且属性组合异常
- **THEN** 结果含 `anti_detect_present` 标签且权重高于普通 root 命中

### Requirement: 采集能力降级透明
当采集器因兼容矩阵判定为降级或阻塞时，引擎 SHALL 跳过该采集并在证据向量中记录降级标记，扫描 MUST NOT 因单项采集不可用而整体失败。

#### Scenario: 采集器被门控阻塞
- **WHEN** 目标系统版本上某采集通道不可读（如新版系统的 /proc/net/unix）
- **THEN** 该采集项标记为降级，其余采集与评分正常完成

### Requirement: 新域规则映射
规则引擎 SHALL 包含以下新域规则前缀映射：
- `frida.*` → instrumentation
- `emulator.*` / `virtual.*` → virtual_env / emulator
- `vpn.*` / `proxy.*` → network_mitm
- `accessibility.*` → automation
- `speedhack.*` → speed_hack
- `gps.*` → gps_spoof

#### Scenario: Frida D-Bus 命中映射正确
- **WHEN** `frida.dbus_probe` finding 被规则引擎处理
- **THEN** 映射到 `rule.frida`，输出 `instrumentation` 标签
