# Spec Delta

## Purpose

检测引擎负责编排全部采集器执行、按弱/中/强置信分级加权评分，并以风险分+证据向量+分类标签的形式输出分级延迟档位的检测结果。

## ADDED Requirements

### Requirement: 扫描编排与聚合
引擎 SHALL 编排全部已启用采集器的执行，并将各采集器的取证观测聚合为统一结果结构。

#### Scenario: L2 标准扫描
- **WHEN** 用户发起一次标准（L2）扫描
- **THEN** 全部启用的采集器结果被聚合进同一份扫描结果中

### Requirement: 分级延迟档位
引擎 SHALL 提供三档输出：L1 快通道仅含快信号布尔结果且耗时 MUST NOT 超过 10ms；L2 标准档含全量采集、评分与证据向量且耗时 MUST NOT 超过 100ms；L3 异步档附加硬件证明发起。

#### Scenario: L1 时延达标
- **WHEN** 在中端机型（骁龙 7 系）上执行 L1 快通道
- **THEN** 总耗时不超过 10ms

#### Scenario: L2 时延达标
- **WHEN** 在中端机型上执行 L2 标准扫描
- **THEN** 总耗时不超过 100ms（证明的异步部分不计入）

### Requirement: 证据向量输出
任何档位的检测结果 MUST 包含 `risk_score(0-100)`、`evidence_vector`（命中规则 ID 列表）与分类标签（root_kernel / root_userspace / hook / zygisk / attestation_spoof / repackaged / anti_detect_present），引擎 MUST NOT 输出裸布尔结果。

#### Scenario: 输出结构完整
- **WHEN** 任一档位扫描完成
- **THEN** 结果同时包含风险分、证据向量与至少一个分类标签

### Requirement: 置信判定权限
强（A）级信号单条命中即可推高风险分；中（B）级信号 MUST 在两条及以上共振时才参与定性；弱（C）级信号仅作加权，MUST NOT 单独触发任何处置级结论。

#### Scenario: 单条中级信号不触发
- **WHEN** 仅一条中级信号命中（如单个特征路径）
- **THEN** 不产生高风险结论，仅在证据向量中加权记录

#### Scenario: 强信号单条定性
- **WHEN** 三路调用 diff 检出层间不一致（强信号）
- **THEN** 风险分被推高并可单独支撑 hook 类定性

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
