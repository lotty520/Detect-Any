# Spec Delta

## MODIFIED Requirements

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

## ADDED Requirements

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
