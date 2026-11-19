# Spec Delta

## ADDED Requirements

### Requirement: Virtual display enumeration and classification

系统 SHALL 枚举全部非默认 Display（`DisplayManager.getDisplays()`）并记录自身 Activity 所在 displayId；每个非默认 Display MUST 被归入五类之一：`shell-owned`（shell/adb 身份创建，如 scrcpy vhd）、`container-app`（多开/虚拟化引擎 app 创建）、`legit-cast-oem`（系统投屏/DeX/OEM 副屏）、`dev-simulate`（开发者模拟副屏，`Settings.Global` overlay 标志）、`unknown`（无法归因）。

#### Scenario: scrcpy 虚拟屏被枚举并归类

- **WHEN** scrcpy 以 `--new-display` 模式运行且本 app 被启动到该虚拟屏
- **THEN** 采集器枚举到该 Display 并归入 `shell-owned` 类（或与 ADB 会话并存的 `unknown`），类别字段出现在采集结果中

#### Scenario: 默认屏运行

- **WHEN** app 运行于 `Display.DEFAULT_DISPLAY` 且系统中无其他 Display
- **THEN** 不产出任何虚拟显示器相关 finding

### Requirement: 非默认显示器姿态信号

app 自身运行于非默认显示器且该显示器类别**非** `legit-cast-oem` 时，系统 SHALL 产出虚拟显示器姿态 finding；`legit-cast-oem` 类 MUST NOT 产出定性 finding（仅可计入 C 级观察或不出 finding，依机型基线）。

#### Scenario: 运行于未归因虚拟屏

- **WHEN** 自身 Activity displayId ≠ DEFAULT_DISPLAY 且类别为 `unknown`
- **THEN** 产出 C 级姿态 finding（weight-only，不参与定性）

#### Scenario: 合法投屏不误报

- **WHEN** app 被投屏到 Chromecast/DeX 等系统合法外接屏（类别 `legit-cast-oem`）
- **THEN** 不产出定性 finding

### Requirement: 分类定级纪律（矩阵前置）

虚拟显示器**单信号**（该显示器本身的存在与类别）在未通过 fp_certify 多厂商矩阵（≥2 厂商干净真机 + 合法状态矩阵「外接显示器/投屏激活」行）核验前，MUST NOT 高于 C 级。唯一例外是**复合信号**：自身运行于 `shell-owned` 虚拟屏 **且** 同 scan 存在 ADB 会话姿态（两个独立信号族共现，均由 C12 采集）时，SHALL 产出一条 B 级「shell 建屏远程操控」复合 finding；其定性路径复用 ScoreModel 既有共振规则（同域 B+C 或任意两条 B，2026-11-06 校准语义），不新增定性机制。

#### Scenario: 复合信号 B 级

- **WHEN** 自身运行于 `shell-owned` 虚拟屏 且 ADB 会话姿态 finding 同 scan 存在
- **THEN** C12 产出一条 B 级「shell 建屏远程操控」复合 finding，evidence 同时携带两族信号判定链

#### Scenario: 未经矩阵核验单信号不升 B

- **WHEN** 某类别仅有单厂商或零真机验证数据，且无 ADB 姿态共现
- **THEN** 该类别信号保持 C 级，不参与定性

### Requirement: 分类证据可回放

每条虚拟显示器 finding 的 evidence MUST 携带：displayId、Display 名称、flags、分类判定链（命中了哪个特征、按什么优先级归入该类），满足证据回放要求。

#### Scenario: 证据回放

- **WHEN** 用户在 Threats 页展开一条虚拟显示器 finding
- **THEN** 可看到 displayId/名称/flags 与「特征命中 → 类别」的完整判定链

### Requirement: 分类特征表可维护

分类器的名称/flags/路由特征 SHALL 维护在特征数据（signature DB 或 calibration 表）中，新增合法形态（新 OEM 副屏/新投屏方案）MUST 通过数据更新而非代码变更完成，且伴随特征库版本 bump。

#### Scenario: 新投屏方案入库

- **WHEN** 某新投屏方案的 Display 特征需要加入 `legit-cast-oem` 白名单
- **THEN** 仅更新特征数据并 bump 版本，无采集器代码变更
