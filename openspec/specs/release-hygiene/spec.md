# release-hygiene Specification

## Purpose

约束 Detect-Any 对外分发面（GitHub Release、README 下载入口、演示资产）的完备性与时效性：访客在任何时刻点进仓库，拿到的 MUST 是与当前代码一致的最新可安装产物，且产物指纹可核验。本能力由 2026-11 发现的「代码 v0.4.2 / Releases 停在 v0.1.1」漂移催生。

## Requirements

### Requirement: Tag release 资产完备

每个语义化版本 git tag 对应的 GitHub Release MUST 携带可安装 APK 资产与 changelog；changelog MUST 按新增检测、FP 修复、其他变更分组。

#### Scenario: v0.4.2 发布完备

- **WHEN** 维护者推送 `v0.4.2` tag 并创建 Release
- **THEN** 该 Release 含至少一个可安装 APK 资产，且 notes 按三组结构列出变更

#### Scenario: 缺资产即不达标

- **WHEN** 某 tag 的 Release 只有文字说明、无 APK 资产
- **THEN** 该发布视为违反本契约，校验脚本 MUST 报告 FAIL

### Requirement: APK 指纹随 Release 公示

每个 Release 的 notes MUST 公示其 APK 资产的 SHA-256 指纹，供安全工具用户在安装前核验。

#### Scenario: 下载前可核验

- **WHEN** 用户从 Release 页下载 APK
- **THEN** 用户能在同一页面 notes 中找到该 APK 的 SHA-256 并本地比对

### Requirement: Release 不得落后于代码标签

最新 GitHub Release 的版本 MUST 不落后于仓库最新版本 tag；落后即视为分发面漂移，MUST 在下一次发布前修复。

#### Scenario: 校验脚本检出漂移

- **WHEN** 仓库存在比最新 Release 更新的版本 tag（如 tag `v0.5.0` 而 Release 停在 `v0.4.2`）
- **THEN** 校验脚本以非零退出码报告漂移

#### Scenario: 漂移修复

- **WHEN** 维护者为最新 tag 补齐 Release（含 APK 与 notes）
- **THEN** 校验脚本退出码为 0

### Requirement: README 下载入口指向最新 Release

README 的 APK 下载入口 MUST 使用 `releases/latest` 永久链接形式（或等价自动跟踪机制），使新 Release 发布后无需修改 README 即解析到最新产物。

#### Scenario: 新版本发布后入口自动跟进

- **WHEN** 维护者发布 `v0.5.0` Release 且未改动 README
- **THEN** README 中的下载链接解析到 `v0.5.0` 的 APK 资产

### Requirement: 演示资产随 UI 版本更新

README demo GIF 与 GitHub social preview MUST 反映当前发布版本的 UI 形态；UI 主版本更替进入发布时，两者 MUST 在同一变更内更新。

#### Scenario: UI 改版后资产同步

- **WHEN** 扫描页 UI 从 v18 改版为 v19 并随某 Release 发布
- **THEN** 该 Release 对应的 README GIF 与 social preview 展示 v19 形态

#### Scenario: 资产过期可发现

- **WHEN** 校验脚本比对演示资产的录制版本标记与 README 声明的当前 UI 版本
- **THEN** 两者不一致时输出 WARN 提示维护者更新
