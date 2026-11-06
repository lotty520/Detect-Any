# Spec Delta

## Purpose

定义检测特征数据（路径表、包名与 APK 内容指纹、supercall magic 表、socket 名表、keybox 黑名单、机型基线）的存储、签名验证与热更新机制，使特征与 App 发版解耦。

## ADDED Requirements

### Requirement: 内置签名基线
应用 SHALL 内置一份经签名验证的特征基线，保证离线首次使用即可完成标准档扫描。

#### Scenario: 离线首扫
- **WHEN** 应用首次安装且无网络
- **THEN** L2 扫描使用内置基线正常完成

### Requirement: 增量热更新
特征数据 SHALL 支持增量下发，单次增量 MUST NOT 超过 200KB；更新包 MUST 经内置公钥的签名验证，验证失败时 MUST 拒绝装载并保留旧版本。

#### Scenario: 签名无效的更新被拒
- **WHEN** 收到签名验证失败的特征更新
- **THEN** 更新被拒绝且当前生效版本不变

#### Scenario: 更新立即生效
- **WHEN** 合法增量更新装载完成
- **THEN** 下一次扫描即使用新特征，无需重启应用或发版

### Requirement: 条目版本化与置信标注
每个特征条目 MUST 携带适用框架版本区间（since/until）与置信级别（A/B/C）；条目因框架版本演进失效时 MUST 通过数据更新停用，MUST NOT 要求代码变更。

#### Scenario: 失效条目停用
- **WHEN** 某框架新版本移除了某静态特征且特征数据将该条目标记 until
- **THEN** 该条目停止参与判定，其余条目不受影响

### Requirement: 通道无关的数据格式
特征数据的格式与验证逻辑 MUST 与下发通道无关（在线拉取、文件导入等价）。

#### Scenario: 手动导入等价在线更新
- **WHEN** 用户手动导入一份签名合法的特征文件
- **THEN** 其验证、装载与生效行为与在线更新完全一致
