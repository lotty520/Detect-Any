# Spec Delta

## MODIFIED Requirements

### Requirement: 采集器框架无关
采集器 SHALL 只输出取证观测（原始事实），MUST NOT 内嵌任何具体框架的判定逻辑或特征常量；新增框架目标 MUST NOT 导致新增采集器。新增：内存编辑器、脚本自动化工具、虚拟机应用、模拟器构建属性模式全部走特征数据热更新，不新增采集器。

#### Scenario: 新框架仅改数据
- **WHEN** 特征数据更新引入一个此前未覆盖的框架
- **THEN** 仅规则与特征数据变化，采集器代码保持不变

#### Scenario: 新作弊工具仅改数据
- **WHEN** 特征数据更新引入 GameGuardian / Lucky Patcher / VMOS / 模拟器等新条目
- **THEN** 仅特征数据与规则变化，采集器代码保持不变

### Requirement: 应用指纹覆盖作弊工具
C5 应用指纹采集 SHALL 通过特征数据覆盖以下作弊工具类别：
- 内存编辑器（GameGuardian guardian.aurora、Cheat Engine ceserver、八门神器、烧饼修改器、葫芦侠）
- 脚本自动化（AutoX.js、EasyClick、按键精灵、触动精灵、MacroDroid）
- 虚拟机/沙箱（VMOS、光速虚拟机、X8 Sandbox、Parallel Space、VirtualXposed）
- IAP 破解（Lucky Patcher）
- SSL 绕过（JustTrustMe、Zygisk-SSL-Unpinning）

#### Scenario: GameGuardian detected via package
- **WHEN** guardian.aurora is installed
- **THEN** C5 produces B-grade memory editor finding

#### Scenario: VMOS detected via package
- **WHEN** com.vmos.* is installed
- **THEN** C5 produces B-grade virtual environment finding

## ADDED Requirements

### Requirement: 模拟器构建属性模式
特征数据 SHALL 包含模拟器构建属性匹配模式（Build.FINGERPRINT/MODEL/PRODUCT/HARDWARE/BRAND 的已知模拟器字符串），供 C2 虚拟环境采集器消费。

#### Scenario: 模拟器特征模式可热更新
- **WHEN** 新模拟器发布并添加到特征数据
- **THEN** 无需代码变更即可检测
