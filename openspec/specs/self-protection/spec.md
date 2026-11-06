# self-protection Specification

## Purpose

应用自保护能力：自身完整性与签名校验、反调试、分体混淆与静默延迟响应，保证检测结论在被攻击环境下尽可能可信。

## Requirements

### Requirement: 自身完整性校验
应用 SHALL 在 native 层校验自身 APK 签名摘要与关键代码 CRC，预期值 MUST 加密分散存储；校验失败 MUST 产出 `repackaged` 类证据。

#### Scenario: 重打包被检出
- **WHEN** 应用被重签名重打包
- **THEN** 签名摘要与预期值不符并输出 repackaged 证据

### Requirement: 反调试
应用 SHALL 监测自身 TracerPid 状态并支持子进程反查父进程，被调试时产出证据并记录。

#### Scenario: 被调试器附加
- **WHEN** 进程被调试器附加
- **THEN** TracerPid 观测异常并进入证据向量

### Requirement: 静默延迟响应
检出篡改或调试时，应用 SHALL 静默记分并可延迟响应，MUST NOT 即时崩溃或弹出可被攻击者用作定位反馈的提示。

#### Scenario: 检测逻辑被篡改不崩溃
- **WHEN** 检测相关逻辑被运行时篡改
- **THEN** 应用不立即崩溃，异常进入报告证据

### Requirement: 分体与分散
采集、判定与自保护逻辑 SHALL 分体混淆且检测点分散布置，单点修补 MUST NOT 使全部检测失效。

#### Scenario: 单点 patch 不致瘫
- **WHEN** 攻击者成功 patch 单一检测点
- **THEN** 其余分散检测点与完整性校验仍产出异常证据
