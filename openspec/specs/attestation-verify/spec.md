# attestation-verify Specification

## Purpose

硬件证明能力：发起带随机 nonce 的 key attestation、离线解析证书链并按 Google 双根与官方 CRL 校验，按设备首发 API 等级分级降级，为 L3 档提供硬件信任锚。

## Requirements

### Requirement: 证明发起与取链
应用 SHALL 以本地生成的随机 nonce 发起硬件密钥 attestation，并获取完整证书链用于校验。

#### Scenario: 支持设备取链
- **WHEN** 设备密钥库支持 attestation
- **THEN** 返回携带 nonce 回显的完整证书链

### Requirement: 根锚定与硬件判定
证书链校验 MUST 只信任 Google attestation 双根（旧 RSA 根与 2026-02 起新启用的 ECDSA 根并存）；链根不匹配或安全级别为软件实现的结果 MUST 判为「无硬件证明」，MUST NOT 作为信任依据。

#### Scenario: 软件 attestation 不被采信
- **WHEN** 证书链由软件 attestation 密钥（AOSP 公开密钥）签出
- **THEN** 结果标注为无硬件证明，仅作采集信号

### Requirement: 链校验规则
校验 MUST 只采信链上第一个出现的 attestation 扩展；MUST 对链上每张证书执行 CRL 吊销检查；attestationApplicationId MUST 与应用自身包名和签名摘要绑定。

#### Scenario: 追加伪造叶子被拒
- **WHEN** 攻击者在合法链尾追加自签叶子证书
- **THEN** 追加的 attestation 扩展不被采信

#### Scenario: 应用绑定不匹配
- **WHEN** 证书扩展中的应用标识与本应用不符（中继）
- **THEN** 校验失败并产出异常证据

### Requirement: CRL 消费与离线快照
应用 SHALL 按官方端点拉取 keybox 吊销状态（遵循缓存控制节流）并维护离线快照；命中吊销序列号 MUST 产出 `attestation_spoof` 类证据。

#### Scenario: 吊销序列号命中
- **WHEN** 证书链中的序列号存在于 CRL
- **THEN** 输出 attestation_spoof 证据并推高风险分

### Requirement: 设备等级降级
当设备 `ro.product.first_api_level` 低于 26 或链根不满足硬件锚定时，证明结果 MUST 只采集不采信并标注降级，由 L2 本地信号兜底。

#### Scenario: Android 7 设备降级
- **WHEN** 在 7.x 且首发 API 低于 26 的设备上发起证明
- **THEN** 结果标注降级，最终判定不依赖该证明

### Requirement: 证明字段交叉
校验 SHALL 将 RootOfTrust（verifiedBootState、deviceLocked）、补丁级别与 StrongBox 声明同系统声称值及机型能力基线交叉，矛盾时产出异常证据。

#### Scenario: StrongBox 声明越权
- **WHEN** 证明声称 StrongBox 而机型能力库无此能力
- **THEN** 产出能力矛盾证据
