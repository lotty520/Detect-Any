# Detect-Any 能力边界声明

> 本文件为对外材料必读（change add-detect-any-app / specs 各能力「能力边界」条款）。
> 结论：检测是概率性的证据组合，不是单点绝对判定。

## 明确不承诺客户端检出的场景

| 场景 | 原因 | 兜底路径 |
|---|---|---|
| **KPM（内核补丁模块）存在性** | KPM 为纯内核态 ELF，加载/控制全部经 supercall（需 superkey），无用户态进程与驻留文件。公开文献不存在用户态 KPM 检测器 | C9 硬件证明（TrickyStore 类伪造会被证明链交叉捕获）；KPM 本体不做任何检出承诺 |
| **susfs 完整配置下的部分静态痕迹** | susfs 的 sus_path/sus_mount/sus_kstat 可对非 SU 进程隐藏挂载与统计字段 | 三路一致性残差（libc vs svc 的 stat/statfs 字段级发散 → `mount.fstype_cross`）、挂载数基线偏离（`mount.too_clean`）、证明交叉。验收按对抗组「组合风险分捕获 ≥85%」口径，非单信号 100% |
| **Play Integrity / 服务端图谱联合判定（L3 完整形态）** | 属 Phase 2 服务端（keybox 复用图谱、Integrity 解码通道） | 当前 C9 离线校验（双根锚定 + CRL + 字段交叉）已可用；服务端装配后升级 |

## 检出的概率性本质

- 全部 B/C 级信号都会被针对（军备竞赛）；长期有效性锚定三类物理不变量：
  指令字节（prologue/GOT）、syscall 行为（三路 diff）、keybox 供应链（CRL/序列号）。
- 对外承诺锚定 **L3 组合检出率**，不承诺任何单点特征永久有效。
- rooted 合法用户与定制 ROM 正常用户是真实群体：默认分级响应（提示/降权/限功能），
  不做一刀切断；误处置率验收 <0.1%（干净样本集）。

## 环境相关边界

| 环境 | 边界 |
|---|---|
| Android 7（first_api_level < 26） | key attestation API 可用但硬件链不保证 → 只采集不采信，本地信号兜底（specs/attestation-verify「设备等级降级」） |
| Android 10+ / 现代 targetSdk | /proc/net/unix EACCES → C4 透明降级（ProbeCap 门控），不产生误报 |
| seccomp（Android 8+） | reboot 探针 fork 隔离执行；SIGSYS 死亡 = 不可判定而非证据 |
| 未装配真实 Google 双根 PEM | C9 验证走 Degraded（不采信），绝不误报 Spoof |
| 发布构建未替换 XOR 常量 | 自保护签名/CRC 校验在 debug 构建以当前构建实测值为预期（机制由专项冒烟覆盖） |

## 合规

- 应用枚举走 `<queries>` 声明式（不申报 QUERY_ALL_PACKAGES）。
- 出端数据最小化：属性键仅哈希形态、值脱敏截断（`Redactor`）。
- 遥测默认关闭；FP 申诉样本经结构化导出（ReportExporter）人工回传。
