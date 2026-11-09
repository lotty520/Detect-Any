# Design

## Context

2026-11-09 威胁模型（docs/CHEATING_THREAT_MODEL.md）识别 6 个检测缺口域、80+ 工具。本 change 补齐 P0（Frida/VM/内存编辑器）+ P1（模拟器/MITM/自动化/速度），新增 3 个采集器模块 + 扩展 2 个既有能力。

## Goals / Non-Goals

**Goals:**
- 覆盖全部 11 个作弊域（从 5/11 → 11/11）
- Frida 检测在反检测分叉（hluda/Florida）下仍然有效（不依赖字符串/端口）
- 虚拟环境检测覆盖 VirtualApp 商业版 seccomp-bpf 遮蔽场景
- 新采集器融入并行引擎（L2 ≤1.5s 增量预算）
- 特征库 v4：30+ 新条目全部可热更新

**Non-Goals:**
- 不做服务端行为分析（客户端范围外）
- 不做 KPM 检测（物理不可行，既有边界）
- 不做云手机指纹库（主要依赖服务端 IP/行为信号）
- 不做 HID 硬件级输入检测（Bot.Js Pro，仅有行为信号，属服务端域）

## Decisions

### D1. 模块架构：3 新采集器 + 扩展现有 C5

```
新增模块：
  collectors/instrument-probe/  → C9: Frida D-Bus + maps + behavioral
  collectors/virtual-env/        → C10: emulator props + sensors + GL + container
  collectors/screen-share/       → C11: scrcpy + ADB + remote desktop + overlay + input injection
  collectors/behavior-check/     → C12: VPN + proxy + accessibility + clock + GPS

扩展模块：
  collectors/app-fingerprint/    → C5 新增 30+ 条目（内存编辑器/脚本/VM/IAP）
```

**Rationale**: 保持「采集器框架无关」原则——Frida/VM/作弊工具的特征常量全部走特征库 v4，采集器只做取证。C5 已有完善的包枚举+内容指纹基础设施，直接扩展。

**Alternatives**: 把 Frida 检测并入 C8 行为探针 → 放弃：C8 已聚焦内核 syscall 探测，混入应用层网络探测/线程扫描违反单一职责。

### D2. Frida 检测策略：三层防线

| 层 | 方法 | 抗对抗 |
|---|---|---|
| L1 字符串 | maps 扫 frida-agent/linjector; 线程名扫 gum-js-loop | ❌ hluda 重命名即失效 |
| L2 协议 | 全端口 D-Bus AUTH 探测（`\0AUTH\r\n` → 响应模式匹配） | ✅ 重命名不影响协议行为 |
| L3 行为 | 注入页 RWX 特征扫描（连续 RWX 页 + 特定大小/对齐模式） | ✅ 物理特征，不可伪装 |

**Rationale**: 调研实证 hluda/Florida 重命名所有字符串/符号/线程名，字符串层必然失效。D-Bus 协议是 Frida 通信层的物理需求（不可改名）；RWX 页权限特征是 agent 注入的内存布局必然产物。

### D3. 虚拟环境检测策略：四维交叉

| 维度 | 检测点 | 置信 |
|---|---|---|
| 构建属性 | Build.FINGERPRINT 含 generic/sdk_gphone/vbox/nox/goldfish | B |
| 硬件痕迹 | /dev/qemu_pipe, /dev/vboxguest, 传感器缺失, 基带缺失 | A |
| 容器特征 | data-dir 路径异常, getPackageCodePath ≠ sourceDir | B |
| 渲染器 | GL_RENDERER 含 Translator/SwiftShader/Bluestacks | B |

**Rationale**: 单一维度可被商业 VA 引擎（seccomp-bpf 遮蔽 /proc）绕过；四维同时命中的组合概率在真机上趋零。

### D4. 行为检测：全被动、零 syscall 开销

VPN/代理/无障碍/GPS/时钟全部使用 Android Framework API 或系统设置读取——不发起任何网络请求、不执行特权 syscall。多时钟一致性检测在 100ms 窗口内采样三个时钟源差值。

### D5. 评分与分类扩展

```
新增分类标签:
  INSTRUMENTATION    ← Frida/objection/Il2Cpp hooks
  VIRTUAL_ENV        ← VA/VMOS/LightSpeed containers
  EMULATOR           ← 模拟器硬件/构建属性
  NETWORK_MITM       ← VPN/proxy/CA 证书
  AUTOMATION         ← 无障碍自动化/脚本引擎
  SPEED_HACK         ← 多时钟不一致

新域 B 级信号适用跨域双 B 共振（与既有规则一致）
```

## Risks / Trade-offs

- [Frida D-Bus 全端口探测增加时延] → 限制扫描本进程监听端口 + 常见端口范围（1024-65535 子集），预估 ≤50ms
- [模拟器检测误报定制 ROM] → 构建属性模式仅作 B 级；传感器/基带缺失才 A 级
- [无障碍服务检测误报合法辅助工具] → 仅对已知自动化包名 B 级，未知服务 C 级不单独定性
- [多时钟检测在低端设备上漂移] → 阈值设为 50ms/1s（调研正常漂移 <5ms），留 10x 余量
