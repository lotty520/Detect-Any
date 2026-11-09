# 准确性与边界问题核对报告

> 逐项审查 close-detection-gaps 全部 5 个 spec 的误报风险、边界条件和准确度问题。

---

## 🔴 CRITICAL — 必须修改后才能实施

### 1. VPN 检测 B 级 → 必须降为 C 级

**Spec**: behavioral-anomaly / VPN transport detection
**问题**: spec 将 VPN 检测定为 B 级。但企业环境 always-on VPN 是常态（Cisco AnyConnect、WireGuard、企业 MDM 强制 VPN），隐私用户日常使用 ProtonVPN/NordVPN。B 级信号参与双 B 共振 → 企业用户 VPN + 模拟器传感器缺失 = 误定性。

**修正**: VPN 存在 MUST 降为 C 级（仅加权）。只有当 VPN 伴随已知 MITM 工具 CA 证书（HTTP Toolkit / Packet Capture 特征证书链）时才升 B 级。

### 2. 传感器缺失不可单独作为模拟器信号

**Spec**: virtual-env-detect / Hardware sensor absence
**问题**: 大量低端手机无陀螺仪（Redmi 9A、Realme C11）；WiFi-only 平板无基带无 SIM；Chromebook 上运行 Android 应用无加速度计。`SensorManager returns zero sensors and TelephonyManager reports no SIM` → **在这些合法设备上全部误报**。

**修正**: 传感器/基带缺失 MUST 与其他维度（构建属性、CPU 架构）共振才产出 Finding。不可单独产出 A 或 B 级信号。

### 3. 无障碍服务枚举的误报白名单

**Spec**: behavioral-anomaly / Accessibility service enumeration
**问题**: 以下全部是合法使用场景，spec 未设白名单：
- **TalkBack**（Android 系统屏幕阅读器，视觉障碍用户必需）
- **密码管理器**（LastPass、1Password、Bitwarden 通过 AccessibilityService 填充）
- **启动器**（Nova Launcher 的手势功能）
- **系统服务**（Android 自身的无障碍快捷方式）
- **开关控制**（Switch Access，运动障碍用户使用）
- **Select to Speak**（系统功能）

**修正**: MUST 维护系统/OEM 无障碍服务白名单（`com.google.android.marvin.*`、`com.android.*`、已知密码管理器包名）。仅对特征库中的已知自动化工具包名出 B 级，白名单外未知服务 C 级且 MUST NOT 参与定性。

### 4. 容器检测 vs 工作资料（Work Profile）

**Spec**: virtual-env-detect / Virtual container detection
**问题**: `data directory path not matching expected package path` 在以下场景误报：
- **企业 Work Profile**（`/data/user/10/` 而非 `/data/user/0/`）—— Island、Shelter、Android 15 Private Space
- **多用户/访客模式**（`/data/user/<id>/`）
- **Android Go 简化存储路径**

**修正**: MUST 区分 `Process.myUserHandle()` 的 userId：0 = 主用户（可检测容器异常），≥10 = 工作资料/副用户（路径差异属正常，不产出 Finding）。同时 `isProfileOwner` / `isDeviceOwner` 存在时抑制容器检测。

---

## 🟡 HIGH — 设计需调整

### 5. RWX 页扫描的 JIT 误报

**Spec**: instrumentation-detect / Frida behavioral fingerprint
**问题**: 连续 RWX 页不唯一于 Frida：
- **ART JIT**：`jit-cache` 映射可能显示为 `rwxp`（取决于 Android 版本与内核配置）
- **V8/Hermes**（React Native、Flutter 应用）：JS 引擎 JIT 创建 RWX 页
- **Unity IL2CPP**：运行时代码生成可能创建 RWX 页
- **某些 GPU 驱动**：着色器编译缓冲

**修正**: RWX 页特征 MUST 加大小/对齐过滤（Frida agent 典型 16KB 连续 RWX + 特定偏移模式），不能仅凭「存在 RWX 页」就出 Finding。建议置信 B 级而非 spec 暗示的 A 级，且 MUST 与 maps 字符串命中共振。

### 6. GL_RENDERER 中 "SwiftShader" 的合法场景

**Spec**: virtual-env-detect / GL renderer fingerprint
**问题**: SwiftShader 是 Google 的软件 GL 渲染器，在以下场景合法使用：
- **Android Go 低端设备**（无硬件 GPU）
- **虚拟化容器**（Waydroid 使用 host 渲染）
- **某些 Chromebook** 的 Android 子系统

**修正**: "SwiftShader" 单独命中 MUST 降为 C 级。"Translator" / "Bluestacks" / "ttVM" / "VBox" 保持 B 级（这些确实只在模拟器中出现）。

### 7. D-Bus 全端口探测的时延与安全风险

**Spec**: instrumentation-detect / D-Bus protocol probe
**问题**:
- **时延**: 扫描 `1024-65535` 全端口在真机上需数秒（connect timeout × 端口数）
- **副作用**: 向系统服务端口发送 `\0AUTH\r\n` 可能触发安全告警或导致某些服务异常
- **隔离进程**: 在 isolated process 中，部分端口可能属于宿主进程

**修正**: MUST 限制扫描范围：(a) 仅本进程 `/proc/net/tcp` 中 LISTEN 状态的端口（非全端口），(b) 常见 Frida 默认端口 + 动态端口范围（32768-60999），(c) connect timeout ≤5ms/端口。预估总时延 ≤100ms。补充「不可对非本进程端口发起探测」约束。

### 8. 多时钟一致性在 DOZE 模式下的边界

**Spec**: behavioral-anomaly / Multi-clock consistency
**问题**:
- **DOZE 模式**: Android 省电模式下 `SystemClock.elapsedRealtime()` 可能暂停（深度休眠时 BOOTTIME 不含休眠时间），而 `System.nanoTime()` 继续走
- **NTP 时间同步**: `currentTimeMillis` 可被 NTP 跳变（±数秒）
- **OEM 时钟实现差异**: 某些 OEM 的 BOOTTIME 实现与标准不一致

**修正**: MUST 排除 `currentTimeMillis`（受 NTP/用户调整影响），仅比较 `elapsedRealtimeNanos`（CLOCK_BOOTTIME） vs `nanoTime`（CLOCK_MONOTONIC）。阈值从 50ms 放宽至 **100ms/1s**（DOZE 唤醒边缘场景余量）。MUST 在检测窗口内保持 CPU 活跃（如自旋短循环）避免 DOZE 干扰。

---

## 🟢 MEDIUM — 实施注意事项

### 9. `gmain` 线程名不唯一于 Frida

**Spec**: instrumentation-detect / Frida artifacts in memory maps
**问题**: `gmain` 是 GLib 主循环的默认线程名——任何使用 GLib 的 native 库（某些 codec、图像处理库）都可能创建 `gmain` 线程。

**修正**: `gmain` 单独出现 MUST NOT 产出 Finding。必须同时命中 `gum-js-loop` **或** `pool-frida` 才产出 B 级。

### 10. Il2Cpp 检测的版本依赖

**Spec**: instrumentation-detect / Il2Cpp hook detection
**问题**: Il2Cpp 内部结构（domain resolver table 偏移、方法指针表布局）随 Unity 版本变化（2019→2022→6.0 各不相同）。不维护版本映射则检测无效。

**修正**: 首版仅做「libil2cpp.so 附近出现异常 RWX 映射」的宽泛检测（B 级），不做精确的 resolver table 遍历。精确遍历列入 Phase 2 待 Unity 版本映射库建立后实施。

### 11. x86 架构检测的合法场景

**Spec**: virtual-env-detect / CPU architecture consistency
**问题**: 合法的 x86 Android 设备存在：Chromebook（x86_64 + Android 子系统）、Intel Nexus Player（历史设备）、部分 Dell/HP Android 平板。

**修正**: x86 CPU 检测 MUST 交叉验证 `Build.DEVICE` 是否在已知 x86 设备白名单中。如果 `Build.CPU_ABI` 声称 ARM 但 `/proc/cpuinfo` 显示 x86 → A 级（架构声明不一致 = 模拟器）；`CPU_ABI` 本来就声明 x86 且设备型号合法 → 不产出 Finding。

### 12. 特征库包名扫描的覆盖局限

**问题**: EasyClick 脚本打包为自定义包名 APK；GameGuardian VIP 支持重命名包名。纯包名扫描对这两类工具无效。

**修正**: 这是已知局限（不是 bug）。在 `docs/CAPABILITY_BOUNDARIES.md` 中声明：包名扫描覆盖标准发行版，定制/重命名版本需依赖行为检测兜底。

---

## 修正后的置信等级分配

| 检测项 | 原 spec 定级 | 修正定级 | 理由 |
|---|---|---|---|
| VPN 存在 | B | **C** | 企业/隐私 VPN 是合法常态 |
| VPN + 已知 MITM CA | — | **B** | 双信号共振 |
| 传感器全部缺失 | 未明确 | **C**（需共振） | 低端设备无传感器 |
| x86 on ARM claim | A | **A**（仅当不一致时） | 必须验证 CPU_ABI 交叉 |
| x86 on x86 device | A | **不产出** | Chromebook 等合法 |
| SwiftShader GL | B | **C** | 低端设备合法使用 |
| Translator/VBox GL | B | **B** | 仅模拟器出现 |
| gmain 线程 | B | **不单独产出** | GLib 合法使用 |
| gum-js-loop + pool-frida | B | **B** | Frida 特有 |
| RWX 页（仅权限特征） | A | **B**（需大小/对齐过滤） | JIT 合法使用 |
| RWX + maps 字符串命中 | — | **A**（共振） | 双信号 |
| 容器路径异常（user=0） | B | **B** | 仅主用户 |
| 容器路径异常（user≥10） | B | **不产出** | Work Profile 合法 |
| 无障碍已知自动化 | B | **B** | |
| 无障碍未知服务 | C | **C**（不参与定性） | TalkBack 等白名单 |
| 时钟差 >100ms/1s | B | **B**（仅 BOOTTIME vs MONOTONIC） | 排除 wall clock |

---

## 🟡 HIGH — 屏幕共享/远程控制域（新增 2026-11-09）

### 13. ADB 启用 ≠ 作弊

**Spec**: screen-share-detect / ADB session indicator
**问题**: 开发者、极客用户、传输文件时经常开启 ADB。仅 `ADB_ENABLED=1` 就出 B 级会对大量技术用户误报。

**修正**: ADB 单独 = C 级。**ADB + USB 已连接 + 游戏前台运行** 三条件同时满足才升 B 级。spec 中的场景「Developer testing (not cheating)」已体现此约束，但需要确保实现严格遵循。

### 14. 远程桌面应用安装 ≠ 正在控制

**Spec**: screen-share-detect / Remote desktop app detection
**问题**: AnyDesk/TeamViewer 也用于合法远程协助（父母手机出问题远程指导）。

**修正**: 包存在 + 无障碍未启用 = C 级（spec 已正确设定）。包存在 + 无障碍已启用 = B 级。不可因「安装了远程桌面」就定性。

### 15. 蓝光过滤器/屏幕调光器的白名单

**Spec**: screen-share-detect / Overlay permission detection
**问题**: Twilight、Night Owl、f.lux 等屏幕过滤器持有 overlay 权限是合法的。Dimple、Assistive Touch 类悬浮球也是。

**修正**: `canDrawOverlays()` 单独 = C 级。MUST 维护已知过滤器/辅助工具白名单。仅当 overlay 权限 + 触摸事件 FLAG_WINDOW_IS_OBSCURED 同时命中时升 B 级。

### 16. API 34/35 屏幕录制回调的版本边界

**Spec**: screen-share-detect / Screen recording detection
**问题**: `addScreenRecordingCallback` 是 API 35，`registerScreenCaptureCallback` 是 API 34。在 minSdk 24 上，绝大部分设备无法使用这些 API。FLAG_SECURE 也可被 root/Xposed hook 绕过。

**修正**: spec 已正确设定为「API 34+，API < 34 回退到无直接信号」。但 MUST NOT 在 API < 34 上对「无法检测屏幕录制」产出任何 Finding（这是能力边界而非检出）。

### 17. 云手机电池/传感器信号的弱点

**问题**: Group-IB 研究指出云手机有真实 ARM 芯片、真实传感器、真实 IMEI——传统模拟器检测全部失效。电池 100% 不放电是弱信号（充电中游玩也 100%）。

**修正**: 电池/传感器信号仅 C 级。云手机的主要检测在服务端（IP/ASN/账号图谱），客户端仅做辅助信号（数据中心 IP 归属地 + OEM 预装应用缺失）。

---

## 新增置信等级分配（screen-share-detect）

| 检测项 | 定级 | 理由 |
|---|---|---|
| scrcpy unix socket | **A** | scrcpy 专属特征 |
| scrcpy HID 设备名 | **A** | scrcpy 专属 |
| app_process scrcpy-server | **A** | scrcpy 专属 |
| ADB + USB + 游戏前台 | **B** | 三条件组合 |
| ADB 单独 | **C** | 开发者常用 |
| 无线调试开启 | **C** | 合法用途 |
| 远程桌面 + 无障碍启用 | **B** | 双信号 |
| 远程桌面安装（无障碍未启用） | **C** | 合法远程协助 |
| FLAG_IS_ACCESSIBILITY_EVENT | **B** | 自动化输入 |
| 虚拟设备输入 | **B** | 合成事件 |
| API 35 录制回调 | **C** | 非独占检测 |
| overlay 权限 + 触摸遮蔽 | **B** | 双信号 |
| overlay 权限（单独） | **C** | 过滤器合法 |
| KittyMemory/Dobby maps 命中 | **A** | 注入证据 |
| 云手机电池/传感器 | **C** | 弱信号 |

---

## 建议的 spec 修改清单

| Spec | Requirement | 修改 |
|---|---|---|
| behavioral-anomaly | VPN | B→C；增加 MITM CA 共振升 B |
| behavioral-anomaly | Accessibility | 增加白名单要求；C 级不参与定性 |
| behavioral-anomaly | Multi-clock | 排除 currentTimeMillis；阈值 50→100ms；保持 CPU 活跃 |
| virtual-env-detect | Sensor absence | 单独不产出；需共振 |
| virtual-env-detect | Container | 排除 user≥10 / Work Profile |
| virtual-env-detect | GL Renderer | SwiftShader→C；其余保持 B |
| virtual-env-detect | CPU Arch | 排除合法 x86 设备 |
| instrumentation-detect | D-Bus probe | 限制扫描范围；≤100ms |
| instrumentation-detect | RWX pages | 加大小/对齐过滤；降为 B |
| instrumentation-detect | Thread names | gmain 不单独产出 |
| instrumentation-detect | Il2Cpp | 首版降为宽泛检测（B） |
| screen-share-detect | ADB indicator | 三条件组合才升 B；单独 C |
| screen-share-detect | Remote desktop | 安装+无障碍=B；仅安装=C |
| screen-share-detect | Overlay | 白名单过滤器；单独 C；+触摸遮蔽=B |
| screen-share-detect | Screen recording | API < 34 不产出 Finding |
