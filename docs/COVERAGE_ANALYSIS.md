# 检测覆盖度分析：三层面 × 四维度交叉矩阵

> 2026-11-09 全量盘点。基于代码实际实现（非 spec 理想态）。

---

## 总览

| 维度 | 覆盖率 | 说明 |
|---|---|---|
| **安装层** | ** █████░░░░ 65%** | 包名/路径覆盖广，但定制包名/免安装工具是盲区 |
| **运行层** | **███████░░░ 78%** | Root/Frida/scrcpy 运行时检测强，内存编辑器/速度篡改待补 |
| **入侵层** | **█████████░ 92%** | 指令级完整性 + 三路 diff + 自保护是核心强项 |
| **设备完整性** | **██████░░░░ 71%** | 模拟器检测全面，GL 渲染器/云手机/定制 ROM 有缺口 |
| **Root 状态** | **██████████ 98%** | 5 种 root 框架全覆盖，KPM 是唯一边界 |
| **姿态** | **████░░░░░░ 55%** | VPN/无障碍已实现，时钟/GPS/输入模式/录制待补 |

---

## 一、三层面交叉分析

### 层面 1：安装（工具已安装但未运行）

| 检测面 | 已覆盖 | 采集器 | 缺口 |
|---|---|---|---|
| **Root 管理器** | Magisk / KSU / KSU-Next / SukiSU / APatch 包名 | C5 | ✅ 完整 |
| **作弊工具** | GameGuardian / Lucky Patcher / 烧饼 / 葫芦侠 / 八门 | C5 特征库 | EasyClick 自定义包名 / GG VIP 重命名 |
| **注入框架** | LSPosed / Vector / TrustMeAlready / NeoZygisk / NyaZygisk | C5 特征库 | Frida server 二进制（未入库）|
| **远程桌面** | AnyDesk / TeamViewer×3 / AirDroid×2 / Vysor / ChromeRemote | C12 包指纹 | ✅ 完整 |
| **文件路径** | /system/bin/su / /data/adb/{ksu,ap,rezygisk,riru} | C1 特征库 | /data/local/tmp/frida-server |
| **虚拟机** | VMOS / Parallel Space / X8 Sandbox / F1 VM | C5 特征库 | 光速虚拟机去虚拟化版 / 大三K |
| **重打包** | APK 签名钉住（A 级） | SelfGuard | ✅ 完整 |

**安装层盲区**：
1. **免安装工具**：Frida server 直接 push 到 `/data/local/tmp`，无需安装 APK
2. **自定义包名**：EasyClick 脚本打包为完全自定义的包名/图标
3. **重命名版**：GameGuardian VIP 支持随机化包名
4. **云手机控制端**：安装在 PC 端，设备上无痕迹

---

### 层面 2：运行（工具正在运行）

| 检测面 | 已覆盖 | 采集器 | 缺口 |
|---|---|---|---|
| **Root supercall** | KSU reboot 双魔数 / APatch syscall45 / 旧 prctl | C8 | ✅ 核心 |
| **SELinux 语义** | magisk / ksu_file / lsposed 域存在性探测 | C8 | ✅ |
| **Frida 运行时** | maps 字符串 / 线程名 / RWX 页 / D-Bus 协议 | C9 | hluda 字符串全部改名时仅剩 RWX + D-Bus |
| **scrcpy 运行时** | unix socket `scrcpy_` / HID 设备名 / ADB 会话 | C12 | `--new-display` 虚拟显示器不可见 |
| **挂载伪装** | overlay 检测 / too-clean / fstype 交叉 / st_dev | C2 | susfs v2.x 用户态 umount 一致化（降权）|
| **内存注入** | maps 注入 memfd / known_path / hidden_mapping / RWX 自探针 | C6 | NyaZygisk 双隐藏（maps + solist）|
| **无障碍自动化** | 已知自动化包 B 级 / 未知 C 级（白名单制） | C11 | 未知服务不参与定性（TalkBack 白名单）|
| **VPN/代理** | TRANSPORT_VPN / proxyHost | C11 | ✅（均 C 级）|
| **NativeBridge** | NativeBridgeError() 粘滞标志 | C8 | ✅ |
| **ptrace 残留** | PTRACE_GETEVENTMSG 父进程 | C8 | NeoZygisk ≥10-30 已清除 |

**运行层盲区**：
1. **内存编辑器扫描行为**：GameGuardian 读取 `/proc/pid/mem` 的行为本身不可从被读进程检测
2. **速度篡改**：多时钟一致性检测已 spec 但未实现（需异步 1s 窗口）
3. **脚本引擎运行**：AutoX.js/EasyClick 运行时无进程特征（在自身 JVM 中执行）
4. **云手机**：真实 ARM 芯片 + 真实传感器，客户端静态检测全部失效

---

### 层面 3：入侵（正在入侵/修改目标进程）

| 检测面 | 已覆盖 | 采集器 | 缺口 |
|---|---|---|---|
| **指令级完整性** | 自身 JNI 入口 prologue 内存 vs 磁盘（**A 级**） | C7 | ✅ 核心强项 |
| **GOT/PLT 完整性** | 槽位解析地址 vs 磁盘期望（排除 IFUNC）（**A 级**） | C7 | ✅ |
| **三路调用 diff** | Java / libc / 裸 svc 结果不一致（**A 级**物理不变量） | C8+C1 | ✅ |
| **Maps 篡改** | RWX 自探针：自建可执行映射不可见 = maps 被 hook（**A 级**） | C6 | ✅ |
| **自身签名** | APK 签名摘要 XOR 分散常量（**A 级**） | SelfGuard | ✅ |
| **DEX CRC** | classes.dex CRC32 校验（B 级） | SelfGuard | ✅ |
| **反调试** | TracerPid + 子进程 PTRACE_ATTACH | SelfGuard | ✅ |
| **重打包检测** | 签名不匹配 = repackaged（A 级） | SelfGuard | ✅ |

**入侵层优势**：这是我们的**最强领域**——全部基于物理不变量（指令字节、syscall 行为、内存布局），不可通过重命名/配置绕过。2026-11-06 Pixel 8 真机实证：作弊环境定向 hook 了全部 5 个检测器 JNI 入口，但 prologue 字节比对仍然检出。

---

## 二、四维度分析

### 维度 A：设备完整性 / 真实性

| 子维度 | 检测方法 | 覆盖 | 缺口 |
|---|---|---|---|
| **模拟器检测** | Build 属性 × 9 模式 / qemu=1 / 硬件节点 × 6 / CPU 架构交叉 | ✅ **A 级** | GL 渲染器未实现 |
| **硬件证明** | Key attestation 双根 / RKP-only / CRL / appKey 绑定 | ✅ **A 级** | Play Integrity 服务端未接入 |
| **定制 ROM** | test-keys / Build.FINGERPRINT vs 基线 | ⬜ **B 级** | 无 OEM 基线数据库 |
| **PIF 伪装** | 成对属性交叉（ro.build vs ro.bootimage） | ✅ **B 级** | 用户可自定义覆盖 |
| **云手机** | — | ⛔ | 客户端不可检测（真实硬件）|
| **设备身份** | IMEI/序列号验证 | ⛔ | 需服务端设备数据库 |
| **Work Profile** | userId ≥ 10 排除 | ✅ 边界处理 | — |

### 维度 B：Root 状态

| 子维度 | 检测方法 | 覆盖 | 缺口 |
|---|---|---|---|
| **Magisk** | 包名 + mount + 属性 + st_dev + SELinux + /debug_ramdisk | ✅ **多路** | — |
| **KernelSU** | supercall + 包名 + ksud + /proc/modules + 基线 | ✅ **多路** | — |
| **KSU-Next/SukiSU** | 包名 + spoofed 内容指纹 | ✅ | — |
| **APatch** | supercall + 包名 + /data/adb/ap | ✅ | — |
| **隐藏栈 susfs** | fstype 交叉 + too-clean + 三路 diff | ⬜ **降权** | v2.x 用户态 umount 一致化 |
| **Shamiko** | too-clean + anti_detect | ⬜ **间接** | 无直接特征 |
| **KPM** | — | ⛔ | **物理不可检测**（内核态，唯一边界）|

### 维度 C：姿态（当前使用状态）

| 子维度 | 检测方法 | 覆盖 | 缺口 |
|---|---|---|---|
| **VPN** | TRANSPORT_VPN | ✅ C 级 | 企业 VPN 误报已校准 |
| **代理** | proxyHost | ✅ C 级 | — |
| **无障碍** | 枚举 + 白名单 + 已知自动化 B 级 | ✅ | — |
| **ADB 调试** | ADB_ENABLED + USB + 前台 三条件 | ✅ B/C 分级 | — |
| **屏幕共享** | scrcpy socket + HID | ✅ **A 级** | `--new-display` 模式不可见 |
| **远程桌面** | 包指纹 + 无障碍双信号 | ✅ B/C 分级 | — |
| **速度篡改** | — | ⛔ | **多时钟一致性未实现** |
| **GPS 伪造** | — | ⛔ | Location.isMock 未实现 |
| **输入模式** | — | ⛔ | 触摸事件行为分析未实现 |
| **屏幕录制** | — | ⛔ | API 34+ 回调未注册 |

### 维度 D：自身防护

| 子维度 | 覆盖 | 说明 |
|---|---|---|
| 签名完整性 | ✅ A 级 | XOR 分散常量 + 常数时间比较 |
| 代码完整性 | ✅ A 级 | prologue 字节比对 |
| 反调试 | ✅ B 级 | TracerPid + 子进程反查 |
| 静默响应 | ✅ | 不崩溃不弹窗 + 延迟回调 |
| 混淆 | ⬜ | 发布期 minify 启用（RUNBOOK 清单）|

---

## 三、覆盖度热力图

```
                    安装    运行    入侵
                  ┌───────┬───────┬───────┐
  Root 管理器     │  ██   │  ██   │  ██   │ ← 全覆盖
  注入框架        │  ██   │  ██   │  ██   │ ← 全覆盖
  Frida          │  ░░   │  ██   │  ██   │ ← 安装层缺 frida-server 路径
  作弊工具        │  ▓▓   │  ░░   │  ░░   │ ← 包名有/运行时无
  虚拟机/模拟器   │  ▓▓   │  ██   │  —    │ ← 安装有缺口
  远程桌面        │  ██   │  ██   │  —    │
  屏幕共享        │  —    │  ██   │  —    │
  网络劫持        │  —    │  ▓▓   │  ░░   │ ← 运行时 C 级/入侵无
  速度篡改        │  —    │  ░░   │  ░░   │ ← 未实现
  内存编辑器      │  ▓▓   │  ░░   │  ░░   │ ← 包名有/运行时无
  自身防护        │  ██   │  ██   │  ██   │ ← 全覆盖
  证明伪造        │  —    │  —    │  ██   │ ← 入侵层强
                  └───────┴───────┴───────┘
  ██ = A/B 级覆盖  ▓▓ = C 级/部分  ░░ = 未实现/缺口
```

---

## 四、关键缺口排序

### 🔴 P0 — 影响核心检测完整性

| # | 缺口 | 影响 | 建议 |
|---|---|---|---|
| G1 | **速度篡改检测**（多时钟一致性） | GameGuardian speed hack 完全不可见 | 实现 BOOTTIME vs MONOTONIC 异步比对（spec 已有） |
| G2 | **GL 渲染器指纹** | 模拟器四维交叉缺一角 | 实现 GLES20.glGetString 查询（spec 已有） |
| G3 | **Frida server 安装路径** | `/data/local/tmp/frida-server` 可作为安装层信号 | C1 特征库加路径条目 |

### 🟡 P1 — 提升覆盖面

| # | 缺口 | 影响 |
|---|---|---|
| G4 | GPS mock 检测 | 位置类作弊不可见 |
| G5 | 屏幕录制回调（API 34+） | 需 Activity 持续注册 |
| G6 | 输入事件行为分析 | 自动化机器人不可见（需持续监听） |
| G7 | OEM 基线数据库 | 定制 ROM 检测依赖 |

### 🟢 P2 — 已知边界（不可客户端检测）

| # | 缺口 | 原因 |
|---|---|---|
| B1 | KPM 内核补丁模块 | 用户态无观测接口 |
| B2 | 云手机 | 真实 ARM 硬件 + 真实传感器 |
| B3 | EasyClick 自定义包名 | 包名完全随机化 |
| B4 | NeoZygisk ptrace 残留清除 | 2026-10-30 起主动清除 |
| B5 | 定制 ROM 指纹 | 需服务端 OEM 基线库 |
