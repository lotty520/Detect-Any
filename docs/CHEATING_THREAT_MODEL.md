# Android Client-Side Cheating: Complete Threat Model

> Data source: 2026-11-09 deep web research (GitHub, XDA, Chinese security forums, vendor docs).
> Each item: mechanism | detection gap | priority.

---

## Coverage Summary

| Domain | We Detect | Total Known | Gap |
|---|---|---|---|
| Root frameworks | 5+分叉 | 5 | ✅ Complete（KPM 物理边界） |
| Zygisk/Hook injection | 7 | 7 | ✅ Complete |
| Attestation spoofing | 2 | 3 | ⬜ Play Integrity 服务端 |
| Hiding stack（含深隐藏穿透） | 2 | 2 | ✅ Complete（v5/v6 verified boot 矛盾 A 级） |
| Dynamic instrumentation | 全部 | 12 | ✅ Complete（C9 四防线，2026-11 落地） |
| Memory editors | 包级 | 6 | 🟡 运行时扫描行为不可观测 |
| Virtual machines | 包级+容器检测 | 11 | ✅ 安装层 Complete |
| Emulators | 全部 | 8 | ✅ Complete（C10 四维交叉 + 传感器节律） |
| Network MITM | VPN/代理×3/全局 | 8 | ✅ 客户端可达面 Complete |
| IAP cracking | 包级 | 4 | ✅（Lucky Patcher 已核名排除瑞幸） |
| Code injection libs | 入侵层 A 级 | 10 | ✅ prologue/GOT/三路 diff |
| Script automation | 无障碍+包级 | 10 | ✅ B/C 分级 |
| Speed manipulation | 时钟一致性 B | 3 | ✅（G1） |
| GPS spoofing | 包级+地理三方 | 2 | ✅ 安装层（运行时需定位权限不做） |
| Cloud phones | 合围共振可定性 | 6 | 🟡 虚拟外设可检；真实直通服务端（第四批） |
| RAT / malware (BTMOB class) | 辅助信号 | **家族级** | ⛔ 客户端壁垒（B6，见 §12） |

> 2026-11-10 统一刷新：close-detection-gaps 与四批感知扩展落地后的实态。
> 原 2026-11-09 表格的 11 个「We Detect 0」行已全部过时。

---

## 1. Dynamic Instrumentation (Frida ecosystem) — 🔴 P0

### 1.1 Frida Server (rooted)

| Variant | Mechanism | Detection Vectors |
|---|---|---|
| frida-server v17.26.2 | ptrace attach → frida-agent injection | Port 27042 + D-Bus AUTH; maps scan (frida-agent, linjector); thread names (gum-js-loop, gmain, pool-frida) |
| **strongR-frida (hluda)** v17.26.2 | Auto-rebuilt with renamed strings/symbols/thread names | String/port checks **FAIL**; need D-Bus protocol behavior + page-permission characteristics |
| **Florida** v17.26.2 | Same evasion approach | Same as hluda |
| zer0def/undetected-frida | Same, auto-tracks upstream | Same |
| Frida Gadget (no-root) | Embedded in repackaged APK; loads at startup | ✅ We detect via signature pinning; maps scan for frida-gadget.so |
| Objection v1.12.5 | Frida-powered toolkit; `patchapk` embeds gadget | Same as Frida + gadget |

**Key insight**: anti-detection forks defeat all naive string/port checks. Detection must anchor in **D-Bus protocol fingerprinting** (even after rename) and **hook-integrity scans** (trampoline structure).

### 1.2 Il2Cpp Game Hacking

| Tool | Target |
|---|---|
| Il2CppHookScripts (~19k downloads) | Unity games: dynamic IL2CPP parsing for logic tampering |
| frida-il2cpp-bridge | Runtime access to Unity managed heap |

---

## 2. Memory Editors — 🔴 P0

| Tool | Status | Mechanism | Detection |
|---|---|---|---|
| **GameGuardian** v101.4 | **Active again** (2025 revival, Android 5-16, 16KB support) | /proc/pid/mem scanning; speed hack; Lua scripting; overlay UI | Package guardian.aurora; VIP builds rename; /proc access patterns; overlay detection |
| Cheat Engine (ceserver) v7.6 | Active | ceserver on device + PC client via adb:52736 | Rooted + port scan; ceserver process |
| 八门神器 (免root 4.0.5) | Transformed to sandbox platform | Virtual space + value modification | Sandbox/VM detection |
| 烧饼修改器 v20 | Legacy | Memory value search | Package name |
| 葫芦侠 | Declining | Data modify + built-in VM | Package + VM detection |
| CrabDroid | **Unverified** (no public repo found) | Unknown | N/A |

---

## 3. Virtual Machines / Sandbox — 🔴 P0

| Tool | Mechanism | Detection |
|---|---|---|
| **VirtualApp** (commercial) | Binder proxy AMS/PMS; stub Activities; ClassLoader chain; seccomp-bpf masking | Host pkg names; data-dir path anomalies; stack traces with VA classes; hardened: syscall-level /proc verification |
| VirtualXposed | VA + epic hooker | VA artifacts + XposedBridge classloader |
| **Parallel Space** (com.lbe.parallel.*) | LBE VA-derived container | Package scan; container process detection |
| **光速虚拟机** (VPhoneGaGa) | Independent virtual kernel + own memory mgmt | Guest /proc/version nonstandard; ROM build props; "去虚拟化" builds scrub these |
| **VMOS Pro** | Full Android OS-in-app; root toggle inside VM | Guest ROM fingerprints; com.vmos.* packages |
| X8 Sandbox | Guest ROM 5.1/7.1.2; root+Xposed toggles | ROM fingerprint; cn.x8box.* |
| Taichi / 太极 | VA container + epic (免root) or Magisk mode (阳) | Container or Magisk artifacts |
| SandVXposed | VA + SandHook | Container + SandHook artifacts |
| F1 VM / Virtual Master / twoyi | Full guest ROM in container | ROM fingerprint |
| LSPatch | Patches target APK to embed Xposed (no container) | ✅ We detect via signature pinning |

**Key insight**: commercial VA engines now use seccomp-bpf to mask /proc reads — static client checks alone are insufficient. Combine with syscall-level verification and hardware attestation.

---

## 4. Emulators — 🟡 P1

| Emulator | Key Fingerprints |
|---|---|
| BlueStacks 5 | /data/bluestacks.prop; com.bluestacks.*; GL_RENDERER "Bluestacks" |
| LDPlayer 9 | ldmnq.com props; ldplayer9_ld_* model; built-in device spoofing |
| NoxPlayer | vbox* props/files |
| Genymotion | vbox/genymotion strings in Build.* |
| MuMu 12 | com.mumu.launcher; com.netease.mumu.cloner |
| GameLoop | ttVM props (Tencent) |
| Waydroid | Linux namespaces container; host kernel visible; NOT classic VM detectable |
| Android Emulator (AVD) | goldfish/ranchu props; qemu_pipe; generic/sdk_gphone |

**Detection vectors** (validated):
1. Build.FINGERPRINT/MODEL/PRODUCT/HARDWARE patterns
2. /dev/qemu_pipe, /dev/socket/qemud, /dev/vboxguest
3. x86 CPU on "ARM phone" (instruction timing)
4. Sensor absence (accelerometer/gyro/baseband)
5. GL_RENDERER/VENDOR strings
6. Network: eth0 without wlan0; known emulator MAC OUIs

---

## 5. Network Manipulation — 🟡 P1

| Tool | Mechanism | Detection |
|---|---|---|
| Charles Proxy | Wi-Fi proxy + breakpoint edit + request replay | http.proxyHost property; user CA store |
| **mitmproxy** v12.3.1 | Scriptable Python MITM | Same as Charles |
| **HTTP Toolkit** | On-device VPN + auto-inject system CA via ADB | VPN transport detection; frida-interception module |
| Packet Capture / PCAPdroid | Local VPNService capture | VPN transport |
| Burp Suite | Proxy + Magisk user-cert-to-system module | Proxy settings; system CA anomalies |
| **Zygisk-SSL-Unpinning** | Zygisk module injects at zygote; disables pinning system-wide | Zygisk framework artifacts (we detect); hook-integrity on TrustManagerImpl |
| JustTrustMe | Xposed module hooking TrustManagerImpl | XposedBridge classloader (we detect) |
| TrustMeAlready (archived) | System-wide SSL bypass via Riru/LSPosed | ✅ We detect via package scan |

**Detection vectors**:
1. `ConnectivityManager.hasTransport(TRANSPORT_VPN)`
2. `System.getProperty("http.proxyHost")`
3. User-installed CA enumeration
4. SSL handshake: intentionally-invalid pin succeeding

---

## 6. IAP Cracking — 🟡 P1

| Tool | Status | Mechanism |
|---|---|---|
| **Lucky Patcher** | Active | Patch APK billing code / fake billing via local proxy |
| Freedom | Dead | Legacy billing intercept |
| CreeHack / AppSara | Dead | Same fake-response pattern |

**Detection**: Server-side purchase token verification (only robust defense); billing proxy interface detection.

---

## 7. Code Injection Libraries (embedded in repackaged APKs)

| Library | Type | Status |
|---|---|---|
| **Pine** (canyie) | ART method hook | **Active** (2025-11-08); Android 4.4-15 |
| **Dobby** | Native inline hook | Active; used by LSPosed/mod menus |
| **ShadowHook** (ByteDance) | Native inline hook | Very active; production in TikTok |
| **bhook / ByteHook** (ByteDance) | PLT/GOT hook | Active |
| Android-Mod-Menu (LGLTeam) | Prebuilt floating cheat menu | Active; KittyMemory+Dobby+xDL |
| SandHook | ART hook | Abandoned (~Android 11) |
| Epic | VM-level hook | Dormant |
| Whale | Native hook | Abandoned |
| xHook | PLT hook | **Archived** (superseded by bhook) |
| Substrate | Legacy | Dead on modern Android |

**Key insight**: These are embedded in repackaged APKs — **signature verification is the durable answer** (we already have this). No separate runtime detection needed.

---

## 8. Script Automation / Bots — 🟡 P1 (behavioral)

| Tool | Mechanism | Detection |
|---|---|---|
| AutoX.js / AutoJs6 | JS + AccessibilityService | Accessibility enumeration; behavioral |
| **EasyClick** | JS; scripts packaged as standalone APKs with **custom package names** | Package blocklists FAIL; accessibility + input behavioral |
| 按键精灵 | OCR-driven input macros | Accessibility + input source |
| 触动精灵 | Lua engine; root + iOS | Root artifacts; package |
| MacroDroid / Tasker | Legitimate automation abused | Package + accessibility + behavioral |
| Bot.Js Pro | **HID hardware-level input** | Hardest; behavioral only |
| sendevent replay (root) | Byte-identical kernel input events | Behavioral: zero jitter, periodic intervals |

**Detection vectors**:
1. `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` enumeration
2. Input event pattern: inter-event variance, coordinate entropy, pressure consistency
3. `MotionEvent` injected-source flags
4. ADB connection detection during gameplay

---

## 9. Speed Manipulation — 🟢 P2

| Tool | Mechanism |
|---|---|
| GameGuardian speedhack | Hooks time() / gettimeofday / clock_gettime in target process |
| Xposed speed modules | Hook System.currentTimeMillis / SystemClock |
| Letomaniy/Speed-Hack (archived) | Native gettimeofday/clock_gettime multiplier |

**Detection**: Multi-clock consistency (`elapsedRealtime` vs `nanoTime` vs `currentTimeMillis`); server time sync.

---

## 10. GPS Spoofing — 🟢 P2

| Tool | Mechanism |
|---|---|
| Fake GPS apps | Mock location provider |
| Rooted hooks | Strip isMock flag via Frida/LSPosed |

**Detection**: `Location.isMock()` (API 31+); physics anomalies; GNSS metadata absence.

---

## 11. Cloud Phones — 🟢 P2 (primarily server-side)

| Service | Feature |
|---|---|
| 红手指 Red Finger | ARM cloud instances; 24/7 AFK; mass multi-open |
| 多多云 DuoDuoYun | Huawei Cloud ARM; swarm control |
| 河马云 | Self-built ARM; web console swarm |
| 雷电云 LDCloud | Root toggle; multi-region |

**Detection**: Datacenter IP ranges; sensor absence; 24/7 uptime; behavioral patterns; hardware fingerprint library.

---

## 12. RAT / Mobile Malware — BTMOB Family — ⛔ 客户端能力边界（2026-11-10 整理）

> 与前 11 域（作弊工具）不同，RAT 是**恶意软件**：社工投放、凭据窃取、设备接管。
> 整理目的：明确客户端完整性检测在此域的能力边界（B6），避免重复论证。

### 12.1 家族概况

| 项 | 内容 |
|---|---|
| 性质 | Android RAT（远程访问木马），前身 SpySolr（2025-02 首现） |
| 商业模式 | MaaS 恶意软件即服务：~$5,000 终身 / ~$700 月付，no-code APK 构建器 |
| 版本演化 | v2.5 → v4.6.1（"Live Screen Access"）→ v5.6 |
| 泄露事件 | **2026-01 构建器暗网免费泄露** → 变体爆炸进行中 |
| 地理分布 | 巴西/阿根廷（主力）、摩洛哥、印度；全球扩散中 |
| 投放链 | 钓鱼站（假流媒体/加密货币）→ 假应用商店 → 侧载 APK |

### 12.2 技术特征（识别相关）

| 特征 | 细节 | 客户端可观测性 |
|---|---|---|
| **无障碍滥用（核心）** | 提权、自动授权（Android 13-15）、键盘记录、PIN/图案窃取、2FA 拦截（Google Authenticator）| ✅ 非白名单无障碍 C 级（C11）；**图标状态不可查**（见 12.4） |
| **隐藏图标** | 安装后隐藏 launcher 图标 | ⛔ 包可见性壁垒（B6） |
| **Overlay 注入** | 16 类命令含 `ject`：C2 动态下发注入 ZIP（`/protected` 目录），对 Binance/Trust Wallet/支付宝叠假页面 | ✅ C12 overlay 检测 |
| **实时屏幕** | MediaProjection 串流/截屏/录像；黑屏阻断；光标移动 | ✅ C12 屏幕共享域（部分） |
| **WebView 凭据钓取** | `brows` 命令：加载 URL/HTML，JS 捕获输入框、自动点击滚动输入 | ⛔ 它进程内行为 |
| **C2 通道** | WebSocket（`/con`）；16 命令协议（optns/fetch/brows/lock/ject/file/clip/chat/wrk/srh/mic/add/bc/upload/screen/scread）；BeatBanker 变体走 **FCM** | ⛔ /proc/net/tcp 未特权 EACCES |
| **持久化** | BOOT_COMPLETED 广播接收器；BeatBanker 变体播放近不可闻音频防杀 + 假"系统更新"通知 | ⛔ 它进程内行为 |
| **RAM-only 模块** | BeatBanker：模块注入内存无落地文件 | ⛔ 非我进程 |
| **反分析** | 检测模拟器/分析环境则自终止 | — |
| **多阶段安装** | 阶段一伪装 Google Play 仅要 "install apps" 权限 | ⚠️ 可设计但未实现（需可见性，同 B6 壁垒） |

### 12.3 IOC（时效性强——构建器批量生成，老化快）

- C2：`server[.]yaarsa[.]com`（WebSocket `/con`）、`78[.]135[.]93[.]123`（80541.php + ws:8080）
- 钓鱼：`tvipguncelpro[.]com`
- 样本：lnat-tv-pro.apk 等 ~35 个 SHA256（ESET/Cyble 报告；**包名未公开**——动态拉取注入目标）
- 判定族：ESET `Android/Spy.Agent.EED/EIJ/EIK`、`Spysolr.A`、构建器 `MSIL/BtmobRat`；Kaspersky `HEUR:Trojan-Dropper.AndroidOS.BeatBanker`

### 12.4 Detect-Any 覆盖结论（2026-11-10 实验论证）

**命中面**（全部辅助级，不参与定性）：非白名单无障碍 C（C11）、overlay C/B（C12）、ADB 会话 B/C（C12）、已知自动化包 B（C11）。

**三条死路实证**（自制 fakerat APK 真绑定验证）：
1. 包可见性豁免证伪——无障碍服务真绑定后 `getPackageInfo` 仍 NameNotFoundException（TalkBack 可见属系统特例）
2. `getPackagesForOps` SystemApi 不可用
3. `/proc/net/tcp` 未特权 EACCES

**结论**：RAT 形态（无障碍+隐藏图标+非系统）探测需 `QUERY_ALL_PACKAGES`，与 specs 冲突 → **B6 边界**。此域主战场在杀毒引擎（hash/行为仿真）与服务端风控。

### 12.5 生态工具

| 工具 | 角色 |
|---|---|
| BTMOB Builder | no-code APK 生成器（地区化钓鱼模板），泄露后泛滥 |
| BeatBanker | dropper：投放 BTMOB + Monero 矿机 + 钱包覆叠套件 + FCM C2 |
| 伪装载体 | 假 Starlink、假巴西 INSS 退税、假 Google Play 钓鱼页 |
| 地下渠道 | Telegram（@CyberDev137 等）：源码/经销商面板/多版本售卖 |

---

## Priority Action Items

### 🔴 P0 — Major Detection Gaps

| # | Item | Approach |
|---|---|---|
| 1 | **Frida detection** (all variants incl. anti-detection forks) | D-Bus protocol probe（端口枚举 API28+ EACCES 门控，恒探 27042，多端口仅 root/旧版；改端口兜底=maps/线程名/RWX 三防线）; maps scan for agent patterns; thread-name scan; page-permission characteristics |
| 2 | **Virtual environment detection** (VA/VMOS/Parallel Space/LightSpeed) | Build prop cross-check; data-dir path anomaly; getPackageName vs sourceDir mismatch; container process detection; seccomp-aware /proc verification |
| 3 | **Memory editor detection** (GameGuardian) | /proc/pid/mem access pattern; known packages; overlay window detection |

### 🟡 P1 — Medium Gaps

| # | Item | Approach |
|---|---|---|
| 4 | **Emulator detection** | Build props + hardware props + sensor absence + GL strings |
| 5 | **VPN/MITM detection** | TRANSPORT_VPN; proxy properties; user CA enumeration |
| 6 | **Accessibility bot detection** | ENABLED_ACCESSIBILITY_SERVICES; behavioral input analysis |
| 7 | **Speed hack detection** | Multi-clock consistency check |

### 🟢 P2 — Low Priority / Server-Side

| # | Item |
|---|---|
| 8 | GPS mock detection |
| 9 | Cloud phone fingerprinting |
| 10 | Server-side behavioral analysis (beyond client scope) |

---

## Already Covered by Detect-Any

| Domain | Detection Method |
|---|---|
| Magisk / KSU family / APatch | Supercall probes; package fingerprints; mount forensics |
| ZN / ReZygisk / NeoZygisk / NyaZygisk | NativeBridgeError; socket paths; maps artifacts; ptrace residue |
| LSPosed / Vector / TrustMeAlready | Package scan; maps (lspd); classloader; SELinux labels |
| LSPatch / repackaging | Signature pinning (A-grade); dex CRC |
| TrickyStore / PIF | Attestation chain validation; paired property comparison |
| susfs / Shamiko hiding | Mount "too clean"; statfs cross-check; syscall diff |
| Hook frameworks (generic) | Triple-path diff (A-grade); prologue/GOT integrity (A-grade) |
