# Android Client-Side Cheating: Complete Threat Model

> Data source: 2026-11-09 deep web research (GitHub, XDA, Chinese security forums, vendor docs).
> Each item: mechanism | detection gap | priority.

---

## Coverage Summary

| Domain | We Detect | Total Known | Gap |
|---|---|---|---|
| Root frameworks | 5 | 5 | ✅ Complete |
| Zygisk/Hook injection | 7 | 7 | ✅ Complete |
| Attestation spoofing | 2 | 3 | ⬜ Play Integrity server-side |
| Hiding stack | 2 | 2 | ✅ Complete |
| Dynamic instrumentation | 0 | **12** | 🔴 Major gap |
| Memory editors | 0 | **6** | 🔴 Major gap |
| Virtual machines | 0 | **11** | 🔴 Major gap |
| Emulators | 0 | **8** | 🔴 Major gap |
| Network MITM | 0 | **8** | 🟡 Medium gap |
| IAP cracking | 0 | **4** | 🟡 Medium gap |
| Code injection libs | 0 | **10** | 🟡 Covered via repackaging detection |
| Script automation | 0 | **10** | 🟡 Behavioral, not signature |
| Speed manipulation | 0 | **3** | 🟡 Clock consistency |
| GPS spoofing | 0 | **2** | 🟢 Low priority |
| Cloud phones | 0 | **6** | 🟢 Server-side primarily |

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

## Priority Action Items

### 🔴 P0 — Major Detection Gaps

| # | Item | Approach |
|---|---|---|
| 1 | **Frida detection** (all variants incl. anti-detection forks) | D-Bus protocol probe on all TCP ports; maps scan for agent patterns; thread-name scan (post-rename behavioral); page-permission characteristics |
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
