# AGENTS.md

## Project

Detect-Any — Android environment integrity detection framework. Detects root frameworks, hook injection, Zygisk, attestation spoofing, virtual machines, emulators, dynamic instrumentation (Frida), screen sharing, and behavioral anomalies.

**License**: Apache 2.0 · **minSdk**: 24 (Android 7.0) · **targetSdk**: 35 · **ABIs**: arm64-v8a + armeabi-v7a · **Page size**: 16KB aligned

---

## Architecture

21 Gradle modules, all detection flows through a single pipeline:

```
Collector (C1-C12) → DetectionEngine (parallel) → RulesEngine → ScoreModel → ScanReport
```

### Core SPI (must not break)

```kotlin
// core/model/src/main/kotlin/.../Collector.kt
interface Collector {
    val id: CollectorId
    fun collect(input: ScanInput): CollectorResult  // MUST NOT throw
}

enum class CollectorId { C1_PATH .. C12_SCREEN_SHARE }
enum class Confidence { A(40), B(15), C(5) }
```

**Every detection item** implements `Collector`. No special paths. The `DetectionEngine` runs all collectors in parallel via `CompletableFuture` — total scan time = `max(individual collector)`, not sum.

### Module map

| Module | Role |
|---|---|
| `core/model` | Collector SPI, Finding, Confidence, ScanInput/Result |
| `core/engine` | Parallel orchestration, ScoreModel (A/B/C grading) |
| `core/rules` | JSON rule engine (hot-updatable), RuleSet definitions |
| `core/native-platform` | JNI: raw svc executor, ELF parser, syscall guard, probes |
| `collectors/fs-probe` | C1 paths + C2 mounts |
| `collectors/properties` | C3 system properties |
| `collectors/endpoints` | C4 network sockets (gated by ProbeCap) |
| `collectors/app-fingerprint` | C5 package + APK content fingerprint |
| `collectors/memory-map` | C6 maps/smaps/solist |
| `collectors/code-integrity` | C7 prologue/GOT verification |
| `collectors/behavior-probe` | C8 supercall/SELinux/ptrace/triple-diff |
| `collectors/instrument-probe` | C9 Frida (D-Bus/maps/threads/RWX) |
| `collectors/virtual-env` | C10 emulator/VM/sensors/GL |
| `collectors/behavior-check` | C11 VPN/proxy/accessibility/clock |
| `collectors/screen-share` | C12 scrcpy/ADB/remote desktop/overlay |
| `feature/attestation` | Key attestation + CRL + Play Integrity scaffold |
| `feature/report` | Report presenter, exporter, signature import |
| `data/signature` | Hot-updatable signature DB (ed25519 signed) |
| `compat/platform` | API 24-16 capability gating (ProbeCap) |
| `selfguard` | Anti-debug, repackaging detection, silent response |
| `app` | Compose UI + navigation (4 tabs: Scan/Threats/Capabilities/Settings) |

---

## Build & Test

```bash
./gradlew assembleDebug                        # Build debug APK
./gradlew test                                # Host unit tests (~150+)
./gradlew :app:connectedDebugAndroidTest      # Device tests (21 per device)
./gradlew :app:verify16kAlignment             # 16KB page alignment gate (MUST pass)
./gradlew :app:lintDebug                      # Android Lint (NewApi=0 强制；2026-11-10 审计实证抓到 API 24-27 启动崩溃)
```

**Prerequisites**: JDK 17+, Android SDK (API 35), NDK 25.2+, CMake 3.22+

**16KB gate**: Runs automatically after every `packageDebug`/`packageRelease`. Checks zipalign AND PT_LOAD p_align ≥ 16384 for every packaged .so. Build fails if any library violates.

---

## Code Conventions

### Detection items

1. **Implement `Collector` interface** — never bypass the pipeline
2. **Never throw from `collect()`** — return `BLOCKED` status instead
3. **Framework names go in signature DB** (`data/signature`), not in collector code
4. **Confidence levels are non-negotiable**:
   - A = physical invariant (single hit conclusive)
   - B = behavioral (needs 2 hits from different domains)
   - C = static trace (weight only, never conclusive alone)
5. **New framework = new DB entry, not new collector module**

### Native code (`core/native-platform/src/main/cpp/`)

- All raw syscalls go through the guard in `raw_syscalls.cpp` (whitelist-based)
- **Never** use "try and fallback" for syscalls — Android 8+ seccomp kills with SIGSYS
- Use `textRead()` (mprotect-based) for reading execute-only pages, not `memRead()`
- 16KB linker flags required: `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384`

### UI (`app/src/main/kotlin/`)

- Material 3 with dynamic color (Android 12+) / brand fallback
- 4-tab navigation: Scan / Threats / Capabilities / Settings
- Score gauge uses animated arc; confidence badges color-coded (强=red, 中=orange, 弱=gray)
- Report model is a direct translation of engine output (no transformation)

---

## Mandatory Verification Protocol

**Every new detection probe or modification to an existing probe MUST pass a clean emulator verification before commit.** No exceptions.

### Procedure

```bash
# 1. Build
./gradlew :app:assembleDebug

# 2. Install on clean emulator
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk

# 3. Run L2 full scan
adb -s emulator-5554 shell am force-stop com.detectany.app
adb -s emulator-5554 shell am start -n com.detectany.app/.MainActivity
sleep 3 && adb -s emulator-5554 shell input tap 194 498
sleep 10

# 4. Check threats page — new probe MUST NOT produce findings
#    (only pre-existing emulator signals: qemu, sdk_gphone, ranchu, etc.)
adb -s emulator-5554 shell input tap 402 2274 && sleep 2
adb -s emulator-5554 shell uiautomator dump /sdcard/verify.xml
adb -s emulator-5554 shell cat /sdcard/verify.xml
```

### Pass criteria

- Zero findings from the new probe on clean emulator
- Zero new HOOK/ROOT/INSTRUMENTATION findings
- Pre-existing emulator signals (qemu/sdk_gphone/ranchu/translator/swiftshader/ADB) unchanged
- Score change ≤ 0 (should not increase on clean device)

### If verification fails

1. Do NOT commit
2. Diagnose root cause (wrong base, control group missing, threshold too aggressive)
3. Fix, rebuild, re-verify
4. If the probe produces both true positive (on test device) and false positive (on emulator), add control group or differential baseline

---

## Critical Lessons (do not repeat)

### False positive history

| What happened | Root cause | Fix |
|---|---|---|
| C7 prologue 295 HOOK on clean devices | `locateOwnLib()` phdr voting selected wrong base for APK-embedded libs | Replaced with solist + symbol byte verification; verify-or-return-null |
| Timing side-channel on emulator | truncate vs ftruncate difference was path resolution cost, not supercall | Differential control group (newfstatat/fstat) proved no signal; disabled |
| `com.lucky.luckyclient` misidentified as Lucky Patcher | Name similarity; actually Luckin Coffee app | Verified DEX content before adding to signature DB |
| `ro.dalvik.vm.native.bridge=0` triggered detection | Default value on all devices | Added `valueContains` condition to property entries |
| 5 个 properties 主机单测 UnsatisfiedLinkError（被 -x 排除掩盖 2 天） | v6 把 PropJni.propGet 内联进纯 Kotlin 的 PropertyAnalyzer，破坏主机可测性；模块被排除后真回归无人察觉 | 2026-11-10 审计修复：native 直读改注入式（directRead 参数）；教训——**给模块加测试排除时要设定期复检点，排除不是永久豁免** |
| 干净华为真机 58 分误定性（PIF build_pair×3 B 级假阳性） | 华为出厂 bootimage.build.tags=dev-keys vs 主指纹 release-keys、bootimage fingerprint 为 generic_a15 模板、vendor.product.* 全空——六对成对属性全部存在 OEM 出厂合法不一致；原 B 级仅在 Pixel 验证属验证面不足 | 2026-11-11 修复：六对全部降 C（PIF 定性改由 verified_boot_lie A 级承担）；华为系统无障碍入白名单（distributedpasteboard 拖拽服务）。教训——**OEM 属性形态必须在多厂商矩阵验证后才能定 B 级** |

### Principle: false negatives are recoverable, false positives destroy trust

When uncertain about a detection signal's reliability:
- Demote to C-level (weight only)
- Add control group / baseline comparison
- Test on clean emulator AND clean real device before promoting to B or A

---

## Key Constraints

1. **minSdk 24**: No `statx`, no `memfd_create` bionic wrapper, no `getrandom` bionic wrapper, no `posix_spawn` — use `ProbeCap` gating and fallbacks
2. **16KB pages**: Android 15+ enforces; all native code must pass `verify16kAlignment`
3. **Parallel execution**: Collectors run concurrently; blocking in one collector delays the entire scan to `max()`
4. **APK-embedded native libs**: `extractNativeLibs=false` is the default; `locateOwnLib()` must handle this (solist approach, not maps phdr voting)
5. **Seccomp on Android 8+**: Unlisted syscalls get SIGSYS (process kill), not ENOSYS; all raw syscalls must go through the guard
6. **Conscrypt removed**: `conscrypt-android` 2.5.2 has 4KB-aligned .so; Android 7 TLS 1.3 uses GMS provider instead

---

## Signature Database

Versioned, ed25519-signed, hot-updatable. Current: **v12**.

```bash
# Location: data/signature/src/main/kotlin/.../BundledSignatureDb.kt
# Update flow: edit entries → bump version → update tests (they hardcode version)
# Verify: ./gradlew :data:signature:test
```

**Important**: When bumping the DB version, update these test files:
- `data/signature/src/test/.../SignatureStoreTest.kt`
- `feature/report/src/test/.../ReportTest.kt`

---

## Documentation

| Doc | |
|---|---|
| `docs/DETECTION_CATALOG.md` | All detection items with confidence levels |
| `docs/CHEATING_THREAT_MODEL.md` | Threat landscape (80+ tools across 11 domains) |
| `docs/COVERAGE_ANALYSIS.md` | Coverage matrix (install/runtime/intrusion × 4 dimensions) |
| `docs/CAPABILITY_BOUNDARIES.md` | What we explicitly don't promise |
| `docs/REGRESSION.md` | Device test data, timing benchmarks |
| `docs/RUNBOOK.md` | Ops, hot-update, release checklist, troubleshooting |
| `openspec/specs/` | 6 capability behavior contracts (31 requirements) |

---

## Known Limitations (documented, not bugs)

- **KPM (Kernel Patch Module)**: Not detectable from userspace
- **Cloud phones (real-peripheral passthrough)**: 高端云手机直通真实传感器/电池时客户端仅剩单点信号；虚拟外设形态可由 C 级合围共振定性（sensor rhythm B + battery cross-layer + SIM absent，引擎规则 ≥3 即定性）；真实硬件直通仍需服务端
- **Deep hiding (susfs + manager uninstall)**: ✅ 已穿透（v5/v6，P8 实证）——verified boot 矛盾（A）+ zygisk 残留属性（B）双信号；残余边界：自定义 resetprop 全擦除 profile 只剩行为面
- **EasyClick custom packages**: Random package names defeat signature scanning
- **NeoZygisk ≥10-30**: ptrace residue being neutralized
