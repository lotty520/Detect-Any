# Detect-Any

**Industrial-grade Android Root / Hook / Attestation-Spoofing Detection Framework**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![minSdk](https://img.shields.io/badge/minSdk-24_(Android_7.0)-orange.svg)](app/build.gradle.kts)
[![16KB](https://img.shields.io/badge/Page_Size-16KB_Aligned-green.svg)](docs/RUNBOOK.md)
[![Tests](https://img.shields.io/badge/Tests-153_host_+_42_device-brightgreen.svg)](#testing)

---

## What It Does

Detect-Any scans Android devices for 19 root frameworks, injection layers, and attestation spoofing tools. It combines **filesystem forensics**, **kernel syscall probing**, **instruction-level integrity verification**, and **hardware key attestation** into a single weighted risk score with per-item evidence replay.

```
┌─────────────────────────────────────────────────────┐
│  Detect-Any                                          │
├─────────────────────────────────────────────────────┤
│                                                      │
│        ╭──────────╮                                  │
│        │    50    │   ← Risk Score (0-100)           │
│        │  ─────   │                                  │
│        ╰──────────╯                                  │
│   检出 · 判定性证据成立                                │
│   L2 · 847ms · 1 domain degraded                     │
│                                                      │
│   [APatch 29] [ZygiskDetect 25] [TrustMeAlready 17] │
│                                                      │
│   → 对比上次  持平 · 环境未变化                         │
│                                                      │
├─────────────────────────────────────────────────────┤
│  [扫描]      [威胁]      [能力]      [设置]            │
└─────────────────────────────────────────────────────┘
```

## Covered Frameworks (19)

| Category | Frameworks |
|---|---|
| **Kernel Root** | KernelSU, KernelSU-Next, SukiSU-Ultra, APatch (KP+KPM) |
| **Userspace Root** | Magisk (v31.1+) |
| **Zygisk Injection** | ZygiskNext, ReZygisk, NeoZygisk, NyaZygisk |
| **Hook Frameworks** | LSPosed, Vector (LSPosed successor), TrustMeAlready |
| **Repackaging** | LSPatch (+ active fork) |
| **Attestation Spoofing** | TrickyStore (+ TeeSimulator forks), PIF |
| **Hiding Stack** | susfs, Shamiko |
| **Detection Tools** | ZygiskDetect |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    :app  (Compose UI)                │
│   Scan / Threats / Capabilities / Settings          │
├─────────────────────────────────────────────────────┤
│                 :core:engine                         │
│   Parallel collectors → Rules → Weighted Score       │
├──────────┬──────────┬──────────┬───────────────────┤
│  :core:  │ :collectors (×7)  │  :feature:           │
│  rules   │ C1  Paths         │  attestation (C9)   │
│  model   │ C2  Mounts        │  report / export    │
│  native- │ C3  Properties    ├───────────────────┤
│  platform│ C4  Endpoints     │  :selfguard         │
│  (JNI)   │ C5  App Fingerprints│  Anti-debug      │
│          │ C6  Memory Maps   │  Integrity check    │
│          │ C7  Code Integrity│                     │
│          │ C8  Behavior     │                     │
├──────────┴──────────────────┴───────────────────┤
│  :data:signature (hot-updatable)  │  :compat:platform│
│  58 detection entries             │  API 24-16 gates  │
└─────────────────────────────────────────────────────┘
```

## Key Detection Techniques

### Physical Invariants (A-grade: single-hit conclusive)

| Technique | How It Works |
|---|---|
| **Triple-Path Diff** | Same file stat via Java API / libc / raw `svc` syscall — any disagreement proves hooking |
| **Instruction Prologue** | Own JNI entry-point bytes compared memory vs disk ELF — inline hooks physically cannot hide |
| **GOT Slot Verification** | Resolved address must match disk `st_value + base` for the mapped library (no dlsym dependency) |
| **SELinux Label Probe** | Write test labels: `EPERM` = domain exists / `EINVAL` = absent — kernel-level, unforgeable |
| **st_dev Sampling** | Filesystem device numbers on `/dev` `/proc` `/sys` `/dev/pts` deviate from OEM baseline when early tmpfs slots are consumed |
| **RWX Self-Probe** | mmap own RWX page, check if visible in own maps — if not, maps read is hooked |

### Behavioral Probes (B-grade: two-hit resonance)

| Technique | Target |
|---|---|
| KSU supercall (`reboot` magic → `anon_inode:[ksu_driver]` fd) | KernelSU family |
| APatch supercall (syscall 45 + superkey + `0x1158` layout) | APatch |
| `NativeBridgeError()` sticky flag | ZygiskNext / ReZygisk |
| PTRACE_GETEVENTMSG residue on parent | ReZygisk (⚠️ NeoZygisk neutralizing) |
| Paired property comparison (`ro.build.*` vs `ro.bootimage.*`) | PIF fingerprint spoofing |
| APK content fingerprint (DEX string probes) | Spoofed manager packages |
| Mount forensics (overlay detection, statfs cross-check, "too clean" heuristic) | Magisk modules / susfs |

### Hardware Attestation (C9)

- Key attestation chain validation with **dual-root anchoring** (RSA 2016 + ECDSA P-384 2026)
- **RKP-only enforcement**: Android 16 launch devices (`first_api_level ≥ 36`) must present ECDSA chains — RSA chain = spoof signal
- Google's official CRL consumption (`android.googleapis.com/attestation/status`)
- `attestationApplicationId` binding (anti-relay)
- Shadow revocation awareness (CRL-clean ≠ trustworthy)

## Confidence & Scoring

| Level | Rule |
|---|---|
| **A** (强) | Single hit → conclusive (risk ≥ 50) |
| **B** (中) | Any 2 B-grades across domains → conclusive |
| **B + C** | Same-domain B + C resonance → conclusive |
| **C** (弱) | Weight only, never triggers alone |
| **anti_detect** | Detected hiding stack ×1.5 weight multiplier |

## Minimum Requirements

| Requirement | Value |
|---|---|
| minSdk | **24** (Android 7.0) |
| targetSdk | 35 (Android 15) |
| ABIs | arm64-v8a + armeabi-v7a |
| Page size | 16KB aligned (Android 15+ enforced) |
| Native size | ~613KB stripped (budget ≤1.5MB) |

## Build

```bash
# Clone
git clone https://github.com/lotty520/Detect-Any.git
cd Detect-Any

# Build debug
./gradlew assembleDebug

# Run all host tests
./gradlew test

# Run device tests (requires connected device/emulator)
./gradlew :app:connectedDebugAndroidTest

# Verify 16KB alignment gate
./gradlew :app:verify16kAlignment
```

**Prerequisites**: JDK 17+, Android SDK (API 35), NDK 25.2+, CMake 3.22+

## Testing

| Suite | Count | Scope |
|---|---|---|
| Host unit tests | 153 | All analyzers, scoring, attestation, signature store |
| Device tests (per device) | 42 | Collector smoke, self-guard, attestation, code integrity, timing, UI |
| 16KB gate | 3 APKs | zipalign + PT_LOAD p_align verification |

## Performance (Pixel 8, Android 16, real data)

| Metric | Value |
|---|---|
| L2 full scan | **847ms** (parallel: max of single collector) |
| L1 quick scan | **~10ms** |
| Bottleneck | C5 APK content scan (880ms) — see [optimization roadmap](docs/REGRESSION.md) |

## Project Structure

```
Detect-Any/
├── app/                          # Compose UI + navigation
├── core/
│   ├── model/                    # Collector SPI, Finding, Confidence
│   ├── engine/                   # Parallel orchestration + scoring
│   ├── rules/                    # JSON rule engine (hot-updatable)
│   └── native-platform/          # JNI: raw svc, ELF parser, guards
├── collectors/
│   ├── fs-probe/                 # C1 paths + C2 mounts
│   ├── properties/               # C3 properties
│   ├── endpoints/                # C4 sockets
│   ├── app-fingerprint/          # C5 package + APK content
│   ├── memory-map/               # C6 maps/smaps/solist
│   ├── code-integrity/           # C7 prologue/GOT
│   └── behavior-probe/           # C8 supercall/SELinux/ptrace
├── feature/
│   ├── attestation/              # C9 key attestation + Play Integrity
│   └── report/                   # Export, presenter, signature import
├── data/signature/               # Hot-updatable signature DB (ed25519)
├── compat/platform/              # API 24-16 capability gating
├── selfguard/                    # Anti-debug, repackaging detection
├── docs/
│   ├── DETECTION_CATALOG.md      # All 58 detection items
│   ├── CAPABILITY_BOUNDARIES.md  # What we don't promise
│   ├── REGRESSION.md             # Device matrix + timing
│   └── RUNBOOK.md                # Ops, hot-update, release checklist
└── openspec/                     # Spec-driven development artifacts
```

## Documentation

| Doc | Purpose |
|---|---|
| [Detection Catalog](docs/DETECTION_CATALOG.md) | All 58 items across 7 capability domains |
| [Capability Boundaries](docs/CAPABILITY_BOUNDARIES.md) | What we explicitly don't promise (KPM, full susfs) |
| [Regression Matrix](docs/REGRESSION.md) | Device test data, timing benchmarks |
| [Runbook](docs/RUNBOOK.md) | Build, test, hot-update, release checklist, troubleshooting |
| [OpenSpec Specs](openspec/specs/) | 6 capability behavior contracts (31 requirements) |

## Real-Device Validation

| Device | Environment | Result |
|---|---|---|
| Pixel 8 / Android 16 | ROOT + APatch + Zygisk tools + TrustMeAlready | **50/检出** — 3 threats, 3 evidence items, 847ms |
| Pixel 8 / Android 16 | Hook injection active | **50/检出** — 5× prologue hooks detected (inline hook trampolines) |
| Emulator / Android 15 | Clean | **0/未达定性** — zero false positives |

## Known Limitations

- **KPM (Kernel Patch Module)**: Not detectable from userspace; hardware attestation is the only defense
- **susfs full configuration**: Partial static traces may be hidden; combo score ≥85% is the acceptance criterion
- **NeoZygisk ≥10-30**: ptrace residue probe being neutralized; still effective against ReZygisk
- **Play Integrity server decode**: Requires Google Play Console credentials (scaffold provided)

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Run tests (`./gradlew test`)
4. Verify 16KB alignment (`./gradlew :app:verify16kAlignment`)
5. Commit and submit a PR

Detection signatures are hot-updatable — new framework entries don't require app release. See [Runbook § Hot Update](docs/RUNBOOK.md#特征热更新运营).

## License

Apache License 2.0 — see [LICENSE](LICENSE)

## Acknowledgments

- Detection techniques informed by community research: [Chunqiu Detector](https://github.com/mingzun09/Chunqiu-Detector-Problem-solution), [Momo](https://t.me/magiskalpha), [vvb2060/MagiskDetector](https://github.com/vvb2060/MagiskDetector)
- Android seccomp/16KB alignment guidance from [Android Developers](https://developer.android.com/guide/practices/page-sizes)
- [OWASP MASTG](https://mas.owasp.org/MASTG/) resilience methodology baseline
