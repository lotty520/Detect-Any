# Detection Coverage

145 detection items across 13 collectors, every item graded by evidence strength. Full catalog (中文, source of truth): [DETECTION_CATALOG.md](https://github.com/lotty520/Detect-Any/blob/main/docs/DETECTION_CATALOG.md).

## Covered targets

| Category | Frameworks / Tools |
|---|---|
| Kernel root | KernelSU, KernelSU-Next, SukiSU-Ultra, APatch |
| Userspace root | Magisk (+ Magisk Delta) |
| Zygisk injection | ZygiskNext, ReZygisk, NeoZygisk, NyaZygisk |
| Hook frameworks | LSPosed, Vector, TrustMeAlready |
| Repackaging | LSPatch (signature pinning, A-grade) |
| Attestation spoofing | TrickyStore, PIF (+ forks) |
| Hiding stacks | susfs (verified-boot contradiction), Shamiko |
| Dynamic instrumentation | Frida — all variants incl. hluda/Florida renamed builds (rename-immune defenses) |
| Virtual displays | scrcpy `--new-display` shell-created displays (5-class classifier, composite-B with ADB posture) |
| Emulators / VMs | QEMU family, 4-dimension cross (props / hardware / sensors / GL) |
| Multi-open & containers | X8 Sandbox, VPhoneOS, F1 VM, Virtual Master, Parallel Space, VMOS, OEM clone profiles |
| Cloud phones | cross-subsystem C-signal resonance (sensor rhythm, battery cross-layer, SIM absence) |
| Device spoofing | appenv, Device ID Changer, VirtualNet, fake GPS/camera tools |
| Remote control / screen | scrcpy, ADB sessions, remote desktop (AnyDesk/TeamViewer/AirDroid/Vysor), overlays, screen recording |
| Risk postures | VPN/proxy (3 layers), SIM anomalies, geo inconsistency, speed-hack clock drift, automation services |

## The grading model

| Grade | Meaning | Verdict power |
|---|---|---|
| **A** | Physical invariant — prologue byte comparison (memory vs disk), triple-path syscall diff, verified-boot contradiction, maps-tamper self-probe | single hit conclusive |
| **B** | Behavioral — supercall magic numbers (source-audited), D-Bus protocol handshake, sensor rhythm, mount forensics, composite signals (e.g. shell-owned virtual display × ADB posture) | two hits from independent domains |
| **C** | Static trace — paths, sockets, packages, properties | weight only, never conclusive |

New framework targets are **signature-DB entries, not code** — the DB is ed25519-signed, versioned, and hot-updatable (v19 current).

## Architecture

```
Collector (C1-C13, parallel) → DetectionEngine → RulesEngine → ScoreModel → ScanReport
```

21 Gradle modules; every detection flow implements the same `Collector` SPI — total scan time equals the slowest collector, not the sum. Native layer (~1,400 lines C/C++): raw-syscall guard, ELF parser, prologue/GOT verification — all syscall paths whitelisted against seccomp (Android 8+ SIGSYS discipline).
