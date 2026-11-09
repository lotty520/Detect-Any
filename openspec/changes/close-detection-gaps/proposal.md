# Proposal

## Why

The 2026-11-09 deep web research (docs/CHEATING_THREAT_MODEL.md) identified 11 cheating domains with 80+ tools. Detect-Any currently covers 5 domains completely (root, hook injection, attestation spoofing, hiding stack, repackaging), leaving **6 major gaps** — most critically Frida ecosystem (12 variants), virtual machines/sandbox (11 tools), and memory editors (6 tools). These represent the highest-volume real-world cheating vectors that our current 58-item detection catalog does not address at all.

## What Changes

Add **3 new detection capability domains** with new collector modules, plus extend 2 existing capabilities:

### New Capabilities

1. **Dynamic instrumentation detection** (`instrumentation-detect`): Frida server/gadget/fork detection via D-Bus protocol probe, maps scan, thread-name scan, and page-permission characteristics — resilient against anti-detection forks (hluda, Florida)
2. **Virtual environment detection** (`virtual-env-detect`): VM/sandbox/emulator detection via build-property cross-check, sensor absence, data-dir path anomaly, container process detection, and GL renderer fingerprint
3. **Screen share / remote control detection** (`screen-share-detect`): scrcpy socket/process/HID detection, ADB session indicator, remote desktop app fingerprints (AnyDesk/TeamViewer/AirDroid/Vysor), input injection forensics, overlay/tapjacking detection, and screen recording API callbacks
4. **Behavioral anomaly detection** (`behavioral-anomaly`): Emulator signals (sensor absence, CPU architecture mismatch), VPN/MITM presence (transport detection, proxy properties), accessibility bot enumeration, multi-clock consistency for speed hack

### Extended Capabilities

5. **signal-collection** (modify): Add application enumeration entries for known cheat tools (GameGuardian, Lucky Patcher, memory editors, script engines, virtual machine apps) to the signature database
6. **detection-engine** (modify): Score model must weight the new domain findings; rules must map new ruleId prefixes to threat labels

## Capabilities

### New Capabilities

- `instrumentation-detect`: Detect Frida (all variants including anti-detection forks), objection, Il2Cpp hooks, and embedded gadget in repackaged APKs
- `virtual-env-detect`: Detect VirtualApp-family containers, full VMs (VMOS/LightSpeed), emulators (8 platforms), and app cloning frameworks
- `screen-share-detect`: Detect scrcpy (all modes), remote desktop tools (AnyDesk/TeamViewer/AirDroid/Vysor), ADB session indicators, input injection forensics, overlay/tapjacking, and screen recording
- `behavioral-anomaly`: Detect VPN-based MITM, proxy configuration, user-installed CA certificates, accessibility service abuse, emulator hardware signals, multi-clock speed inconsistency

### Modified Capabilities

- `signal-collection`: Extend application fingerprint entries to cover cheat tools (GameGuardian, Lucky Patcher, 八门/烧饼/葫芦侠, auto-clickers, VM apps); add emulator build-property patterns to signature database
- `detection-engine`: Extend scoring model and rules to incorporate the three new domains

## Impact

- **New modules**: 3 collectors + supporting native probes (D-Bus probe, sensor check, clock consistency)
- **Signature database**: v4 with 30+ new entries (cheat tool packages, emulator fingerprints, VM build props)
- **Rules**: 15+ new rules mapping new signals to threat categories
- **Performance**: New collectors must run within the parallel engine (L2 ≤1.5s on Pixel 8); behavioral checks are passive (zero syscall overhead)
- **Architecture boundary**: Virtual-env and emulator detection cross into hardware attestation domain — must coordinate with existing C9 to avoid duplicate findings
