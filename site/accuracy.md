# Accuracy Discipline

> **False negatives are recoverable; false positives destroy trust.**
> A missed cheat tool costs one adversarial test later. A false "this phone is hacked" verdict shown to one ordinary user costs the product.

This page summarizes how Detect-Any enforces that principle. The forensic story behind it: [Why a Clean Huawei Scored 58, and a Clean Xiaomi 98](essay-oem-fp-forensics.md).

## The three-layer FP certification

Every probe / signature / grading change must pass before commit (methodology in [FP_CERTIFICATION.md](https://github.com/lotty520/Detect-Any/blob/main/docs/FP_CERTIFICATION.md), 2026-11-13 onward):

1. **L1 — Input-source verification (static).** Each probe's trigger is a pure function of OS-level inputs. On a clean device we prove each input absent, item by item, automatically (`fp_certify.sh`). Absent input = structurally impossible false positive — stronger than "we ran it and nothing fired."
2. **L2 — Clean-matrix scan (dynamic).** A device × legal-state matrix — ADB on, no SIM, accessibility enabled, factory OEM overlays, GPU runtime loads, external displays… Each cell must scan to zero A-grade, zero unexpected B-grade findings, and a score within the per-model baseline.
3. **L3 — Grading audit (semantic).** Every A/B-grade signal must answer in writing: *why can this signal not physically occur in a legitimate environment?* If the answer invokes luck or "it didn't fire on my phone" — it's a C.

## Honest boundaries — what we do NOT promise

Full document: [CAPABILITY_BOUNDARIES.md](https://github.com/lotty520/Detect-Any/blob/main/docs/CAPABILITY_BOUNDARIES.md). Highlights:

- **KPM (Kernel Patch Module)** — not detectable from userspace
- **High-end cloud phones with real-peripheral passthrough** — client-side reduced to single-point signals; virtual-peripheral shapes are detectable via C-signal resonance
- **Legitimate virtual displays** (DeX / Chromecast / secondary screens) — classification whitelist stays **empty** until a ≥2-vendor clean-device matrix validates each shape; unmatched displays are C-grade weight-only by design
- **RAT form-factors** (accessibility + hidden icon + non-system) — package-visibility wall; that battle belongs to AV engines and server-side risk

Every item's current verification status (dual / TP-side / FP-side / unreachable / curated) is tracked in the per-item ledger: [DETECTION_ACCURACY.md](https://github.com/lotty520/Detect-Any/blob/main/docs/DETECTION_ACCURACY.md).

## Verification infrastructure

- Clean-emulator protocol: mandatory per probe change (AGENTS.md)
- Adversarial Pixel 8 (APatch + susfs deep hiding): deep-hiding penetration verified — verified-boot contradiction (A) + zygisk residue (B)
- Real-device E2E for virtual-display detection: composite-B finding confirmed in the verdict evidence vector on Android 16 hardware
- 16KB page-size alignment enforced as a build gate; lint NewApi=0 enforced
