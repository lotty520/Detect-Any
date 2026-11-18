# Detect-Any v0.4.2

Everything since v0.1.1 — two weeks of adversarial hardening, FP eradication, and certification infrastructure. Full history: compare [`v0.1.1...v0.4.2`](https://github.com/lotty520/Detect-Any/compare/v0.1.1...v0.4.2).

## New Detection Coverage

- **Chinese multi-open / VM families (signature DB v19)**: X8 Sandbox, VPhoneOS, F1 VM, Virtual Master — four families verified on real devices (`8bca37d`)
- **Multi-instance & container detection**: dual-app / clone-user / virtual-container posture — three independent defenses, live-validated on adversarial Pixel 8 (`b797b15`)
- **Rename-immune Frida defenses (C9)**: three new defenses that survive renamed/embedded Frida builds, closed-loop hardened on a rooted Pixel 8 (`5e0ccd7`)
- **Google test-stack detection**: instrumentation posture, emulator vectors, Appium signatures (`cc931b5`)
- **glib_threads promoted to B-grade**; cuttlefish C-grade face added; TP adversarial certification tooling (`fe8145c`)
- **Signature DB v17**: HMA + legacy LSPosed manager signatures (`e8c49a5`)
- **Native /proc descent (v16.1)**: C9/C11 proc reads moved to native layer — JVM-layer `File` hooks can no longer blind them (`90a3cb8`)

## False-Positive Fixes

- **Eradicated two systematic FP families found by clean-device zero-positive testing on Xiaomi Android 16** (`a75a9a7`) — HyperOS factory overlayfs mounts no longer score as root; solist/maps snapshot race fixed by reordering (see README "Accuracy Discipline")
- **Attestation trusted-path unblocked on real TEE** — three chained root-cause fixes (`5ac1805`, `250525e`)
- **Doc-drift corrections + ProcSelfReads double-read bug** (`bad0775`)

## Other Changes

- **UI v18**: full design-system rework — segmented tier selector (L1/L2/L3), single primary CTA, severity token system; verified on real hardware, light + dark, font-scale matrix incl. 1.3 (`94e8e13`, `6bd97be`, `822431c`)
- **FP certification system**: methodology, automated harness (`fp_certify.sh`), device baselines; first full-device PASS on Redmi HyperOS Android 15 (`d7c76cd`, `35a220e`)
- **R8 calibration root cause closed**, CI fix, host-test debt (`c08098e`)
- README English translation + verified-against matrix refresh (`39d073d`, `d634a2b`, `3ebeba2`, `f02fa22`)

## Install

| Asset | SHA-256 |
|---|---|
| `Detect-Any-v0.4.2-debug-signed.apk` | `de33c265e3c0db9112fdba0f1c7c0765cd9b4d20c3f5911996a019a8638480fd` |

- Requires Android 7.0+ (API 24); no root needed; scan runs fully offline
- This build is **debug-signed** (same signing as previous releases and the FP-certification baseline). Release-signed builds + automated assembly checklist are tracked on the roadmap.
- Verify before installing: `shasum -a 256 Detect-Any-v0.4.2-debug-signed.apk` must match the fingerprint above
