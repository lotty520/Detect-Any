# Essay: Why a Clean Huawei Scored 58, and a Clean Xiaomi Scored 98

> Mirror of [docs/essays/oem-fp-forensics.md](https://github.com/lotty520/Detect-Any/blob/main/docs/essays/oem-fp-forensics.md) (source of truth).


*False-positive forensics from building [Detect-Any](https://github.com/lotty520/Detect-Any), an open-source Android environment integrity detector — and the certification system the incidents forced us to build.*

---

A flagship phone straight out of the box. No root, no Magisk, no injection framework, nothing. Our scanner gave it a risk score of **98 out of 100** and called it conclusive. The week before, a different clean flagship had scored **58** with three B-grade "attestation spoofing" findings.

Both phones were fine. Both verdicts were wrong. This is the story of what those two false positives taught us about the real enemy of integrity detection — not clever adversaries, but legitimate factory variation in the Android ecosystem — and how we turned the cleanup into a repeatable certification pipeline.

## Background: how Detect-Any grades evidence

Detect-Any assigns every signal one of three confidence grades:

- **A — physical invariant.** Impossible to forge from userspace in a legitimate environment: prologue byte comparison (memory vs disk), triple-path syscall diff, verified-boot contradiction. A single A-grade hit is a conclusive verdict.
- **B — behavioral.** Supercall magic numbers, D-Bus protocol handshakes, sensor rhythm. Two B-grade hits from independent domains are required to conclude.
- **C — static trace.** Paths, packages, properties, fstypes. Weight only — never conclusive alone.

The design principle is asymmetric on purpose: **false negatives are recoverable; false positives destroy trust.** A missed cheat tool costs you one adversarial test later. A false "this phone is hacked" verdict shown to one ordinary user costs you the product.

Both incidents below were failures of *grading*, not of detection logic — the probes found exactly what they were looking for. What they found just wasn't evidence of anything.

## Case 1: The Huawei that "spoofed attestation" (58 points)

Our Play-Integrity-Fix (PIF) family detection included a set of **paired property consistency checks**. The intuition is sound: spoofing tools rewrite selected build fingerprint properties (`ro.build.*`), and a rewrite often leaves the fingerprint inconsistent with sibling properties the tool forgot to patch. Six pairs, e.g. main fingerprint vs `bootimage.build.*` vs `vendor.product.*`. If a pair disagrees, something rewrote the device — B-grade, behavioral.

On a Pixel, that intuition holds. On a factory-fresh Huawei, it falls apart:

- The main build fingerprint said `release-keys`, but `bootimage.build.tags` said `dev-keys` — **from the factory**.
- The `bootimage` fingerprint was a `generic_a15` template string — again, as shipped.
- `vendor.product.*` was simply **empty** — Huawei doesn't populate those keys on this model.

All six "tamper-indicating" inconsistencies were legitimate factory states. But the original B grade had been validated on exactly one vendor (Pixel), where none of these shapes occur. Three of the six pairs fired, the rule engine saw multiple B-grade hits, and the score model produced 58 points of pure fiction.

### The fix

Two changes, both about honest grading rather than detection:

1. **All six property pairs demoted B → C.** They are real signals — PIF does leave such traces — but they are weight-only now. The conclusive verdict for PIF-style spoofing is carried by the **verified-boot contradiction** A-grade signal (ro.boot.* verified state vs claimed fingerprint), which *cannot* legitimately disagree.
2. **The device matrix grew a Huawei column**, including its OEM accessibility services (the drag-and-paste `distributedpasteboard` service was initially flagged as an unknown automation service).

The lesson we wrote down: **an OEM property shape may be promoted to B-grade only after matrix validation across at least two vendors.** A signal verified on one vendor is a hypothesis, not a fact.

## Case 2: The Xiaomi that was "rooted" twice over (98 points)

This one was nastier — two *independent* systematic FP families on a clean Xiaomi Android 16 device, producing `mount.overlay` B×24 and `mem.hidden_mapping` B×12. Twenty-four "root mount" findings and twelve "hidden memory mapping" findings. Conclusive.

### Family 1: Factory overlayfs is not your overlayfs

HyperOS ships with `overlayfs` overlays on `/product`, `/oem`, and parts of `/system` — **from the factory**. Our rule said `fstype == overlay` on system partitions → B-grade (Magisk-style magic mount). On the Xiaomi, twenty-four system mounts were genuine OEM customization.

The fix differentiates by **physical fingerprint**, not filesystem type: an overlayfs mounted by root modules always has its writable layer (`upperdir`/`workdir`) under `/data/adb/...` — that's where module storage physically lives. OEM customization overlays have their upper layers elsewhere (or none). So:

- `fstype=overlay` **and** `upperdir|workdir` contains `/data/adb` → B-grade, as before
- OEM-shaped overlay → no finding
- everything else → demoted to C-grade weight

The detection semantics for actual Magisk mounts are unchanged — the module fingerprint is *more* specific than the fstype test ever was.

### Family 2: A race condition between two snapshots

This is the one systems people will enjoy. Collector C6 cross-checks the dynamic linker's module list (`solist`) against `/proc/self/maps`: a module present in the linker list but absent from maps is being hidden from the maps view — a known hiding technique. B-grade.

The original code read **maps first, then solist**. Between the two snapshots — milliseconds apart — the Adreno graphics stack `dlopen`ed a library. Result: the linker list (taken second) contained a module that the maps snapshot (taken first) didn't. Twelve "hidden mappings," all of them a GPU driver minding its own business.

The forensic clincher: running the solist-vs-maps diagnostic alone, with no scan around it, showed `uncovered = 0`. The finding existed *only* in the presence of the scan itself — the signature of a self-induced race, not a device state.

The fix has three parts:

1. **Snapshot order reversed** — solist first, then maps. The race window now closes in the safe direction: a module that loads between the snapshots appears in *neither* the "present in solist, absent in maps" direction... and the direction that catches true erasure (hiding tools remove maps entries *after* the process formed them) is untouched. True-erasure detection capability is unchanged.
2. **Solist output switched to the real mapped address** of the first allocatable segment, eliminating a class of address-matching artifacts.
3. A rule written into the project's engineering doc, because it generalizes: **for snapshot-based cross-checks, read order is part of correctness** — not an implementation detail.

## What we built afterward: the FP certification system

Both incidents were found by *accident* (first scan on a new vendor). That's not a QA strategy. [FP_CERTIFICATION.md](https://github.com/lotty520/Detect-Any/blob/main/docs/FP_CERTIFICATION.md) turns "clean device scans clean" from a manual ritual into a three-layer, partially automated pipeline:

**L1 — Input-source verification (static).** Every probe's trigger is a pure function of OS-level inputs: package lists, system properties, mountinfo, accessibility settings. On a clean device, we prove each input *absent*, item by item (`fp_certify.sh` automates this). Absent input on a clean device = structurally impossible false positive — a stronger claim than "we ran it and nothing fired."

**L2 — Clean-matrix scan (dynamic).** A device × legal-state matrix — ADB debugging on, no SIM, accessibility enabled, **factory OEM overlays**, **GPU runtime loads**, dark mode, large fonts... Each cell must scan to zero A-grade, zero *unexpected* B-grade findings, `Inconclusive` verdict, and a score within the per-model baseline. Any finding outside the model's recorded baseline fails certification; a baseline entry that *disappears* triggers a review of whether its grading is still correct.

**L3 — Grading audit (semantic).** Every A- or B-grade signal must answer, in writing: *why can this signal not physically occur in a legitimate environment?* If the answer invokes luck, hope, or "it didn't fire on my phone" — it's a C.

Since 2026-11-13, this certification is mandatory for every probe/signature/grading change: clean emulator verification **plus** a full-matrix clean-device run per model, PASS required before commit.

## Transferable lessons

If you build detection of any kind — anti-fraud, anti-cheat, malware, integrity — these four generalize beyond Android:

1. **Grade by physical invariant, not by intuition.** "Properties should be consistent" is intuition. "A verified-boot state cannot legitimately contradict the fingerprint" is physics. Only the second deserves a conclusive grade.
2. **A signal validated on one vendor is a hypothesis.** The Android ecosystem's factory variation (Huawei's `dev-keys` bootimage, Xiaomi's shipping overlayfs) routinely mimics tamper indicators. Multi-vendor matrix before promotion.
3. **Self-induced findings are real.** If a finding appears only when your scanner runs (and never in isolation), you're looking at your own race condition. Diagnostic-runs-alone is the test.
4. **Snapshot read order is part of correctness.** Any two-view cross-check (list vs maps, cache vs disk, query vs query) has an interleaving story you must be able to tell out loud.

False negatives are recoverable. False positives destroy trust. We'd rather miss a clever adversary today than accuse an honest user tonight.

---

*Detect-Any is Apache-2.0, minSdk 24, 142 evidence-graded checks, honest per-item accuracy ledger ([DETECTION_ACCURACY.md](https://github.com/lotty520/Detect-Any/blob/main/docs/DETECTION_ACCURACY.md)). If you run a deep-hiding stack (susfs + manager uninstall, Shamiko, …), try the [Deep-Hiding Challenge](https://github.com/lotty520/Detect-Any/issues/1) — reported misses and catches both make the tool better.*
