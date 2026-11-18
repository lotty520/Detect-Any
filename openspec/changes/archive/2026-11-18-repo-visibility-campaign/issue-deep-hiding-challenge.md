# Title: `Deep-Hiding Challenge` — can your hiding stack survive an L2 scan?

**Body:**

> **Pin this issue.** Labels: `challenge`, `community`

This is a standing adversarial playground. If you run a root/hiding stack (KernelSU/APatch + susfs, Shamiko, Zygisk hiders, TrickyStore, PIF forks, ...), run Detect-Any's **L2 full scan** against it and report the result — **catches and misses alike**. Both make the tool better; a reported miss becomes a detection backlog item, a reported catch calibrates our grading.

## Rules

1. **Only clean-baseline + deep-hiding scenarios.** No planted malware samples, no modified/scanner-tampered builds — we want your real daily-driver hiding stack, not a synthetic zoo.
2. **One comment per setup.** Use the template below.
3. Be specific: "it missed everything" without a stack description is not actionable.
4. Detect-Any is Apache-2.0 and fully auditable — every signal it fires is traceable to source. If you believe a finding on your device is a **false positive**, say so explicitly; FPs get the same forensic treatment as misses ([see how we handle them](https://github.com/lotty520/Detect-Any/blob/main/docs/FP_CERTIFICATION.md)).

## Template (copy into your comment)

```
Device / ROM:            e.g. Pixel 8 · stock Android 16 · Nov 2026 patch
Root solution:           e.g. KernelSU-Next 1.0.x (kernel) / APatch ...
Hiding stack:            e.g. susfs 0.x + ZygiskNext + Shamiko + TrickyStore(keybox) + PIF fork
Manager visibility:      installed / hidden / uninstalled
Detect-Any version:      e.g. v0.4.2 (see Settings tab)
Scan tier:               L2 Full   (L3 attestation results welcome as a bonus)

L2 risk score:           0-100
Verdict:                 Clean / Inconclusive / Conclusive-risky

What it caught:          <list findings that are TRUE on your setup>
What it missed:          <list your components that produced NO finding>
Screenshots:             Scan + Threats tabs (redact serials if you care)
```

## Known honest boundaries (don't report these as misses)

- **KPM (Kernel Patch Module)** — not detectable from userspace
- **High-end cloud phones with real-peripheral passthrough** — client-side reduced to single-point signals
- **Custom resetprop full-profile erasure** — behavioral-surface residue only

Everything else is fair game. Happy hiding. 🐱🐭

---

*Get the scanner: [releases/latest](https://github.com/lotty520/Detect-Any/releases/latest) — Android 7.0+, no root needed, runs offline. It's a normal app; installing it on a rooted device is fine.*
