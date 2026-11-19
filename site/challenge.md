# Deep-Hiding Challenge

> Can your hiding stack survive an L2 scan? **Catches and misses both make the tool better.**

This is the standing adversarial playground from the [pinned issue](https://github.com/lotty520/Detect-Any/issues/1). If you run a root/hiding stack — KernelSU/APatch + susfs, Shamiko, Zygisk hiders, TrickyStore, PIF forks — run Detect-Any's **L2 full scan** against your real daily driver and report the result.

## How to participate

1. Download the [latest APK](https://github.com/lotty520/Detect-Any/releases/latest) (Android 7.0+, no root needed, fully offline — installing it on a rooted device is fine)
2. Run an **L2 Full** scan
3. Post a comment on [issue #1](https://github.com/lotty520/Detect-Any/issues/1) using the template: device/ROM, root solution, hiding stack + versions, manager visibility, L2 score + verdict, what it caught, what it missed (screenshots welcome)

## Rules

- Only clean-baseline + deep-hiding scenarios — your real daily driver, not planted malware samples
- Be specific: "it missed everything" without a stack description is not actionable
- If you believe a finding is a **false positive**, say so explicitly — FPs get the same forensic treatment as misses ([how we handle them](accuracy.md))

## Known honest boundaries (not misses)

- KPM (Kernel Patch Module) — userspace has no observation interface
- High-end cloud phones with real-peripheral passthrough
- Custom `resetprop` full-profile erasure — behavioral-surface residue only

Everything else is fair game. Happy hiding. 🐱🐭
