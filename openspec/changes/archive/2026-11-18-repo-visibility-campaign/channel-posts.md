# Channel Post Drafts — repo-visibility-campaign

Copy-paste drafts for the manual channel pushes (tasks 4.1–4.6). All in English per instruction — for Coolapk/V2EX you may prefer to adapt into Chinese at posting time (your call; content is identical).

Timing guard (design D6): **do not post anywhere until `scripts/check_release_hygiene.sh` exits 0** (i.e. after the v0.4.2 release is live).

---

## 4.1 Coolapk (酷安) — experience angle

**Title:** Detect-Any — open-source Android integrity scanner: can your Magisk/KernelSU hide from it?

**Body:**

Scan your own phone in 10 seconds. Detect-Any is an open-source (Apache-2.0) environment integrity scanner: 142 evidence-graded checks across root (KernelSU/APatch/Magisk), Zygisk injection, LSPosed, Frida, emulators/VMs, cloud phones, multi-open containers, attestation spoofing (PIF/TrickyStore) — plus hardware key attestation (L3).

- Fully offline, no root needed, Android 7.0+
- Every signal graded A/B/C by evidence strength — a single physical-invariant A-grade is conclusive; static traces alone never are
- Every false positive we've ever shipped is documented and forensically explained (Huawei 58-score and Xiaomi 98-score incidents, both root-caused): https://lotty520.github.io/Detect-Any/accuracy/ (EN) · https://github.com/lotty520/Detect-Any/blob/main/docs/FP_CERTIFICATION.md (中文)

Website: https://lotty520.github.io/Detect-Any/
Download (latest): https://github.com/lotty520/Detect-Any/releases/latest

Root users: we want to lose. Post your hiding stack + L2 result in the Deep-Hiding Challenge pinned issue — catches and misses both welcome.

---

## 4.2 V2EX — engineering angle

**Title:** 开源 Detect-Any：Android 环境完整性检测框架（142 项证据分级 / 真机 FP 认证体系） *(adapt language as you prefer)*

**Body:**

分享一个做了几周的 Apache-2.0 项目：https://github.com/lotty520/Detect-Any

要点：
- 21 个 Gradle 模块、12 个 collector 并行（扫描耗时 = 最慢 collector，不是求和）
- A/B/C 证据分级：A级物理不变量（prologue 字节比对 / 三路 syscall diff / verified boot 矛盾）单发定性；B 级需跨域双命中；C 级只加权
- FP 认证体系：干净机型矩阵 + 合法状态矩阵（ADB 开/无 SIM/无障碍/出厂 overlayfs…）自动化核准，探针改动必须过干净真机才能 commit——起因是干净华为 58 分、干净小米 98 分两次系统性误报（取证过程写在 docs/essays/）
- 深度隐藏（susfs + manager 卸载）可穿透：verified boot 矛盾(A) + zygisk 残留属性(B)

APK 直链（Android 7.0+，离线运行）：https://github.com/lotty520/Detect-Any/releases/latest

欢迎 root 玩家来 pinned issue 打靶（Deep-Hiding Challenge）。

---

## 4.3 Show HN

**Title:** Show HN: Detect-Any – Open-source Android environment integrity detection

**Text:**

Hi HN — we built an open-source (Apache-2.0) Android integrity scanner: https://github.com/lotty520/Detect-Any

It detects root frameworks (KernelSU/APatch/Magisk), Zygisk injection, LSPosed, Frida (rename-immune defenses), emulators, cloud phones, multi-open containers, and attestation spoofing — 142 checks, each graded by evidence strength: A = physical invariant (single hit is conclusive: prologue byte comparison, triple-path syscall diff, verified-boot contradiction), B = behavioral (needs two independent domains), C = static trace (weight only, never conclusive).

Two things we think are unusual:

1. Every false positive we've shipped is publicly documented with full forensics. A clean Huawei scored 58 and a clean Xiaomi scored 98 before we built a certification pipeline — the Xiaomi incident included a solist-vs-maps snapshot race where our own scanner induced the finding. Write-up: https://lotty520.github.io/Detect-Any/essay-oem-fp-forensics/
2. There's an honest accuracy ledger for all 142 items — including what we can't detect (KPM kernel patches, high-end cloud phones with real-peripheral passthrough): https://lotty520.github.io/Detect-Any/accuracy/

The asymmetry that drives the engineering: false negatives are recoverable, false positives destroy trust.

APK (Android 7.0+, offline): https://github.com/lotty520/Detect-Any/releases/latest — happy to answer anything about the detection techniques or the FP forensics.

*(Remember: post as Show HN, don't ask for upvotes, stay in the thread.)*

---

## 4.4 r/androiddev

**Angle:** FP engineering practice post, not a launch post.

**Title:** We gave a clean flagship a 98/100 "rooted" score — the forensic story of two systematic false positives (and the certification pipeline that came out of it)

**Text:**

While building an open-source Android integrity scanner, our first scan of a factory-fresh Xiaomi Android 16 device returned 24 B-grade "root overlay" findings and 12 "hidden memory mapping" findings — conclusive, and completely wrong. A week earlier a clean Huawei had scored 58 for "attestation spoofing."

Both incidents were grading failures, not detection failures:
- Huawei ships `bootimage.build.tags=dev-keys` while the main fingerprint says release-keys, `vendor.product.*` empty — six "tamper-indicating" property-pair inconsistencies that are factory-legal
- Xiaomi/HyperOS ships overlayfs on /product and /oem from the factory; and our linker-list-vs-maps cross-check had a snapshot race where the Adreno driver's dlopen between two reads looked like maps-hiding

Full write-up with the race-condition forensics: https://lotty520.github.io/Detect-Any/essay-oem-fp-forensics/

We ended up building a three-layer FP certification pipeline (input-source verification, clean device × legal-state matrix scan, per-signal grading audit) that's now mandatory for every probe change: https://lotty520.github.io/Detect-Any/accuracy/ (EN) · https://github.com/lotty520/Detect-Any/blob/main/docs/FP_CERTIFICATION.md (中文)

Curious how others handle OEM variation in integrity/anti-fraud signals — the "validated on one vendor" trap seems universal.

---

## 4.5 awesome-android-security PR

Fork https://github.com/ashishb/android-security — edit README.md, add under the relevant section (e.g. *"Dynamic Analysis and Reverse Engineering Tools"* / app integrity area):

```
- [Detect-Any](https://github.com/lotty520/Detect-Any) - Open-source Android environment integrity detection: root/Zygisk/hook/Frida/emulator, 142 evidence-graded checks, hardware attestation
```

PR title: `Add Detect-Any - open-source Android integrity detection`

---

## 4.6 Android Weekly submission

https://androidweekly.net/ → submit link. Use either:
- Repo: https://github.com/lotty520/Detect-Any
- Article (better fit for newsletters): https://lotty520.github.io/Detect-Any/essay-oem-fp-forensics/

Suggested description: *"How two clean flagship phones scored 58 and 100 on an Android integrity scanner — FP forensics and the certification pipeline that fixed it."*

Also: https://androiddevweekly.com/ (issue-based, DM/PR the maintainer).
