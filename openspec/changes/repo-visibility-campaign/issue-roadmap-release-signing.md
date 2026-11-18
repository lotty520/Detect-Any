# Title: Roadmap: release-signed APK + automated release assembly checklist

**Body:**

> Labels: `roadmap`, `release-engineering`

Current releases ship **debug-signed** APKs (same signing as the FP-certification baseline builds). This issue tracks the path to release-signed distribution.

## Why not already done

The release assembly checklist ([docs/RUNBOOK.md — 发布装配清单](https://github.com/lotty520/Detect-Any/blob/main/docs/RUNBOOK.md)) requires per-artifact substitutions before a release build is safe to ship:

1. **Self-guard XOR constants** — `SIG_A/SIG_B` (APK signature digest) and `CRC_A/CRC_B` (classes.dex CRC32) in `core/native-platform/src/main/cpp/guard.cpp` must be replaced with the *release artifact's* actual values. Shipping without this step silently disables self-protection.
2. **Google attestation dual-root PEMs** — RSA 2016 + ECDSA P-384 2026 roots must be assembled into `AttestationVerifier`.
3. **ed25519 public key** injection for `SignatureStore` hot-update verification.
4. **keybox blacklist / device baselines** bundled with signature data.

This is a chicken-and-egg loop today (constants depend on the signed artifact, which depends on the constants) that must be broken by a two-pass build, plus keystore management (CI secrets vs local).

## Work items

- [ ] Two-pass release build: assemble → compute SIG/CRC → re-assemble → verify self-guard trips on tamper
- [ ] Keystore provisioning (CI secret or documented local flow)
- [ ] Attestation roots + ed25519 key injection automated in gradle
- [ ] `check_release_hygiene.sh` extended: flag debug-signed assets on releases ≥ v1.0
- [ ] RUNBOOK assembly checklist replaced by `./gradlew :app:assembleReleaseDistribution` (single command)

## Acceptance

- A release tag whose APK is release-signed, self-guard verified, and passing `verify16kAlignment`
- Release notes still publish SHA-256 (per release-hygiene spec)

Related: `release-hygiene` capability (openspec/specs/release-hygiene).
