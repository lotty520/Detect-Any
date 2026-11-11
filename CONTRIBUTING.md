# Contributing to Detect-Any

Thanks for your interest! This project has strict accuracy discipline — the rules below exist because every false positive destroys user trust.

## Read First

- **[AGENTS.md](AGENTS.md)** — build commands, verification protocol, critical lessons. Mandatory reading before touching detection logic.
- **[docs/DETECTION_ACCURACY.md](docs/DETECTION_ACCURACY.md)** — how every detection item is graded by evidence chain.

## The One Rule That Matters Most

> **False negatives are recoverable; false positives destroy trust.**

When uncertain about a detection signal's reliability: demote to C-grade, add a control group, or don't ship it.

## Adding a Detection Item

1. **Research first** — verify the artifact/behavior against primary sources (upstream source code beats forum posts). Record the evidence in your PR description.
2. **Data, not code** — new framework targets go into the signature DB (`data/signature`), not new collector modules. Only genuinely new detection *domains* warrant a collector.
3. **Grade honestly** — A requires a physical invariant argument; B requires cross-domain corroboration; everything else is C.
4. **Clean-emulator verification is mandatory** — see the protocol in [AGENTS.md](AGENTS.md#mandatory-verification-protocol). A probe that fires on a clean device does not ship.
5. **Positive verification when possible** — if you can obtain the actual tool (like we did with DRVCAM), install it and prove the hit, then remove it and prove the baseline returns.

## Pull Request Checklist

- [ ] `./gradlew test` green (host unit tests)
- [ ] `./gradlew :app:assembleDebug` green (includes 16KB gate)
- [ ] `./gradlew :app:lintDebug` — NewApi = 0
- [ ] Clean-emulator scan before/after: baseline unchanged
- [ ] If adding signature DB entries: version bumped, entries carry `since`/`until` where applicable
- [ ] If docs are affected (they usually are): numbers updated in DETECTION_CATALOG / COVERAGE_ANALYSIS / README

## Reporting a False Positive

Open an issue with: device model, Android version, the exact finding `ruleId` (visible in evidence detail), and whether the device is rooted/modified. False-positive reports are treated as high-priority bugs.

## Reporting a Bypass (False Negative)

Describe the hiding stack (framework + versions + modules). Note that some scenarios are documented boundaries (see [CAPABILITY_BOUNDARIES.md](docs/CAPABILITY_BOUNDARIES.md)) — check there first.
