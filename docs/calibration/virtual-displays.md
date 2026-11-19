# Virtual Display Ground Truth (Lab Calibration)

> Change `virtual-display-detect` · D4 lab capture · 2026-11-18
> Environment: API 35 google_apis arm64 emulator (Android 15), scrcpy 5.0.1 (Homebrew), adb over USB-transport.
> Method: `adb shell dumpsys display` is the ground-truth instrument (NOT app-observable — used only to calibrate; the classifier must rely on the app-observable mapping below).

## Truth Table

| Class | `DisplayDeviceInfo` (dumpsys ground truth) | App-observable mapping |
|---|---|---|
| Built-in (default) | name `"Built-in Screen"`, uniqueId `local:<id>`, type INTERNAL, touch INTERNAL, `FLAG_ALLOWED_TO_BE_DEFAULT_DISPLAY \| FLAG_ROTATES_WITH_CONTENT \| FLAG_SECURE \| FLAG_SUPPORTS_PROTECTED_BUFFERS \| FLAG_TRUSTED`, displayId 0 | own `displayId == 0`; no finding |
| **scrcpy `--new-display`** | name **`"scrcpy"`**, uniqueId **`virtual:com.android.shell,2000,scrcpy,0`** (owner package + **uid 2000** + name), type VIRTUAL, touch VIRTUAL, flags `ROTATES_WITH_CONTENT \| PRESENTATION \| OWN_CONTENT_ONLY \| DESTROY_CONTENT_ON_REMOVAL \| SHOULD_SHOW_SYSTEM_DECORATIONS \| TRUSTED \| OWN_DISPLAY_GROUP \| **ALWAYS_UNLOCKED** \| TOUCH_FEEDBACK_DISABLED \| **OWN_FOCUS** \| SECURE \| SUPPORTS_PROTECTED_BUFFERS`, 1280x720, displayId 2 | **`Display.getName()` == "scrcpy"** → `shell-owned`; flags int has `FLAG_PRESENTATION`; own displayId = 2 ≠ 0 |
| **dev-simulate overlay** (`settings put global overlay_display_devices "1080x1920/420"`) | name **`"Overlay #1"`**, uniqueId `overlay:1`, type OVERLAY, `FLAG_PRESENTATION \| FLAG_DESTROY_CONTENT_ON_REMOVAL` | name pattern `Overlay #N` → `dev-simulate`; corroborated by `Settings.Global.getString(..., "overlay_display_devices")` flipping null → `"1080x1920/420"` (string key — the `OVERLAY_DISPLAY_DEVICES` constant is hidden API, must not be referenced) |
| legit-cast-oem (Chromecast/DeX/secondary) | **not reproducible in this lab** | MediaRouter route + name patterns — initial whitelist EMPTY, pending real-device matrix (see FP boundary) |

## Cross-Validation: Real Device (2026-11-19)

Pixel 8 (shiba, Android 16, patch 2025-11-05, verified-boot green) — identical truth:
`DisplayDeviceInfo{"scrcpy": uniqueId="virtual:com.android.shell,2000,scrcpy,2", 1080x2400/420` — name and shell owner (uid 2000) match the API35 emulator table verbatim. Real-device E2E TP via `am start --display N` + debug broadcast trigger: composite-B finding `screenshare.virtual_display_shell_control` present in the DA-FIND evidence vector. Note: `input -d <id> tap` does NOT reach apps on scrcpy virtual displays (reproduced on both emulator and P8 — platform behavior; the debug scan-trigger broadcast exists for exactly this class of testing).

## Key Findings

1. **The scrcpy display name is "scrcpy"** — resolves the D4 open question: `shell-owned` is name-attributable via public `Display.getName()`. uniqueId/type are hidden-API territory (ground truth only).
2. **`FLAG_PRESENTATION` is the minimal common bit** of every non-default display observed; the scrcpy combo adds `FLAG_OWN_FOCUS + FLAG_ALWAYS_UNLOCKED` (stays unlocked, takes focus — the remote-control signature), but those flag constants are newer-API — record the raw int, mask by ProbeCap.
3. **Lifecycle**: the virtual display exists exactly as long as the on-device `scrcpy-server` process (`app_process / com.genymobile.scrcpy.Server ... new_display=1280x720`) lives. Killing the desktop client alone leaves server + display up (a `CleanUp` helper process was observed). Server kill tears the display down within seconds.
4. **ADB co-presence**: the whole flow rides on adb (server push + shell identity, uid 2000). A `shell-owned` display therefore naturally co-occurs with the ADB posture signal → the composite-B design (display + ADB, both collected by C12) holds empirically.
5. App launch on the virtual display confirmed: our own activity showed `mDisplayId=2` while scrcpy `--start-app` was active.

## Classifier Feature Derivation (app-observable only)

- own displayId ≠ `Display.DEFAULT_DISPLAY` → posture finding (category by classifier)
- per-display: `getName()` → `scrcpy` → shell-owned; `Overlay #N` → dev-simulate; else flags/routes
- `overlay_display_devices` non-null → dev-simulate corroboration
- MediaRouter active route matching the display → legit-cast-oem (matrix-pending)
- unknown fallback → `unknown`
- Cross-check vs C5/C10 signature DB for container-created displays (`container-app` class; no live sample this lab)

## Boundaries

- DeX / Chromecast / foldable secondary / CarPlay-class displays: **no lab reproduction** — `legit-cast-oem` starts with an empty whitelist; all unmatched → `unknown` at **C-grade** until the fp_certify matrix row passes (≥2 vendors).
- Waydroid/other containers not covered by this capture.
