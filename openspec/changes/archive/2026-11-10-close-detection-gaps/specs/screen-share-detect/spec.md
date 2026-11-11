# Spec Delta

## Purpose

Detect screen sharing, mirroring, remote control, and overlay injection — covering scrcpy, Vysor, AnyDesk, TeamViewer, AirDroid, cloud phone controllers, and mod menu overlays. These enable "screen-off" cheating, remote bot control, and UI-layer tampering.

## ADDED Requirements

### Requirement: ADB session indicator
The system SHALL detect active ADB debugging sessions: (a) `Settings.Global.ADB_ENABLED` for USB debugging, (b) `Settings.Global.getInt("adb_wifi_enabled")` for wireless debugging (Android 11+), (c) `BatteryManager.BATTERY_PLUGGED_USB` combined with ADB enabled and no charging app in foreground. USB + ADB + game running is a B-grade scrcpy/Vysor session signal.

#### Scenario: scrcpy over USB detected
- **WHEN** USB is plugged AND ADB_ENABLED is 1 AND no charging app is foreground
- **THEN** B-grade remote session finding is produced

#### Scenario: Wireless debugging detected
- **WHEN** adb_wifi_enabled is 1
- **THEN** C-grade debugging finding is produced

#### Scenario: Developer testing (not cheating)
- **WHEN** ADB_ENABLED is 1 but USB is not plugged and game is not in foreground
- **THEN** no finding is produced (developer is not screen-sharing during gameplay)

### Requirement: scrcpy artifacts detection
The system SHALL detect scrcpy-specific artifacts: (a) `/proc/net/unix` abstract socket names starting with `scrcpy_`, (b) `/proc/[pid]/cmdline` containing `com.genymobile.scrcpy.Server` via app_process, (c) `InputDevice` enumeration finding a device named "scrcpy" (uhid/HID mode).

#### Scenario: scrcpy server socket detected
- **WHEN** /proc/net/unix contains an abstract socket starting with scrcpy_
- **THEN** A-grade screen sharing finding is produced

#### Scenario: scrcpy HID device detected
- **WHEN** InputDevice.getDeviceIds() contains a device named "scrcpy"
- **THEN** A-grade remote control finding is produced

### Requirement: Remote desktop app detection
The system SHALL detect known remote desktop packages via application fingerprint: AnyDesk (`com.anydesk.anydeskandroid`), TeamViewer (`com.teamviewer.quicksupport.market`, `.host.market`, `.teamviewer.market.mobile`), AirDroid/AirMirror (`com.sand.airdroid`, `com.sand.airmirror`), Vysor (`com.koushikdutta.vysor`), Chrome Remote Desktop (`com.google.chromeremotedesktop`). Presence alone is C-grade; presence + accessibility service enabled is B-grade.

#### Scenario: TeamViewer with accessibility control
- **WHEN** com.teamviewer.quicksupport.market is installed AND its accessibility service is enabled
- **THEN** B-grade remote control finding is produced

#### Scenario: AnyDesk installed but not active
- **WHEN** com.anydesk.anydeskandroid is installed but no accessibility service is enabled
- **THEN** C-grade informational finding is produced

### Requirement: Input injection forensics
The system SHALL detect non-physical touch input: (a) `MotionEvent.FLAG_IS_ACCESSIBILITY_EVENT` flag set (accessibility-injected, covers AnyDesk/TeamViewer/auto-clickers), (b) `InputDevice.isVirtual()` on the event source device, (c) input event with device ID 0 (synthetic from Instrumentation/adb). Each is a B-grade signal; combined with known remote desktop package is A-grade.

#### Scenario: Accessibility-injected touch detected
- **WHEN** onTouchEvent receives event with FLAG_IS_ACCESSIBILITY_EVENT set
- **THEN** B-grade automated input finding is produced

#### Scenario: Virtual device input detected
- **WHEN** MotionEvent.getDeviceId() resolves to a virtual InputDevice
- **THEN** B-grade synthetic input finding is produced

### Requirement: Screen recording detection
The system SHALL detect screen recording on API 34+ via `WindowManager.addScreenRecordingCallback` (Android 15) and `Activity.registerScreenCaptureCallback` (Android 14). On API < 34, the system MUST fall back to MediaProjection foreground service detection via package manager. This detection is advisory only (C-grade) since not all capture methods use MediaProjection.

#### Scenario: MediaProjection recording detected on Android 15
- **WHEN** screen recording callback fires with SCREEN_RECORDING_STATE_VISIBLE
- **THEN** C-grade screen recording finding is produced

#### Scenario: API 24 device (no callback available)
- **WHEN** device runs API 24 and screen recording callback is unavailable
- **THEN** fallback checks FLAG_SECURE bypass artifacts and produces no direct recording signal

### Requirement: Overlay permission and tapjacking detection
The system SHALL detect overlay-based UI injection: (a) `Settings.canDrawOverlays()` for non-system apps holding overlay permission, (b) `MotionEvent.FLAG_WINDOW_IS_OBSCURED` or `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (API 29+) on touch events, (c) known mod menu native library fingerprints (KittyMemory, Dobby, xDL strings in `/proc/self/maps`).

#### Scenario: GameGuardian floating overlay detected
- **WHEN** a non-system app holds overlay permission AND data directories starting with GG- exist
- **THEN** B-grade overlay finding is produced

#### Scenario: Mod menu without overlay permission
- **WHEN** canDrawOverlays is false but KittyMemory/Dobby strings found in loaded native libraries
- **THEN** A-grade injected mod menu finding is produced

#### Scenario: Legitimate screen dimmer
- **WHEN** a screen dimmer or blue light filter app holds overlay permission
- **THEN** C-grade informational finding only (whitelist known filter packages)
