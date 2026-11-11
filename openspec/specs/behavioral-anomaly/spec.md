# behavioral-anomaly Specification

## Purpose

Detect behavioral anomalies that indicate cheating: VPN-based MITM, proxy configuration, accessibility service abuse for automation, speed manipulation via clock hooking, and GPS spoofing.

## Requirements

### Requirement: VPN transport detection
The system SHALL check `ConnectivityManager.getNetworkCapabilities()` for `hasTransport(TRANSPORT_VPN)`. An active VPN during app execution is a B-grade signal for network manipulation (HTTP Toolkit, Packet Capture, PCAPdroid).

#### Scenario: HTTP Toolkit VPN detected
- **WHEN** HTTP Toolkit's on-device VPN service is active
- **THEN** VPN transport check produces B-grade finding

### Requirement: Proxy configuration detection
The system SHALL check `System.getProperty("http.proxyHost")` and `System.getProperty("http.proxyPort")` for non-null values. A configured proxy is a C-grade signal for Charles/Burp/mitmproxy.

#### Scenario: Charles proxy detected
- **WHEN** Wi-Fi proxy is set to Charles host
- **THEN** proxy property check produces C-grade finding

### Requirement: Accessibility service enumeration
The system SHALL enumerate enabled accessibility services via `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES`. Known automation packages (AutoX.js, EasyClick, MacroDroid, auto-clickers) produce B-grade findings. Unexpected non-OS accessibility services produce C-grade findings.

#### Scenario: Auto-clicker accessibility service detected
- **WHEN** a known auto-clicker package has an enabled accessibility service
- **THEN** B-grade bot finding is produced

#### Scenario: Unknown accessibility service present
- **WHEN** an unexpected non-OS accessibility service is enabled
- **THEN** C-grade behavioral anomaly finding is produced

### Requirement: Multi-clock consistency check
The system SHALL compare elapsed time from multiple independent clock sources over a measurement window: `SystemClock.elapsedRealtimeNanos()` (CLOCK_BOOTTIME), `System.nanoTime()` (CLOCK_MONOTONIC), and `System.currentTimeMillis()` (wall clock). Divergence beyond normal drift indicates speed manipulation（校准后阈值：>100ms / 500ms 窗口，calibration #8——spec 原稿 50ms/1s 已按实测修订）。

#### Scenario: GameGuardian speed hack detected
- **WHEN** clock_gettime is hooked to run at 2x speed
- **THEN** BOOTTIME vs MONOTONIC divergence exceeds threshold and produces B-grade finding

#### Scenario: Clean device clocks consistent
- **WHEN** no speed manipulation is active
- **THEN** clock divergence remains within normal drift bounds (<5ms)

### Requirement: GPS mock location detection
The system SHALL check `Location.isMock()` (API 31+) or `Location.isFromMockProvider()` (pre-31) on the last known location. A mock location flag is a C-grade signal.
- **范围修订（2026-11-10 审计）**：运行时 isMock 需 ACCESS_FINE/COARSE_LOCATION
  （隐私敏感，产品决策不申请）——落地为伪造定位应用包指纹（特征库 app.fakegps）+
  地理三方交叉（geo.tz_sim_mismatch）替代，运行时 mock 判定列为不做。

#### Scenario: Fake GPS app active
- **WHEN** last location update has isMock=true
- **THEN** GPS spoofing finding is produced
