# virtual-env-detect Specification

## Purpose

Detect virtual machines, sandbox containers, app virtualization frameworks, and Android emulators — 11 known tools that allow cheating without root by running the target app in a controlled environment.

## Requirements

### Requirement: Emulator build-property detection
The system SHALL cross-check `Build.FINGERPRINT`, `Build.MODEL`, `Build.PRODUCT`, `Build.HARDWARE`, and `Build.BRAND` against known emulator patterns: `generic`, `google_sdk`, `sdk_gphone`, `vbox86`, `nox`, `ttVM`, `ldplayer`, `goldfish`, `ranchu`. The system MUST also check `ro.kernel.qemu` system property.

#### Scenario: BlueStacks emulator detected
- **WHEN** Build.FINGERPRINT contains "generic" or /data/bluestacks.prop exists
- **THEN** emulator finding is produced with B-grade confidence

#### Scenario: LDPlayer with device spoofing
- **WHEN** LDPlayer spoofs Build.MODEL but /dev/vboxguest still exists
- **THEN** hardware artifact check produces A-grade finding

### Requirement: Hardware sensor absence detection
The system SHALL enumerate available hardware sensors and flag absence of accelerometer, gyroscope, proximity, or light sensors on a device claiming to be a phone. The system MUST also check for absent baseband/cellular capability.

#### Scenario: Emulator without sensors detected
- **WHEN** SensorManager returns zero sensors and TelephonyManager reports no SIM
- **THEN** emulator hardware finding is produced

### Requirement: Virtual container detection
The system SHALL detect VirtualApp-family containers by checking: (a) data directory path not matching expected package path, (b) `getPackageCodePath()` vs `ApplicationInfo.sourceDir` mismatch, (c) stack traces containing VirtualApp host class names, (d) known VA/Parallel Space/VMOS package names in installed apps.

#### Scenario: Parallel Space container detected
- **WHEN** app runs inside com.lbe.parallel.* container
- **THEN** data-dir path anomaly and container process detection fire

#### Scenario: VMOS full VM detected
- **WHEN** guest ROM build properties don't match host hardware
- **THEN** VM fingerprint cross-check produces finding

### Requirement: GL renderer fingerprint
The system SHALL query `GL_RENDERER` and `GL_VENDOR` via OpenGL ES and flag emulator-specific strings: "Android Emulator", "SwiftShader", "Bluestacks", "ttVM", "VBox", "Translator".

#### Scenario: Genymotion GL fingerprint
- **WHEN** GL_RENDERER contains "Translator" or "VBox"
- **THEN** emulator finding is produced

### Requirement: CPU architecture consistency
The system SHALL verify that the CPU architecture reported by `/proc/cpuinfo` matches the expected ARM architecture for the device model. An x86/x86_64 CPU on a device claiming to be an ARM phone is an A-grade emulator signal.

#### Scenario: x86 emulator detected
- **WHEN** /proc/cpuinfo shows x86_64 on a device claiming ARM architecture
- **THEN** A-grade emulator finding is produced
