# Spec Delta

## Purpose

Detect Frida-family dynamic instrumentation frameworks (all variants including anti-detection forks), objection toolkits, and embedded Frida gadgets — covering 12 known tools that represent the single largest cheating vector on Android.

## ADDED Requirements

### Requirement: Frida server detection via D-Bus protocol probe
The system SHALL probe all TCP ports for Frida's D-Bus protocol handshake, not only port 27042. The probe MUST send a D-Bus AUTH message and check for the Frida-specific response pattern, enabling detection even when the port is changed via `-l` flag or when the binary is renamed by anti-detection forks (hluda, Florida, undetected-frida).

#### Scenario: Frida server detected via D-Bus on non-default port
- **WHEN** frida-server runs on port 30000 (renamed to hluda-server)
- **THEN** the D-Bus protocol probe identifies it as a Frida endpoint

#### Scenario: No false positive on clean device
- **WHEN** no Frida instance is running
- **THEN** the D-Bus probe returns no match on any port

### Requirement: Frida artifacts in memory maps
The system SHALL scan `/proc/self/maps` for Frida agent patterns: `frida-agent`, `linjector`, `frida-gadget`, and anonymous RWX pages with Frida-typical sizes. The system MUST also scan `/proc/self/task/*/comm` for thread names including `gum-js-loop`, `gmain`, and `pool-frida`.

#### Scenario: Frida gadget embedded in repackaged APK detected
- **WHEN** the app was repackaged with an embedded frida-gadget.so
- **THEN** maps scan identifies the gadget library

#### Scenario: Renamed fork partially detected
- **WHEN** hluda renames thread names and agent symbols
- **THEN** anonymous RWX page scan still identifies suspicious memory regions

### Requirement: Frida behavioral fingerprint
The system SHALL detect Frida via page-permission characteristics of the agent's injected memory (consecutive RWX pages with specific alignment patterns), even when all string artifacts are renamed. The system MUST NOT rely solely on string matching for conclusive detection.

#### Scenario: All strings renamed
- **WHEN** hluda renames every frida/gum/gadget string
- **THEN** page-permission characteristics still identify the agent

### Requirement: Il2Cpp hook detection
The system SHALL detect Unity Il2Cpp runtime tampering by checking for hook trampolines in the il2cpp domain resolver table and foreign code pages mapped near libil2cpp.so.

#### Scenario: Il2CppHookScripts injection detected
- **WHEN** a Frida script hooks Il2Cpp internal method resolution
- **THEN** foreign code pages near libil2cpp.so are identified
