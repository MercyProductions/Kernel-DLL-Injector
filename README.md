# Kernel-DLL-Injector

Kernel-DLL-Injector is the Aegis-maintained fork of the Face Injector V3 lineage. It started from [masterpastaa/Face-Injector-V3](https://github.com/masterpastaa/Face-Injector-V3), which itself follows the Face Injector family, and has since been heavily modified into a broader Windows kernel-assisted loader research project.

This repository is intended for authorized lab, reverse-engineering, and defensive research environments. Do not use it against systems, processes, games, services, or software you do not own or have explicit permission to test.

## What This Fork Adds

The original Face Injector V3 project focused on a narrower DLL injection flow. This fork keeps that heritage but has grown into a multi-backend loader with stronger project structure, driver abstraction, target prompting, local history, scanner tooling, and safer operator feedback.

Major additions include:

- A unified driver backend layer in `drv_unified.h`.
- Support for the original EIQDV IOCTL-style backend used by the Face Injector path.
- Support for `AegisDriver2`, a separate shared-memory driver backend.
- A startup driver setup screen that lets the user choose the supported backend.
- A new option-1 driver-source prompt that keeps the original EIQDV backend available and lets users review VulnerableDriverScanner findings for audit context.
- Manual map support with configurable target selection.
- Kernel-assisted LoadLibrary workflows for several thread creation approaches.
- A target helper layer for configured process detection and manual process fallback.
- Loader history stored under `%LOCALAPPDATA%\AegisLoader\loader_history.ini`.
- Driver self-tests for basic backend health and invalid-request behavior.
- A separate `VulnerableDriverScanner` project for passive vulnerable-driver inventory and before/after comparison reports.

## Project Layout

```text
.
|-- main.cpp                         Main loader UI and injection workflow selection
|-- drv_unified.h                    Backend abstraction for supported Aegis drivers
|-- driver/                          User-mode wrappers for EIQDV and AegisDriver2
|-- AegisDriver2/                    Kernel driver project for the shared-memory backend
|-- manualmap.cpp / manualmap.h      Manual mapping implementation
|-- target.cpp / target.h            Potential target detection and target metadata
|-- inject/                          Injection feature helpers
|-- api/                             Low-level utility and shellcode helpers
|-- VulnerableDriverScanner/         Passive loaded-driver scanner and comparison tool
|-- face_injector_v3.vcxproj         Main Visual Studio loader project
|-- NalDrv.sys                       Bundled original backend driver artifact
```

## Supported Driver Paths

The loader has two supported runtime backends:

1. `EIQDV IOCTL`
   - The original Face Injector-style backend.
   - Selected from the driver setup screen as option `1`.
   - The loader now asks whether to continue with this original backend or review scanner findings first.

2. `AegisDriver2 Shared Memory`
   - A newer Aegis backend that communicates through shared memory and synchronization objects.
   - Selected from the driver setup screen as option `2`.
   - The loader attempts service startup first and can fall back to the existing mapper path.

Drivers discovered by `VulnerableDriverScanner` are not automatically treated as injector backends. They are displayed for audit and remediation context only. Each third-party driver would require its own reviewed protocol adapter before it could be supported safely.

## VulnerableDriverScanner

`VulnerableDriverScanner` is a separate C++ console project in `VulnerableDriverScanner/`. It is passive by design:

- Enumerates loaded kernel drivers.
- Records driver service metadata.
- Computes SHA-256 hashes.
- Collects version-resource fields.
- Scores static IOCTL/device-control indicators from imports and strings.
- Saves local TSV snapshots.
- Compares snapshots in both directions.

Supported one-restart workflows:

- If Microsoft's vulnerable-driver blocklist is currently off, take `list1`, enable protection, restart, take `list2`, then compare. Drivers missing after protection is enabled become candidates.
- If the blocklist is already on, take `list1`, disable protection in a controlled test, restart, take `list2`, then compare. Drivers appearing after protection is disabled become candidates.

Example:

```bat
VulnerableDriverScanner.exe snapshot list1
VulnerableDriverScanner.exe snapshot list2
VulnerableDriverScanner.exe compare list1 list2 --mode auto
```

Reports are saved under:

```text
%LOCALAPPDATA%\Aegis\VulnerableDriverScanner
```

## Build

Requirements:

- Windows
- Visual Studio 2022
- MSVC v143 toolset
- Windows 10 or newer SDK

Build the main loader:

```bat
msbuild face_injector_v3.vcxproj /p:Configuration=Release /p:Platform=x64
```

Build the scanner:

```bat
msbuild VulnerableDriverScanner\VulnerableDriverScanner.vcxproj /p:Configuration=Release /p:Platform=x64
```

Generated Visual Studio outputs are intentionally ignored by `.gitignore`.

## Runtime Flow

1. Launch the loader as administrator.
2. Choose a supported driver backend:
   - Option `1` for original Face Injector / EIQDV.
   - Option `2` for AegisDriver2 shared memory.
3. If option `1` is selected, optionally review the latest VulnerableDriverScanner comparison report.
4. Pick an injection method.
5. Confirm or enter the target process and DLL path.
6. The loader stores recent target and DLL choices as defaults for the next run.

## Provenance And Credits

This project initially came from [masterpastaa/Face-Injector-V3](https://github.com/masterpastaa/Face-Injector-V3) and has been significantly reworked for Aegis.

Credits retained from the original project:

- **KANKOSHEV** for Face Injector V2.
- **busybox10** for Face Injector V1 / the original version.

## Responsible Use

Kernel-assisted loading and driver research can destabilize systems and can be misused. Keep this work in isolated, authorized environments, and prefer the scanner for defensive inventory and remediation workflows.
