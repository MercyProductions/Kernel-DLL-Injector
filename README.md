# Kernel-DLL-Injector

Kernel-DLL-Injector is the Aegis-maintained fork of the Face Injector V3 lineage. It started from [masterpastaa/Face-Injector-V3](https://github.com/masterpastaa/Face-Injector-V3), which itself follows the Face Injector family, and has since been heavily modified into a broader Windows kernel-assisted loader research project.

This repository is intended for authorized lab, reverse-engineering, and defensive research environments. Do not use it against systems, processes, games, services, or software you do not own or have explicit permission to test.

## Project Layout

Open `AegisDriverWorkspace.sln` from this folder when you want the whole workspace.

```text
.
|-- AegisDriverWorkspace.sln         Main Visual Studio solution
|-- DllInjector/                     Main loader / DLL injector project
|   |-- face_injector_v3.vcxproj
|   |-- main.cpp
|   |-- drv_unified.h
|   |-- driver/                      User-mode wrappers for EIQDV and AegisDriver2
|   |-- api/                         Low-level utility and embedded mapper payload helpers
|   |-- inject/                      Injection feature helpers
|   |-- third_party/                 ImGui dependency
|-- ExternalTrainer/                 Standalone AegisDriver2 shared-memory trainer template
|-- VulnerableDriverScanner/         Passive loaded-driver scanner and comparison tool
|-- SharedMemoryDriver/              AegisDriver2 kernel driver project
|-- HijackedDriverSetup/             Original EIQDV-style driver artifact
|-- start_aegis.bat                  Admin launcher for the loader
```

## Supported Driver Paths

The loader has two supported runtime backends:

1. `EIQDV IOCTL`
   - The original Face Injector-style backend.
   - Selected from the driver setup screen as option `1`.
   - The bundled original driver artifact lives in `HijackedDriverSetup/`.

2. `AegisDriver2 Shared Memory`
   - A newer Aegis backend that communicates through shared memory and synchronization objects.
   - Selected from the driver setup screen as option `2`.
   - Kernel source lives in `SharedMemoryDriver/`.

Drivers discovered by `VulnerableDriverScanner` are not automatically treated as injector backends. They are displayed for audit and remediation context only. Each third-party driver would require its own reviewed protocol adapter before it could be supported safely.

## Build

Requirements:

- Windows
- Visual Studio 2022
- MSVC v143 toolset
- Windows 10 or newer SDK
- Windows Driver Kit for rebuilding `SharedMemoryDriver/AegisDriver2.vcxproj`

Build the whole workspace:

```bat
msbuild AegisDriverWorkspace.sln /p:Configuration=Release /p:Platform=x64
```

Build individual projects:

```bat
msbuild DllInjector\face_injector_v3.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild ExternalTrainer\ExternalTrainer.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild VulnerableDriverScanner\VulnerableDriverScanner.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild SharedMemoryDriver\AegisDriver2.vcxproj /p:Configuration=Release /p:Platform=x64
```

Generated Visual Studio outputs are intentionally ignored by `.gitignore`.

## VulnerableDriverScanner

`VulnerableDriverScanner` is a separate C++ console project in `VulnerableDriverScanner/`. It is passive by design:

- Enumerates loaded kernel drivers.
- Records driver service metadata.
- Computes SHA-256 hashes.
- Collects version-resource fields.
- Scores static IOCTL/device-control indicators from imports and strings.
- Saves local TSV snapshots.
- Compares snapshots in both directions.

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
