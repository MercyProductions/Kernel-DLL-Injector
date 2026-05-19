# Changelog

All notable Aegis-maintained changes to this fork are tracked here.

## 2026-05-19

### Added

- Added an interactive console menu for `VulnerableDriverScanner.exe` when it is launched without arguments.
- Added menu options for capturing `list1`, capturing `list2`, custom snapshots, default comparison, custom comparison, workflow help, and output-folder changes.
- Added the `VulnerableDriverScanner` Visual Studio project.
- Added loaded-driver snapshot capture with local TSV output.
- Added SHA-256 hashing, service metadata capture, version-resource capture, and static IOCTL/device-control scoring.
- Added bidirectional scanner comparison:
  - off-to-on protection flow reports drivers missing after the Microsoft vulnerable-driver blocklist is enabled.
  - on-to-off protection flow reports drivers that appear after the blocklist is disabled in a controlled test.
- Added compare modes: `auto`, `removed`, `added`, and `both`.
- Added scanner report metadata for blocklist and HVCI registry hints.
- Added scanner report parsing to the loader startup flow.
- Added an option-1 driver-source prompt:
  - use the original Face Injector / EIQDV backend.
  - review VulnerableDriverScanner candidates for audit context.
- Added `.gitignore` rules for Visual Studio build outputs and generated runtime artifacts.

### Changed

- Expanded the README into a full product overview.
- Documented project provenance from `masterpastaa/Face-Injector-V3`.
- Documented the two supported driver backends.
- Documented why scanner-discovered third-party drivers are audit findings, not selectable injector backends.
- Moved the scanner intermediate build output under the ignored `x64` output tree.

### Verified

- Built `face_injector_v3.vcxproj` in `Release|x64` with 0 warnings and 0 errors.
- Built `VulnerableDriverScanner.vcxproj` in `Release|x64` with 0 warnings and 0 errors.
- Smoke-tested scanner compare behavior for:
  - off-to-on protection state.
  - on-to-off protection state.
  - unchanged same-snapshot comparison.

## Historical Base

- Started from [masterpastaa/Face-Injector-V3](https://github.com/masterpastaa/Face-Injector-V3).
- Retains original project credit to **KANKOSHEV** for Face Injector V2.
- Retains original project credit to **busybox10** for Face Injector V1 / original Face Injector.
- Earlier local changes included manual map support and target window-class prompting.
