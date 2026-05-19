# VulnerableDriverScanner

Passive helper for finding drivers that are likely affected by Microsoft's vulnerable driver blocklist.

## Workflow If The Blocklist Is Currently Off

1. Run an elevated baseline scan:

   ```bat
   VulnerableDriverScanner.exe snapshot list1
   ```

2. Enable Microsoft's vulnerable driver blocklist in Windows Security, restart the PC, then run:

   ```bat
   VulnerableDriverScanner.exe snapshot list2
   ```

3. Compare the snapshots:

   ```bat
   VulnerableDriverScanner.exe compare list1 list2
   ```

Auto compare mode treats drivers that existed in `list1` but are missing from `list2` as blocklist candidates.

## Workflow If The Blocklist Is Already On

1. Run an elevated protected-state scan:

   ```bat
   VulnerableDriverScanner.exe snapshot list1
   ```

2. In a controlled test environment, disable Microsoft's vulnerable driver blocklist, restart the PC, then run:

   ```bat
   VulnerableDriverScanner.exe snapshot list2
   ```

3. Compare the snapshots:

   ```bat
   VulnerableDriverScanner.exe compare list1 list2
   ```

Auto compare mode treats drivers that were missing from protected `list1` but appeared in unprotected `list2` as blocklist candidates.

Both flows require only one restart. The comparison result is a strong hint, not proof, because drivers can also appear or disappear if hardware, services, or startup conditions changed between boots.

## Compare Modes

```bat
VulnerableDriverScanner.exe compare list1 list2 --mode auto
VulnerableDriverScanner.exe compare list1 list2 --mode removed
VulnerableDriverScanner.exe compare list1 list2 --mode added
VulnerableDriverScanner.exe compare list1 list2 --mode both
```

- `auto` uses snapshot metadata to choose `removed` or `added`.
- `removed` reports drivers present in the first snapshot and missing from the second.
- `added` reports drivers missing from the first snapshot and present in the second.
- `both` reports both directions when protection state is ambiguous or unchanged.

## What It Checks

- Currently loaded kernel drivers via `EnumDeviceDrivers`.
- Driver service metadata from the Service Control Manager.
- SHA-256 hashes and version-resource fields.
- Static IOCTL/device-control indicators from PE imports and embedded strings.
- DOS device symbolic links from `QueryDosDevice`.

The scanner does not load drivers, unload drivers, fuzz IOCTLs, or call `DeviceIoControl` against arbitrary device objects.

## Output Location

Snapshots and comparison reports are saved locally under:

```text
%LOCALAPPDATA%\Aegis\VulnerableDriverScanner
```
