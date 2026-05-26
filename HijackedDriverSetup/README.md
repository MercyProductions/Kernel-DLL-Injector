# Hijacked Driver Setup

This folder keeps the original EIQDV-style driver artifact separate from the
project source folders so the workspace root stays easy to scan.

- `NalDrv.sys` is the bundled original backend driver artifact retained from the
  Face Injector lineage.
- The loader's option `1` path still uses the EIQDV IOCTL backend wrapper under
  `DllInjector/driver/`.
- Keep this folder for authorized lab and defensive research workflows only.
