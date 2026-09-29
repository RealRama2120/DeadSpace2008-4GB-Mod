# Dead Space (2008) 4GB Mod

Source and release archive for Rama2120's standalone Large Address Aware mod for the original Dead Space (2008). This repository is separate from the Vortex extension and other Dead Space mods.

The newest locally preserved version is **1.1.2**. The source files at the repository root are the verified 1.1.2 source snapshot. The original release ZIPs are preserved byte for byte under [`versions/`](versions/README.md). The repository does not contain a copy of `Dead Space.exe` or NTCore's patcher.

## Build

On Windows 10 or 11 with the Visual Studio 2022 C++ x86 build tools and PowerShell, run:

```powershell
.\build-and-test.ps1
```

This builds `build\dsound.dll` and runs the source's synthetic patch, restore, and Steam compatibility checks. [`SOURCE_README.md`](SOURCE_README.md) describes the source package and test coverage. `README.txt` is the original 1.1.2 player installation guide. The root files match the local 1.1.2 source checksum manifest; the `vendor/minhook-1.3.4` directory retains MinHook's redistribution license.

## Preserved versions

| Version | Original install ZIP | Original source ZIP | Original checksum record |
| --- | --- | --- | --- |
| 1.1.0 | Yes | Yes, with a browsable extracted snapshot | `RELEASE_CHECKSUMS_v1.1.0.txt` |
| 1.1.1 | Yes | No separate source archive found locally | No original checksum file found; a clearly marked checksum was generated for this backup |
| 1.1.2 | Yes | Yes | Two original `.sha256` sidecars |

The 1.1.1 ZIP contains the same `dsound.dll` bytes as 1.1.0; its package removes developer-facing files and updates the player documentation. That does not make the 1.1.0 source ZIP a separately archived 1.1.1 source snapshot. No historical Git tags have been fabricated.

The original release archives and checksum records remain unchanged. `versions/README.md` describes each archived file and the gaps. The separate September 8 Steam diagnostic candidate is private test material and is not part of the version archive.

Copyright (c) 2026 Rama2120. The mod's source is under the MIT License in [`LICENSE.txt`](LICENSE.txt). Bundled MinHook source has its own license in [`vendor/minhook-1.3.4/LICENSE.txt`](vendor/minhook-1.3.4/LICENSE.txt).
