# Dead Space (2008) - 4GB Mod source

This archive contains the complete source for version 1.1.2. It includes the
Steam compatibility path and preserves the original EA launch behavior. It does
not contain NTCore code or `4gb_patch.exe`.

## Build and test

Requirements:

- Windows 10 or 11
- Visual Studio 2022 C++ x86 build tools
- Windows PowerShell 5.1 or PowerShell 7

Run:

```powershell
.\build-and-test.ps1
```

The script builds the x86 release DLL with reproducibility and Windows mitigation
flags, builds a synthetic 32-bit game fixture, then tests the normal-launch
handoff, exact LAA change, backup, verification, restore, failure containment,
relaunch context, proxy exports, and version metadata. The release DLL is
written to `build\dsound.dll`.

Version 1.1.2 passed the full existing suite, the targeted Steam file-validation
tests, and normal first/repeat launches through both Steam and EA App. I (Rama2120) manually test every release. I have played through the entire game with recent versions of all my Dead Space (2008) mods installed together, including the 4GB mod, with no issues.
ReShade and other proxy combinations
remain configuration-dependent.

The main mod archive contains only the compiled DLL, restore command, license,
and documentation. This source-only archive is not required to install or use
the mod, and its source files are not meant to be installed into the game.

Copyright (c) 2026 Rama2120. Released under the MIT License.
