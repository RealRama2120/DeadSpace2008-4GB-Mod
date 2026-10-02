DEAD SPACE (2008) 4GB MOD v1.1.2
Steam compatibility and launch reliability update, dated 2026-09-08.
Based on the existing 1.1.1 release; the previous release remains a rollback option.


INSTALL
With Dead Space closed, extract this archive beside Dead Space.exe, replacing
the existing 4GB mod's dsound.dll if installed. Do not overwrite a dsound.dll
belonging to another mod. Launch normally through Steam.
You can also install this flat archive with Vortex and deploy as usual.
On an unpatched executable, the existing automatic patch process closes and
reopens the game once. Subsequent launches require no extra restart.


STEAM FIX
Fixes the reproduced Application load error 3:0000065432 for the tested Steam
Dead Space (2008) executable. Windows retains the larger address space, while
Steam startup file validation sees the verified original executable bytes.
The original backup and patched executable stay protected against replacement
while the game runs. No game executable is included in this package.


Supported original Steam SHA-256:
81aeb158c2fc756607c7dcdb3dd29952c87608ea6cab2cc65c09fbf656b294f2
Steam build 252137, game version 1.0.0.222, app 17470.
Different executable builds are not verified. The new Steam compatibility path
requires this exact executable and this mod's verified backup/manifest. EA
launches skip that Steam-only path and retain the normal LAA bootstrap. The
existing patch, restore, elevation, and audio forwarding behavior is unchanged.


RESTORE / UNINSTALL
Close Dead Space. While dsound.dll is still installed, run
"Restore Dead Space 4GB Mod.cmd" and wait for its verified SUCCESS message.
Then remove this mod or disable it and deploy in Vortex before launching.
Removing dsound.dll while leaving the Steam executable patched can bring back
the Steam load error. Steam Verify Integrity can restore the store executable
if the mod was removed before running Restore.


This mod uses dsound.dll. Ishimura's xinput1_3.dll can coexist with it.
Keep the .deadspace-laa.bak and .deadspace-laa.manifest.json files beside the
executable while using this Steam fix. Launch the game normally, not as admin.


VALIDATION
Normal Steam first-launch patch/relaunch and later launches reached the menu.
A live startup probe successfully reserved an address above 2 GB.
The existing patch/restore/launcher suite and targeted file-hook tests passed.
The candidate's Restore function recovered the exact original Steam executable.
The final pair launched through EA and Steam together. I tested this mod on the Steam release with normal movement, sound, and subtitles, and it works there as well as on the EA App release.
The EA
executable and save remained unchanged; the EA combined launch completed its
automatic patch/relaunch and reached the main menu. ReShade and other proxy
combinations remain configuration-dependent.


LICENSES
The mod's license is LICENSE.txt. This release statically links MinHook 1.3.4;
its full license, including its disassembler notices, is MINHOOK_LICENSE.txt.
See THIRD_PARTY_NOTICES.txt for the source URL.

