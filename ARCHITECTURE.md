# Architecture and safety model

Dead Space is a 32-bit game. Windows reads the PE
`IMAGE_FILE_LARGE_ADDRESS_AWARE` flag when it creates the process, so changing
the executable after the game has started cannot alter that already-running
process. A safe automatic first launch therefore requires a short handoff and
one restart.

The deployed x86 `dsound.dll` is both a transparent DirectSound proxy and the
normal-launch bootstrap. It forwards the twelve system DirectSound exports at
their original ordinals. On the first unpatched launch, after the game calls
`DirectSoundCreate` or `GetDeviceID`, the DLL makes a SHA-256-verified private
runtime copy of itself and starts that copy's out-of-process callback through
Windows' 32-bit `rundll32.exe`.

The proxy and callback use a ready, commit, acknowledgement, and final-go
handshake. The original process exits only after the callback has validated and
accepted the request. A handshake cancellation or timeout leaves the current
executable and launch untouched, and the callback cannot later patch or relaunch
on its own.

The callback then:

1. waits for the exact original process handle to signal exit;
2. opens and pins the exact non-reparse target against concurrent write, rename,
   replacement, or a second patch worker;
3. validates a bounded PE32 i386 executable named `Dead Space.exe` through that
   pinned handle;
4. hashes the original and creates a verified backup;
5. computes the expected SHA-256 for the exact one-byte result;
6. writes only the low-byte LAA bit through the pinned handle and flushes it;
7. verifies the resulting PE state and SHA-256 through that same handle;
8. writes a manifest binding the original and patched hashes; and
9. relaunches the exact command line and working directory with a one-process
   bypass marker.

If the game directory requires Windows approval, a narrowly scoped elevated
callback performs only the verified file operation. The original callback—not
the elevated callback—relaunches Dead Space with the same integrity level as the
user's original game launch. The worker and request are pinned and hash-bound
across the elevation boundary.

First-time bootstrap refuses if the game process itself is already elevated.
Users launch the store/game normally and elevate only the narrow patch callback
when Windows requires it, keeping state-folder operations at ordinary integrity.

The included restore command requires the backup file. While holding the same
target protections, the callback independently proves that the current file and
backup are an exact one-bit LAA pair and also uses the manifest hashes when the
manifest is valid. It can recover from missing or incomplete manifest content
only when that exact file comparison proves the state. It clears the one LAA
bit, flushes, and verifies the exact original bytes before removing the active
manifest.

No network code, telemetry, game executable, NTCore binary, packing, or
obfuscation is included.

For Steam build 252137 (App ID 17470), the compatibility path is enabled only
when the exact supported executable, verified original backup, and manifest are
present. Windows keeps the process's large address space while read-only
validation reads of that exact executable from external modules are served from
the verified original backup. The mod's own checks continue to read the actual
patched file. EA launches skip this path and retain the normal LAA bootstrap.

Changing the PE header invalidates any existing digital signature on the game
executable. Restoring the verified backup returns the exact original bytes.

## Verification boundary

The synthetic suite verifies the proxy, handoff, patch, failure containment,
relaunch, and restore paths. Version 1.1.2 worked through normal EA App and Steam launches after the same existing synthetic and regression checks. The release was additionally validated by my full manual playthrough of the entire game with all my Dead Space (2008) mods installed together.

