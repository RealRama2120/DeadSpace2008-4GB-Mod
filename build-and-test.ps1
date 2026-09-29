[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root 'build'
$base = Join-Path $build 'fixture-base'
$success = Join-Path $build 'success'
$failure = Join-Path $build 'failure'
$writeFinalize = Join-Path $build 'write-finalize-failure'
$unsafeRecovery = Join-Path $build 'unsafe-recovery'
$corruptRecovery = Join-Path $build 'corrupt-recovery'
$pinnedRace = Join-Path $build 'pinned-race'
$concurrent = Join-Path $build 'concurrent-launch'
$concurrentFailure = Join-Path $build 'concurrent-local-failure'
$concurrentCancel = Join-Path $build 'concurrent-elevation-cancel'
$externalLaa = Join-Path $build 'external-laa'
$reparseReal = Join-Path $build 'reparse-real'
$reparseLink = Join-Path $build 'reparse-link'
$elevation = Join-Path $build 'elevation'
$elevationForgery = Join-Path $build 'elevation-forgery'
$elevationExitMismatch = Join-Path $build 'elevation-exit-mismatch'
$manifestRace = Join-Path $build 'manifest-reparse-race'
$manifestHostile = Join-Path $build 'manifest-hostile-target'
$highIntegrity = Join-Path $build 'high-integrity-launch'
$cancel = Join-Path $build 'ready-cancel'
$ackCancel = Join-Path $build 'ack-cancel'
$parentTimeout = Join-Path $build 'parent-timeout'
New-Item -ItemType Directory -Force -Path $build,$base,$success,$failure,$writeFinalize,$unsafeRecovery,$corruptRecovery,$pinnedRace,$concurrent,$concurrentFailure,$concurrentCancel,$externalLaa,$reparseReal,$elevation,$elevationForgery,$elevationExitMismatch,$manifestRace,$manifestHostile,$highIntegrity,$cancel,$ackCancel,$parentTimeout | Out-Null

$vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = (& $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $vs) { throw 'Visual Studio C++ x86 tools not found.' }
$dev = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'
function Invoke-Native([string]$command) {
    & $env:ComSpec /d /s /c ('call "' + $dev + '" -no_logo -arch=x86 -host_arch=x64 >nul && ' + $command)
    if ($LASTEXITCODE) { throw "Native build failed: $LASTEXITCODE" }
}

$dll = Join-Path $build 'dsound.dll'
& (Join-Path $root 'build-dll.ps1')

$baseExe = Join-Path $base 'Dead Space.exe'
Invoke-Native ('cl.exe /nologo /EHsc /O2 /MT /W4 /DUNICODE /D_UNICODE "' + (Join-Path $root 'fixture.cpp') +
    '" /Fo"' + (Join-Path $build 'fixture.obj') + '" /Fe:"' + $baseExe + '" /link /SUBSYSTEM:WINDOWS "' +
    (Join-Path $build 'dsound.lib') + '" dxguid.lib advapi32.lib')

function Assert-FixturePath([string]$directory) {
    $resolved = [IO.Path]::GetFullPath($directory)
    $safeRoot = [IO.Path]::GetFullPath($build).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($safeRoot,[StringComparison]::OrdinalIgnoreCase)) {
        throw "Fixture cleanup escaped candidate build folder: $resolved"
    }
    $entry = Get-Item -LiteralPath $resolved -Force -ErrorAction SilentlyContinue
    if ($entry -and ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Fixture cleanup refuses reparse directory: $resolved"
    }
}

function Reset-Case([string]$directory) {
    Assert-FixturePath $directory
    Get-ChildItem -LiteralPath $directory -Force | Remove-Item -Force -Recurse
    Copy-Item -LiteralPath $baseExe -Destination (Join-Path $directory 'Dead Space.exe')
    Copy-Item -LiteralPath $dll -Destination (Join-Path $directory 'dsound.dll')
}
function Reset-State([string]$directory) {
    Assert-FixturePath $directory
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    Get-ChildItem -LiteralPath $directory -Force | Remove-Item -Force -Recurse
}
function Read-SharedUnicodeText([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    try {
        $share = [IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
        $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
        try {
            $length = [int]$stream.Length
            if (-not $length) { return '' }
            $bytes = New-Object byte[] $length
            $offset = 0
            while ($offset -lt $length) {
                $count = $stream.Read($bytes,$offset,$length - $offset)
                if (-not $count) { break }
                $offset += $count
            }
            return [Text.Encoding]::Unicode.GetString($bytes,0,$offset)
        }
        finally { $stream.Dispose() }
    }
    catch [IO.IOException] { return '' }
}
function Wait-FixtureLog([string]$directory, [int]$minimumLines = 1) {
    $path = Join-Path $directory 'fixture-runs.log'
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 100
        $text = Read-SharedUnicodeText $path
        $lines = @($text -split "`r?`n" | Where-Object { $_ })
    } while ($lines.Count -lt $minimumLines -and [DateTime]::UtcNow -lt $deadline)
    if ($lines.Count -lt $minimumLines) { throw "Fixture did not produce $minimumLines log line(s): $directory" }
    return $text
}
function Get-Laa([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $pe = [BitConverter]::ToInt32($bytes,0x3c)
    $characteristics = [BitConverter]::ToUInt16($bytes,$pe + 4 + 18)
    return ($characteristics -band 0x20) -ne 0
}
function Get-LaunchFields([string]$text) {
    $clean = $text.TrimEnd("`r","`n")
    $match = [regex]::Match($clean, '^.*;cwd=(?<cwd>[^\r\n]*);cmd=(?<cmd>[^\r\n]*)$')
    if (-not $match.Success) { throw "Fixture launch fields could not be parsed exactly: $text" }
    return [pscustomobject]@{ Cwd=$match.Groups['cwd'].Value; Command=$match.Groups['cmd'].Value }
}
function Wait-Path([string]$path, [int]$seconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    while (-not (Test-Path -LiteralPath $path) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
    if (-not (Test-Path -LiteralPath $path)) { throw "Timed out waiting for path: $path" }
}
function Wait-LogPattern([string]$path, [string]$pattern, [int]$seconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    do {
        $text = Read-SharedUnicodeText $path
        if ($text -match $pattern) { return $text }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for '$pattern' in $path"
}
function Wait-StateFile([string]$directory, [string]$filter, [int]$seconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    do {
        $file = Get-ChildItem -LiteralPath $directory -Filter $filter -File -Force -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($file) { return $file.FullName }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for $filter in $directory"
}
function Wait-StateFileRegex([string]$directory, [string]$pattern, [int]$seconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    do {
        $file = Get-ChildItem -LiteralPath $directory -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $pattern } | Select-Object -First 1
        if ($file) { return $file.FullName }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for state-file regex $pattern in $directory"
}
function Assert-MutationBlocked([string]$path, [string]$label) {
    $writeBlocked = $false
    try { $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite); $stream.Dispose() }
    catch [IO.IOException] { $writeBlocked = $true }
    catch [UnauthorizedAccessException] { $writeBlocked = $true }
    if (-not $writeBlocked) { throw "$label unexpectedly allowed mutation while guarded: $path" }
    $deleteBlocked = $false
    try { [IO.File]::Delete($path); $deleteBlocked = Test-Path -LiteralPath $path }
    catch [IO.IOException] { $deleteBlocked = $true }
    catch [UnauthorizedAccessException] { $deleteBlocked = $true }
    if (-not $deleteBlocked -or -not (Test-Path -LiteralPath $path)) { throw "$label unexpectedly allowed deletion while guarded: $path" }
}
function Assert-DeletionBlocked([string]$path, [string]$label) {
    $deleteBlocked = $false
    try { [IO.File]::Delete($path); $deleteBlocked = Test-Path -LiteralPath $path }
    catch [IO.IOException] { $deleteBlocked = $true }
    catch [UnauthorizedAccessException] { $deleteBlocked = $true }
    if (-not $deleteBlocked -or -not (Test-Path -LiteralPath $path)) { throw "$label unexpectedly allowed deletion/replacement while guarded: $path" }
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$label unexpectedly resolved to a reparse point: $path"
    }
}
function Write-ForgedLegacyElevationResult([string]$path, [string]$token) {
    # Recreate the strongest possible version of the removed v2 result-file
    # attack: correct magic/version/token, success, role/log audit fields, and a
    # hash-sized payload.  The current DLL must never open or trust this file.
    [IO.File]::WriteAllBytes($path,[byte[]](0x46,0x4f,0x52,0x47,0x45,0x44))
    $stream = [IO.File]::Open($path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    $writer = New-Object IO.BinaryWriter($stream,[Text.Encoding]::UTF8,$false)
    try {
        $writer.Write([uint32]0x52473444)
        $writer.Write([uint32]2)
        $writer.Write([Text.Encoding]::ASCII.GetBytes($token))
        $writer.Write([uint32]1)
        $writer.Write([uint32]0)
        $writer.Write([byte[]](New-Object byte[] 32))
        $writer.Write([uint32]1)
        $writer.Write([uint32]1)
        $writer.Write([uint32]0)
        $writer.Flush()
    }
    finally { $writer.Dispose() }
}
function Invoke-RestoreCommand([string]$directory) {
    $command = Join-Path $directory 'Restore.cmd'
    Copy-Item -LiteralPath (Join-Path $root 'Restore.cmd') -Destination $command -Force
    $arguments = @('/d','/s','/c',('""{0}" --no-pause"' -f $command))
    $process = Start-Process -FilePath $env:ComSpec -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    return $process.ExitCode
}
function Invoke-RestoreCallback([string]$directory, [string]$target) {
    $rundll = Join-Path $env:SystemRoot 'System32\rundll32.exe'
    $wow = Join-Path $env:SystemRoot 'SysWOW64\rundll32.exe'
    if (Test-Path -LiteralPath $wow) { $rundll = $wow }
    $env:DEADSPACE4GB_RESTORE_TARGET = $target
    $process = Start-Process -FilePath $rundll -ArgumentList ('"' + (Join-Path $directory 'dsound.dll') + '",Restore') -Wait -PassThru -WindowStyle Hidden
    Remove-Item Env:DEADSPACE4GB_RESTORE_TARGET -ErrorAction SilentlyContinue
    return $process.ExitCode -eq 1297303297
}

Reset-Case $success
$exe = Join-Path $success 'Dead Space.exe'
$state = Join-Path $build 'state-success'
Reset-State $state
$env:DEADSPACE4GB_STATE_DIRECTORY = $state
$env:DEADSPACE4GB_SENTINEL = 'preserve-me'
$env:DEADSPACE4GB_TEST_SUPPRESS_UI = '1'
$env:DEADSPACE4GB_TEST_ROLE_MARKER = '1'
$env:DEADSPACE4GB_TEST_ASSERT_READONLY_GUARDS = '1'
$env:DEADSPACE4GB_BYPASS = '1'
$baselineProcess = Start-Process -FilePath $exe -WorkingDirectory $success -ArgumentList '--alpha','"two words"' -PassThru -WindowStyle Hidden
$baselineProcess.WaitForExit()
$baselineRaw = Wait-FixtureLog $success
$baselineLaunch = Get-LaunchFields $baselineRaw
Remove-Item -LiteralPath (Join-Path $success 'fixture-runs.log') -Force
Remove-Item Env:DEADSPACE4GB_BYPASS -ErrorAction SilentlyContinue
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_PATCH_FAILURE -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $exe -WorkingDirectory $success -ArgumentList '--alpha','"two words"' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$raw = Wait-FixtureLog $success
$patchedLaunch = Get-LaunchFields $raw
if ($patchedLaunch.Cwd -cne $baselineLaunch.Cwd -or $patchedLaunch.Command -cne $baselineLaunch.Command) {
    throw "Relaunch did not preserve exact raw command/cwd. Baseline=$($baselineLaunch | ConvertTo-Json -Compress) Patched=$($patchedLaunch | ConvertTo-Json -Compress)"
}
if ($raw -notmatch 'laa=1;bypass=1;sentinel=preserve-me;request=;role=original-worker;elevatedWorker=;forwarders=12;cwd=' -or $raw -notmatch '--alpha') {
    throw "Success run did not preserve command/cwd/environment or clear internal request: $raw"
}
if (-not (Test-Path -LiteralPath ($exe + '.deadspace-laa.bak'))) { throw 'Verified backup was not created.' }
if (-not (Test-Path -LiteralPath ($exe + '.deadspace-laa.manifest.json'))) { throw 'Manifest was not created.' }
if (-not (Get-Laa $exe)) { throw 'Success target is not LAA.' }
$successBootstrapLog = [IO.File]::ReadAllText((Join-Path $state 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
if ($successBootstrapLog -notmatch 'request retained guard verified read-only') {
    throw 'The inherited request guard did not prove that write permission was removed.'
}

# The same runtime worker provides a manifest/hash-validated restore path.
$worker = Join-Path $state 'DeadSpace4GBWorker.dll'
$env:DEADSPACE4GB_RESTORE_TARGET = $exe
$env:DEADSPACE4GB_TEST_FORCE_WRITE_FINALIZE_FAILURE = '1'
$restore = Start-Process -FilePath "$env:WINDIR\SysWOW64\rundll32.exe" -ArgumentList ('"' + $worker + '",Restore') -Wait -PassThru -WindowStyle Hidden
Remove-Item Env:DEADSPACE4GB_RESTORE_TARGET,Env:DEADSPACE4GB_TEST_FORCE_WRITE_FINALIZE_FAILURE -ErrorAction SilentlyContinue
if ($restore.ExitCode -ne 1297303297 -or (Get-Laa $exe)) { throw "Restore failed with exit $($restore.ExitCode)." }
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath ($exe + '.deadspace-laa.bak')).Hash) {
    throw 'Restored target does not match verified backup.'
}
if (Test-Path -LiteralPath ($exe + '.deadspace-laa.manifest.json')) { throw 'Successful restore left active manifest behind.' }

# A deliberately elevated/high-integrity game launch is unsupported in v1. The
# proxy must stop before resolving the user state directory, logging, copying a
# worker, or creating any request/patch artifact.
Reset-Case $highIntegrity
$highExe = Join-Path $highIntegrity 'Dead Space.exe'
$highState = Join-Path $build 'state-high-integrity'
Reset-State $highState
$env:DEADSPACE4GB_STATE_DIRECTORY = $highState
$env:DEADSPACE4GB_TEST_FORCE_HIGH_INTEGRITY = '1'
$highProcess = Start-Process -FilePath $highExe -WorkingDirectory $highIntegrity -ArgumentList '--high-integrity' -PassThru -WindowStyle Hidden
$highProcess.WaitForExit()
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_HIGH_INTEGRITY -ErrorAction SilentlyContinue
if ($highProcess.ExitCode -ne 740 -or (Get-Laa $highExe) -or
    (Test-Path -LiteralPath (Join-Path $highIntegrity 'fixture-runs.log')) -or
    (Test-Path -LiteralPath ($highExe + '.deadspace-laa.bak')) -or
    @(Get-ChildItem -LiteralPath $highState -Force -ErrorAction SilentlyContinue).Count -ne 0) {
    throw "High-integrity launch did not fail closed before all state writes (exit=$($highProcess.ExitCode))."
}

# A failed finalization report after the single pinned byte may already mean the
# byte changed. Patch must prove the exact original on that same handle before
# fallback; the following normal launch must then retry and succeed.
Reset-Case $writeFinalize
$writeFinalizeExe = Join-Path $writeFinalize 'Dead Space.exe'
$writeFinalizeState = Join-Path $build 'state-write-finalize-failure'
Reset-State $writeFinalizeState
$env:DEADSPACE4GB_STATE_DIRECTORY = $writeFinalizeState
$baseHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $baseExe).Hash
$env:DEADSPACE4GB_TEST_FORCE_WRITE_FINALIZE_FAILURE = '1'
$p = Start-Process -FilePath $writeFinalizeExe -WorkingDirectory $writeFinalize -ArgumentList '--write-finalize-failure' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$writeFinalizeRaw = Wait-FixtureLog $writeFinalize
$writeFinalizeLog = [IO.File]::ReadAllText((Join-Path $writeFinalizeState 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
if ($writeFinalizeRaw -notmatch 'laa=0;bypass=1;.*role=original-worker;.*forwarders=12' -or
    @($writeFinalizeRaw -split "`r?`n" | Where-Object { $_ }).Count -ne 1 -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $writeFinalizeExe).Hash -ne $baseHash -or
    (Test-Path -LiteralPath ($writeFinalizeExe + '.deadspace-laa.manifest.json')) -or
    $writeFinalizeLog -notmatch 'exact original was restored') {
    throw 'A possibly-applied pinned-byte write failure was not proven restored before unchanged fallback.'
}
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_WRITE_FINALIZE_FAILURE -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $writeFinalizeExe -WorkingDirectory $writeFinalize -ArgumentList '--write-finalize-retry' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$writeFinalizeRetryRaw = Wait-FixtureLog $writeFinalize 2
if ($writeFinalizeRetryRaw -notmatch 'laa=1;bypass=1;.*role=original-worker;.*forwarders=12' -or
    -not (Get-Laa $writeFinalizeExe)) {
    throw 'Normal launch did not retry successfully after contained write-finalization failure.'
}

# Forced failure must relaunch the unchanged game once with a process-only bypass,
# then a later normal launch must retry instead of being permanently disabled.
Reset-Case $failure
$failureExe = Join-Path $failure 'Dead Space.exe'
$failureState = Join-Path $build 'state-failure'
Reset-State $failureState
$env:DEADSPACE4GB_STATE_DIRECTORY = $failureState
$env:DEADSPACE4GB_TEST_FORCE_PATCH_FAILURE = '1'
$p = Start-Process -FilePath $failureExe -WorkingDirectory $failure -ArgumentList '--failure-case' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$failedRaw = Wait-FixtureLog $failure
if ($failedRaw -notmatch 'laa=0;bypass=1;sentinel=preserve-me;request=;role=original-worker;elevatedWorker=;forwarders=12;cwd=') { throw "Failure fallback did not run unchanged exactly once with bypass: $failedRaw" }
if (@($failedRaw -split "`r?`n" | Where-Object { $_ }).Count -ne 1) { throw 'Failure fallback entered a relaunch loop.' }
$failureBootstrapLog = [IO.File]::ReadAllText((Join-Path $failureState 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
$uiAt = $failureBootstrapLog.LastIndexOf('user-visible patch failure suppressed for synthetic test')
$relaunchAt = $failureBootstrapLog.LastIndexOf('relaunched target with process-scoped bypass')
if ($uiAt -lt 0 -or $relaunchAt -lt 0 -or $uiAt -gt $relaunchAt) { throw 'Failure UI was not emitted before unchanged fallback relaunch.' }
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_PATCH_FAILURE -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $failureExe -WorkingDirectory $failure -ArgumentList '--retry-case' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$retryRaw = Wait-FixtureLog $failure 2
if ($retryRaw -notmatch 'laa=1;bypass=1;sentinel=preserve-me;request=;role=original-worker;elevatedWorker=;forwarders=12;cwd=' -or -not (Get-Laa $failureExe)) {
    throw 'Next normal launch did not safely retry and succeed after the prior failure.'
}

# If post-patch verification and rollback are both forced to fail, the target is
# neither the exact original nor a complete manifest-verified patch.  The worker
# must show/log the failure and withhold relaunch instead of starting uncertainty.
Reset-Case $unsafeRecovery
$unsafeExe = Join-Path $unsafeRecovery 'Dead Space.exe'
$unsafeState = Join-Path $build 'state-unsafe-recovery'
Reset-State $unsafeState
$env:DEADSPACE4GB_STATE_DIRECTORY = $unsafeState
$env:DEADSPACE4GB_TEST_FORCE_POST_VERIFY_FAILURE = '1'
$env:DEADSPACE4GB_TEST_FORCE_ROLLBACK_FAILURE = '1'
$p = Start-Process -FilePath $unsafeExe -WorkingDirectory $unsafeRecovery -ArgumentList '--unsafe-recovery' -PassThru -WindowStyle Hidden
$p.WaitForExit()
Start-Sleep -Seconds 2
$unsafeRunLog = Join-Path $unsafeRecovery 'fixture-runs.log'
if (Test-Path -LiteralPath $unsafeRunLog) {
    $unsafeRaw = [IO.File]::ReadAllText($unsafeRunLog,[Text.Encoding]::Unicode)
    if ($unsafeRaw -match 'bypass=1') { throw "Uncertain recovery state was relaunched: $unsafeRaw" }
}
$unsafeBootstrapLog = [IO.File]::ReadAllText((Join-Path $unsafeState 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
if ($unsafeBootstrapLog -notmatch 'restart was withheld' -or $unsafeBootstrapLog -match 'relaunched target' -or
    -not (Get-Laa $unsafeExe) -or (Test-Path -LiteralPath ($unsafeExe + '.deadspace-laa.manifest.json'))) {
    throw 'Uncertain post-patch/rollback failure was not contained without relaunch.'
}
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_POST_VERIFY_FAILURE,Env:DEADSPACE4GB_TEST_FORCE_ROLLBACK_FAILURE -ErrorAction SilentlyContinue

# The next normal launch must detect the LAA executable plus incomplete own
# artifacts, show the distinct recovery error, and exit before forwarding.
$beforeBlockedLines = if (Test-Path -LiteralPath $unsafeRunLog) {
    @([IO.File]::ReadAllText($unsafeRunLog,[Text.Encoding]::Unicode) -split "`r?`n" | Where-Object { $_ }).Count
} else { 0 }
$p = Start-Process -FilePath $unsafeExe -WorkingDirectory $unsafeRecovery -ArgumentList '--blocked-incomplete' -PassThru -WindowStyle Hidden
$p.WaitForExit()
Start-Sleep -Milliseconds 500
$afterBlockedLines = if (Test-Path -LiteralPath $unsafeRunLog) {
    @([IO.File]::ReadAllText($unsafeRunLog,[Text.Encoding]::Unicode) -split "`r?`n" | Where-Object { $_ }).Count
} else { 0 }
$unsafeBootstrapLog = [IO.File]::ReadAllText((Join-Path $unsafeState 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
if ($afterBlockedLines -ne $beforeBlockedLines -or $unsafeBootstrapLog -notmatch 'critical recovery block' -or
    $unsafeBootstrapLog -match 'blocked-incomplete.*relaunched') {
    throw 'Next launch did not block before forwarding on incomplete own patch state.'
}

# Missing-manifest recovery is allowed only because the DLL pins both files and
# proves they differ by exactly the LAA bit. Restore.cmd must trust its token
# marker plus byte-for-byte postcheck, not rundll32's exit code.
$restoreExit = Invoke-RestoreCommand $unsafeRecovery
if ($restoreExit -ne 0 -or (Get-Laa $unsafeExe) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $unsafeExe).Hash -ne
    (Get-FileHash -Algorithm SHA256 -LiteralPath ($unsafeExe + '.deadspace-laa.bak')).Hash) {
    throw 'Exact-bit incomplete recovery did not succeed through Restore.cmd.'
}
$repeatRestoreExit = Invoke-RestoreCommand $unsafeRecovery
if ($repeatRestoreExit -eq 0) { throw 'Already-restored repeat unexpectedly reported success.' }

# A missing-manifest target with any second changed byte must be refused and left
# untouched, directing the user to the store repair/verify path.
Reset-Case $corruptRecovery
$corruptExe = Join-Path $corruptRecovery 'Dead Space.exe'
Copy-Item -LiteralPath $corruptExe -Destination ($corruptExe + '.deadspace-laa.bak')
$corruptBytes = [IO.File]::ReadAllBytes($corruptExe)
$corruptPe = [BitConverter]::ToInt32($corruptBytes,0x3c)
$corruptBytes[$corruptPe + 4 + 18] = $corruptBytes[$corruptPe + 4 + 18] -bor 0x20
$corruptBytes[$corruptBytes.Length - 1] = $corruptBytes[$corruptBytes.Length - 1] -bxor 0x01
[IO.File]::WriteAllBytes($corruptExe,$corruptBytes)
$corruptBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $corruptExe).Hash
$attackerMarker = Join-Path $build 'attacker-restore-result.ok'
$attackerMarkerText = 'x"=="x" & exit /b 0 & rem attacker-controlled marker text'
[IO.File]::WriteAllText($attackerMarker,$attackerMarkerText,[Text.Encoding]::UTF8)
$env:DEADSPACE4GB_RESTORE_RESULT = $attackerMarker
$env:DEADSPACE4GB_RESTORE_TOKEN = 'x" & exit /b 0 & rem '
$corruptExit = Invoke-RestoreCommand $corruptRecovery
Remove-Item Env:DEADSPACE4GB_RESTORE_RESULT,Env:DEADSPACE4GB_RESTORE_TOKEN -ErrorAction SilentlyContinue
if ($corruptExit -eq 0 -or (Get-FileHash -Algorithm SHA256 -LiteralPath $corruptExe).Hash -ne $corruptBefore -or
    [IO.File]::ReadAllText($attackerMarker,[Text.Encoding]::UTF8) -cne $attackerMarkerText) {
    throw 'Corrupted multi-byte incomplete restore was not refused unchanged.'
}

# An executable made LAA by some other tool, with none of this mod's artifacts,
# remains a silent not-needed case and must forward normally.
Reset-Case $externalLaa
$externalExe = Join-Path $externalLaa 'Dead Space.exe'
$externalBytes = [IO.File]::ReadAllBytes($externalExe)
$externalPe = [BitConverter]::ToInt32($externalBytes,0x3c)
$externalBytes[$externalPe + 4 + 18] = $externalBytes[$externalPe + 4 + 18] -bor 0x20
[IO.File]::WriteAllBytes($externalExe,$externalBytes)
$externalState = Join-Path $build 'state-external-laa'
Reset-State $externalState
$env:DEADSPACE4GB_STATE_DIRECTORY = $externalState
$p = Start-Process -FilePath $externalExe -WorkingDirectory $externalLaa -ArgumentList '--external-laa' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$externalRaw = Wait-FixtureLog $externalLaa
if ($externalRaw -notmatch 'laa=1;bypass=;.*forwarders=12' -or
    (Test-Path -LiteralPath ($externalExe + '.deadspace-laa.bak'))) {
    throw 'Artifact-free externally-LAA executable was not treated as a silent not-needed case.'
}

# While Patch holds the target and final-directory handles, an updater-style
# pathname replacement must fail. Its source bytes must remain intact and the
# mod may write only the pinned target's LAA byte.
Reset-Case $pinnedRace
$pinnedExe = Join-Path $pinnedRace 'Dead Space.exe'
$updaterExe = Join-Path $pinnedRace 'Dead Space.updater.exe'
$updaterBase = [IO.File]::ReadAllBytes($baseExe)
$updaterTag = [Text.Encoding]::ASCII.GetBytes('UPDATER-BYTES-MUST-SURVIVE')
$updaterBytes = New-Object byte[] ($updaterBase.Length + $updaterTag.Length)
[Array]::Copy($updaterBase,$updaterBytes,$updaterBase.Length)
[Array]::Copy($updaterTag,0,$updaterBytes,$updaterBase.Length,$updaterTag.Length)
[IO.File]::WriteAllBytes($updaterExe,$updaterBytes)
$updaterHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $updaterExe).Hash
$pinnedState = Join-Path $build 'state-pinned-race'
Reset-State $pinnedState
$env:DEADSPACE4GB_STATE_DIRECTORY = $pinnedState
$env:DEADSPACE4GB_TEST_PINNED_DELAY_MS = '3000'
$p = Start-Process -FilePath $pinnedExe -WorkingDirectory $pinnedRace -ArgumentList '--pinned-race' -PassThru -WindowStyle Hidden
$pinnedBootstrapPath = Join-Path $pinnedState 'one-dll-bootstrap.log'
Wait-LogPattern $pinnedBootstrapPath 'target handle and final directory pinned' | Out-Null
$replacementSucceeded = $false
try { [IO.File]::Replace($updaterExe,$pinnedExe,(Join-Path $pinnedRace 'updater-replace-backup.tmp')); $replacementSucceeded = $true }
catch [IO.IOException] { }
catch [UnauthorizedAccessException] { }
if ($replacementSucceeded -or -not (Test-Path -LiteralPath $updaterExe) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $updaterExe).Hash -ne $updaterHash) {
    throw 'Concurrent updater replacement was not refused with its source bytes preserved.'
}
$p.WaitForExit()
$pinnedRaw = Wait-FixtureLog $pinnedRace
if ($pinnedRaw -notmatch 'laa=1;bypass=1;.*forwarders=12' -or -not (Get-Laa $pinnedExe) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath ($pinnedExe + '.deadspace-laa.bak')).Hash -ne
    (Get-FileHash -Algorithm SHA256 -LiteralPath $baseExe).Hash) {
    throw 'Pinned target patch did not finish safely after the refused updater replacement.'
}
Remove-Item Env:DEADSPACE4GB_TEST_PINNED_DELAY_MS -ErrorAction SilentlyContinue

# Pinned restore rejects a reparse-point final directory. A file symlink is also
# exercised when the current Windows policy permits unprivileged creation.
Reset-Case $reparseReal
$reparseExe = Join-Path $reparseReal 'Dead Space.exe'
Copy-Item -LiteralPath $reparseExe -Destination ($reparseExe + '.deadspace-laa.bak')
$reparseBytes = [IO.File]::ReadAllBytes($reparseExe)
$reparsePe = [BitConverter]::ToInt32($reparseBytes,0x3c)
$reparseBytes[$reparsePe + 4 + 18] = $reparseBytes[$reparsePe + 4 + 18] -bor 0x20
[IO.File]::WriteAllBytes($reparseExe,$reparseBytes)
if (Test-Path -LiteralPath $reparseLink) { [IO.Directory]::Delete($reparseLink) }
New-Item -ItemType Junction -Path $reparseLink -Target $reparseReal | Out-Null
$junctionTarget = Join-Path $reparseLink 'Dead Space.exe'
if (Invoke-RestoreCallback $reparseLink $junctionTarget) { throw 'Final-directory junction unexpectedly passed pinned restore validation.' }
if (-not (Get-Laa $reparseExe)) { throw 'Rejected junction restore changed the real executable.' }
[IO.Directory]::Delete($reparseLink)

Reset-Case $reparseReal
$realExecutable = Join-Path $reparseReal 'Dead Space.real.exe'
Move-Item -LiteralPath (Join-Path $reparseReal 'Dead Space.exe') -Destination $realExecutable
$fileLink = Join-Path $reparseReal 'Dead Space.exe'
Copy-Item -LiteralPath $realExecutable -Destination ($fileLink + '.deadspace-laa.bak')
$linkBytes = [IO.File]::ReadAllBytes($realExecutable)
$linkPe = [BitConverter]::ToInt32($linkBytes,0x3c)
$linkBytes[$linkPe + 4 + 18] = $linkBytes[$linkPe + 4 + 18] -bor 0x20
[IO.File]::WriteAllBytes($realExecutable,$linkBytes)
$symlinkCreated = $false
try { New-Item -ItemType SymbolicLink -Path $fileLink -Target $realExecutable -ErrorAction Stop | Out-Null; $symlinkCreated = $true }
catch { Write-Host 'SKIP: file-symlink restore refusal requires Developer Mode or elevation on this machine.' }
if ($symlinkCreated) {
    if (Invoke-RestoreCallback $reparseReal $fileLink) { throw 'Target-file symlink unexpectedly passed pinned restore validation.' }
    if (-not (Get-Laa $realExecutable)) { throw 'Rejected file-symlink restore changed its real target.' }
    [IO.File]::Delete($fileLink)
}

# Two simultaneous normal launches serialize on the per-target mutex. The
# queued duplicate exits after proving the first worker completed a valid patch,
# so the race produces one final game process and one verified patch state.
Reset-Case $concurrent
$concurrentExe = Join-Path $concurrent 'Dead Space.exe'
$concurrentState = Join-Path $build 'state-concurrent'
Reset-State $concurrentState
$env:DEADSPACE4GB_STATE_DIRECTORY = $concurrentState
$env:DEADSPACE4GB_TEST_PINNED_DELAY_MS = '1000'
$first = Start-Process -FilePath $concurrentExe -WorkingDirectory $concurrent -ArgumentList '--concurrent-one' -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 100
$second = Start-Process -FilePath $concurrentExe -WorkingDirectory $concurrent -ArgumentList '--concurrent-two' -PassThru -WindowStyle Hidden
$first.WaitForExit(); $second.WaitForExit()
$concurrentRaw = Wait-FixtureLog $concurrent 1
$concurrentLogPath = Join-Path $concurrentState 'one-dll-bootstrap.log'
Wait-LogPattern $concurrentLogPath 'queued duplicate launch suppressed after verified patch completion' 15 | Out-Null
Start-Sleep -Milliseconds 750
$concurrentRaw = [IO.File]::ReadAllText((Join-Path $concurrent 'fixture-runs.log'),[Text.Encoding]::Unicode)
$concurrentLines = @($concurrentRaw -split "`r?`n" | Where-Object { $_ })
$concurrentLog = [IO.File]::ReadAllText($concurrentLogPath,[Text.Encoding]::Unicode)
$relaunchCount = ([regex]::Matches($concurrentLog,'relaunched target with process-scoped bypass')).Count
$manifestObject = Get-Content -LiteralPath ($concurrentExe + '.deadspace-laa.manifest.json') -Raw | ConvertFrom-Json
$currentHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $concurrentExe).Hash.ToLowerInvariant()
$backupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath ($concurrentExe + '.deadspace-laa.bak')).Hash.ToLowerInvariant()
if ($concurrentLines.Count -ne 1 -or $concurrentLines[0] -notmatch 'laa=1;bypass=1;.*role=original-worker;.*forwarders=12' -or
    $relaunchCount -ne 1 -or $manifestObject.patchedSha256 -ne $currentHash -or
    $manifestObject.originalSha256 -ne $backupHash -or $backupHash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $baseExe).Hash.ToLowerInvariant()) {
    throw "Concurrent launch serialization failed: relaunches=$relaunchCount runs=$concurrentRaw"
}
Remove-Item Env:DEADSPACE4GB_TEST_PINNED_DELAY_MS -ErrorAction SilentlyContinue

# A queued second first-launch worker never inherits ownership after the first
# owner fails locally and performs its one unchanged fallback.  In particular,
# it must not retry the patch, display a second failure, or launch a second copy.
Reset-Case $concurrentFailure
$concurrentFailureExe = Join-Path $concurrentFailure 'Dead Space.exe'
$concurrentFailureState = Join-Path $build 'state-concurrent-local-failure'
Reset-State $concurrentFailureState
$env:DEADSPACE4GB_STATE_DIRECTORY = $concurrentFailureState
$env:DEADSPACE4GB_TEST_FORCE_PATCH_FAILURE = '1'
$env:DEADSPACE4GB_TEST_WORKER_READY_DELAY_MS = '1000'
$first = Start-Process -FilePath $concurrentFailureExe -WorkingDirectory $concurrentFailure -ArgumentList '--local-failure-owner' -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 100
$second = Start-Process -FilePath $concurrentFailureExe -WorkingDirectory $concurrentFailure -ArgumentList '--local-failure-queued' -PassThru -WindowStyle Hidden
$first.WaitForExit(); $second.WaitForExit()
$concurrentFailureRaw = Wait-FixtureLog $concurrentFailure 1
$concurrentFailureLogPath = Join-Path $concurrentFailureState 'one-dll-bootstrap.log'
$concurrentFailureLog = Wait-LogPattern $concurrentFailureLogPath 'queued duplicate launch suppressed after verified unchanged fallback' 15
Start-Sleep -Milliseconds 750
$concurrentFailureRaw = [IO.File]::ReadAllText((Join-Path $concurrentFailure 'fixture-runs.log'),[Text.Encoding]::Unicode)
$concurrentFailureLines = @($concurrentFailureRaw -split "`r?`n" | Where-Object { $_ })
$concurrentFailureLog = [IO.File]::ReadAllText($concurrentFailureLogPath,[Text.Encoding]::Unicode)
if ($concurrentFailureLines.Count -ne 1 -or
    $concurrentFailureLines[0] -notmatch 'laa=0;bypass=1;.*role=original-worker;.*forwarders=12' -or
    ([regex]::Matches($concurrentFailureLog,'relaunched target with process-scoped bypass')).Count -ne 1 -or
    ([regex]::Matches($concurrentFailureLog,'user-visible patch failure suppressed for synthetic test')).Count -ne 1 -or
    $concurrentFailureLog -match 'requesting narrow elevated patch worker' -or
    (Get-Laa $concurrentFailureExe) -or
    (Test-Path -LiteralPath ($concurrentFailureExe + '.deadspace-laa.manifest.json'))) {
    throw "Queued local-failure worker stole fallback/elevation/relaunch ownership: $concurrentFailureRaw"
}
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_PATCH_FAILURE,Env:DEADSPACE4GB_TEST_WORKER_READY_DELAY_MS -ErrorAction SilentlyContinue

# The same ownership rule applies when the first owner encounters access denial
# and the user declines the simulated UAC prompt.  There is one elevation
# attempt, one failure message, and one unchanged fallback; the queued worker is
# silent and never opens a second consent path.
Reset-Case $concurrentCancel
$concurrentCancelExe = Join-Path $concurrentCancel 'Dead Space.exe'
$concurrentCancelState = Join-Path $build 'state-concurrent-elevation-cancel'
Reset-State $concurrentCancelState
$env:DEADSPACE4GB_STATE_DIRECTORY = $concurrentCancelState
$env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_CANCEL = '1'
$env:DEADSPACE4GB_TEST_WORKER_READY_DELAY_MS = '1000'
$first = Start-Process -FilePath $concurrentCancelExe -WorkingDirectory $concurrentCancel -ArgumentList '--cancel-owner' -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 100
$second = Start-Process -FilePath $concurrentCancelExe -WorkingDirectory $concurrentCancel -ArgumentList '--cancel-queued' -PassThru -WindowStyle Hidden
$first.WaitForExit(); $second.WaitForExit()
$concurrentCancelRaw = Wait-FixtureLog $concurrentCancel 1
$concurrentCancelLogPath = Join-Path $concurrentCancelState 'one-dll-bootstrap.log'
$concurrentCancelLog = Wait-LogPattern $concurrentCancelLogPath 'queued duplicate launch suppressed after verified unchanged fallback' 15
Start-Sleep -Milliseconds 750
$concurrentCancelRaw = [IO.File]::ReadAllText((Join-Path $concurrentCancel 'fixture-runs.log'),[Text.Encoding]::Unicode)
$concurrentCancelLines = @($concurrentCancelRaw -split "`r?`n" | Where-Object { $_ })
$concurrentCancelLog = [IO.File]::ReadAllText($concurrentCancelLogPath,[Text.Encoding]::Unicode)
if ($concurrentCancelLines.Count -ne 1 -or
    $concurrentCancelLines[0] -notmatch 'laa=0;bypass=1;.*role=original-worker;.*forwarders=12' -or
    ([regex]::Matches($concurrentCancelLog,'medium-integrity write was denied; requesting narrow elevated patch worker')).Count -ne 1 -or
    ([regex]::Matches($concurrentCancelLog,'user-visible patch failure suppressed for synthetic test')).Count -ne 1 -or
    ([regex]::Matches($concurrentCancelLog,'relaunched target with process-scoped bypass')).Count -ne 1 -or
    $concurrentCancelLog -notmatch 'Windows administrator permission was declined' -or
    (Get-Laa $concurrentCancelExe) -or
    (Test-Path -LiteralPath ($concurrentCancelExe + '.deadspace-laa.bak')) -or
    (Test-Path -LiteralPath ($concurrentCancelExe + '.deadspace-laa.manifest.json'))) {
    throw "Queued access-denied/UAC-cancel worker opened a second outcome path: $concurrentCancelRaw"
}
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED,Env:DEADSPACE4GB_TEST_ELEVATION_CANCEL,Env:DEADSPACE4GB_TEST_WORKER_READY_DELAY_MS -ErrorAction SilentlyContinue

# A forced original-integrity permission failure takes the no-UAC seam through
# the same protocol.  The retained exact process handle and its deliberate exit
# status are the only trusted elevated completion channel; elevation remains
# patch-only and the original worker performs the relaunch.
Reset-Case $elevation
$elevationExe = Join-Path $elevation 'Dead Space.exe'
$elevationState = Join-Path $build 'state-elevation'
Reset-State $elevationState
$env:DEADSPACE4GB_STATE_DIRECTORY = $elevationState
$env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_HANDOFF_DELAY_MS = '3000'
$p = Start-Process -FilePath $elevationExe -WorkingDirectory $elevation -ArgumentList '--elevation-seam' -PassThru -WindowStyle Hidden
$guardedRequest = Wait-StateFile $elevationState 'request-*.bin'
$guardedDescriptor = Wait-StateFileRegex $elevationState '^elevation-[0-9a-f]{32}\.bin$'
Assert-MutationBlocked $guardedRequest 'Request handoff'
Assert-MutationBlocked $guardedDescriptor 'Elevation descriptor'
$elevationBootstrapLogPath = Join-Path $elevationState 'one-dll-bootstrap.log'
Wait-LogPattern $elevationBootstrapLogPath 'descriptor retained guard verified read-only' 10 | Out-Null
if (Get-ChildItem -LiteralPath $elevationState -Filter 'elevation-result-*.bin' -File -Force -ErrorAction SilentlyContinue) {
    throw 'The elevation path recreated a user-writable result file.'
}

# Turn the user-controlled log pathname into a deliberately hostile target for
# the entire elevated callback. The success exit status is emitted only when
# the elevated role proves that Log suppressed calls before any filesystem
# attempt; the medium worker independently validates the exact patched state.
$hostileLogGuard = [IO.File]::Open($elevationBootstrapLogPath,[IO.FileMode]::Open,
    [IO.FileAccess]::Read,[IO.FileShare]::Read)
$hostileLogBefore = [IO.File]::ReadAllBytes($elevationBootstrapLogPath)
try {
    Assert-MutationBlocked $elevationBootstrapLogPath 'Hostile elevated-role log target'
    $p.WaitForExit()
    $elevationRaw = Wait-FixtureLog $elevation
    $hostileLogDuring = [IO.File]::ReadAllBytes($elevationBootstrapLogPath)
    if ([Convert]::ToBase64String($hostileLogDuring) -cne [Convert]::ToBase64String($hostileLogBefore)) {
        throw 'The locked hostile log target changed while the elevated role was active.'
    }
}
finally {
    $hostileLogGuard.Dispose()
}
if ($elevationRaw -notmatch 'laa=1;bypass=1;sentinel=preserve-me;request=;role=original-worker;elevatedWorker=;forwarders=12;cwd=' -or -not (Get-Laa $elevationExe)) {
    throw "Elevation seam did not patch via elevated role then relaunch via the original worker: $elevationRaw"
}
$elevationBootstrapLog = [IO.File]::ReadAllText($elevationBootstrapLogPath,[Text.Encoding]::Unicode)
if ($elevationBootstrapLog -notmatch 'descriptor retained guard verified read-only') {
    throw 'The retained elevation descriptor guard did not prove that write permission was removed.'
}
if (Get-ChildItem -LiteralPath $elevationState -Filter 'elevation-result-*.bin' -File -Force -ErrorAction SilentlyContinue) {
    throw 'Successful elevation left a result file even though process exit is the only completion channel.'
}
$successRid = [int]([regex]::Match($raw,'integrityRid=(\d+)').Groups[1].Value)
$elevationRid = [int]([regex]::Match($elevationRaw,'integrityRid=(\d+)').Groups[1].Value)
if (-not $successRid -or $elevationRid -ne $successRid) {
    throw "Patch-only elevation did not preserve the original worker integrity level ($successRid vs $elevationRid)."
}
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED,Env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC,Env:DEADSPACE4GB_TEST_ELEVATION_HANDOFF_DELAY_MS -ErrorAction SilentlyContinue

# Even a complete patched-looking target is not authenticated for this launch
# unless the exact elevated process handle also returns the fixed success code.
# Force a valid elevated patch followed by the fixed failure exit and prove the
# medium worker withholds relaunch instead of overriding that failed status.
Reset-Case $elevationExitMismatch
$elevationExitMismatchExe = Join-Path $elevationExitMismatch 'Dead Space.exe'
$elevationExitMismatchState = Join-Path $build 'state-elevation-exit-mismatch'
Reset-State $elevationExitMismatchState
$env:DEADSPACE4GB_STATE_DIRECTORY = $elevationExitMismatchState
$env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC = '1'
$env:DEADSPACE4GB_TEST_FORCE_ELEVATED_FAILURE_EXIT_AFTER_PATCH = '1'
$p = Start-Process -FilePath $elevationExitMismatchExe -WorkingDirectory $elevationExitMismatch -ArgumentList '--elevated-exit-mismatch' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$elevationExitMismatchLogPath = Join-Path $elevationExitMismatchState 'one-dll-bootstrap.log'
$elevationExitMismatchLog = Wait-LogPattern $elevationExitMismatchLogPath 'exact authenticated success status' 15
Start-Sleep -Milliseconds 500
$elevationExitMismatchRunLog = Join-Path $elevationExitMismatch 'fixture-runs.log'
if ((Test-Path -LiteralPath $elevationExitMismatchRunLog) -or
    -not (Get-Laa $elevationExitMismatchExe) -or
    -not (Test-Path -LiteralPath ($elevationExitMismatchExe + '.deadspace-laa.bak')) -or
    -not (Test-Path -LiteralPath ($elevationExitMismatchExe + '.deadspace-laa.manifest.json')) -or
    $elevationExitMismatchLog -match 'patch result handoff failed, but complete patched state was independently verified' -or
    $elevationExitMismatchLog -match 'relaunched target with process-scoped bypass' -or
    ([regex]::Matches($elevationExitMismatchLog,'user-visible patch failure suppressed for synthetic test')).Count -ne 1) {
    throw 'A patched-looking target overrode a non-success exit from the exact elevated process.'
}
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED,Env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC,Env:DEADSPACE4GB_TEST_FORCE_ELEVATED_FAILURE_EXIT_AFTER_PATCH -ErrorAction SilentlyContinue

# A same-user attacker can freely create and overwrite a legacy-looking result
# file.  Force the real elevated patch to fail, forge every old success field,
# and prove that the process HANDLE exit status wins: the target stays original,
# the forged bytes remain untouched/unread, and the hostile log cannot change.
Reset-Case $elevationForgery
$forgeryExe = Join-Path $elevationForgery 'Dead Space.exe'
$forgeryState = Join-Path $build 'state-elevation-forgery'
Reset-State $forgeryState
$env:DEADSPACE4GB_STATE_DIRECTORY = $forgeryState
$env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_HANDOFF_DELAY_MS = '3000'
$env:DEADSPACE4GB_TEST_FORCE_ELEVATED_PATCH_FAILURE = '1'
$p = Start-Process -FilePath $forgeryExe -WorkingDirectory $elevationForgery -ArgumentList '--forged-result' -PassThru -WindowStyle Hidden
$forgeryRequest = Wait-StateFile $forgeryState 'request-*.bin'
$forgeryDescriptor = Wait-StateFileRegex $forgeryState '^elevation-[0-9a-f]{32}\.bin$'
Assert-MutationBlocked $forgeryRequest 'Forgery-case request handoff'
Assert-MutationBlocked $forgeryDescriptor 'Forgery-case elevation descriptor'
$tokenMatch = [regex]::Match([IO.Path]::GetFileName($forgeryDescriptor),'^elevation-([0-9a-f]{32})\.bin$')
if (-not $tokenMatch.Success) { throw 'Could not derive the exact elevation token for the forgery regression.' }
$forgedResult = Join-Path $forgeryState ('elevation-result-' + $tokenMatch.Groups[1].Value + '.bin')
Write-ForgedLegacyElevationResult $forgedResult $tokenMatch.Groups[1].Value
$forgedBefore = [IO.File]::ReadAllBytes($forgedResult)
$forgeryBootstrapLogPath = Join-Path $forgeryState 'one-dll-bootstrap.log'
Wait-LogPattern $forgeryBootstrapLogPath 'descriptor retained guard verified read-only' 10 | Out-Null
$forgeryHostileLogGuard = [IO.File]::Open($forgeryBootstrapLogPath,[IO.FileMode]::Open,
    [IO.FileAccess]::Read,[IO.FileShare]::Read)
$forgeryHostileLogBefore = [IO.File]::ReadAllBytes($forgeryBootstrapLogPath)
try {
    Assert-MutationBlocked $forgeryBootstrapLogPath 'Forgery-case hostile elevated-role log target'
    $p.WaitForExit()
    $forgeryRaw = Wait-FixtureLog $elevationForgery
    $forgeryHostileLogDuring = [IO.File]::ReadAllBytes($forgeryBootstrapLogPath)
    if ([Convert]::ToBase64String($forgeryHostileLogDuring) -cne [Convert]::ToBase64String($forgeryHostileLogBefore)) {
        throw 'The locked hostile log changed during the forged-result elevation attempt.'
    }
}
finally { $forgeryHostileLogGuard.Dispose() }
$forgedAfter = [IO.File]::ReadAllBytes($forgedResult)
if ([Convert]::ToBase64String($forgedAfter) -cne [Convert]::ToBase64String($forgedBefore)) {
    throw 'The removed result-file channel was unexpectedly opened or rewritten.'
}
if ($forgeryRaw -notmatch 'laa=0;bypass=1;sentinel=preserve-me;request=;role=original-worker;elevatedWorker=;forwarders=12;cwd=' -or
    (Get-Laa $forgeryExe) -or (Test-Path -LiteralPath ($forgeryExe + '.deadspace-laa.bak')) -or
    (Test-Path -LiteralPath ($forgeryExe + '.deadspace-laa.manifest.json'))) {
    throw "A forged legacy elevation result manufactured patch success: $forgeryRaw"
}
Remove-Item -LiteralPath $forgedResult -Force
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED,Env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC,Env:DEADSPACE4GB_TEST_ELEVATION_HANDOFF_DELAY_MS,Env:DEADSPACE4GB_TEST_FORCE_ELEVATED_PATCH_FAILURE -ErrorAction SilentlyContinue

# Simulate a writable game directory whose executable still needs elevation.
# During the consent-window delay, a same-user attacker plants a directory
# junction at the final manifest name. The elevated worker must open the final
# name without following it, reject the non-normal handle, roll back the exact
# target byte, and return failure through its process HANDLE.
Reset-Case $manifestRace
Reset-State $manifestHostile
$manifestExe = Join-Path $manifestRace 'Dead Space.exe'
$manifestState = Join-Path $build 'state-manifest-race'
Reset-State $manifestState
$hostileSentinel = Join-Path $manifestHostile 'must-not-change.txt'
[IO.File]::WriteAllText($hostileSentinel,'hostile-target-must-remain-unchanged',[Text.Encoding]::UTF8)
$hostileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $hostileSentinel).Hash
$env:DEADSPACE4GB_STATE_DIRECTORY = $manifestState
$env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC = '1'
$env:DEADSPACE4GB_TEST_ELEVATION_HANDOFF_DELAY_MS = '3000'
$p = Start-Process -FilePath $manifestExe -WorkingDirectory $manifestRace -ArgumentList '--manifest-reparse-race' -PassThru -WindowStyle Hidden
$manifestDescriptor = Wait-StateFileRegex $manifestState '^elevation-[0-9a-f]{32}\.bin$'
Assert-MutationBlocked $manifestDescriptor 'Manifest-race elevation descriptor'
$manifestPath = $manifestExe + '.deadspace-laa.manifest.json'
New-Item -ItemType Junction -Path $manifestPath -Target $manifestHostile | Out-Null
$p.WaitForExit()
$manifestRaw = Wait-FixtureLog $manifestRace
$manifestItem = Get-Item -LiteralPath $manifestPath -Force
if ($manifestRaw -notmatch 'laa=0;bypass=1;sentinel=preserve-me;request=;role=original-worker;elevatedWorker=;forwarders=12;cwd=' -or
    (Get-Laa $manifestExe) -or -not ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $hostileSentinel).Hash -ne $hostileHash -or
    @(Get-ChildItem -LiteralPath $manifestHostile -Force).Count -ne 1) {
    throw "Elevated manifest write followed or replaced a same-user reparse race: $manifestRaw"
}
[IO.Directory]::Delete($manifestPath)
Remove-Item Env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED,Env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC,Env:DEADSPACE4GB_TEST_ELEVATION_HANDOFF_DELAY_MS -ErrorAction SilentlyContinue

# A pre-planted hardlink must likewise be read-only and rejected before any
# privileged truncate/write. This normally needs no special Windows policy; if
# the host filesystem cannot create hardlinks, keep the refusal test explicit.
Reset-Case $manifestRace
Reset-State $manifestHostile
$hardlinkExe = Join-Path $manifestRace 'Dead Space.exe'
$hardlinkManifest = $hardlinkExe + '.deadspace-laa.manifest.json'
$hardlinkDonor = Join-Path $manifestHostile 'hardlink-donor.txt'
[IO.File]::WriteAllText($hardlinkDonor,'hardlink-donor-must-not-change',[Text.Encoding]::UTF8)
$hardlinkHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $hardlinkDonor).Hash
$hardlinkCreated = $false
try { New-Item -ItemType HardLink -Path $hardlinkManifest -Target $hardlinkDonor -ErrorAction Stop | Out-Null; $hardlinkCreated = $true }
catch { Write-Host 'SKIP: manifest hardlink refusal requires a hardlink-capable local filesystem.' }
if ($hardlinkCreated) {
    $hardlinkState = Join-Path $build 'state-manifest-hardlink'
    Reset-State $hardlinkState
    $env:DEADSPACE4GB_STATE_DIRECTORY = $hardlinkState
    $env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED = '1'
    $env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC = '1'
    $p = Start-Process -FilePath $hardlinkExe -WorkingDirectory $manifestRace -ArgumentList '--manifest-hardlink' -PassThru -WindowStyle Hidden
    $p.WaitForExit()
    $hardlinkRaw = Wait-FixtureLog $manifestRace
    Remove-Item Env:DEADSPACE4GB_TEST_FORCE_ACCESS_DENIED,Env:DEADSPACE4GB_TEST_ELEVATION_NO_UAC -ErrorAction SilentlyContinue
    if ($hardlinkRaw -notmatch 'laa=0;bypass=1;.*role=original-worker;.*forwarders=12' -or
        (Get-Laa $hardlinkExe) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $hardlinkDonor).Hash -ne $hardlinkHash -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $hardlinkManifest).Hash -ne $hardlinkHash) {
        throw "Elevated manifest write modified a pre-planted hardlink target: $hardlinkRaw"
    }
}

# Ready timeout must send cancel; the delayed worker must never patch later.
Reset-Case $cancel
$cancelExe = Join-Path $cancel 'Dead Space.exe'
$cancelState = Join-Path $build 'state-cancel'
Reset-State $cancelState
$env:DEADSPACE4GB_STATE_DIRECTORY = $cancelState
$env:DEADSPACE4GB_TEST_WORKER_READY_DELAY_MS = '3000'
$env:DEADSPACE4GB_TEST_READY_TIMEOUT_MS = '1000'
$p = Start-Process -FilePath $cancelExe -WorkingDirectory $cancel -ArgumentList '--ready-timeout' -PassThru -WindowStyle Hidden
$cancelRequest = Wait-StateFile $cancelState 'request-*.bin'
Assert-MutationBlocked $cancelRequest 'Creation-to-worker request guard'
$p.WaitForExit()
$cancelRaw = Wait-FixtureLog $cancel
Start-Sleep -Seconds 2
if ($cancelRaw -notmatch 'laa=0;bypass=;sentinel=preserve-me;request=;role=;elevatedWorker=;forwarders=12;cwd=' -or (Get-Laa $cancelExe) -or
    (Test-Path -LiteralPath ($cancelExe + '.deadspace-laa.bak'))) { throw "Cancelled readiness handoff changed or relaunched the game: $cancelRaw" }
$cancelBootstrapLog = [IO.File]::ReadAllText((Join-Path $cancelState 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
if ($cancelBootstrapLog -notmatch 'cancelled without patching' -or $cancelBootstrapLog -notmatch 'user-visible patch failure suppressed for synthetic test' -or
    $cancelBootstrapLog -match 'relaunched target') { throw 'Pre-handoff ready failure did not log/show exactly once while continuing current launch.' }
Remove-Item Env:DEADSPACE4GB_TEST_WORKER_READY_DELAY_MS,Env:DEADSPACE4GB_TEST_READY_TIMEOUT_MS -ErrorAction SilentlyContinue

# A worker that signals ready but dies/stalls before commit ACK must be stopped;
# the proxy keeps the original launch alive and no later patch is possible.
Reset-Case $ackCancel
$ackExe = Join-Path $ackCancel 'Dead Space.exe'
$ackState = Join-Path $build 'state-ack-cancel'
Reset-State $ackState
$env:DEADSPACE4GB_STATE_DIRECTORY = $ackState
$env:DEADSPACE4GB_TEST_WORKER_ACK_DELAY_MS = '6000'
$p = Start-Process -FilePath $ackExe -WorkingDirectory $ackCancel -ArgumentList '--ack-timeout' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$ackRaw = Wait-FixtureLog $ackCancel
Start-Sleep -Seconds 1
if ($ackRaw -notmatch 'laa=0;bypass=;sentinel=preserve-me;request=;role=;elevatedWorker=;forwarders=12;cwd=' -or (Get-Laa $ackExe) -or
    (Test-Path -LiteralPath ($ackExe + '.deadspace-laa.bak'))) { throw "Commit-ACK failure changed or relaunched the game: $ackRaw" }
$ackBootstrapLog = [IO.File]::ReadAllText((Join-Path $ackState 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
if ($ackBootstrapLog -notmatch 'did not acknowledge commit' -or $ackBootstrapLog -match 'ending unpatched first process') {
    throw 'Missing commit ACK did not contain the worker while leaving the current game alive.'
}
Remove-Item Env:DEADSPACE4GB_TEST_WORKER_ACK_DELAY_MS -ErrorAction SilentlyContinue

# After commit, a parent-exit timeout must not create a duplicate game process.
Reset-Case $parentTimeout
$parentExe = Join-Path $parentTimeout 'Dead Space.exe'
$parentState = Join-Path $build 'state-parent-timeout'
Reset-State $parentState
$env:DEADSPACE4GB_STATE_DIRECTORY = $parentState
$env:DEADSPACE4GB_TEST_DO_NOT_END_PARENT = '1'
$env:DEADSPACE4GB_TEST_PARENT_WAIT_MS = '500'
$p = Start-Process -FilePath $parentExe -WorkingDirectory $parentTimeout -ArgumentList '--parent-timeout' -PassThru -WindowStyle Hidden
$p.WaitForExit()
$parentRaw = Wait-FixtureLog $parentTimeout
Start-Sleep -Seconds 1
if (@($parentRaw -split "`r?`n" | Where-Object { $_ }).Count -ne 1 -or
    $parentRaw -notmatch 'laa=0;bypass=;sentinel=preserve-me;request=;role=;elevatedWorker=;forwarders=12;cwd=' -or (Get-Laa $parentExe)) {
    throw "Parent-exit timeout patched or launched a duplicate process: $parentRaw"
}
$parentBootstrapLog = [IO.File]::ReadAllText((Join-Path $parentState 'one-dll-bootstrap.log'),[Text.Encoding]::Unicode)
if ($parentBootstrapLog -notmatch 'did not exit in time' -or $parentBootstrapLog -match 'relaunched target') {
    throw 'Post-commit parent timeout did not suppress duplicate relaunch.'
}
Remove-Item Env:DEADSPACE4GB_TEST_DO_NOT_END_PARENT,Env:DEADSPACE4GB_TEST_PARENT_WAIT_MS -ErrorAction SilentlyContinue

# Verify exports and ordinals from the actual DLL.
$dumpbin = 'dumpbin.exe /nologo /exports "' + $dll + '"'
$exportText = & $env:ComSpec /d /s /c ('call "' + $dev + '" -no_logo -arch=x86 -host_arch=x64 >nul && ' + $dumpbin) | Out-String
$expected = @{
    1='DirectSoundCreate';2='DirectSoundEnumerateA';3='DirectSoundEnumerateW';4='DllCanUnloadNow';5='DllGetClassObject';
    6='DirectSoundCaptureCreate';7='DirectSoundCaptureEnumerateA';8='DirectSoundCaptureEnumerateW';9='GetDeviceID';
    10='DirectSoundFullDuplexCreate';11='DirectSoundCreate8';12='DirectSoundCaptureCreate8'
}
foreach ($entry in $expected.GetEnumerator()) {
    if ($exportText -notmatch ('(?m)^\s*' + $entry.Key + '\s+[0-9A-F]+\s+[0-9A-F]+\s+' + [regex]::Escape($entry.Value) + '\s*$')) {
        throw "Missing exact export ordinal $($entry.Key): $($entry.Value)`n$exportText"
    }
}

$source = [IO.File]::ReadAllText((Join-Path $root 'dsound_one_dll.cpp'))
if ($source -match 'ReplaceFileW') { throw 'Path-based ReplaceFileW remains in the one-DLL release source.' }
$patchMatch = [regex]::Match($source, 'static bool Patch\([\s\S]*?\n\}')
if (-not $patchMatch.Success) { throw 'Static pinned-Patch audit could not extract its target; refusing to pass open.' }
if ($patchMatch.Value -match 'CopyFileW|MoveFileExW|ReplaceFileW|WritePatchedCopy') {
    throw 'Patch critical section contains a forbidden path-copy/replacement operation.'
}
if ($patchMatch.Value -match 'StateDirectory\(|ClearFailureMarker\(|WriteFailureMarker\(|MarkerPath\(') {
    throw 'Patch still resolves or mutates user state and is not safe for the privileged patch-only role.'
}
$manifestWriterMatch = [regex]::Match($source, 'static bool WriteManifest\([\s\S]*?\r?\n\}')
if (-not $manifestWriterMatch.Success -or
    $manifestWriterMatch.Value -notmatch 'CREATE_NEW' -or
    $manifestWriterMatch.Value -notmatch 'FILE_FLAG_OPEN_REPARSE_POINT' -or
    $manifestWriterMatch.Value -notmatch 'NormalFileHandle\(f\)' -or
    $manifestWriterMatch.Value -notmatch 'before\.nNumberOfLinks == 1' -or
    $manifestWriterMatch.Value -notmatch 'after\.nNumberOfLinks == 1' -or
    $manifestWriterMatch.Value -notmatch 'ReadAt\(f, 0, readback, bytes\)' -or
    $manifestWriterMatch.Value -notmatch 'PathStillNamesPinnedFile\(path, f\)' -or
    $manifestWriterMatch.Value -match 'CREATE_ALWAYS|OPEN_ALWAYS|SetEndOfFile|MoveFileExW|\.tmp\.') {
    throw 'Manifest writer is not a single-link, non-reparse, create-new/read-only-existing same-handle protocol.'
}
$dllMainMatch = [regex]::Match($source, 'BOOL WINAPI DllMain[\s\S]*?\n\}')
if (-not $dllMainMatch.Success) { throw 'Static DllMain audit could not extract its target; refusing to pass open.' }
$dllMain = $dllMainMatch.Value
if ($dllMain -match 'LoadLibrary|CreateProcess|CreateFile|ReadFile|WriteFile|ShellExecute|DisableThreadLibraryCalls|FreeLibrary') {
    throw "DllMain contains a forbidden loader-lock operation: $dllMain"
}
$elevatedMatch = [regex]::Match($source, 'extern "C" void CALLBACK Elevated[\s\S]*?\n\}')
if (-not $elevatedMatch.Success) { throw 'Static elevated-callback audit could not extract its target; refusing to pass open.' }
$elevatedBody = $elevatedMatch.Value
if ($elevatedBody -match 'Relaunch\(|CreateProcessW\(|ShellExecute') { throw 'Elevated callback contains a game-launch path.' }
if ($elevatedBody -notmatch '^extern "C" void CALLBACK Elevated\([^\r\n]*\)\r?\n\{\s*InterlockedExchange\(&g_elevatedRole,\s*1\);') {
    throw 'The elevated-role fail-closed flag is not the first callback statement.'
}
$logMatch = [regex]::Match($source, 'static void Log\([^\r\n]*\)\r?\n\{[\s\S]*?\r?\n\}')
if (-not $logMatch.Success) { throw 'Static Log audit could not extract its target; refusing to pass open.' }
$logBody = $logMatch.Value
$logRoleCheck = $logBody.IndexOf('InterlockedCompareExchange(&g_elevatedRole')
$logAttemptCounter = $logBody.IndexOf('InterlockedIncrement(&g_logFilesystemAttempts)')
$logStatePath = $logBody.IndexOf('StateDirectory(')
$logCreateDirectory = $logBody.IndexOf('CreateDirectoryW(')
$logCreateFile = $logBody.IndexOf('CreateFileW(')
if ($logRoleCheck -lt 0 -or $logAttemptCounter -lt 0 -or $logStatePath -lt 0 -or
    $logCreateDirectory -lt 0 -or $logCreateFile -lt 0 -or
    $logRoleCheck -gt $logAttemptCounter -or $logAttemptCounter -gt $logStatePath -or
    $logRoleCheck -gt $logCreateDirectory -or $logRoleCheck -gt $logCreateFile -or
    $logBody -notmatch 'InterlockedIncrement\(&g_elevatedLogCallsSuppressed\);\s*return;') {
    throw 'Log does not fail closed for elevated role before every filesystem path/open operation.'
}
$elevatedExitMatch = [regex]::Match($source, '__declspec\(noreturn\) static void FinishElevatedProcess\([^\r\n]*\)\r?\n\{[\s\S]*?\r?\n\}')
if (-not $elevatedExitMatch.Success -or
    $elevatedExitMatch.Value -notmatch 'g_elevatedRole' -or
    $elevatedExitMatch.Value -notmatch 'g_elevatedLogCallsSuppressed' -or
    $elevatedExitMatch.Value -notmatch 'g_logFilesystemAttempts' -or
    $elevatedExitMatch.Value -notmatch 'ExitProcess\(patchSucceeded && audited \? kElevatedSuccessExitCode : kElevatedFailureExitCode\)') {
    throw 'The elevated process exit code does not fail closed on role and zero-filesystem-log audit state.'
}
$launchElevatedMatch = [regex]::Match($source, 'static bool LaunchElevatedPatch\([\s\S]*?\r?\n\}')
if (-not $launchElevatedMatch.Success -or
    $launchElevatedMatch.Value -notmatch 'GetExitCodeProcess\(process, &exitCode\)' -or
    $launchElevatedMatch.Value -notmatch 'exitCode == kElevatedSuccessExitCode' -or
    $launchElevatedMatch.Value -notmatch 'ValidatePatchedStateForOriginal\(target, expectedOriginalHash, patchedHash\)') {
    throw 'The medium worker does not bind elevated success to the exact process handle and independent patched-state validation.'
}
$queuedOwnerStart = $source.IndexOf('if (mutexQueued && parentEnded && mutexOwned)')
$queuedOwnerEnd = if ($queuedOwnerStart -ge 0) {
    $source.IndexOf('if (parentEnded && mutexOwned && !alreadyPatched)', $queuedOwnerStart)
} else { -1 }
if ($queuedOwnerStart -lt 0 -or $queuedOwnerEnd -le $queuedOwnerStart) {
    throw 'Static queued-owner audit could not isolate the serialized outcome branch.'
}
$queuedOwnerBranch = $source.Substring($queuedOwnerStart, $queuedOwnerEnd - $queuedOwnerStart)
if ($queuedOwnerBranch -notmatch 'TargetStatePatched' -or
    $queuedOwnerBranch -notmatch 'TargetStateOriginal' -or
    $queuedOwnerBranch -notmatch 'ShowRecoveryBlocked\(' -or
    $queuedOwnerBranch -notmatch 'ReleaseTargetMutex\(targetMutex\)' -or
    $queuedOwnerBranch -notmatch '\breturn;' -or
    $queuedOwnerBranch -match '\bPatch\(|LaunchElevatedPatch\(|Relaunch\(') {
    throw 'A queued first-launch worker can still write, elevate, relaunch, or escape without final-state classification.'
}
if ($source -notmatch 'else if \(!patched && targetState == TargetStatePatched && !elevationAttempted\)' -or
    $source -notmatch 'else if \(!patched && targetState == TargetStatePatched && elevationAttempted\)' -or
    $source -notmatch 'patched-looking state was not accepted and restart was withheld' -or
    $source -notmatch 'ValidatePatchedStateForOriginal\(target, expectedOriginalHash, currentHash\)') {
    throw 'A non-success elevated process exit can still be overridden by mutable target state.'
}
if ($source -match 'ElevationResult|ReadElevationResult|WriteElevationResult|elevation-result-|DeadSpace4GBElevated-') {
    throw 'A user-writable elevation result file or named result event remains in the release source.'
}
$restoreCallbackMatch = [regex]::Match($source, 'extern "C" void CALLBACK Restore[\s\S]*?\r?\n\}')
if (-not $restoreCallbackMatch.Success -or
    $restoreCallbackMatch.Value -notmatch '^extern "C" void CALLBACK Restore\([^\r\n]*\)\r?\n\{\s*InterlockedExchange\(&g_elevatedRole,\s*1\);' -or
    $restoreCallbackMatch.Value -notmatch 'FinishRestoreProcess\(restored\)' -or
    $restoreCallbackMatch.Value -match 'StateDirectory\(|CreateFileW\(|WriteFile\(|DeleteFileW\(') {
    throw 'Restore callback does not enter the no-filesystem-log role first and exit only through the fixed-status helper.'
}
$restoreExitMatch = [regex]::Match($source, '__declspec\(noreturn\) static void FinishRestoreProcess\([^\r\n]*\)\r?\n\{[\s\S]*?\r?\n\}')
if (-not $restoreExitMatch.Success -or
    $restoreExitMatch.Value -notmatch 'g_elevatedRole' -or
    $restoreExitMatch.Value -notmatch 'g_elevatedLogCallsSuppressed' -or
    $restoreExitMatch.Value -notmatch 'g_logFilesystemAttempts' -or
    $restoreExitMatch.Value -notmatch 'ExitProcess\(restoreSucceeded && audited \? kRestoreSuccessExitCode : kRestoreFailureExitCode\)') {
    throw 'Restore fixed exit status is not bound to the no-filesystem-log audit.'
}
if ($source -match 'DEADSPACE4GB_RESTORE_RESULT|DEADSPACE4GB_RESTORE_TOKEN|kRestoreResultEnvironment|kRestoreTokenEnvironment') {
    throw 'Removed restore marker environment/file trust remains in the DLL.'
}
$restoreScript = [IO.File]::ReadAllText((Join-Path $root 'Restore.cmd'))
if ($restoreScript -match 'set\s+/p|ACTUAL_TOKEN|RESTORE_RESULT|RESTORE_TOKEN|DeadSpace4GBRestore-' -or
    $restoreScript -notmatch 'if not "%RUNDLL_RESULT%"=="1297303297" goto :restore_failed' -or
    $restoreScript -notmatch 'fc\.exe" /b "%TARGET%" "%BACKUP%"' -or
    $restoreScript -notmatch 'if exist "%MANIFEST%" goto :verification_failed') {
    throw 'Restore.cmd still trusts expandable marker content or lacks independent fixed-exit/byte/manifest verification.'
}
$startBootstrapMatch = [regex]::Match($source, 'static BootstrapStartResult StartBootstrap\([\s\S]*?\r?\n\}')
if (-not $startBootstrapMatch.Success) { throw 'Static StartBootstrap audit could not extract its target; refusing to pass open.' }
$highCheck = $startBootstrapMatch.Value.IndexOf('HighIntegrityOrUnknown()')
$inspectCheck = $startBootstrapMatch.Value.IndexOf('Inspect(executable')
$stateCheck = $startBootstrapMatch.Value.IndexOf('StateDirectory(state')
if ($highCheck -lt 0 -or $inspectCheck -lt 0 -or $stateCheck -lt 0 -or
    $highCheck -gt $inspectCheck -or $highCheck -gt $stateCheck) {
    throw 'High-integrity normal-game launch is not rejected before artifact/state inspection and writes.'
}
$highBranchMatch = [regex]::Match($source, 'else if \(result == BootstrapHighIntegrityBlocked\)\s*\{[\s\S]*?\r?\n\s*\}')
if (-not $highBranchMatch.Success -or $highBranchMatch.Value -match 'Log\(' -or
    $highBranchMatch.Value -notmatch 'ShowHighIntegrityBlocked\(\)' -or
    $highBranchMatch.Value -notmatch 'ExitProcess\(ERROR_ELEVATION_REQUIRED\)') {
    throw 'High-integrity launch block is not a log-free, MessageBox-only fail-closed path.'
}
$version = (Get-Item -LiteralPath $dll).VersionInfo
if ($version.ProductName -ne 'Dead Space (2008) 4GB Mod' -or $version.FileVersion -ne '1.1.2.0' -or $version.LegalCopyright -notmatch 'Rama2120') {
    throw 'DLL version metadata is missing or incorrect.'
}

Write-Host 'PASS: one x86 DLL passed pinned one-byte patch/restore, incomplete-state recovery/block, high-integrity launch refusal before state writes, original-integrity relaunch with process-handle-authenticated patch-only elevation, non-success elevated-exit rejection, forged-result and manifest reparse/hardlink rejection, fixed-exit marker-free restore, zero privileged filesystem log attempts, hostile-log/handoff/path mutation refusal, single-owner concurrent success/local-failure/UAC-cancel launches, ready/ACK cancel, parent-timeout, all 12 runtime forwarders and exact ordinals, clean DllMain, and metadata tests.'
