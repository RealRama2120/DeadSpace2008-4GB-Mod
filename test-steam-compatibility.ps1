$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$build=Join-Path $root 'build'
$fixture=Join-Path $build 'steam-read-fixture'
New-Item -ItemType Directory -Force -Path $fixture | Out-Null
$dev='C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat'
$objects=@('buffer','hook','trampoline','hde32') | ForEach-Object { '"'+(Join-Path $build ('mh_'+$_+'.obj'))+'"' }
$exe=Join-Path $build 'SteamCompatibilityTest.exe'
& $env:ComSpec /d /s /c ('call "'+$dev+'" -no_logo -arch=x86 -host_arch=x64 >nul && cl.exe /nologo /EHsc /std:c++17 /O2 /MT /W4 /DUNICODE /D_UNICODE "'+(Join-Path $root 'steam_compatibility_test.cpp')+'" /Fo"'+(Join-Path $build 'steam_compatibility_test.obj')+'" /Fe:"'+$exe+'" /link '+($objects -join ' ')+' bcrypt.lib ole32.lib shell32.lib user32.lib advapi32.lib')
if($LASTEXITCODE){throw 'Steam compatibility test build failed'}
$stdout=Join-Path $build 'steam-test-output.txt'
$stderr=Join-Path $build 'steam-test-errors.txt'
$process=Start-Process -FilePath $exe -ArgumentList ('"'+$fixture+'"') -WorkingDirectory $build -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
if(-not $process.WaitForExit(20000)){Stop-Process -Id $process.Id -Force; throw 'Steam compatibility test timed out'}
Get-Content -LiteralPath $stdout,$stderr
if($process.ExitCode -ne 0){throw "Steam compatibility test failed: $($process.ExitCode)"}
if(-not (Select-String -LiteralPath $stdout -Pattern '^PASS:')){throw 'Steam compatibility test did not reach its success marker'}
