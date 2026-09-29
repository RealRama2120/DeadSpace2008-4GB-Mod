$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$build=Join-Path $root 'build'
New-Item -ItemType Directory -Force -Path $build | Out-Null
$dev='C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat'
$resource=Join-Path $build 'version.res'
$dll=Join-Path $build 'dsound.dll'
$obj=Join-Path $build 'dsound_one_dll.obj'
$minhook=Join-Path $root 'vendor\minhook-1.3.4'
$hookObjects=@()
foreach($unit in @('buffer','hook','trampoline','hde\hde32')) {
    $out=Join-Path $build ('mh_'+(Split-Path -Leaf $unit)+'.obj')
    $src=Join-Path $minhook ('src\'+$unit+'.c')
    & $env:ComSpec /d /s /c ('call "'+$dev+'" -no_logo -arch=x86 -host_arch=x64 >nul && cl.exe /nologo /O2 /MT /W4 /guard:cf /c "'+$src+'" /Fo"'+$out+'"')
    if($LASTEXITCODE){throw 'MinHook build failed'}
    $hookObjects += '"'+$out+'"'
}
& $env:ComSpec /d /s /c ('call "'+$dev+'" -no_logo -arch=x86 -host_arch=x64 >nul && rc.exe /nologo /fo "'+$resource+'" "'+(Join-Path $root 'version.rc')+'"')
if($LASTEXITCODE){throw 'Resource build failed'}
& $env:ComSpec /d /s /c ('call "'+$dev+'" -no_logo -arch=x86 -host_arch=x64 >nul && cl.exe /nologo /EHsc /O2 /MT /W4 /guard:cf /LD /DUNICODE /D_UNICODE "'+(Join-Path $root 'dsound_one_dll.cpp')+'" /Fo"'+$obj+'" /link /DEF:"'+(Join-Path $root 'dsound.def')+'" /OUT:"'+$dll+'" /IMPLIB:"'+(Join-Path $build 'dsound.lib')+'" /Brepro /guard:cf /DYNAMICBASE /NXCOMPAT /ignore:4104 "'+$resource+'" '+($hookObjects -join ' ')+' bcrypt.lib ole32.lib shell32.lib user32.lib advapi32.lib')
if($LASTEXITCODE){throw 'DLL build failed'}
Get-FileHash -LiteralPath $dll -Algorithm SHA256
