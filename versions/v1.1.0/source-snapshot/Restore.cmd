@echo off
setlocal DisableDelayedExpansion
title Dead Space (2008) - Restore 4GB Mod

set "NO_PAUSE="
if /I "%~1"=="--no-pause" set "NO_PAUSE=1"

set "MOD_DIR=%~dp0"
set "DLL=%MOD_DIR%dsound.dll"
set "TARGET=%MOD_DIR%Dead Space.exe"
set "BACKUP=%TARGET%.deadspace-laa.bak"
set "MANIFEST=%TARGET%.deadspace-laa.manifest.json"
set "STATE_ROOT=%LOCALAPPDATA%"
if not defined STATE_ROOT set "STATE_ROOT=%TEMP%"
set "LOG=%STATE_ROOT%\DeadSpace4GBMod\one-dll-bootstrap.log"
set "RESULT=1"
set "RUNDLL_RESULT=not started"

echo.
echo Dead Space (2008) 4GB Mod - Restore
echo -----------------------------------
echo.

if not exist "%DLL%" goto :missing_dll
if not exist "%TARGET%" goto :missing_target
if not exist "%BACKUP%" goto :missing_backup

rem dsound.dll is an x86 DLL. On 64-bit Windows, SysWOW64 contains the
rem 32-bit x86 rundll32. On 32-bit Windows, System32 is already 32-bit.
set "RUNDLL=%SystemRoot%\System32\rundll32.exe"
if exist "%SystemRoot%\SysWOW64\rundll32.exe" set "RUNDLL=%SystemRoot%\SysWOW64\rundll32.exe"
if not exist "%RUNDLL%" goto :missing_rundll

echo Close Dead Space before restoring.
echo Using: "%RUNDLL%"
echo.

rem Do not rely on the caller's working directory. The environment variable
rem also avoids rundll32's legacy ANSI command-line parsing for the target path.
pushd "%MOD_DIR%" >nul 2>&1
if errorlevel 1 goto :working_directory_failed
set "DEADSPACE4GB_RESTORE_TARGET=%TARGET%"
"%RUNDLL%" "%DLL%",Restore
set "RUNDLL_RESULT=%ERRORLEVEL%"
set "DEADSPACE4GB_RESTORE_TARGET="
popd

rem The DLL deliberately exits rundll32 with one fixed success status only
rem after its pinned-handle restore and no-filesystem-log audit succeed. No
rem marker pathname or marker content is trusted. FC then independently proves
rem byte-for-byte equality, and the active manifest must be gone.
if not "%RUNDLL_RESULT%"=="1297303297" goto :restore_failed
"%SystemRoot%\System32\fc.exe" /b "%TARGET%" "%BACKUP%" >nul 2>&1
if errorlevel 1 goto :verification_failed
if exist "%MANIFEST%" goto :verification_failed

echo SUCCESS: The original Dead Space.exe was restored and verified.
echo.
echo Vortex: disable/remove the mod and Deploy Mods before launching again.
echo Manual install: remove dsound.dll and this restore command before launching again.
echo If dsound.dll remains deployed, the next launch will apply the patch again.
set "RESULT=0"
goto :finish

:missing_dll
echo FAILED: dsound.dll is not beside this Restore.cmd file.
goto :failure_help

:missing_target
echo FAILED: Dead Space.exe is not beside this Restore.cmd file.
goto :failure_help

:missing_backup
echo FAILED: The original backup was not found:
echo "%BACKUP%"
goto :failure_help

:missing_rundll
echo FAILED: Windows' 32-bit rundll32.exe was not found.
goto :failure_help

:working_directory_failed
echo FAILED: The game folder could not be opened as the working directory.
goto :failure_help

:restore_failed
echo FAILED: The DLL did not complete a verified restore.
echo rundll32 exit code: %RUNDLL_RESULT%
goto :failure_help

:verification_failed
echo FAILED: The restored executable does not exactly match the verified backup.
echo rundll32 exit code: %RUNDLL_RESULT%
goto :failure_help

:failure_help
echo.
echo Make sure Dead Space is closed, then try again.
echo If the game is under Program Files, try Run as administrator.
echo For safety, the restore callback does not write a diagnostic log.

:finish
echo.
if not defined NO_PAUSE pause
endlocal & exit /b %RESULT%
