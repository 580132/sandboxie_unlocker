@echo off
setlocal enabledelayedexpansion

:: Builds and runs the live PTE check (tests\ptelive.c).  Needs BOTH the
:: MSVC toolchain and administrator rights: it loads the embedded helper
:: driver and writes through a page-table alias, i.e. the exact code path
:: the unlock uses for SbieDrv >= 1.18.7.  Nothing in Sandboxie is
:: touched; the helper driver stays loaded until reboot, like any unlock.
::
:: Started WITHOUT arguments (e.g. double-click) the console stays open.

set "REPO=%~dp0."
set "OUT=%TEMP%\sbie_tests"
set "RC=0"
if not exist "%OUT%" mkdir "%OUT%"

:: net session needs the Server service, so fall back to a plain admin probe.
net session >nul 2>&1
if %errorlevel% neq 0 fltmc >nul 2>&1
if errorlevel 1 (
    echo [^^!] Administrator rights required - right-click and "Run as administrator".
    set "RC=1"
    goto done
)

:: ===== Toolchain =====
call "%~dp0_msvc_env.bat"
if not "%ENV_RC%"=="0" (
    set "RC=1"
    goto done
)

echo [*] Building ptelive...
"%CL_EXE%" /nologo /W4 /O2 /MT "%REPO%\tests\ptelive.c" advapi32.lib user32.lib /Fo"%OUT%\ptelive.obj" /Fe"%OUT%\sbie_ptelive.exe"
if errorlevel 1 (
    echo [-] build failed
    set "RC=1"
    goto done
)

echo.
"%OUT%\sbie_ptelive.exe"
if errorlevel 1 set "RC=1"

:done
if not "%RC%"=="0" echo [-] PTE LIVE CHECK FAILED
if "%RC%"=="0" echo [+] PTE LIVE CHECK PASSED

if "%~1"=="" pause
exit /b %RC%
