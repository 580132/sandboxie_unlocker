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

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [^^!] Administrator rights required - right-click and "Run as administrator".
    set "RC=1"
    goto done
)

:: ===== Toolchain (same discovery as _build.bat) =====
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found. Install Visual Studio Build Tools.
    set "RC=1"
    goto done
)
for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSROOT=%%v"
if not defined VSROOT (
    echo [-] Visual Studio installation not found.
    set "RC=1"
    goto done
)
for /f "delims=" %%v in ('dir /b "%VSROOT%\VC\Tools\MSVC"') do set "MSVC_VER=%%v"
set "MSVC=%VSROOT%\VC\Tools\MSVC\%MSVC_VER%"
set "WINSDK="
for /f "delims=" %%k in ('dir /b /ad "C:\Program Files (x86)\Windows Kits\10\Include\10.*"') do (
    if exist "C:\Program Files (x86)\Windows Kits\10\Include\%%k\ucrt\stdlib.h" set "WINSDK=%%k"
)
if not defined WINSDK (
    echo [-] No complete Windows SDK found ^(with ucrt headers^).
    set "RC=1"
    goto done
)
set "CL_EXE=%MSVC%\bin\Hostx64\x64\cl.exe"
set "INCLUDE=%MSVC%\include;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\um;C:\Program Files (x86)\Windows Kits\10\Include\%WINSDK%\shared"
set "LIB=%MSVC%\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%WINSDK%\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%WINSDK%\um\x64"

echo [*] Building ptelive...
"%CL_EXE%" /nologo /W3 /O2 /MT "%REPO%\tests\ptelive.c" advapi32.lib user32.lib /Fo"%OUT%\ptelive.obj" /Fe"%OUT%\sbie_ptelive.exe"
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
