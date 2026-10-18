@echo off
setlocal enabledelayedexpansion

:: Tests runner: builds the DLL, the two test binaries, and runs them from
:: the repo root.  Exit code is non-zero when any test fails.  Safe on
:: machines without Sandboxie: kernel paths are never exercised.
::
:: Started WITHOUT arguments (e.g. double-click) the console stays open
:: after the run so the results can be read.  Pass any argument (CI)
:: to exit immediately.

set "REPO=%~dp0."
set "OUT=%TEMP%\sbie_tests"
set "RC=0"
if not exist "%OUT%" mkdir "%OUT%"

:: ===== Toolchain =====
call "%~dp0_msvc_env.bat"
if not "%ENV_RC%"=="0" (
    set "RC=1"
    goto done
)

:: ===== Build the DLL under test (always: a stale copy would be tested) =====
echo [*] Building dist\version.dll...
call "%REPO%\_build.bat" ci
if errorlevel 1 (
    set "RC=1"
    goto done
)

:: ===== Build test binaries =====
echo [*] Building selftest...
"%CL_EXE%" /nologo /W4 /O2 /MT "%REPO%\tests\selftest.c" bcrypt.lib advapi32.lib user32.lib /Fo"%OUT%\selftest.obj" /Fe"%OUT%\sbie_selftest.exe"
if errorlevel 1 (
    echo [-] selftest build failed
    set "RC=1"
    goto done
)

echo [*] Building proxytest...
"%CL_EXE%" /nologo /W4 /O2 /MT "%REPO%\tests\proxytest.c" user32.lib advapi32.lib /Fo"%OUT%\proxytest.obj" /Fe"%OUT%\sbie_proxytest.exe"
if errorlevel 1 (
    echo [-] proxytest build failed
    set "RC=1"
    goto done
)

:: ===== Run =====
pushd "%REPO%"
echo.
echo [*] Running selftest...
"%OUT%\sbie_selftest.exe" "dist\version.dll"
if errorlevel 1 set "RC=1"
echo.
echo [*] Running proxytest...
"%OUT%\sbie_proxytest.exe" "dist\version.dll"
if errorlevel 1 set "RC=1"
popd

:done
if not "%RC%"=="0" echo [-] TEST SUITE FAILED
if "%RC%"=="0" echo [+] TEST SUITE PASSED

:: Interactive run (no arguments): keep the console open.
if "%~1"=="" pause
exit /b %RC%
