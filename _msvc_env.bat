@echo off
:: _msvc_env.bat - MSVC toolchain discovery shared by _build.bat, _tests.bat
:: and _ptelive.bat.  Call it (no setlocal here, so the variables land in the
:: caller's scope) and check ENV_RC afterwards: 0 = ready, 1 = not usable.
::
:: Sets: VSROOT, VSVER, MSVC_VER, WINSDK, CL_EXE, LINK_EXE, RC_EXE,
::       INCLUDE, LIB.

set "ENV_RC=1"
set "VSROOT="
set "VSVER="
set "MSVC_VER="
set "WINSDK="

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found. Install Visual Studio Build Tools.
    goto :eof
)

for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSROOT=%%v"
for /f "usebackq delims=" %%v in (`"%VSWHERE%" -latest -products * -property installationVersion`) do set "VSVER=%%v"
if not defined VSROOT (
    echo [-] Visual Studio installation not found.
    goto :eof
)

for /f "delims=" %%v in ('dir /b "%VSROOT%\VC\Tools\MSVC" 2^>nul') do set "MSVC_VER=%%v"
if not defined MSVC_VER (
    echo [-] No MSVC toolset under "%VSROOT%\VC\Tools\MSVC".
    goto :eof
)
set "MSVC=%VSROOT%\VC\Tools\MSVC\%MSVC_VER%"

:: Skip non-version folders (e.g. "wdf") and driver-only kits without the
:: ucrt headers needed for user-mode builds.
for /f "delims=" %%k in ('dir /b /ad "%ProgramFiles(x86)%\Windows Kits\10\Include\10.*" 2^>nul') do (
    if exist "%ProgramFiles(x86)%\Windows Kits\10\Include\%%k\ucrt\stdlib.h" set "WINSDK=%%k"
)
if not defined WINSDK (
    echo [-] No complete Windows SDK found ^(with ucrt headers^).
    goto :eof
)

set "CL_EXE=%MSVC%\bin\Hostx64\x64\cl.exe"
set "LINK_EXE=%MSVC%\bin\Hostx64\x64\link.exe"
set "RC_EXE=%ProgramFiles(x86)%\Windows Kits\10\bin\%WINSDK%\x64\rc.exe"
if not exist "%CL_EXE%" (
    echo [-] cl.exe not found under "%MSVC%".
    goto :eof
)
set "INCLUDE=%MSVC%\include;%ProgramFiles(x86)%\Windows Kits\10\Include\%WINSDK%\ucrt;%ProgramFiles(x86)%\Windows Kits\10\Include\%WINSDK%\um;%ProgramFiles(x86)%\Windows Kits\10\Include\%WINSDK%\shared"
set "LIB=%MSVC%\lib\x64;%ProgramFiles(x86)%\Windows Kits\10\Lib\%WINSDK%\ucrt\x64;%ProgramFiles(x86)%\Windows Kits\10\Lib\%WINSDK%\um\x64"

set "ENV_RC=0"
