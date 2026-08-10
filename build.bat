@echo off
REM Delayed expansion is deliberately NOT enabled: it eats the "!" in the [!]
REM tag. `if errorlevel 1` reads the code at run time, so nothing here needs it.
setlocal

REM Console colour. The ESC byte comes from `prompt $E`; if that fails or NO_COLOR
REM is set, every code stays empty and the output is the plain text as before.
set "ESC="
if not defined NO_COLOR for /f %%E in ('echo prompt $E^| cmd') do set "ESC=%%E"

set "C_RST=" & set "C_RED=" & set "C_GRN=" & set "C_YEL=" & set "C_CYN=" & set "C_DIM=" & set "C_BLD="
if defined ESC (
    set "C_RST=%ESC%[0m"  & set "C_RED=%ESC%[91m" & set "C_GRN=%ESC%[92m"
    set "C_YEL=%ESC%[93m" & set "C_CYN=%ESC%[96m" & set "C_DIM=%ESC%[90m"
    set "C_BLD=%ESC%[1m"
)

set "T_OK=%C_GRN%[+]%C_RST%"
set "T_ERR=%C_RED%[-]%C_RST%"
set "T_INFO=%C_CYN%[*]%C_RST%"
set "T_WARN=%C_YEL%[!]%C_RST%"
set "T_FAIL=%C_BLD%%C_RED%[ERROR]%C_RST%"
set "T_DONE=%C_BLD%%C_GRN%[SUCCESS]%C_RST%"

REM Decide up front whether the console needs holding open at the end - see the
REM :hold subroutine for why, and MV2_BUILD_NOPAUSE to suppress it. Done with
REM plain string substitution rather than `echo %cmdcmdline% | find`: `find` on
REM PATH may well be Git's Unix find, which takes neither /i nor that syntax.
REM `call set` gives the second expansion pass %~nx0 needs inside the :pattern=.
set "HOLD="
set "CL=%cmdcmdline%"
set "CL=%CL:"=%"
call set "CL_CUT=%%CL:%~nx0=%%"
if not "%CL_CUT%"=="%CL%" set "HOLD=1"
if defined MV2_BUILD_NOPAUSE set "HOLD="

echo %C_CYN%===================================================%C_RST%
echo         %C_BLD%Building Chrome Manifest V2 Patcher (Go)%C_RST%
echo %C_CYN%===================================================%C_RST%

REM 0. Require the Go toolchain.
where go >nul 2>&1
if errorlevel 1 (
    echo %T_FAIL% Could not find go.exe. Install Go from https://go.dev/dl and re-run.
    call :hold
    exit /b 1
)

REM 1. Read the version from the Go source (single source of truth: appVersion
REM    in internal\app\app.go, e.g. `const appVersion = "1.1.0"`).
set "APP_VER=0.0.0"
for /f tokens^=2^ delims^=^" %%i in ('findstr /c:"appVersion = " internal\app\app.go') do set "APP_VER=%%i"
echo %T_INFO% Patcher version: %C_BLD%%APP_VER%%C_RST%

set "PKG=./cmd/chrome-mv2"
set "OUTDIR=build"

REM 2. Fresh build/ tree.
if exist "%OUTDIR%" rmdir /s /q "%OUTDIR%"
mkdir "%OUTDIR%"

REM 3. Embed the Windows UAC manifest (requireAdministrator) for the release
REM    build. The .syso is a transient artifact regenerated from the manifest
REM    each run and removed in the tidy step (step 5), so a plain
REM    `go build ./cmd/chrome-mv2` stays manifest-free - handy for unelevated
REM    offline testing with MV2_TEST_NO_ELEVATION. `go build` auto-links the
REM    rsrc_windows_<GOARCH>.syso matching each target, so one is generated per
REM    Windows arch (amd64 + 386); the _windows_ suffix keeps them out of the
REM    Linux cross-build. rsrc runs via `go run pkg@version` - fetched to the
REM    module cache, never added to go.mod.
set "MANIFEST=cmd\chrome-mv2\chrome-mv2.exe.manifest"
call :manifest amd64
call :manifest 386

REM 4. Build + package one binary per platform. Each :package call cross-builds
REM    from this one toolchain (no CGO), stages the binary + LICENSE + README
REM    into build\stage\<os>-<arch>\, and zips it to build\<os>-<arch>.zip.
set "FAILED="
call :package windows amd64 chrome-mv2.exe
call :package windows 386   chrome-mv2-x86.exe
call :package linux   amd64 chrome-mv2

REM 5. Tidy: drop the staging tree and the transient manifest resources, leaving
REM    the loose binaries and the per-platform .zip in build\.
rmdir /s /q "%OUTDIR%\stage" 2>nul
del /q cmd\chrome-mv2\rsrc_windows_*.syso 2>nul

REM 6. Every target must have produced its loose binary. :package reports its own
REM    build/archive failures, but a `call` that never lands - an unfindable
REM    label, say - reports nothing and would otherwise leave a silent SUCCESS on
REM    a release that is missing a whole platform.
call :require chrome-mv2.exe     windows-amd64
call :require chrome-mv2-x86.exe windows-386
call :require chrome-mv2         linux-amd64

echo.
if defined FAILED (
    echo %C_CYN%===================================================%C_RST%
    echo %T_WARN% Finished with errors: %FAILED%
    echo %C_CYN%===================================================%C_RST%
    call :hold
    exit /b 1
)
echo %C_CYN%===================================================%C_RST%
echo %T_DONE% Build complete. Artifacts in %C_BLD%%OUTDIR%\%C_RST%
echo %C_CYN%===================================================%C_RST%
call :hold
endlocal
exit /b 0

REM ---------------------------------------------------------------------------
REM :hold  - keep the window open when build.bat was double-clicked from
REM Explorer, which spawns a dedicated console that closes the instant the
REM script ends, taking the build output with it. Detected at the top: Explorer
REM launches us as `cmd /c "<full path to build.bat>"`, so our own name appears
REM in %cmdcmdline%, whereas from an existing shell that variable is just
REM "cmd.exe" (or the pwsh/bash parent's command). So an interactive run - and
REM any CI or scripted caller - is never blocked by a pause it can't answer.
REM Set MV2_BUILD_NOPAUSE=1 to force it off regardless.
REM ---------------------------------------------------------------------------
:hold
if not defined HOLD exit /b 0
echo.
pause
exit /b 0

REM ---------------------------------------------------------------------------
REM :require <binary-name> <platform>  - assert a target actually produced its
REM loose binary, so a call that silently never ran can't pass as a clean build.
REM ---------------------------------------------------------------------------
:require
if exist "%OUTDIR%\%~1" exit /b 0
echo %T_ERR% %~2 produced no %~1 - that target did not run.
set "FAILED=%FAILED% %~2-missing"
exit /b 0

REM ---------------------------------------------------------------------------
REM :manifest <goarch>  - regenerate the per-arch UAC manifest .syso. A
REM subroutine (not an inline `for ( )` block) so the parens in
REM "(requireAdministrator)" don't break the batch parser.
REM ---------------------------------------------------------------------------
:manifest
echo %T_INFO% Embedding Windows manifest (requireAdministrator) for %~1...
go run github.com/akavel/rsrc@v0.10.2 -manifest "%MANIFEST%" -arch %~1 -o "cmd\chrome-mv2\rsrc_windows_%~1.syso" 2>nul
if errorlevel 1 (
    echo %T_WARN% Could not generate the %~1 manifest resource - offline first run? That Windows exe will NOT request elevation.
) else (
    echo %T_OK% Manifest resource: %C_BLD%cmd\chrome-mv2\rsrc_windows_%~1.syso%C_RST%
)
exit /b 0

REM ---------------------------------------------------------------------------
REM :package <goos> <goarch> <binary-name>
REM ---------------------------------------------------------------------------
:package
set "GOOS=%~1"
set "GOARCH=%~2"
set "BIN=%~3"
set "PLAT=%~1-%~2"
set "STAGE=%OUTDIR%\stage\%PLAT%"
mkdir "%STAGE%" 2>nul

echo %T_INFO% Building %C_BLD%%BIN%%C_RST% (%PLAT%)...
go build -trimpath -ldflags "-s -w" -o "%STAGE%\%BIN%" %PKG%
if errorlevel 1 (
    echo %T_ERR% %PLAT% build failed.
    set "FAILED=%FAILED% %PLAT%"
    goto :package_reset
)
REM Loose binary + its runtime signature table at build\ for quick local use.
copy /y "%STAGE%\%BIN%" "%OUTDIR%\%BIN%" >nul
copy /y signatures.json "%OUTDIR%\signatures.json" >nul
REM Bundle the runtime table (read from beside the binary) + docs in the zip.
copy /y signatures.json "%STAGE%\signatures.json" >nul
copy /y LICENSE "%STAGE%\LICENSE" >nul 2>nul
copy /y README.md "%STAGE%\README.md" >nul 2>nul

REM Archive the staged tree: Linux ships a .tar.gz (platform convention), Windows
REM a .zip. Both are :subroutine calls, not an inline `if ( ) else ( )`, because
REM each sets a variable and then uses it - without delayed expansion that only
REM works across a fresh parse, which a `call` gives (same reason as :manifest).
if "%GOOS%"=="linux" (call :archive_tar) else (call :archive_zip)

:package_reset
set "GOOS="
set "GOARCH="
exit /b 0

REM ---------------------------------------------------------------------------
REM :archive_tar  - Linux release tarball, written by tools\mktargz.go rather
REM than the host `tar`. There is no portable tar here: Windows 10+ ships bsdtar
REM in System32 and Git for Windows ships GNU tar, and whichever wins the PATH
REM race decides whether --mode is accepted at all (bsdtar rejects it). --mode is
REM what restores the execute bit the Windows-staged binary has no way to carry,
REM so the extracted chrome-mv2 runs without a manual chmod. The Go helper needs
REM only the toolchain already required in step 0, and records the modes and the
REM entry order itself. Members are named explicitly rather than globbed so a
REM stray file in the stage dir can't slip into a release.
REM ---------------------------------------------------------------------------
:archive_tar
set "TARBALL=%OUTDIR%\chrome-mv2-v%APP_VER%-%PLAT%.tar.gz"
REM The helper has to build and run for the HOST, so drop the cross-build vars
REM :package set (:package_reset clears them again right after this returns).
set "GOOS="
set "GOARCH="
go run tools\mktargz.go -o "%TARBALL%" -C "%STAGE%" -exec "%BIN%" "%BIN%" signatures.json LICENSE README.md
if errorlevel 1 (
    echo %T_WARN% %PLAT% built, but tarring failed.
    set "FAILED=%FAILED% %PLAT%-tar"
) else (
    echo %T_OK% %PLAT%: %C_BLD%%OUTDIR%\%BIN%%C_RST% + %C_BLD%%TARBALL%%C_RST%
)
exit /b 0

REM ---------------------------------------------------------------------------
REM :archive_zip  - Windows release zip.
REM ---------------------------------------------------------------------------
:archive_zip
set "ZIP=%OUTDIR%\chrome-mv2-v%APP_VER%-%PLAT%.zip"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%STAGE%\*' -DestinationPath '%ZIP%' -Force"
if errorlevel 1 (
    echo %T_WARN% %PLAT% built, but zipping failed - is PowerShell available?
    set "FAILED=%FAILED% %PLAT%-zip"
) else (
    echo %T_OK% %PLAT%: %C_BLD%%OUTDIR%\%BIN%%C_RST% + %C_BLD%%ZIP%%C_RST%
)
exit /b 0
