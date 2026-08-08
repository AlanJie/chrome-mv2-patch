@echo off
REM Delayed expansion is deliberately NOT enabled: it eats the "!" in the [!]
REM tag, and every escape that survives a `set` was worse than the alternative.
REM `if errorlevel 1` reads the code at run time, so nothing here needs it.
setlocal

REM Console colour. The ESC byte comes from `prompt $E`; if that fails or NO_COLOR
REM is set, every code stays empty and the output is the plain text as before.
REM Batch cannot detect a redirected stdout, so NO_COLOR is the way to silence it.
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

echo %C_CYN%===================================================%C_RST%
echo         %C_BLD%Building Chrome Manifest V2 Patcher%C_RST%
echo %C_CYN%===================================================%C_RST%

REM 0. Read the version from chrome-mv2-patch.cpp (single source of truth).
set "VMAJ=0"
set "VMIN=0"
set "VPAT=0"
set "VBLD=0"
for /f "tokens=3" %%i in ('findstr /b /c:"#define APP_VER_MAJOR" chrome-mv2-patch.cpp') do set "VMAJ=%%i"
for /f "tokens=3" %%i in ('findstr /b /c:"#define APP_VER_MINOR" chrome-mv2-patch.cpp') do set "VMIN=%%i"
for /f "tokens=3" %%i in ('findstr /b /c:"#define APP_VER_PATCH" chrome-mv2-patch.cpp') do set "VPAT=%%i"
for /f "tokens=3" %%i in ('findstr /b /c:"#define APP_VER_BUILD" chrome-mv2-patch.cpp') do set "VBLD=%%i"
set "APP_VER=%VMAJ%.%VMIN%.%VPAT%"
echo %T_INFO% Patcher version: %C_BLD%%APP_VER%%C_RST%

REM 1. Locate Visual Studio vcvars64.bat (auto-detect any edition/version)
set "VS_PATH="

REM 1a. Preferred: ask vswhere for any install with the C++ toolset (covers all editions incl. Build Tools).
for %%V in ("%ProgramFiles(x86)%" "%ProgramFiles%") do (
    if not defined VS_PATH if exist "%%~V\Microsoft Visual Studio\Installer\vswhere.exe" (
        for /f "usebackq tokens=*" %%i in (`"%%~V\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
            if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" (
                set "VS_PATH=%%i\VC\Auxiliary\Build\vcvars64.bat"
            )
        )
    )
)

REM 1b. Fallback: scan both Program Files roots for ANY vcvars64.bat (any year/edition).
if not defined VS_PATH (
    for %%R in ("%ProgramFiles%\Microsoft Visual Studio" "%ProgramFiles(x86)%\Microsoft Visual Studio") do (
        if not defined VS_PATH if exist "%%~R" (
            for /f "delims=" %%i in ('dir /b /s "%%~R\vcvars64.bat" 2^>nul') do (
                if not defined VS_PATH set "VS_PATH=%%i"
            )
        )
    )
)

if defined VS_PATH (
    echo %T_INFO% Found Visual Studio vcvars64 at: %C_DIM%"%VS_PATH%"%C_RST%
    call "%VS_PATH%" >nul
) else (
    echo %T_WARN% vcvars64.bat not found automatically. Checking if cl.exe is in PATH...
)

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo %T_FAIL% Could not find cl.exe. Please run build.bat from Visual Studio Developer Command Prompt.
    exit /b 1
)

REM 2. Generate + compile the Windows version resource (embeds FILEVERSION /
REM    "Details" tab). The .rc is written here from the version parsed above, so
REM    the .cpp stays the only source of truth and no .rc is checked in. rc.exe
REM    ships with the Windows SDK and is on PATH after vcvars64. If it is missing,
REM    build without the resource rather than failing the whole build.
set "RES_FILE="
set "RC_TMP=chrome-mv2-patch.rc"
where rc.exe >nul 2>&1
if errorlevel 1 (
    echo %T_WARN% rc.exe not found; building without embedded version resource.
) else (
    echo %T_INFO% Generating and compiling version resource...
    (
        echo #include ^<winver.h^>
        echo VS_VERSION_INFO VERSIONINFO
        echo  FILEVERSION    %VMAJ%,%VMIN%,%VPAT%,%VBLD%
        echo  PRODUCTVERSION %VMAJ%,%VMIN%,%VPAT%,%VBLD%
        echo  FILEFLAGSMASK  0x3fL
        echo  FILEFLAGS      0x0L
        echo  FILEOS         0x40004L
        echo  FILETYPE       0x1L
        echo  FILESUBTYPE    0x0L
        echo BEGIN
        echo     BLOCK "StringFileInfo"
        echo     BEGIN
        echo         BLOCK "040904b0"
        echo         BEGIN
        echo             VALUE "CompanyName",      "chrome-patcher"
        echo             VALUE "FileDescription",  "Google Chrome chrome.dll Manifest V2 Patcher"
        echo             VALUE "FileVersion",      "%APP_VER%"
        echo             VALUE "InternalName",     "chrome-mv2-patch"
        echo             VALUE "OriginalFilename", "chrome-mv2-patch.exe"
        echo             VALUE "ProductName",      "Chrome MV2 Patcher"
        echo             VALUE "ProductVersion",   "%APP_VER%"
        echo         END
        echo     END
        echo     BLOCK "VarFileInfo"
        echo     BEGIN
        echo         VALUE "Translation", 0x409, 1200
        echo     END
        echo END
    ) > "%RC_TMP%"
    rc.exe /nologo /fo chrome-mv2-patch.res "%RC_TMP%"
    if errorlevel 1 (
        echo %T_WARN% rc.exe failed; building without embedded version resource.
    ) else (
        set "RES_FILE=chrome-mv2-patch.res"
    )
    del /q "%RC_TMP%" 2>nul
)

REM 3. Compile chrome-mv2-patch.exe (Standalone chrome.dll Binary Patcher)
echo %T_INFO% Compiling chrome-mv2-patch.exe (x64)...
cl.exe /O2 /EHsc /std:c++17 /W3 /D_CRT_SECURE_NO_WARNINGS chrome-mv2-patch.cpp %RES_FILE% /link /OUT:chrome-mv2-patch.exe /MANIFEST /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" /MANIFEST:EMBED shell32.lib user32.lib advapi32.lib version.lib rstrtmgr.lib

if errorlevel 1 (
    echo %T_FAIL% chrome-mv2-patch.exe compilation failed.
    del /q chrome-mv2-patch.obj 2>nul
    del /q chrome-mv2-patch.res 2>nul
    exit /b 1
)

echo %T_OK% Compilation succeeded: %C_BLD%chrome-mv2-patch.exe%C_RST%

REM 4. Clean up intermediate build artifacts
echo %T_INFO% Cleaning up intermediate build artifacts...
del /q chrome-mv2-patch.obj 2>nul
del /q chrome-mv2-patch.res 2>nul

REM 5. Package the versioned release zip (exe only) for GitHub releases.
set "ZIP_NAME=chrome-mv2-patch-v%APP_VER%.zip"
echo %T_INFO% Packaging release archive %ZIP_NAME%...
del /q "%ZIP_NAME%" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path 'chrome-mv2-patch.exe' -DestinationPath '%ZIP_NAME%' -Force"
if errorlevel 1 (
    echo %T_WARN% Failed to create %ZIP_NAME%. The exe built fine; is PowerShell available?
) else (
    echo %T_OK% Release archive ready: %C_BLD%%ZIP_NAME%%C_RST%
)

echo.
echo %C_CYN%===================================================%C_RST%
echo %T_DONE% Build process completed successfully!
echo %C_CYN%===================================================%C_RST%

endlocal
