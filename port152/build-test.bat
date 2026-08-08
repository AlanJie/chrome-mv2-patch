@echo off
setlocal
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VSP=%%i"
if not defined VSP set "VSP=C:\Program Files\Microsoft Visual Studio\18\Community"
call "%VSP%\VC\Auxiliary\Build\vcvars64.bat" >nul
cl.exe /nologo /O2 /EHsc /std:c++17 /W3 /D_CRT_SECURE_NO_WARNINGS /DMV2_TEST_NO_ELEVATION chrome-mv2-patch.cpp /Fe:mv2-test.exe /link shell32.lib user32.lib advapi32.lib version.lib rstrtmgr.lib
del /q chrome-mv2-patch.obj 2>nul
endlocal
