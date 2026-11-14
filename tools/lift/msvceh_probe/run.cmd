@echo off
rem MSVC exception handling, end to end: compile ehprobe.cpp with MSVC (x86,
rem /O2, static CRT), catalog it with disasm32, lift it, build it on
rem native32 and run it. Prints PASS/FAIL per case and N/N; exits 0 when all
rem pass. Needs Visual Studio 2022 (C++ x86 tools) and Python with capstone.
rem Everything it makes goes in work\ (gitignored).
setlocal
cd /d "%~dp0"
set "R=%~dp0..\..\.."
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VS=%%i"
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul || exit /b 1
if not exist work mkdir work
cl /nologo /O2 /MT /EHsc /GS- /Fowork\ /Fework\ehprobe.exe ehprobe.cpp /link /FIXED /BASE:0x400000 /DYNAMICBASE:NO >work\build.log || exit /b 1
work\ehprobe.exe >nul || (echo the probe fails natively & exit /b 1)
python "%R%\tools\disasm\disasm32.py" work\ehprobe.exe -o work\functions.json >work\disasm.log || exit /b 1
python lift.py --all --out work\gen --seeds none >work\lift.log || exit /b 1
set "P=%R%\runtime"
cl /nologo /w /O1 /MT /DRECOMP_RETADDR=0u /DRECOMP_FLAT_MEMORY /DRECOMP_LOCAL_REGS /D_CRT_SECURE_NO_WARNINGS ^
   /I. /Iwork\gen /I"%P%\native32" /I"%P%\recomp32" /Fowork\ /Fework\host.exe host.c work\gen\*.c ^
   "%P%\native32\native32.c" "%P%\recomp32\image_loader.c" "%P%\recomp32\recomp_trace.c" user32.lib gdi32.lib ole32.lib ^
   /link /BASE:0x60000000 /FIXED:NO /DYNAMICBASE:NO /NXCOMPAT /STACK:0x1000000 >>work\build.log || exit /b 1
work\host.exe "%~dp0work\ehprobe.exe"
