@echo off
echo =======================================
echo    CONAN Ultimate Test - mal_05 Builder
echo =======================================
echo.
echo Compiling the ultimate stress test...
echo This will create the most comprehensive test executable!
echo.

REM Try Visual Studio first
where cl.exe >nul 2>&1
if %errorlevel%==0 (
    echo Using Microsoft Visual C++ Compiler (Optimized Build)
    cl mal_05.c /Fe:mal_05.exe /O2 /GL /link kernel32.lib user32.lib advapi32.lib psapi.lib /LTCG
    goto success
)

REM Try GCC with full optimizations
where gcc.exe >nul 2>&1
if %errorlevel%==0 (
    echo Using GCC with full optimizations
    gcc -O3 -fomit-frame-pointer -ffast-math -march=native mal_05.c -o mal_05.exe -lkernel32 -luser32 -ladvapi32 -lpsapi
    goto success
)

echo ERROR: No suitable C compiler found!
echo Please install Visual Studio or MinGW-w64
echo.
echo mal_05.exe requires advanced compiler features:
echo - Inline assembly support
echo - Windows API linking
echo - Optimization capabilities
pause
exit /b 1

:success
echo.
echo Cleaning up build artifacts...
del *.obj *.ilk *.pdb >nul 2>&1

echo.
echo =======================================
echo    ULTIMATE TEST BUILD COMPLETED!
echo =======================================
echo.
echo mal_05.exe statistics:
dir mal_05.exe
echo.
echo This executable contains 60+ anti-reversing techniques:
echo - 10+ Anti-Debug methods
echo - 15+ VM Detection techniques  
echo - 20+ Obfuscation/Packing methods
echo - 15+ Anti-Disassembly tricks
echo.
echo Ready to stress-test CONAN framework!
echo Run: python CONAN.pyw and load mal_05.exe
echo.
pause