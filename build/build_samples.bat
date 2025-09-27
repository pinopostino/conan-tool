@echo off
echo =======================================
echo    CONAN Test Samples Builder
echo =======================================
echo.
echo Compiling test samples...
echo.

REM Controlla se cl.exe (Visual Studio) è disponibile
where cl.exe >nul 2>&1
if %errorlevel%==0 (
    echo Using Microsoft Visual C++ Compiler
    cl mal_01.c /Fe:mal_01.exe /link kernel32.lib user32.lib
    cl mal_02.c /Fe:mal_02.exe /link kernel32.lib user32.lib  
    cl mal_03.c /Fe:mal_03.exe /link kernel32.lib user32.lib advapi32.lib
    cl mal_04.c /Fe:mal_04.exe /link kernel32.lib user32.lib
    goto cleanup
)

REM Controlla se gcc (MinGW) è disponibile
where gcc.exe >nul 2>&1
if %errorlevel%==0 (
    echo Using GCC (MinGW)
    gcc mal_01.c -o mal_01.exe -lkernel32 -luser32
    gcc mal_02.c -o mal_02.exe -lkernel32 -luser32
    gcc mal_03.c -o mal_03.exe -lkernel32 -luser32 -ladvapi32
    gcc mal_04.c -o mal_04.exe -lkernel32 -luser32
    goto cleanup
)

echo ERROR: No C compiler found!
echo Please install Visual Studio or MinGW-w64
pause
exit /b 1

:cleanup
echo.
echo Cleaning up object files...
del *.obj *.ilk *.pdb >nul 2>&1

echo.
echo =======================================
echo    Build completed!
echo =======================================
echo.
echo Generated test samples:
dir *.exe
echo.
echo Test samples ready for CONAN analysis!
pause