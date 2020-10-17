set SOLUTION_DIR=%1
set PLATFORM_ARG=%2
set CONFIGURATION_ARG=%3
set CXPLAT_BUILD_DIR=%SOLUTION_DIR%\build\winkernel\%PLATFORM_ARG%_%CONFIGURATION_ARG%_schannel

mkdir %CXPLAT_BUILD_DIR%\inc
mc.exe -um -h %CXPLAT_BUILD_DIR%\inc -r %CXPLAT_BUILD_DIR%\inc %SOLUTION_DIR%\src\manifest\CxPlatEtw.man

clog --installDirectory %SOLUTION_DIR%\build\clog

cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat %CXPLAT_BUILD_DIR% %SOLUTION_DIR% %SOLUTION_DIR%\src\platform PLATFORM
