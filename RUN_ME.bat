@echo off
title We See You
echo Starting We See You...
echo.

REM Check if executable exists
if exist "dist\We_See_You.exe" (
    echo Running from dist folder...
    dist\We_See_You.exe
) else if exist "We_See_You.exe" (
    echo Running from current folder...
    We_See_You.exe
) else (
    echo ERROR: We_See_You.exe not found!
    echo Please build the executable first using build_exe.bat
    pause
    exit
)

pause