@echo off
title We See You
echo Starting We See You...
echo.

REM Check if executable exists in parent directory
if exist "..\dist\We_See_You.exe" (
    echo Running from dist folder...
    ..\dist\We_See_You.exe
) else if exist "..\We_See_You.exe" (
    echo Running from parent folder...
    ..\We_See_You.exe
) else (
    echo Running Python script directly...
    cd ..
    python We_See_You.py %*
    cd windows
)

pause 
