@echo off
title fsociety Terminal - Windows Installation

echo ================================================================
echo                    FSOCIETY TERMINAL INSTALLER
echo                         Windows Version
echo ================================================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

echo Python found! Installing dependencies...
echo.

pip install opencv-python numpy pyinstaller

echo.
echo Installation complete!
echo.
echo You can now run fsociety terminal using:
echo   - cd windows ^&^& RUN_ME.bat (for quick launch)
echo   - cd windows ^&^& build_exe.bat (to create executable)  
echo   - cd windows ^&^& edit_text.bat (to customize messages)
echo.
echo ================================================================
echo              WELCOME TO THE FSOCIETY COLLECTIVE
echo ================================================================
pause