@echo off
echo Building We See You executable...
echo.

REM Install PyInstaller if not already installed
pip install pyinstaller

REM Create the executable
pyinstaller --onefile --noconsole --name "We_See_You" --icon=icon.ico We_See_You.py

echo.
echo Build complete! Check the 'dist' folder for We_See_You.exe
pause