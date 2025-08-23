@echo off
echo Building We See You executable...
echo.

REM Install PyInstaller if not already installed
pip install pyinstaller

REM Go to parent directory and build
cd ..
pyinstaller --onefile --name "We_See_You" --add-data "text_config.json;." We_See_You.py
cd windows

echo.
echo Build complete! Check the '../dist' folder for We_See_You.exe
pause