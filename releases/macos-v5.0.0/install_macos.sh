#!/bin/bash

echo "================================================================"
echo "                    FSOCIETY TERMINAL INSTALLER"
echo "                         macOS Version"
echo "================================================================"
echo ""

# Go to parent directory first
cd "$(dirname "$0")/.."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3 from: https://www.python.org/downloads/"
    echo "Or using Homebrew: brew install python3"
    echo ""
    read -p "Press Enter to exit..."
    exit 1
fi

echo "Python 3 found! Installing dependencies..."
echo ""

# Install required packages
pip3 install opencv-python numpy pyinstaller

# Make shell scripts executable
chmod +x macos/*.sh

echo ""
echo "Installation complete!"
echo ""
echo "You can now run fsociety terminal using:"
echo "  - cd macos && ./run_macos.sh (for quick launch)"
echo "  - cd macos && ./build_macos.sh (to create executable)"
echo "  - python3 text_editor.py (to customize messages)"
echo ""
echo "================================================================"
echo "              WELCOME TO THE FSOCIETY COLLECTIVE"
echo "================================================================" 
