#!/bin/bash

echo "Building fsociety terminal for macOS..."
echo ""

# Go to parent directory
cd "$(dirname "$0")/.."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed. Please install Python 3."
    exit 1
fi

# Install required packages
echo "Installing required packages..."
pip3 install pyinstaller opencv-python numpy

# Create the executable
echo "Creating macOS executable..."
pyinstaller --onefile --name "fsociety-terminal" --add-data "text_config.json:." We_See_You.py

# Make executable runnable
chmod +x dist/fsociety-terminal

echo ""
echo "Build complete! Check the 'dist' folder for fsociety-terminal"
echo "You can run it with: ./dist/fsociety-terminal" 
