#!/bin/bash

# fsociety Terminal Launcher for macOS
# Make sure we're in the parent directory
cd "$(dirname "$0")/.."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required. Please install it first."
    echo "You can install it from: https://www.python.org/downloads/"
    read -p "Press Enter to exit..."
    exit 1
fi

# Install dependencies if needed
if ! python3 -c "import cv2" &> /dev/null; then
    echo "Installing required dependencies..."
    pip3 install opencv-python numpy
fi

# Launch the terminal
echo "Launching fsociety terminal..."
python3 We_See_You.py "$@"