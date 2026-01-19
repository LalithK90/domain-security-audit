#!/bin/bash

# Security Scanner Runner
# 
# This is the only script you need to run.
# It handles virtual environment setup, dependencies, and launches the scanner.

set -e  # Exit on error

echo "=========================================="
echo "Security Scanner"
echo "=========================================="

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "✗ Error: .env file not found"
    echo ""
    echo "Create a .env file with at minimum:"
    echo "  DOMAIN=your-domain.com"
    echo ""
    echo "Example:"
    echo "  DOMAIN=ac.lk"
    echo "  OUT_DIR=out"
    echo "  ENABLE_EXCEL=false"
    exit 1
fi

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "✗ Error: python3 not found"
    echo "Install Python 3.8 or higher"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "Python version: $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install/upgrade dependencies
if [ -f "src/requirements.txt" ]; then
    echo "Installing dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -r src/requirements.txt
else
    echo "No requirements.txt found, installing minimal dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet aiohttp python-dotenv openpyxl pandas python-dateutil
fi

echo "✓ Environment ready"
echo ""

# Run the scanner
echo "Starting scan..."
python src/app.py

# Deactivate virtual environment
deactivate
