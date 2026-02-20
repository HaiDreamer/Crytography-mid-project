#!/bin/bash

# HTTPS Server Startup Script
# Runs the Secure Banking Application with TLS

echo "=================================="
echo "Starting Secure Banking App"
echo "=================================="
echo ""

# Check if we're in the correct directory
if [ ! -f "app/main.py" ]; then
    echo "Error: Must run from bank-secure/ directory"
    echo "Current directory: $(pwd)"
    exit 1
fi

# Check if certificates exist
if [ ! -f "cert.pem" ] || [ ! -f "key.pem" ]; then
    echo "TLS certificates not found!"
    echo ""
    echo "Generate certificates first:"
    echo "  bash scripts/gen_local_certs.sh"
    echo ""
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed"
    exit 1
fi

# Check if required packages are installed
echo "Checking dependencies..."
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Flask not installed"
    echo "Install with: pip install -r requirements.txt"
    exit 1
fi

python3 -c "import bcrypt" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "bcrypt not installed"
    echo "Install with: pip install -r requirements.txt"
    exit 1
fi

echo "✓ All dependencies installed"
echo ""

# Set PYTHONPATH to include current directory
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Run the application
echo "Starting server..."
echo ""
python3 app/main.py