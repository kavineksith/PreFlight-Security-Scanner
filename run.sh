#!/bin/bash

# PreFlight Security Scanner - Launcher Script
# Educational use only

echo "🔒 PreFlight Security Scanner"
echo "================================"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update requirements
echo "📦 Installing dependencies..."
pip install -q -r requirements.txt

# Run the scanner
if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh <target_url> [options]"
    echo ""
    echo "Examples:"
    echo "  ./run.sh https://staging.app.com"
    echo "  ./run.sh https://staging.app.com --login-url /login --username admin --password admin123"
    echo "  ./run.sh https://staging.app.com --api-base https://api.staging.app.com/v1"
    echo ""
    exit 1
fi

python3 preflight.py "$@"

# Deactivate virtual environment
deactivate