#!/bin/bash

# PreFlight Security Scanner v2.0 (Enterprise) - Launcher Script
# Warning: Ensure you have authorization before scanning target infrastructures.

echo -e "\033[1;36m"
echo "=================================================="
echo " 🛡️  PreFlight Security Scanner v2.0 Enterprise"
echo "=================================================="
echo -e "\033[0m"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Determine the correct virtual environment folder (.venv is preferred, fallback to venv)
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    if [ -d "venv" ]; then
        VENV_DIR="venv"
    else
        echo "📦 Creating virtual environment ($VENV_DIR)..."
        python3 -m venv $VENV_DIR
    fi
fi

# Activate virtual environment securely based on OS
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    source $VENV_DIR/Scripts/activate
else
    source $VENV_DIR/bin/activate
fi

# Install/update requirements automatically
echo "📦 Verifying dependencies..."
pip install -q -r requirements.txt

# Display usage if no arguments provided
if [ $# -eq 0 ]; then
    echo -e "\033[1;33mUsage:\033[0m ./run.sh <target_url> [options]"
    echo ""
    echo -e "\033[1;32mExamples:\033[0m"
    echo "  ./run.sh https://staging.app.com --mode full"
    echo "  ./run.sh https://staging.app.com --update-payloads --mode full           # Syncs SecLists payloads"
    echo "  ./run.sh https://staging.app.com --severity-threshold CRITICAL           # Fails on Critical vulns"
    echo "  ./run.sh https://staging.app.com --login-url /auth --username u --password p"
    echo ""
    echo -e "Use \033[1;36m./run.sh -h\033[0m for all arguments."
    
    # Deactivate before exiting
    deactivate
    exit 1
fi

# Execute the main orchestrator script with threaded execution
python3 preflight.py "$@"

EXIT_CODE=$?

# Deactivate virtual environment
deactivate

# Pass through the python exit code for CI/CD pipelines
exit $EXIT_CODE