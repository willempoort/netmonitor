#!/bin/bash
# Setup Python virtual environment for NetMonitor

set -e  # Exit on error

echo "========================================="
echo "NetMonitor Python Virtual Environment Setup"
echo "========================================="
echo ""

# Get the absolute path of the netmonitor directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"

echo "NetMonitor directory: ${SCRIPT_DIR}"
echo "Virtual environment will be created at: ${VENV_DIR}"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found. Please install Python 3 first."
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Using: ${PYTHON_VERSION}"
echo ""

# Check if venv already exists
if [ -d "${VENV_DIR}" ]; then
    echo "⚠️  Virtual environment already exists at ${VENV_DIR}"
    read -p "Do you want to recreate it? This will delete the existing venv. (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing venv..."
        rm -rf "${VENV_DIR}"
    else
        echo "Keeping existing venv. Exiting."
        exit 0
    fi
fi

# Create virtual environment
echo "Step 1: Creating virtual environment..."
python3 -m venv "${VENV_DIR}"
echo "✓ Virtual environment created"
echo ""

# Activate venv
source "${VENV_DIR}/bin/activate"

# Upgrade pip
echo "Step 2: Upgrading pip..."
pip install --upgrade pip
echo "✓ pip upgraded"
echo ""

# Install dependencies
echo "Step 3: Installing NetMonitor dependencies..."
echo ""

echo "Installing core dependencies..."
pip install scapy psycopg2-binary flask python-dateutil

echo ""
echo "Installing MCP server dependencies..."
cd "${SCRIPT_DIR}/mcp_server"
pip install -r requirements.txt

echo ""
echo "✓ All dependencies installed"
echo ""

# Create activation helper script
echo "Step 4: Creating activation helper..."
cat > "${SCRIPT_DIR}/activate_venv.sh" <<'EOF'
#!/bin/bash
# Helper script to activate NetMonitor virtual environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/venv/bin/activate"
echo "✓ NetMonitor virtual environment activated"
echo "Python: $(which python3)"
echo "To deactivate, run: deactivate"
EOF
chmod +x "${SCRIPT_DIR}/activate_venv.sh"
echo "✓ Activation helper created: ${SCRIPT_DIR}/activate_venv.sh"
echo ""

# Show summary
echo "========================================="
echo "✓ Virtual Environment Setup Complete"
echo "========================================="
echo ""
echo "Virtual environment location: ${VENV_DIR}"
echo "Python executable: ${VENV_DIR}/bin/python3"
echo ""
echo "To activate the virtual environment:"
echo "  source ${SCRIPT_DIR}/activate_venv.sh"
echo ""
echo "Or manually:"
echo "  source ${VENV_DIR}/bin/activate"
echo ""
echo "To test MCP server:"
echo "  source ${VENV_DIR}/bin/activate"
echo "  cd ${SCRIPT_DIR}/mcp_server"
echo "  python3 server.py --help"
echo ""
echo "Next steps:"
echo "  1. Run: sudo ./install_mcp_service.sh"
echo "     (This will use the venv Python automatically)"
echo ""
