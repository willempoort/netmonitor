#!/bin/bash
# Install NetMonitor MCP Server as systemd service

set -e  # Exit on error

echo "========================================="
echo "NetMonitor MCP Service Installation"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Please run as root (sudo)"
    exit 1
fi

# Get the absolute path of the netmonitor directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_SERVER_DIR="${SCRIPT_DIR}/mcp_server"
VENV_DIR="${SCRIPT_DIR}/venv"

echo "NetMonitor directory: ${SCRIPT_DIR}"
echo "MCP server directory: ${MCP_SERVER_DIR}"
echo ""

# Verify paths exist
if [ ! -f "${MCP_SERVER_DIR}/server.py" ]; then
    echo "❌ Error: server.py not found at ${MCP_SERVER_DIR}/server.py"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "${VENV_DIR}" ]; then
    echo "⚠️  Virtual environment not found at ${VENV_DIR}"
    echo ""
    echo "The MCP server requires a Python virtual environment with all dependencies."
    echo "Do you want to create it now? This will:"
    echo "  - Create a venv at ${VENV_DIR}"
    echo "  - Install all Python dependencies (MCP, psycopg2, etc.)"
    echo ""
    read -p "Create virtual environment now? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        echo ""
        echo "Running setup_venv.sh as current user..."
        # Run as the original user (not root)
        ORIGINAL_USER="${SUDO_USER:-$USER}"
        sudo -u "$ORIGINAL_USER" bash "${SCRIPT_DIR}/setup_venv.sh"
        echo ""
        echo "Virtual environment setup complete. Continuing with service installation..."
        echo ""
    else
        echo ""
        echo "❌ Cannot install service without virtual environment."
        echo "Please run: ./setup_venv.sh first, then try again."
        exit 1
    fi
fi

# Verify venv Python exists
VENV_PYTHON="${VENV_DIR}/bin/python3"
if [ ! -f "${VENV_PYTHON}" ]; then
    echo "❌ Error: Python not found in venv at ${VENV_PYTHON}"
    echo "Please run: ./setup_venv.sh first"
    exit 1
fi

echo "Using Python from venv: ${VENV_PYTHON}"
echo ""

echo "Step 1: Generating service file with correct paths..."
cat > /etc/systemd/system/netmonitor-mcp.service <<EOF
[Unit]
Description=NetMonitor MCP Server (SSE/HTTP)
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=${MCP_SERVER_DIR}
Environment="NETMONITOR_DB_HOST=localhost"
Environment="NETMONITOR_DB_PORT=5432"
Environment="NETMONITOR_DB_NAME=netmonitor"
Environment="NETMONITOR_DB_USER=mcp_readonly"
Environment="NETMONITOR_DB_PASSWORD=mcp_netmonitor_readonly_2024"
ExecStart=${VENV_PYTHON} ${MCP_SERVER_DIR}/server.py --transport sse --host 0.0.0.0 --port 3000
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netmonitor-mcp

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/netmonitor-mcp.service
echo "✓ Service file created: /etc/systemd/system/netmonitor-mcp.service"

echo "Step 2: Reloading systemd..."
systemctl daemon-reload

echo "Step 3: Enabling service (auto-start on boot)..."
systemctl enable netmonitor-mcp.service

echo "Step 4: Starting service..."
systemctl start netmonitor-mcp.service

echo ""
echo "========================================="
echo "✓ MCP Service Installation Complete"
echo "========================================="
echo ""
echo "Service status:"
systemctl status netmonitor-mcp.service --no-pager -l

echo ""
echo "Useful commands:"
echo "  Start:   sudo systemctl start netmonitor-mcp"
echo "  Stop:    sudo systemctl stop netmonitor-mcp"
echo "  Restart: sudo systemctl restart netmonitor-mcp"
echo "  Status:  sudo systemctl status netmonitor-mcp"
echo "  Logs:    sudo journalctl -u netmonitor-mcp -f"
echo "  Disable: sudo systemctl disable netmonitor-mcp"
echo ""
