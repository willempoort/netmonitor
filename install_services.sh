#!/bin/bash
# Install all NetMonitor services (main monitor, feed update, MCP server)

set -e  # Exit on error

echo "========================================="
echo "NetMonitor Services Installation"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Please run as root (sudo)"
    exit 1
fi

# Get the absolute path of the netmonitor directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
MCP_SERVER_DIR="${SCRIPT_DIR}/mcp_server"

echo "NetMonitor directory: ${SCRIPT_DIR}"
echo ""

# Verify main files exist
if [ ! -f "${SCRIPT_DIR}/netmonitor.py" ]; then
    echo "⚠️  Warning: netmonitor.py not found at ${SCRIPT_DIR}/netmonitor.py"
    echo "Main NetMonitor service will be skipped."
    SKIP_MAIN=true
fi

if [ ! -f "${SCRIPT_DIR}/update_feeds.py" ]; then
    echo "⚠️  Warning: update_feeds.py not found at ${SCRIPT_DIR}/update_feeds.py"
    echo "Feed update service will be skipped."
    SKIP_FEED=true
fi

if [ ! -f "${MCP_SERVER_DIR}/server.py" ]; then
    echo "⚠️  Warning: server.py not found at ${MCP_SERVER_DIR}/server.py"
    echo "MCP server service will be skipped."
    SKIP_MCP=true
fi

# Check if virtual environment exists
if [ ! -d "${VENV_DIR}" ]; then
    echo "⚠️  Virtual environment not found at ${VENV_DIR}"
    echo ""
    echo "NetMonitor requires a Python virtual environment with all dependencies."
    echo "Do you want to create it now? This will:"
    echo "  - Create a venv at ${VENV_DIR}"
    echo "  - Install all Python dependencies (scapy, flask, MCP, etc.)"
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
        echo "❌ Cannot install services without virtual environment."
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

# Service installation function
install_service() {
    local SERVICE_NAME=$1
    local SERVICE_FILE=$2

    echo "Installing ${SERVICE_NAME}..."
    cp "${SERVICE_FILE}" /etc/systemd/system/
    chmod 644 /etc/systemd/system/$(basename "${SERVICE_FILE}")
    echo "✓ ${SERVICE_NAME} installed"
}

# Generate service files with correct paths
echo "Step 1: Generating service files with correct paths..."
echo ""

# 1. Main NetMonitor service
if [ -z "$SKIP_MAIN" ]; then
    cat > /etc/systemd/system/netmonitor.service <<EOF
[Unit]
Description=Network Monitor - Verdacht Verkeer Detectie
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_PYTHON} ${SCRIPT_DIR}/netmonitor.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/systemd/system/netmonitor.service
    echo "✓ netmonitor.service created"
else
    echo "⊘ netmonitor.service skipped (file not found)"
fi

# 2. Feed Update service
if [ -z "$SKIP_FEED" ]; then
    cat > /etc/systemd/system/netmonitor-feed-update.service <<EOF
[Unit]
Description=Network Monitor - Threat Feed Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_PYTHON} ${SCRIPT_DIR}/update_feeds.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/systemd/system/netmonitor-feed-update.service
    echo "✓ netmonitor-feed-update.service created"

    # Copy timer (no paths to replace)
    if [ -f "${SCRIPT_DIR}/netmonitor-feed-update.timer" ]; then
        cp "${SCRIPT_DIR}/netmonitor-feed-update.timer" /etc/systemd/system/
        chmod 644 /etc/systemd/system/netmonitor-feed-update.timer
        echo "✓ netmonitor-feed-update.timer installed"
    fi
else
    echo "⊘ netmonitor-feed-update.service skipped (file not found)"
fi

# 3. MCP Server service
if [ -z "$SKIP_MCP" ]; then
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
    echo "✓ netmonitor-mcp.service created"
else
    echo "⊘ netmonitor-mcp.service skipped (file not found)"
fi

echo ""
echo "Step 2: Reloading systemd..."
systemctl daemon-reload

echo ""
echo "Step 3: Which services do you want to enable and start?"
echo ""

# Ask for each service
if [ -z "$SKIP_MAIN" ]; then
    read -p "Enable and start netmonitor.service? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        systemctl enable netmonitor.service
        systemctl start netmonitor.service
        echo "✓ netmonitor.service enabled and started"
    fi
    echo ""
fi

if [ -z "$SKIP_FEED" ]; then
    read -p "Enable and start netmonitor-feed-update.timer? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        systemctl enable netmonitor-feed-update.timer
        systemctl start netmonitor-feed-update.timer
        echo "✓ netmonitor-feed-update.timer enabled and started"
    fi
    echo ""
fi

if [ -z "$SKIP_MCP" ]; then
    read -p "Enable and start netmonitor-mcp.service? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        systemctl enable netmonitor-mcp.service
        systemctl start netmonitor-mcp.service
        echo "✓ netmonitor-mcp.service enabled and started"
    fi
    echo ""
fi

echo ""
echo "========================================="
echo "✓ NetMonitor Services Installation Complete"
echo "========================================="
echo ""
echo "Service Status:"
echo ""

if [ -z "$SKIP_MAIN" ]; then
    echo "--- NetMonitor Main ---"
    systemctl status netmonitor.service --no-pager -l || true
    echo ""
fi

if [ -z "$SKIP_FEED" ]; then
    echo "--- Feed Update Timer ---"
    systemctl status netmonitor-feed-update.timer --no-pager -l || true
    echo ""
fi

if [ -z "$SKIP_MCP" ]; then
    echo "--- MCP Server ---"
    systemctl status netmonitor-mcp.service --no-pager -l || true
    echo ""
fi

echo ""
echo "Useful commands:"
echo ""
echo "NetMonitor Main:"
echo "  Start:   sudo systemctl start netmonitor"
echo "  Stop:    sudo systemctl stop netmonitor"
echo "  Restart: sudo systemctl restart netmonitor"
echo "  Status:  sudo systemctl status netmonitor"
echo "  Logs:    sudo journalctl -u netmonitor -f"
echo ""
echo "Feed Update:"
echo "  Status:  sudo systemctl status netmonitor-feed-update.timer"
echo "  Logs:    sudo journalctl -u netmonitor-feed-update -f"
echo "  Manual:  sudo systemctl start netmonitor-feed-update.service"
echo ""
echo "MCP Server:"
echo "  Start:   sudo systemctl start netmonitor-mcp"
echo "  Stop:    sudo systemctl stop netmonitor-mcp"
echo "  Restart: sudo systemctl restart netmonitor-mcp"
echo "  Status:  sudo systemctl status netmonitor-mcp"
echo "  Logs:    sudo journalctl -u netmonitor-mcp -f"
echo "  Health:  curl http://localhost:3000/health"
echo ""
