#!/bin/bash
# Install NetMonitor MCP Server as systemd service

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

echo "NetMonitor directory: ${SCRIPT_DIR}"
echo "MCP server directory: ${MCP_SERVER_DIR}"
echo ""

# Verify paths exist
if [ ! -f "${MCP_SERVER_DIR}/server.py" ]; then
    echo "❌ Error: server.py not found at ${MCP_SERVER_DIR}/server.py"
    exit 1
fi

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
ExecStart=/usr/bin/python3 ${MCP_SERVER_DIR}/server.py --transport sse --host 0.0.0.0 --port 3000
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
