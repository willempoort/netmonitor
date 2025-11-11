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

echo "Step 1: Copying service file..."
cp /home/user/netmonitor/netmonitor-mcp.service /etc/systemd/system/
chmod 644 /etc/systemd/system/netmonitor-mcp.service

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
