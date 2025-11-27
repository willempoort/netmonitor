#!/bin/bash
# Setup script for MCP HTTP API Server
# This script:
# 1. Creates the database schema for API tokens
# 2. Creates an initial admin token
# 3. Sets up the systemd service (optional)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETMONITOR_DIR="$(dirname "$SCRIPT_DIR")"

echo "=================================================="
echo "MCP HTTP API Server Setup"
echo "=================================================="
echo ""

# Check if running as root for systemd service installation
if [ "$EUID" -eq 0 ]; then
    INSTALL_SERVICE=true
    echo "Running as root - will install systemd service"
else
    INSTALL_SERVICE=false
    echo "Running as user - skipping systemd service installation"
    echo "(Run with sudo to install systemd service)"
fi

echo ""

# Load database credentials from environment or config
DB_HOST="${NETMONITOR_DB_HOST:-localhost}"
DB_PORT="${NETMONITOR_DB_PORT:-5432}"
DB_NAME="${NETMONITOR_DB_NAME:-netmonitor}"
DB_USER="${NETMONITOR_DB_USER:-netmonitor}"
DB_PASSWORD="${NETMONITOR_DB_PASSWORD:-netmonitor}"

echo "Database configuration:"
echo "  Host:     $DB_HOST"
echo "  Port:     $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User:     $DB_USER"
echo ""

# Step 1: Create database schema
echo "Step 1: Creating database schema for API tokens..."
echo ""

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -f "$SCRIPT_DIR/schema_api_tokens.sql"

if [ $? -eq 0 ]; then
    echo "✅ Database schema created successfully"
else
    echo "❌ Failed to create database schema"
    exit 1
fi

echo ""

# Step 2: Create initial admin token
echo "Step 2: Creating initial admin API token..."
echo ""

# Check if Python virtual environment exists
if [ -d "$NETMONITOR_DIR/venv" ]; then
    PYTHON="$NETMONITOR_DIR/venv/bin/python"
    echo "Using virtual environment: $NETMONITOR_DIR/venv"
elif [ -d "$SCRIPT_DIR/venv" ]; then
    PYTHON="$SCRIPT_DIR/venv/bin/python"
    echo "Using virtual environment: $SCRIPT_DIR/venv"
else
    PYTHON="python3"
    echo "Using system Python: $PYTHON"
fi

# Export database credentials
export NETMONITOR_DB_HOST="$DB_HOST"
export NETMONITOR_DB_PORT="$DB_PORT"
export NETMONITOR_DB_NAME="$DB_NAME"
export NETMONITOR_DB_USER="$DB_USER"
export NETMONITOR_DB_PASSWORD="$DB_PASSWORD"

# Create admin token
echo ""
echo "Creating admin token..."
$PYTHON "$SCRIPT_DIR/manage_tokens.py" create \
    --name "Initial Admin Token" \
    --description "Created during setup - full admin access" \
    --scope admin \
    --rate-minute 120 \
    --rate-hour 5000 \
    --rate-day 50000 \
    --created-by "setup_script"

echo ""

# Step 3: Install systemd service (if running as root)
if [ "$INSTALL_SERVICE" = true ]; then
    echo "Step 3: Installing systemd service..."
    echo ""

    SERVICE_FILE="/etc/systemd/system/netmonitor-mcp-http.service"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=NetMonitor MCP HTTP API Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$NETMONITOR_DIR
Environment="NETMONITOR_DB_HOST=$DB_HOST"
Environment="NETMONITOR_DB_PORT=$DB_PORT"
Environment="NETMONITOR_DB_NAME=$DB_NAME"
Environment="NETMONITOR_DB_USER=$DB_USER"
Environment="NETMONITOR_DB_PASSWORD=$DB_PASSWORD"
Environment="CORS_ORIGINS=*"
ExecStart=$PYTHON $SCRIPT_DIR/http_server.py --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    echo "✅ Systemd service file created: $SERVICE_FILE"
    echo ""

    # Reload systemd
    systemctl daemon-reload
    echo "✅ Systemd daemon reloaded"
    echo ""

    # Enable service
    systemctl enable netmonitor-mcp-http.service
    echo "✅ Service enabled (will start on boot)"
    echo ""

    echo "To start the service now:"
    echo "  sudo systemctl start netmonitor-mcp-http"
    echo ""
    echo "To view service status:"
    echo "  sudo systemctl status netmonitor-mcp-http"
    echo ""
    echo "To view logs:"
    echo "  sudo journalctl -u netmonitor-mcp-http -f"
else
    echo "Step 3: Skipping systemd service installation (not root)"
    echo ""
    echo "To install the systemd service, run this script with sudo:"
    echo "  sudo $0"
fi

echo ""
echo "=================================================="
echo "Setup Complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Start the MCP HTTP API server:"
if [ "$INSTALL_SERVICE" = true ]; then
    echo "   sudo systemctl start netmonitor-mcp-http"
else
    echo "   $PYTHON $SCRIPT_DIR/http_server.py"
fi
echo ""
echo "2. Test the API:"
echo "   curl http://localhost:8000/health"
echo ""
echo "3. List your API tokens:"
echo "   $PYTHON $SCRIPT_DIR/manage_tokens.py list"
echo ""
echo "4. View API documentation:"
echo "   http://localhost:8000/docs"
echo ""
echo "5. Configure your AI client to use the token"
echo ""
echo "=================================================="
