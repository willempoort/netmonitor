#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# Setup script for MCP Streamable HTTP Server
#
# This script:
# 1. Checks database schema for API tokens
# 2. Creates an initial admin token if needed
# 3. Sets up the systemd service (optional)
# 4. Provides usage instructions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETMONITOR_DIR="$(dirname "$SCRIPT_DIR")"

echo "=================================================="
echo "NetMonitor MCP Streamable HTTP Server Setup"
echo "=================================================="
echo ""
echo "This is the NEW MCP Streamable HTTP server"
echo "Compatible with:"
echo "  ✓ Claude Desktop (Pro/Max/Team/Enterprise)"
echo "  ✓ Open-WebUI"
echo "  ✓ Any MCP-compliant client"
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

# Function to load .env file
load_env() {
    local env_file="$NETMONITOR_DIR/.env"
    if [ -f "$env_file" ]; then
        echo "Loading credentials from .env..."
        export $(grep -v '^#' "$env_file" | grep -v '^$' | xargs)
        return 0
    fi
    return 1
}

# Try to load .env file
if load_env; then
    echo "✓ Loaded configuration from .env"
else
    echo "ℹ️  No .env file found, using environment variables or defaults"
fi
echo ""

# Load database credentials
DB_HOST="${DB_HOST:-${NETMONITOR_DB_HOST:-localhost}}"
DB_PORT="${DB_PORT:-${NETMONITOR_DB_PORT:-5432}}"
DB_NAME="${DB_NAME:-${NETMONITOR_DB_NAME:-netmonitor}}"
DB_USER="${DB_USER:-${NETMONITOR_DB_USER:-netmonitor}}"
DB_PASSWORD="${DB_PASSWORD:-${NETMONITOR_DB_PASSWORD:-netmonitor}}"

echo "Configuration:"
echo "  Database: $DB_NAME@$DB_HOST:$DB_PORT"
echo "  User: $DB_USER"
echo ""

# Step 1: Check database schema
echo "Step 1: Checking database schema for API tokens..."
echo ""

TABLES_EXIST=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('mcp_api_tokens', 'mcp_api_token_usage')" 2>/dev/null || echo "0")

if [ "$TABLES_EXIST" -eq 2 ]; then
    echo "✅ MCP API tables exist"
else
    echo "⚠️  MCP API tables not found"
    echo "   They will be created automatically when NetMonitor starts."
fi

echo ""

# Step 2: Install Python dependencies
echo "Step 2: Installing/updating Python dependencies..."
echo ""

# Check if Python virtual environment exists
if [ -d "$NETMONITOR_DIR/venv" ]; then
    PYTHON="$NETMONITOR_DIR/venv/bin/python3"
    PIP="$NETMONITOR_DIR/venv/bin/pip3"
    echo "Using virtual environment: $NETMONITOR_DIR/venv"
else
    echo "❌ ERROR: No virtual environment found at $NETMONITOR_DIR/venv"
    echo ""
    echo "Create one first:"
    echo "  cd $NETMONITOR_DIR"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r mcp_server/requirements.txt"
    exit 1
fi

# Install/upgrade dependencies
echo ""
echo "Installing dependencies..."
$PIP install --upgrade pip -q
$PIP install -r "$SCRIPT_DIR/requirements.txt" -q

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""

# Step 3: Create initial admin token (if no tokens exist)
echo "Step 3: Checking for API tokens..."
echo ""

# Export database credentials
export DB_HOST="$DB_HOST"
export DB_PORT="$DB_PORT"
export DB_NAME="$DB_NAME"
export DB_USER="$DB_USER"
export DB_PASSWORD="$DB_PASSWORD"

# Check if any tokens exist
TOKEN_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -tAc "SELECT COUNT(*) FROM mcp_api_tokens WHERE enabled = true" 2>/dev/null || echo "0")

if [ "$TOKEN_COUNT" -gt 0 ]; then
    echo "✅ Found $TOKEN_COUNT existing API token(s)"
    echo ""
    echo "To list tokens:"
    echo "  $PYTHON $SCRIPT_DIR/manage_tokens.py list"
else
    echo "No API tokens found. Creating initial admin token..."
    echo ""

    $PYTHON "$SCRIPT_DIR/manage_tokens.py" create \
        --name "Initial Admin Token" \
        --description "Created during setup - full admin access" \
        --scope admin \
        --rate-minute 120 \
        --rate-hour 5000 \
        --rate-day 50000 \
        --created-by "setup_script" 2>&1

    echo ""
    echo "✅ Initial token created"
fi

echo ""

# Step 4: Install systemd service (if running as root)
if [ "$INSTALL_SERVICE" = true ]; then
    echo "Step 4: Installing systemd service..."
    echo ""

    SERVICE_FILE="/etc/systemd/system/netmonitor-mcp-streamable.service"

    # Replace __INSTALL_DIR__ in template
    sed "s|__INSTALL_DIR__|$NETMONITOR_DIR|g" \
        "$NETMONITOR_DIR/services/netmonitor-mcp-streamable.service.template" \
        > "$SERVICE_FILE"

    echo "✅ Systemd service file created: $SERVICE_FILE"
    echo ""

    # Reload systemd
    systemctl daemon-reload
    echo "✅ Systemd daemon reloaded"
    echo ""

    # Enable service
    systemctl enable netmonitor-mcp-streamable.service
    echo "✅ Service enabled (will start on boot)"
    echo ""

else
    echo "Step 4: Skipping systemd service installation (not root)"
    echo ""
    echo "To install the systemd service, run this script with sudo:"
    echo "  sudo $0"
fi

echo ""
echo "=================================================="
echo "Setup Complete!"
echo "=================================================="
echo ""
echo "📚 Full documentation:"
echo "   $SCRIPT_DIR/STREAMABLE_HTTP_README.md"
echo ""
echo "🚀 Quick start:"
echo ""
echo "1. Start the server:"
if [ "$INSTALL_SERVICE" = true ]; then
    echo "   sudo systemctl start netmonitor-mcp-streamable"
    echo "   sudo systemctl status netmonitor-mcp-streamable"
else
    echo "   $PYTHON $SCRIPT_DIR/streamable_http_server.py"
fi
echo ""
echo "2. Test the health endpoint:"
echo "   curl http://127.0.0.1:8000/health"
echo ""
echo "3. List your API tokens:"
echo "   $PYTHON $SCRIPT_DIR/manage_tokens.py list"
echo ""
echo "4. Configure Claude Desktop:"
echo "   Edit ~/.config/Claude/claude_desktop_config.json:"
echo ""
echo '   {'
echo '     "mcpServers": {'
echo '       "netmonitor": {'
echo '         "type": "streamable-http",'
echo '         "url": "http://127.0.0.1:8000/mcp",'
echo '         "headers": {'
echo '           "Authorization": "Bearer YOUR_TOKEN_HERE"'
echo '         }'
echo '       }'
echo '     }'
echo '   }'
echo ""
echo "5. Configure Open-WebUI:"
echo "   Admin → MCP Servers → Add Server"
echo "   URL: http://127.0.0.1:8000/mcp"
echo "   Token: YOUR_TOKEN_HERE"
echo ""
echo "=================================================="
