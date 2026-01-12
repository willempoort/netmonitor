#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
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

# Load database credentials from .env, environment, or defaults
DB_HOST="${DB_HOST:-${NETMONITOR_DB_HOST:-localhost}}"
DB_PORT="${DB_PORT:-${NETMONITOR_DB_PORT:-5432}}"
DB_NAME="${DB_NAME:-${NETMONITOR_DB_NAME:-netmonitor}}"
DB_USER="${DB_USER:-${NETMONITOR_DB_USER:-netmonitor}}"
DB_PASSWORD="${DB_PASSWORD:-${NETMONITOR_DB_PASSWORD:-netmonitor}}"

echo "Database configuration:"
echo "  Host:     $DB_HOST"
echo "  Port:     $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User:     $DB_USER"
echo ""

# Step 1: Check database schema (auto-created by NetMonitor)
echo "Step 1: Checking database schema for API tokens..."
echo ""
echo "ℹ️  MCP API schema is now auto-managed by database.py"
echo "   Tables are created automatically when NetMonitor starts."
echo ""

# Verify tables exist
TABLES_EXIST=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('mcp_api_tokens', 'mcp_api_token_usage')")

if [ "$TABLES_EXIST" -eq 2 ]; then
    echo "✅ MCP API tables exist"
else
    echo "⚠️  MCP API tables not found"
    echo "   They will be created automatically when NetMonitor starts."
    echo "   Or start netmonitor service now: sudo systemctl start netmonitor"
fi

echo ""

# Step 2: Install Python dependencies
echo "Step 2: Installing/updating Python dependencies..."
echo ""

# Check if Python virtual environment exists
if [ -d "$NETMONITOR_DIR/venv" ]; then
    PYTHON="$NETMONITOR_DIR/venv/bin/python"
    PIP="$NETMONITOR_DIR/venv/bin/pip"
    VENV_DIR="$NETMONITOR_DIR/venv"
    echo "Using virtual environment: $NETMONITOR_DIR/venv"
elif [ -d "$SCRIPT_DIR/venv" ]; then
    PYTHON="$SCRIPT_DIR/venv/bin/python"
    PIP="$SCRIPT_DIR/venv/bin/pip"
    VENV_DIR="$SCRIPT_DIR/venv"
    echo "Using virtual environment: $SCRIPT_DIR/venv"
else
    PYTHON="python3"
    PIP="pip3"
    VENV_DIR=""
    echo "⚠️  WARNING: No virtual environment found!"
    echo "Using system Python: $PYTHON"
    echo ""
    echo "It is HIGHLY RECOMMENDED to use a virtual environment."
    echo "Run this first:"
    echo "  cd $NETMONITOR_DIR"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo ""
    read -p "Continue with system Python? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Setup cancelled. Please create a virtual environment first."
        exit 1
    fi
fi

# Install/upgrade dependencies
echo ""
echo "Installing dependencies from requirements.txt..."
$PIP install --upgrade pip
$PIP install -r "$SCRIPT_DIR/requirements.txt"

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    echo "Try manually:"
    if [ -n "$VENV_DIR" ]; then
        echo "  source $VENV_DIR/bin/activate"
    fi
    echo "  pip install -r $SCRIPT_DIR/requirements.txt"
    exit 1
fi

echo ""

# Step 3: Create initial admin token
echo "Step 3: Creating initial admin API token..."
echo ""

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

# Step 4: Install systemd service (if running as root)
if [ "$INSTALL_SERVICE" = true ]; then
    echo "Step 4: Installing systemd service..."
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
