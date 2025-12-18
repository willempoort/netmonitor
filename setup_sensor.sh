#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# NetMonitor Sensor Complete Installation Script
# - Creates Python venv
# - Generates sensor.conf from user input
# - Installs systemd service
# - Starts and enables service

set -e

# Configuration
INSTALL_DIR="/opt/netmonitor"
VENV_DIR="$INSTALL_DIR/venv"
CONF_FILE="$INSTALL_DIR/sensor.conf"
SERVICE_FILE="/etc/systemd/system/netmonitor-sensor.service"
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================"
echo "   NetMonitor Sensor Installation"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if already installed
if [ -f "$CONF_FILE" ]; then
    echo -e "${YELLOW}⚠️  WARNING: NetMonitor sensor already installed at $INSTALL_DIR${NC}"
    read -p "Reinstall and reconfigure? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    echo ""

    # Stop existing service
    if systemctl is-active --quiet netmonitor-sensor; then
        echo "Stopping existing service..."
        systemctl stop netmonitor-sensor
    fi
fi

# Function to prompt for input with default
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"

    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " value
        value=${value:-$default}
    else
        read -p "$prompt: " value
        while [ -z "$value" ]; do
            echo -e "  ${RED}⚠️  This field is required!${NC}"
            read -p "$prompt: " value
        done
    fi

    eval "$var_name='$value'"
}

echo "============================================"
echo "Step 1: Installation Directory Setup"
echo "============================================"
echo ""

# Create installation directory if needed
if [ "$CURRENT_DIR" != "$INSTALL_DIR" ]; then
    echo "Current directory: $CURRENT_DIR"
    echo "Target directory:  $INSTALL_DIR"
    echo ""

    if [ -d "$INSTALL_DIR" ]; then
        echo "Installation directory already exists."
    else
        echo "Creating installation directory..."
        mkdir -p "$INSTALL_DIR"
    fi

    echo "Copying files to $INSTALL_DIR..."
    cp -r "$CURRENT_DIR"/* "$INSTALL_DIR/"
    cd "$INSTALL_DIR"
else
    echo "Already in installation directory: $INSTALL_DIR"
fi

echo -e "${GREEN}✅ Installation directory ready${NC}"
echo ""

echo "============================================"
echo "Step 2: Python Virtual Environment"
echo "============================================"
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 is not installed${NC}"
    echo "Install with: apt-get install python3 python3-pip python3-venv"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Found: $PYTHON_VERSION"

# Create virtual environment
if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment already exists, recreating..."
    rm -rf "$VENV_DIR"
fi

echo "Creating virtual environment..."
python3 -m venv "$VENV_DIR"

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

echo "Installing dependencies..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

echo -e "${GREEN}✅ Virtual environment created and dependencies installed${NC}"
echo ""

echo "============================================"
echo "Step 3: Sensor Configuration"
echo "============================================"
echo ""
echo "Please provide the following information:"
echo ""

# Network Interface
echo "1. Network Interface"
echo "   Example: eth0, eth1, ens33, wlan0"
prompt_with_default "   Interface" "eth0" INTERFACE
echo ""

# SOC Server URL
echo "2. SOC Server URL"
echo "   Example: http://soc.example.com:8080"
prompt_with_default "   SOC Server URL" "" SOC_SERVER_URL
echo ""

# Authentication (optional)
echo "3. Authentication Secret Key (optional)"
echo "   Leave empty if not using authentication"
echo "   Generate random key? [y/N]"
read -p "   " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    SENSOR_SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)
    echo "   Generated: $SENSOR_SECRET_KEY"
else
    read -p "   Secret Key (or press Enter to skip): " SENSOR_SECRET_KEY
fi
echo ""

# SSL Verification
echo "4. SSL Certificate Verification"
prompt_with_default "   SSL verification (true/false)" "true" SSL_VERIFY
echo ""

# Generate configuration file
echo "Generating $CONF_FILE..."

cat > "$CONF_FILE" <<EOF
# ============================================
# NetMonitor Sensor Configuration
# Generated: $(date)
# Installation: $INSTALL_DIR
# ============================================
#
# MINIMAL LOCAL CONFIGURATION
# Only connection settings are stored locally.
# All other configuration is managed centrally via SOC Dashboard.
#
# ============================================

# ============================================
# Required Connection Settings
# ============================================

# Network Interface (REQUIRED)
# Which network interface to monitor for packets
INTERFACE=$INTERFACE

# SOC Server URL (REQUIRED)
# The URL of your central SOC server dashboard
SOC_SERVER_URL=$SOC_SERVER_URL

# SSL Certificate Verification (OPTIONAL)
# Set to false only for testing with self-signed certificates
SSL_VERIFY=$SSL_VERIFY

# Authentication Secret Key (OPTIONAL)
# For secure sensor-to-server communication
SENSOR_SECRET_KEY=$SENSOR_SECRET_KEY

# ============================================
# All Other Settings From SOC Server
# ============================================
#
# The following are managed centrally via SOC Dashboard
# and automatically synced to sensors:
#
# SENSOR IDENTITY (for dashboard display):
#   - SENSOR_ID (auto-generated from hostname if not set)
#   - SENSOR_LOCATION (set via dashboard)
#
# PERFORMANCE SETTINGS:
#   - HEARTBEAT_INTERVAL (default: 30 seconds)
#   - CONFIG_SYNC_INTERVAL (default: 300 seconds)
#
# NETWORK CONFIGURATION:
#   - INTERNAL_NETWORKS (CIDR ranges)
#   - Whitelist / Allowlist
#
# DETECTION SETTINGS:
#   - All detection rules (13 rules)
#   - All thresholds
#   - Alert sensitivity
#   - Batch intervals
#
# Edit these via: SOC Dashboard → Configuration Management
#
# Sensors sync automatically every 5 minutes (configurable).
# Force immediate sync: systemctl restart netmonitor-sensor
#
# ============================================
EOF

chmod 600 "$CONF_FILE"  # Restrict access (contains potential secrets)

echo -e "${GREEN}✅ Configuration saved to: $CONF_FILE${NC}"
echo ""

echo "============================================"
echo "Step 4: Systemd Service Installation"
echo "============================================"
echo ""

# Create systemd service file
echo "Creating systemd service: $SERVICE_FILE"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=NetMonitor Security Sensor
Documentation=https://github.com/your-org/netmonitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR

# Load environment variables from sensor.conf
EnvironmentFile=$CONF_FILE

# Use sensor_client.py for remote sensors (not netmonitor.py which is for SOC server)
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/sensor_client.py -c $CONF_FILE

# Restart policy
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netmonitor-sensor

# Security hardening
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/netmonitor
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# Create log directory
mkdir -p /var/log/netmonitor
chmod 755 /var/log/netmonitor

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Enable service
echo "Enabling service to start on boot..."
systemctl enable netmonitor-sensor

echo -e "${GREEN}✅ Systemd service installed${NC}"
echo ""

echo "============================================"
echo "Step 5: Starting Service"
echo "============================================"
echo ""

# Start service
echo "Starting netmonitor-sensor service..."
systemctl start netmonitor-sensor

# Wait a moment for service to start
sleep 2

# Check status
if systemctl is-active --quiet netmonitor-sensor; then
    echo -e "${GREEN}✅ Service started successfully${NC}"
else
    echo -e "${RED}⚠️  Service failed to start${NC}"
    echo "Check logs with: journalctl -u netmonitor-sensor -n 50"
fi

echo ""
echo "============================================"
echo "Installation Summary"
echo "============================================"
echo "Installation Dir:   $INSTALL_DIR"
echo "Configuration:      $CONF_FILE"
echo "Virtual Env:        $VENV_DIR"
echo "Service:            $SERVICE_FILE"
echo ""
echo "Sensor Configuration:"
echo "  Interface:        $INTERFACE"
echo "  SOC Server:       $SOC_SERVER_URL"
echo "  SSL Verify:       $SSL_VERIFY"
echo "  Auth Key:         $([ -n "$SENSOR_SECRET_KEY" ] && echo "Configured" || echo "Not configured")"
echo ""
echo "Additional configuration (managed via SOC Dashboard):"
echo "  • Sensor ID & Location"
echo "  • Internal Networks"
echo "  • Detection Rules & Thresholds"
echo "  • Performance Settings"
echo "============================================"
echo ""
echo "Useful Commands:"
echo ""
echo "  Check status:     systemctl status netmonitor-sensor"
echo "  View logs:        journalctl -u netmonitor-sensor -f"
echo "  Restart:          systemctl restart netmonitor-sensor"
echo "  Stop:             systemctl stop netmonitor-sensor"
echo "  Disable:          systemctl disable netmonitor-sensor"
echo ""
echo "  Edit config:      nano $CONF_FILE"
echo "  After editing:    systemctl restart netmonitor-sensor"
echo ""
echo "  SOC Dashboard:    $SOC_SERVER_URL"
echo ""
echo -e "${GREEN}Installation complete! 🚀${NC}"
echo ""
echo "The sensor should now appear in your SOC dashboard within 30 seconds."
echo "Check the dashboard at: $SOC_SERVER_URL"
