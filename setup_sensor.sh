#!/bin/bash
# Interactive NetMonitor Sensor Setup Script
# Generates sensor.conf from user input

set -e

CONF_FILE="sensor.conf"
TEMPLATE_FILE="sensor.conf.template"

echo "============================================"
echo "   NetMonitor Sensor Configuration Setup"
echo "============================================"
echo ""

# Check if config already exists
if [ -f "$CONF_FILE" ]; then
    echo "⚠️  WARNING: $CONF_FILE already exists!"
    read -p "Overwrite existing configuration? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    echo ""
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
            echo "  ⚠️  This field is required!"
            read -p "$prompt: " value
        done
    fi

    eval "$var_name='$value'"
}

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

# Sensor ID
echo "3. Unique Sensor ID"
echo "   Use format: location-vlan-number (e.g., office-vlan10-01)"
prompt_with_default "   Sensor ID" "" SENSOR_ID
echo ""

# Sensor Location
echo "4. Sensor Location Description"
echo "   Example: Building A - VLAN 10 - Production Network"
prompt_with_default "   Location" "" SENSOR_LOCATION
echo ""

# Authentication (optional)
echo "5. Authentication Secret Key (optional)"
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

# Advanced settings
echo "6. Advanced Settings (press Enter for defaults)"
prompt_with_default "   Heartbeat interval (seconds)" "30" HEARTBEAT_INTERVAL
prompt_with_default "   Config sync interval (seconds)" "300" CONFIG_SYNC_INTERVAL
prompt_with_default "   SSL verification (true/false)" "true" SSL_VERIFY
echo ""

# Internal networks
echo "7. Internal Networks (comma-separated CIDR)"
prompt_with_default "   Internal networks" "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" INTERNAL_NETWORKS
echo ""

# Generate configuration file
echo "============================================"
echo "Generating $CONF_FILE..."
echo "============================================"

cat > "$CONF_FILE" <<EOF
# ============================================
# NetMonitor Sensor Configuration
# Generated: $(date)
# ============================================

# Network interface to monitor
INTERFACE=$INTERFACE

# SOC Server URL (REQUIRED)
SOC_SERVER_URL=$SOC_SERVER_URL

# Unique Sensor ID (REQUIRED)
SENSOR_ID=$SENSOR_ID

# Sensor Location Description (REQUIRED)
SENSOR_LOCATION=$SENSOR_LOCATION

# Authentication Secret Key (OPTIONAL)
SENSOR_SECRET_KEY=$SENSOR_SECRET_KEY

# ============================================
# Advanced Settings
# ============================================

# Internal networks (comma-separated CIDR ranges)
INTERNAL_NETWORKS=$INTERNAL_NETWORKS

# Heartbeat interval (seconds)
HEARTBEAT_INTERVAL=$HEARTBEAT_INTERVAL

# Config sync interval (seconds)
CONFIG_SYNC_INTERVAL=$CONFIG_SYNC_INTERVAL

# Enable SSL verification (true/false)
SSL_VERIFY=$SSL_VERIFY
EOF

echo ""
echo "✅ Configuration saved to: $CONF_FILE"
echo ""
echo "============================================"
echo "Summary:"
echo "============================================"
echo "Interface:      $INTERFACE"
echo "SOC Server:     $SOC_SERVER_URL"
echo "Sensor ID:      $SENSOR_ID"
echo "Location:       $SENSOR_LOCATION"
echo "Auth Key:       $([ -n "$SENSOR_SECRET_KEY" ] && echo "Configured" || echo "Not configured")"
echo "============================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Start NetMonitor service:"
echo "   sudo systemctl start netmonitor"
echo ""
echo "2. Check status:"
echo "   sudo systemctl status netmonitor"
echo ""
echo "3. View logs:"
echo "   sudo journalctl -u netmonitor -f"
echo ""
echo "4. Verify sensor appears in SOC dashboard:"
echo "   $SOC_SERVER_URL"
echo ""
echo "Done! 🚀"
