#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
#
# Diagnostic script for Top Talkers issues
# Usage: sudo ./diagnose_top_talkers.sh

echo "========================================"
echo "Top Talkers Diagnostic Tool"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Load database config
if [ -f "config.yaml" ]; then
    DB_HOST=$(grep -A5 "^database:" config.yaml | grep "host:" | awk '{print $2}')
    DB_NAME=$(grep -A5 "^database:" config.yaml | grep "database:" | awk '{print $2}')
    DB_USER=$(grep -A5 "^database:" config.yaml | grep "user:" | awk '{print $2}')
else
    DB_HOST="localhost"
    DB_NAME="netmonitor"
    DB_USER="netmonitor"
fi

echo "Database: postgresql://$DB_USER@$DB_HOST/$DB_NAME"
echo ""

# Function to run SQL query
run_query() {
    sudo -u postgres psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "$1" 2>&1
}

# 1. Check if top_talkers table exists
echo "1️⃣  Checking top_talkers table..."
TABLE_EXISTS=$(run_query "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'top_talkers';")
if [ "$TABLE_EXISTS" -eq "1" ]; then
    echo -e "${GREEN}✅ top_talkers table exists${NC}"
else
    echo -e "${RED}❌ top_talkers table DOES NOT exist!${NC}"
    exit 1
fi
echo ""

# 2. Check total records
echo "2️⃣  Checking total records in top_talkers..."
TOTAL_RECORDS=$(run_query "SELECT COUNT(*) FROM top_talkers;")
echo "   Total records: $TOTAL_RECORDS"
if [ "$TOTAL_RECORDS" -eq "0" ]; then
    echo -e "${RED}   ⚠️  WARNING: No records in top_talkers table!${NC}"
fi
echo ""

# 3. Check recent records (last 5 minutes)
echo "3️⃣  Checking recent records (last 5 minutes)..."
RECENT_RECORDS=$(run_query "SELECT COUNT(*) FROM top_talkers WHERE timestamp > NOW() - INTERVAL '5 minutes';")
echo "   Records in last 5 minutes: $RECENT_RECORDS"
if [ "$RECENT_RECORDS" -eq "0" ]; then
    echo -e "${RED}   ❌ NO recent records! Top Talkers will be empty.${NC}"
else
    echo -e "${GREEN}   ✅ Recent data exists${NC}"
fi
echo ""

# 4. Check which sensors are sending data
echo "4️⃣  Checking which sensors are reporting Top Talkers data..."
echo "   Sensor activity (last 10 minutes):"
run_query "
SELECT
    sensor_id,
    COUNT(*) as records,
    MAX(timestamp) as last_seen,
    NOW() - MAX(timestamp) as age
FROM top_talkers
WHERE timestamp > NOW() - INTERVAL '10 minutes'
GROUP BY sensor_id
ORDER BY last_seen DESC;
" | head -20

SENSOR_COUNT=$(run_query "SELECT COUNT(DISTINCT sensor_id) FROM top_talkers WHERE timestamp > NOW() - INTERVAL '5 minutes';")
echo ""
echo "   Active sensors (last 5 min): $SENSOR_COUNT"
if [ "$SENSOR_COUNT" -eq "0" ]; then
    echo -e "${RED}   ❌ NO sensors reporting data!${NC}"
fi
echo ""

# 5. Check SOC server sensor configuration
echo "5️⃣  Checking SOC server sensor registration..."
SOC_SENSOR=$(run_query "SELECT sensor_id FROM sensors WHERE sensor_id IN ('soc', 'soc-server', 'central') LIMIT 1;")
if [ -z "$SOC_SENSOR" ]; then
    echo -e "${RED}   ❌ SOC server not registered as sensor!${NC}"
    echo "   To fix: The SOC server should register itself on startup"
else
    echo -e "${GREEN}   ✅ SOC server registered as: $SOC_SENSOR${NC}"

    # Check SOC server interface config
    echo ""
    echo "   SOC server configuration:"
    run_query "SELECT sensor_id, config->>'interface' as interface, config->>'available_interfaces' as available_interfaces FROM sensors WHERE sensor_id = '$SOC_SENSOR';" | head -10
fi
echo ""

# 6. Check if self_monitor is enabled
echo "6️⃣  Checking SOC server self_monitor config..."
if [ -f "config.yaml" ]; then
    SELF_MONITOR=$(grep -A5 "^self_monitor:" config.yaml | grep "enabled:" | awk '{print $2}')
    INTERFACE=$(grep -A5 "^self_monitor:" config.yaml | grep "interface:" | awk '{print $2}')

    if [ "$SELF_MONITOR" = "true" ]; then
        echo -e "${GREEN}   ✅ self_monitor.enabled: true${NC}"
    else
        echo -e "${RED}   ❌ self_monitor.enabled: false${NC}"
        echo "   ⚠️  SOC server will NOT collect local traffic!"
    fi

    echo "   Configured interface: $INTERFACE"

    # Check if interface exists on system
    if ip link show "$INTERFACE" &> /dev/null; then
        echo -e "${GREEN}   ✅ Interface $INTERFACE exists on system${NC}"

        # Check if interface is UP
        if ip link show "$INTERFACE" | grep -q "UP"; then
            echo -e "${GREEN}   ✅ Interface $INTERFACE is UP${NC}"
        else
            echo -e "${RED}   ❌ Interface $INTERFACE is DOWN!${NC}"
        fi

        # Check promiscuous mode
        if ip link show "$INTERFACE" | grep -q "PROMISC"; then
            echo -e "${GREEN}   ✅ Interface $INTERFACE is in PROMISC mode${NC}"
        else
            echo -e "${YELLOW}   ⚠️  Interface $INTERFACE is NOT in PROMISC mode${NC}"
        fi
    else
        echo -e "${RED}   ❌ Interface $INTERFACE does NOT exist on system!${NC}"
        echo "   Available interfaces:"
        ip -o link show | awk -F': ' '{print "      - " $2}'
    fi
else
    echo -e "${YELLOW}   ⚠️  config.yaml not found${NC}"
fi
echo ""

# 7. Check sensor_configs for interface setting
echo "7️⃣  Checking database sensor_configs for interface..."
INTERFACE_CONFIG=$(run_query "SELECT parameter_value FROM sensor_configs WHERE parameter_path = 'interface' AND (sensor_id = '$SOC_SENSOR' OR sensor_id IS NULL) ORDER BY sensor_id NULLS LAST LIMIT 1;")
if [ -z "$INTERFACE_CONFIG" ]; then
    echo -e "${YELLOW}   ⚠️  No interface configured in sensor_configs${NC}"
else
    echo "   Configured interface in DB: $INTERFACE_CONFIG"

    # Check if it's empty
    if [ "$INTERFACE_CONFIG" = '""' ] || [ "$INTERFACE_CONFIG" = "" ]; then
        echo -e "${RED}   ❌ Interface configuration is EMPTY!${NC}"
        echo "   This will cause monitoring to fail!"
        echo "   Fix: Configure interface in Dashboard → Sensors → Edit Settings"
    fi
fi
echo ""

# 8. Check netmonitor service status
echo "8️⃣  Checking netmonitor service status..."
if systemctl is-active --quiet netmonitor; then
    echo -e "${GREEN}   ✅ netmonitor service is running${NC}"

    # Show last log lines
    echo ""
    echo "   Recent logs (last 20 lines):"
    journalctl -u netmonitor --no-pager -n 20 | sed 's/^/      /'
else
    echo -e "${RED}   ❌ netmonitor service is NOT running!${NC}"
    echo "   Start with: sudo systemctl start netmonitor"
fi
echo ""

# 9. Sample recent top talkers data
echo "9️⃣  Sample of recent Top Talkers data:"
run_query "
SELECT
    timestamp,
    sensor_id,
    ip_address::text,
    hostname,
    packet_count,
    byte_count,
    direction
FROM top_talkers
WHERE timestamp > NOW() - INTERVAL '5 minutes'
ORDER BY timestamp DESC
LIMIT 10;
" | head -15

echo ""

# Summary and recommendations
echo "========================================"
echo "SUMMARY & RECOMMENDATIONS"
echo "========================================"
echo ""

if [ "$RECENT_RECORDS" -eq "0" ]; then
    echo -e "${RED}❌ PROBLEM FOUND: No recent Top Talkers data${NC}"
    echo ""
    echo "Possible causes:"
    echo "1. SOC server not monitoring (self_monitor.enabled = false)"
    echo "2. No interface selected in sensor configuration"
    echo "3. Interface is DOWN or does not exist"
    echo "4. netmonitor service not running"
    echo "5. Remote sensors not connected"
    echo ""
    echo "Quick fixes:"
    echo "• Check config.yaml: self_monitor.enabled should be 'true'"
    echo "• Configure interface in Dashboard → Sensors → SOC Server → Edit"
    echo "• Restart service: sudo systemctl restart netmonitor"
    echo "• Check logs: journalctl -u netmonitor -f"
else
    echo -e "${GREEN}✅ Top Talkers data is being collected${NC}"
    echo ""
    echo "Active sensors: $SENSOR_COUNT"
    echo "Recent records: $RECENT_RECORDS"
fi

echo ""
echo "========================================"
