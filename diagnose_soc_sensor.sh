#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
################################################################################
# SOC Server Self-Monitoring Diagnostic Script
# Check waarom SOC server niet in sensor overzicht verschijnt
################################################################################

echo "=========================================="
echo "SOC Server Self-Monitoring Diagnostics"
echo "=========================================="
echo

# Function to load .env file
load_env() {
    if [ -f .env ]; then
        export $(grep -v '^#' .env | grep -v '^$' | xargs)
    fi
}

# Load .env if it exists
load_env

# Get database config
DB_HOST="${DB_HOST:-localhost}"
DB_NAME="${DB_NAME:-netmonitor}"
DB_USER="${DB_USER:-netmonitor}"
DB_PASS="${DB_PASS:-${DB_PASSWORD:-netmonitor}}"

echo "Step 1: Checking config.yaml self_monitor settings..."
echo "----------------------------------------------------------------------"
SELF_MONITOR_ENABLED=$(grep -A 10 "self_monitor:" config.yaml | grep "enabled:" | awk '{print $2}')
SENSOR_ID=$(grep -A 10 "self_monitor:" config.yaml | grep "sensor_id:" | awk '{print $2}')

echo "  self_monitor.enabled: $SELF_MONITOR_ENABLED"
echo "  self_monitor.sensor_id: $SENSOR_ID"
echo

if [ "$SELF_MONITOR_ENABLED" != "true" ]; then
    echo "❌ PROBLEEM: self_monitor is disabled in config.yaml!"
    echo "   Fix: Zet 'enabled: true' onder self_monitor in config.yaml"
    echo
fi

echo "Step 2: Checking if netmonitor service is running..."
echo "----------------------------------------------------------------------"
if systemctl is-active --quiet netmonitor; then
    echo "✓ netmonitor service is RUNNING"
    echo
    echo "  Service status:"
    systemctl status netmonitor --no-pager -l | head -20
else
    echo "❌ PROBLEEM: netmonitor service is NOT RUNNING!"
    echo
    echo "  Check logs met:"
    echo "    sudo journalctl -u netmonitor -n 50"
    echo
    echo "  Start service met:"
    echo "    sudo systemctl start netmonitor"
    echo
fi

echo
echo "Step 3: Checking database for sensor registration..."
echo "----------------------------------------------------------------------"

# Query sensor registration
SENSOR_INFO=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -A -c \
  "SELECT sensor_id, hostname, last_seen,
          NOW() - last_seen as time_ago,
          CASE
            WHEN last_seen > NOW() - INTERVAL '2 minutes' THEN 'online'
            WHEN last_seen > NOW() - INTERVAL '10 minutes' THEN 'warning'
            ELSE 'offline'
          END as status
   FROM sensors
   WHERE sensor_id = '$SENSOR_ID'
   LIMIT 1;" 2>&1)

if echo "$SENSOR_INFO" | grep -q "no password supplied\|connection refused\|does not exist"; then
    echo "❌ Database connection error!"
    echo "$SENSOR_INFO"
    echo
    exit 1
fi

if [ -z "$SENSOR_INFO" ] || [ "$SENSOR_INFO" == "" ]; then
    echo "❌ PROBLEEM: Sensor '$SENSOR_ID' is NOT REGISTERED in database!"
    echo
    echo "Mogelijke oorzaken:"
    echo "  1. netmonitor.py draait niet (geen heartbeat)"
    echo "  2. sensor_id in config.yaml is anders dan verwacht"
    echo "  3. self_monitor is disabled"
    echo "  4. Database error bij metrics opslaan"
    echo
    echo "Check logs:"
    echo "  sudo journalctl -u netmonitor -n 100 | grep -i 'sensor\|metrics'"
else
    echo "✓ Sensor GEVONDEN in database!"
    echo
    echo "$SENSOR_INFO" | awk -F'|' '{
        printf "  Sensor ID:   %s\n", $1
        printf "  Hostname:    %s\n", $2
        printf "  Last seen:   %s\n", $3
        printf "  Time ago:    %s\n", $4
        printf "  Status:      %s\n", $5
    }'
fi

echo
echo "Step 4: Checking recent sensor metrics..."
echo "----------------------------------------------------------------------"

METRICS_COUNT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -A -c \
  "SELECT COUNT(*) FROM sensor_metrics WHERE sensor_id = '$SENSOR_ID' AND timestamp > NOW() - INTERVAL '10 minutes';" 2>&1)

echo "  Metrics in last 10 minutes: $METRICS_COUNT"

if [ "$METRICS_COUNT" == "0" ] || [ -z "$METRICS_COUNT" ]; then
    echo
    echo "❌ PROBLEEM: No recent metrics found!"
    echo
    echo "Dit betekent:"
    echo "  - netmonitor.py draait niet, OF"
    echo "  - save_sensor_metrics() faalt"
    echo
    echo "Check logs:"
    echo "  sudo journalctl -u netmonitor -n 100 | grep -i 'metrics'"
else
    echo
    echo "✓ Recent metrics GEVONDEN!"
    echo
    echo "  Latest metrics:"
    PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c \
      "SELECT
         timestamp,
         cpu_percent,
         memory_percent,
         packets_captured,
         alerts_sent,
         network_interface,
         bandwidth_mbps
       FROM sensor_metrics
       WHERE sensor_id = '$SENSOR_ID'
       ORDER BY timestamp DESC
       LIMIT 5;"
fi

echo
echo "Step 5: Checking dashboard sensor query..."
echo "----------------------------------------------------------------------"

DASHBOARD_SENSORS=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -A -c \
  "SELECT sensor_id,
          CASE
            WHEN last_seen > NOW() - INTERVAL '2 minutes' THEN 'online'
            WHEN last_seen > NOW() - INTERVAL '10 minutes' THEN 'warning'
            ELSE 'offline'
          END as status
   FROM sensors
   ORDER BY last_seen DESC;" 2>&1)

echo "  All sensors in database:"
if [ -z "$DASHBOARD_SENSORS" ]; then
    echo "    (none)"
else
    echo "$DASHBOARD_SENSORS" | awk -F'|' '{printf "    - %s (%s)\n", $1, $2}'
fi

echo
echo "=========================================="
echo "Summary & Recommendations"
echo "=========================================="
echo

if [ "$SELF_MONITOR_ENABLED" != "true" ]; then
    echo "❌ Enable self_monitor in config.yaml"
elif ! systemctl is-active --quiet netmonitor; then
    echo "❌ Start netmonitor service: sudo systemctl start netmonitor"
elif [ -z "$SENSOR_INFO" ] || [ "$SENSOR_INFO" == "" ]; then
    echo "❌ Sensor niet geregistreerd - check netmonitor logs"
elif [ "$METRICS_COUNT" == "0" ]; then
    echo "❌ Geen recente metrics - check netmonitor logs"
else
    echo "✅ SOC server self-monitoring lijkt te werken!"
    echo
    echo "   Als sensor nog niet in dashboard verschijnt:"
    echo "   1. Refresh browser (Ctrl+Shift+R)"
    echo "   2. Check dashboard logs: sudo journalctl -u netmonitor-web -n 50"
    echo "   3. Check browser console voor JavaScript errors"
fi

echo
