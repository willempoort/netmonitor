#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
#
# NetMonitor Sensor Status Checker
# Check waarom SOC server sensor offline gaat
#

echo "=========================================="
echo "NetMonitor Sensor Status Checker"
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

# Load database config
echo "📋 Database Info:"
if [ -n "$DB_HOST" ]; then
    # Already loaded from .env
    echo "  (Using .env)"
else
    # Fall back to config.yaml
    if [ -f "config.yaml" ]; then
        echo "  (Using config.yaml)"
        DB_HOST=$(grep -A5 "postgresql:" config.yaml | grep "host:" | awk '{print $2}')
        DB_NAME=$(grep -A5 "postgresql:" config.yaml | grep "database:" | awk '{print $2}')
        DB_USER=$(grep -A5 "postgresql:" config.yaml | grep "user:" | awk '{print $2}')
        PGPASSWORD=$(grep -A5 "postgresql:" config.yaml | grep "password:" | awk '{print $2}')
    else
        echo "❌ Neither .env nor config.yaml found"
        exit 1
    fi
fi

# Set defaults if not found
DB_HOST=${DB_HOST:-localhost}
DB_NAME=${DB_NAME:-netmonitor}
DB_USER=${DB_USER:-netmonitor}
PGPASSWORD=${PGPASSWORD:-${DB_PASSWORD:-netmonitor}}

echo "  Host: $DB_HOST"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"

echo
echo "🔍 Checking Sensor Processes:"

# Check if sensor_client.py is running on this machine
SENSOR_PID=$(pgrep -f "sensor_client.py" | head -1)
if [ -n "$SENSOR_PID" ]; then
    echo "  ✓ sensor_client.py is running (PID: $SENSOR_PID)"

    # Get sensor_id from process
    SENSOR_ID=$(ps aux | grep sensor_client.py | grep -v grep | head -1 | grep -o "\-\-sensor-id [^ ]*" | awk '{print $2}')
    if [ -z "$SENSOR_ID" ]; then
        SENSOR_ID=$(hostname)
        echo "    Using hostname as sensor_id: $SENSOR_ID"
    else
        echo "    Sensor ID: $SENSOR_ID"
    fi
else
    echo "  ⚠ sensor_client.py is NOT running"
    echo "    SOC server sensor won't send heartbeats without sensor_client.py"
    SENSOR_ID=$(hostname)
    echo "    Expected sensor_id: $SENSOR_ID"
fi

echo
echo "📊 Sensor Status in Database:"

# Query database for sensor status (PGPASSWORD already set from .env or config.yaml)
export PGPASSWORD

psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT
    sensor_id,
    hostname,
    last_seen,
    NOW() - last_seen as time_since_heartbeat,
    CASE
        WHEN last_seen > NOW() - INTERVAL '2 minutes' THEN 'online'
        WHEN last_seen > NOW() - INTERVAL '10 minutes' THEN 'warning'
        ELSE 'offline'
    END as status
FROM sensors
WHERE sensor_id LIKE '%$(hostname)%' OR hostname = '$(hostname)'
ORDER BY last_seen DESC;
"

echo
echo "=========================================="
echo "Heartbeat Timing Rules:"
echo "=========================================="
echo "  • Online:  last_seen < 2 minutes ago"
echo "  • Warning: last_seen < 10 minutes ago"
echo "  • Offline: last_seen > 10 minutes ago"
echo
echo "Heartbeat Behavior:"
echo "  • SOC Server (netmonitor.py):   Implicit via metrics (every 60s)"
echo "  • Remote Sensors (sensor_client.py): Explicit heartbeat (every 30s)"
echo
echo "  • SOC: If 2+ metric saves miss → Warning status"
echo "  • Remote: If 4+ heartbeats miss → Warning status"
echo
echo "=========================================="
echo "Troubleshooting:"
echo "=========================================="

if [ -z "$SENSOR_PID" ]; then
    echo "⚠ sensor_client.py is not running!"
    echo
    echo "To start sensor on SOC server:"
    echo "  cd /opt/netmonitor"
    echo "  source venv/bin/activate"
    echo "  python3 sensor_client.py -c sensor.conf"
    echo
    echo "Or install as service:"
    echo "  sudo systemctl enable netmonitor-sensor"
    echo "  sudo systemctl start netmonitor-sensor"
else
    echo "✓ sensor_client.py is running"
    echo
    echo "Check sensor logs for heartbeat errors:"
    echo "  journalctl -u netmonitor-sensor -f | grep -i heartbeat"
    echo
    echo "  Or if running manually:"
    echo "  tail -f /var/log/netmonitor/sensor.log | grep -i heartbeat"
fi

echo
