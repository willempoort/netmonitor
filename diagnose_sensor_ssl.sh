#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# Diagnostic script voor sensor SSL problemen

echo "==================================="
echo "Sensor SSL Diagnostic"
echo "==================================="
echo ""

echo "1. Checking sensor.conf SSL_VERIFY setting:"
if [ -f /opt/netmonitor/sensor.conf ]; then
    grep "^SSL_VERIFY" /opt/netmonitor/sensor.conf
else
    echo "   ❌ /opt/netmonitor/sensor.conf not found!"
fi
echo ""

echo "2. Checking if sensor_client.py has verify parameter:"
if [ -f /opt/netmonitor/sensor_client.py ]; then
    matches=$(grep -c "verify=self.ssl_verify" /opt/netmonitor/sensor_client.py)
    if [ "$matches" -gt 0 ]; then
        echo "   ✅ Found $matches occurrences of verify=self.ssl_verify (NEW CODE)"
    else
        echo "   ❌ No verify=self.ssl_verify found (OLD CODE - needs update!)"
    fi
else
    echo "   ❌ /opt/netmonitor/sensor_client.py not found!"
fi
echo ""

echo "3. Checking Git status:"
if [ -d /opt/netmonitor/.git ]; then
    cd /opt/netmonitor
    echo "   Current commit:"
    git log -1 --oneline
    echo ""
    echo "   Branch:"
    git branch --show-current
    echo ""
    echo "   Uncommitted changes:"
    git status --short
else
    echo "   ❌ Not a git repository"
fi
echo ""

echo "4. Testing SSL certificate from sensor:"
SOC_URL=$(grep "^SOC_SERVER_URL" /opt/netmonitor/sensor.conf | cut -d'=' -f2)
if [ -n "$SOC_URL" ]; then
    echo "   SOC Server: $SOC_URL"
    HOST=$(echo "$SOC_URL" | sed 's|https\?://||' | cut -d':' -f1)
    PORT=$(echo "$SOC_URL" | grep -o ':[0-9]*' | sed 's/://' || echo "443")

    echo ""
    echo "   Testing SSL connection to $HOST:$PORT..."
    timeout 5 openssl s_client -connect $HOST:$PORT -showcerts </dev/null 2>&1 | head -20

    echo ""
    echo "   Certificate chain verification:"
    timeout 5 openssl s_client -connect $HOST:$PORT -showcerts </dev/null 2>&1 | grep -E "verify return:|Verify return code:"
else
    echo "   ❌ Cannot find SOC_SERVER_URL in sensor.conf"
fi
echo ""

echo "5. Checking CA certificates:"
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    echo "   ✅ CA certificates file exists"
    CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt)
    echo "   📋 Total CA certificates: $CERT_COUNT"
else
    echo "   ❌ /etc/ssl/certs/ca-certificates.crt not found!"
fi
echo ""

echo "6. Sensor service status:"
systemctl status netmonitor-sensor --no-pager | head -15
echo ""

echo "==================================="
echo "Recommendations:"
echo "==================================="
echo ""
echo "If OLD CODE detected:"
echo "  cd /opt/netmonitor"
echo "  git pull"
echo "  sudo systemctl restart netmonitor-sensor"
echo ""
echo "If certificate verification fails:"
echo "  Option A: Update CA certificates:"
echo "    sudo apt-get update"
echo "    sudo apt-get install --reinstall ca-certificates"
echo "    sudo update-ca-certificates"
echo ""
echo "  Option B: Disable SSL verification (NOT recommended for production):"
echo "    Edit /opt/netmonitor/sensor.conf:"
echo "    SSL_VERIFY=false"
echo "    sudo systemctl restart netmonitor-sensor"
echo ""
