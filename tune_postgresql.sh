#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# PostgreSQL performance tuning for NetMonitor
# Safe to run on existing installations - will prompt before changes

echo "========================================="
echo "NetMonitor PostgreSQL Tuning"
echo "========================================="
echo ""

# Check if running as sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./tune_postgresql.sh"
    exit 1
fi

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "PostgreSQL is not installed."
    exit 1
fi

# Detect PostgreSQL version
PG_VERSION=$(psql --version | grep -oP '\d+' | head -1)
echo "PostgreSQL version: $PG_VERSION"

# Get current settings
echo ""
echo "Current PostgreSQL Settings:"
echo "-------------------------------------------"
sudo -u postgres psql -t -c "SHOW maintenance_work_mem;" | xargs echo "  maintenance_work_mem:"
sudo -u postgres psql -t -c "SHOW work_mem;" | xargs echo "  work_mem:"
sudo -u postgres psql -t -c "SHOW shared_buffers;" | xargs echo "  shared_buffers:"
sudo -u postgres psql -t -c "SHOW effective_cache_size;" | xargs echo "  effective_cache_size:"
sudo -u postgres psql -t -c "SHOW idle_in_transaction_session_timeout;" | xargs echo "  idle_in_transaction_session_timeout:"
sudo -u postgres psql -t -c "SHOW idle_session_timeout;" | xargs echo "  idle_session_timeout:"

# Calculate recommended values based on system RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
TOTAL_RAM_GB=$((TOTAL_RAM_MB / 1024))

# shared_buffers = 25% of RAM (max 8GB)
SHARED_BUFFERS_MB=$((TOTAL_RAM_MB / 4))
[ $SHARED_BUFFERS_MB -gt 8192 ] && SHARED_BUFFERS_MB=8192

# effective_cache_size = 75% of RAM
EFFECTIVE_CACHE_MB=$((TOTAL_RAM_MB * 3 / 4))

echo ""
echo "System Information:"
echo "-------------------------------------------"
echo "  Total RAM: ${TOTAL_RAM_GB}GB (${TOTAL_RAM_MB}MB)"
echo ""
echo "Recommended Settings for NetMonitor:"
echo "-------------------------------------------"
echo "  maintenance_work_mem: 256MB (prevents memory spikes during VACUUM)"
echo "  work_mem: 10MB (per-operation memory for sorts/hashes)"
echo "  idle_in_transaction_session_timeout: 5 minutes (closes stuck transactions)"
echo "  idle_session_timeout: 10 minutes (closes idle connections)"
echo ""

# Check if settings need to be changed
CURRENT_MAINT=$(sudo -u postgres psql -t -c "SHOW maintenance_work_mem;" | xargs)
CURRENT_IDLE_TX=$(sudo -u postgres psql -t -c "SHOW idle_in_transaction_session_timeout;" | xargs)

NEEDS_UPDATE=false

# Check if maintenance_work_mem is too high (> 512MB is excessive)
if [[ "$CURRENT_MAINT" == *"GB"* ]] || [[ "${CURRENT_MAINT%MB}" -gt 512 ]] 2>/dev/null; then
    echo "WARNING: maintenance_work_mem ($CURRENT_MAINT) is higher than recommended!"
    NEEDS_UPDATE=true
fi

# Check if idle timeouts are disabled
if [[ "$CURRENT_IDLE_TX" == "0" ]] || [[ "$CURRENT_IDLE_TX" == "0ms" ]]; then
    echo "WARNING: idle_in_transaction_session_timeout is disabled (can cause memory leaks)"
    NEEDS_UPDATE=true
fi

if [ "$NEEDS_UPDATE" = false ]; then
    echo "Settings appear to be within recommended ranges."
    echo ""
    read -p "Apply NetMonitor recommended settings anyway? (y/N): " RESPONSE
else
    echo ""
    read -p "Apply NetMonitor recommended settings? (y/N): " RESPONSE
fi

if [[ "$RESPONSE" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Applying settings..."

    # Use ALTER SYSTEM for persistent changes
    sudo -u postgres psql -c "ALTER SYSTEM SET maintenance_work_mem = '256MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET work_mem = '10MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET idle_in_transaction_session_timeout = '300000';"
    sudo -u postgres psql -c "ALTER SYSTEM SET idle_session_timeout = '600000';"

    echo ""
    echo "Settings applied to postgresql.auto.conf"
    echo ""
    read -p "Restart PostgreSQL now to apply changes? (y/N): " RESTART

    if [[ "$RESTART" =~ ^[Yy]$ ]]; then
        echo "Restarting PostgreSQL..."
        systemctl restart postgresql

        echo ""
        echo "New settings:"
        echo "-------------------------------------------"
        sudo -u postgres psql -t -c "SHOW maintenance_work_mem;" | xargs echo "  maintenance_work_mem:"
        sudo -u postgres psql -t -c "SHOW idle_in_transaction_session_timeout;" | xargs echo "  idle_in_transaction_session_timeout:"
        sudo -u postgres psql -t -c "SHOW idle_session_timeout;" | xargs echo "  idle_session_timeout:"

        echo ""
        echo "PostgreSQL tuning complete!"
    else
        echo ""
        echo "Settings saved but not active yet."
        echo "Restart PostgreSQL manually: sudo systemctl restart postgresql"
    fi
else
    echo ""
    echo "No changes made."
fi

echo ""
echo "========================================="
