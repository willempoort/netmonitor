#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Threat Intelligence Setup Script
#
# Initializes the threat intel database and loads the knowledge base.
# Run this once after installation.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "NetMonitor Threat Intelligence Setup"
echo "=============================================="

# Check for .env
if [ ! -f "../.env" ] && [ ! -f ".env" ]; then
    echo "Warning: No .env file found. Using default database credentials."
fi

# Load environment
if [ -f "../.env" ]; then
    export $(grep -v '^#' ../.env | xargs)
elif [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_HOST="${DB_HOST:-localhost}"
DB_NAME="${DB_NAME:-netmonitor}"
DB_USER="${DB_USER:-netmonitor}"

echo ""
echo "Step 1/3: Initialize database schema..."
echo "        Database: $DB_NAME on $DB_HOST"

if command -v psql &> /dev/null; then
    PGPASSWORD="${DB_PASSWORD:-netmonitor}" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -f schema.sql
    echo "        Schema initialized."
else
    echo "        ERROR: psql not found. Please run schema.sql manually."
    exit 1
fi

echo ""
echo "Step 2/3: Load security knowledge base..."
python3 load_knowledge_base.py --reload
echo "        Knowledge base loaded."

echo ""
echo "Step 3/3: Initial threat feed sync (optional)..."
echo "        This downloads threat intel feeds from external sources."
read -p "        Run initial sync now? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 sync_service.py --sync-all
    echo "        Feeds synchronized."
else
    echo "        Skipped. Run 'python3 sync_service.py --sync-all' later."
fi

echo ""
echo "=============================================="
echo "Setup complete!"
echo ""
echo "Available MCP tools:"
echo "  - lookup_threat_intel     : Check IP reputation"
echo "  - get_security_recommendation : Get recommendations for threat types"
echo "  - get_threat_context      : Get full context for analysis"
echo "  - sync_threat_feeds       : Manually sync threat feeds"
echo ""
echo "To enable automatic feed syncing, set up a cron job or systemd timer:"
echo "  */30 * * * * cd $SCRIPT_DIR && python3 sync_service.py --sync-all"
echo "=============================================="
