#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
#
# NetMonitor - Bootstrap Assets + Database Defaults Updater
# Voor bestaande installaties die deze nieuwe features willen toevoegen
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="/opt/netmonitor"

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}NetMonitor - Bootstrap Assets + Database Defaults Update${NC}"
echo -e "${BLUE}============================================================${NC}"
echo

# Check if we're in the right directory
if [ ! -f "$INSTALL_DIR/web_dashboard.py" ]; then
    echo -e "${RED}✗ NetMonitor niet gevonden in $INSTALL_DIR${NC}"
    exit 1
fi

cd $INSTALL_DIR

# 1. Download Bootstrap assets
echo -e "${BLUE}[1/2] Bootstrap Assets Lokaal Downloaden...${NC}"
mkdir -p web/static/css web/static/js web/static/fonts

echo "  → Bootstrap CSS..."
curl -sL https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css -o web/static/css/bootstrap.min.css

echo "  → Bootstrap JS (bundle with Popper)..."
# Download and verify it contains Popper
curl -sL https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js -o web/static/js/bootstrap.bundle.min.js
# Verify download
if ! grep -q "Popper" web/static/js/bootstrap.bundle.min.js; then
    echo "  ⚠ Warning: Downloaded Bootstrap JS might not include Popper"
fi

echo "  → Bootstrap Icons CSS..."
curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css -o web/static/css/bootstrap-icons.css

echo "  → Bootstrap Icons fonts..."
curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff -o web/static/fonts/bootstrap-icons.woff 2>/dev/null || true
curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff2 -o web/static/fonts/bootstrap-icons.woff2 2>/dev/null || true

echo "  → Chart.js..."
curl -sL https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js -o web/static/js/chart.umd.min.js

echo "  → Socket.IO..."
curl -sL https://cdn.socket.io/4.6.0/socket.io.min.js -o web/static/js/socket.io.min.js

# Fix Bootstrap Icons font paths (use absolute path from web root)
# Change CDN URLs
sed -i 's|https://cdn.jsdelivr.net/npm/bootstrap-icons@[^/]*/font/fonts/|/static/fonts/|g' web/static/css/bootstrap-icons.css
# Change relative paths: ./fonts/ -> /static/fonts/ (crucial fix for icon display)
sed -i 's|url("./fonts/bootstrap-icons|url("/static/fonts/bootstrap-icons|g' web/static/css/bootstrap-icons.css
sed -i "s|url('./fonts/bootstrap-icons|url('/static/fonts/bootstrap-icons|g" web/static/css/bootstrap-icons.css

echo -e "${GREEN}✓ Bootstrap assets gedownload${NC}"
echo

# 2. Load database defaults
echo -e "${BLUE}[2/2] Database Default Thresholds Laden...${NC}"

if [ ! -f "venv/bin/activate" ]; then
    echo -e "${RED}✗ Python venv niet gevonden${NC}"
    exit 1
fi

source venv/bin/activate

if [ ! -f "init_database_defaults.py" ]; then
    echo -e "${RED}✗ init_database_defaults.py niet gevonden${NC}"
    echo "  Zorg dat je de laatste code hebt gepulld"
    exit 1
fi

python3 init_database_defaults.py

echo -e "${GREEN}✓ Database defaults geladen${NC}"
echo

# 3. Restart service
echo -e "${BLUE}Service herstarten...${NC}"
sudo systemctl restart netmonitor

sleep 2

if systemctl is-active --quiet netmonitor; then
    echo -e "${GREEN}✓ NetMonitor service herstart${NC}"
else
    echo -e "${RED}✗ Service restart failed - check logs${NC}"
fi

echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}✓ Update Compleet!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo
echo "Ververs de dashboard in je browser met Ctrl+F5"
echo "De dropdown zou nu moeten werken (geen CDN blokkades meer)"
echo "En de database heeft alle default threshold waarden"
echo
