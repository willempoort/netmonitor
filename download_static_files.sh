#!/bin/bash
# Download Static Files for NetMonitor Web Dashboard
# Standalone script to download Bootstrap, Chart.js, Socket.IO

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "NetMonitor Static Files Download"
echo "======================================================================"
echo ""

# Create directories
echo -e "${YELLOW}Creating static directories...${NC}"
mkdir -p web/static/css web/static/js web/static/fonts
echo -e "${GREEN}✅ Directories created${NC}"
echo ""

# Download Bootstrap CSS
echo -e "${YELLOW}Downloading Bootstrap CSS...${NC}"
curl -sL https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css -o web/static/css/bootstrap.min.css
echo -e "${GREEN}✅ Bootstrap CSS downloaded${NC}"

# Download Bootstrap JS
echo -e "${YELLOW}Downloading Bootstrap JS (bundle with Popper)...${NC}"
curl -sL https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js -o web/static/js/bootstrap.bundle.min.js
echo -e "${GREEN}✅ Bootstrap JS downloaded${NC}"

# Download Bootstrap Icons CSS
echo -e "${YELLOW}Downloading Bootstrap Icons CSS...${NC}"
curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css -o web/static/css/bootstrap-icons.css
echo -e "${GREEN}✅ Bootstrap Icons CSS downloaded${NC}"

# Download Bootstrap Icons fonts
echo -e "${YELLOW}Downloading Bootstrap Icons fonts...${NC}"
curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff -o web/static/fonts/bootstrap-icons.woff
curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff2 -o web/static/fonts/bootstrap-icons.woff2
echo -e "${GREEN}✅ Bootstrap Icons fonts downloaded${NC}"

# Download Chart.js
echo -e "${YELLOW}Downloading Chart.js...${NC}"
curl -sL https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js -o web/static/js/chart.umd.min.js
echo -e "${GREEN}✅ Chart.js downloaded${NC}"

# Download Socket.IO client
echo -e "${YELLOW}Downloading Socket.IO client...${NC}"
curl -sL https://cdn.socket.io/4.6.0/socket.io.min.js -o web/static/js/socket.io.min.js
echo -e "${GREEN}✅ Socket.IO client downloaded${NC}"

# Fix Bootstrap Icons CSS paths
echo ""
echo -e "${YELLOW}Fixing Bootstrap Icons CSS paths...${NC}"
sed -i 's|https://cdn.jsdelivr.net/npm/bootstrap-icons@[^/]*/font/fonts/|/static/fonts/|g' web/static/css/bootstrap-icons.css
sed -i 's|url("./fonts/bootstrap-icons|url("/static/fonts/bootstrap-icons|g' web/static/css/bootstrap-icons.css
sed -i "s|url('./fonts/bootstrap-icons|url('/static/fonts/bootstrap-icons|g" web/static/css/bootstrap-icons.css
echo -e "${GREEN}✅ CSS paths fixed${NC}"

echo ""
echo "======================================================================"
echo -e "${GREEN}Static Files Download Complete!${NC}"
echo "======================================================================"
echo ""
echo "Downloaded files:"
echo "  - web/static/css/bootstrap.min.css"
echo "  - web/static/css/bootstrap-icons.css"
echo "  - web/static/js/bootstrap.bundle.min.js"
echo "  - web/static/js/chart.umd.min.js"
echo "  - web/static/js/socket.io.min.js"
echo "  - web/static/fonts/bootstrap-icons.woff"
echo "  - web/static/fonts/bootstrap-icons.woff2"
echo ""
