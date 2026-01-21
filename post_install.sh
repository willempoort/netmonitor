#!/bin/bash
# Post-Installation Setup Script for NetMonitor
# Run this after install_complete.sh to finalize the setup

set -e

echo "======================================================================"
echo "NetMonitor Post-Installation Setup"
echo "======================================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate Python virtual environment
if [ -f "venv/bin/activate" ]; then
    echo -e "${YELLOW}Activating Python virtual environment...${NC}"
    source venv/bin/activate
    echo -e "${GREEN}  ✅ Virtual environment activated${NC}"
    echo ""
else
    echo -e "${RED}  ❌ Virtual environment not found at $SCRIPT_DIR/venv${NC}"
    echo "  Run install_complete.sh first to create the virtual environment"
    exit 1
fi

echo -e "${YELLOW}Step 1: Checking if SOC server self-monitoring is enabled...${NC}"
SELF_MONITOR_ENABLED=$(grep -A 5 "^self_monitor:" config.yaml | grep "enabled:" | awk '{print $2}')
echo "  self_monitor.enabled: $SELF_MONITOR_ENABLED"

if [ "$SELF_MONITOR_ENABLED" != "true" ]; then
    echo -e "${YELLOW}  ⚠️  Self-monitoring is disabled. Enable it in config.yaml if you want SOC server monitoring.${NC}"
else
    echo -e "${GREEN}  ✅ Self-monitoring is enabled${NC}"
    echo ""

    echo -e "${YELLOW}Step 2: Registering SOC server sensor with interface metadata...${NC}"
    python3 tools/register_soc_sensor.py
    echo ""
fi

echo -e "${YELLOW}Step 3: Checking threat feed configuration...${NC}"
echo "  Running threat feed update to verify configuration..."
python3 update_feeds.py
echo -e "${GREEN}  ✅ Threat feeds configured${NC}"
echo ""

echo -e "${YELLOW}Step 4: Verifying database schema...${NC}"
echo "  Checking if all tables exist..."
# Extract database password from config.yaml
DB_PASS=$(grep -A 10 "postgresql:" config.yaml | grep "password:" | head -1 | sed 's/.*password: *//; s/ *#.*//')
if [ -z "$DB_PASS" ]; then
    echo -e "${YELLOW}  ⚠️  Could not extract database password from config.yaml${NC}"
    echo "  Skipping database schema check"
else
    PGPASSWORD="$DB_PASS" psql -h localhost -U netmonitor -d netmonitor -c "\dt" > /dev/null 2>&1 && echo -e "${GREEN}  ✅ Database schema OK${NC}" || echo -e "${RED}  ❌ Database schema issues (check password in config.yaml)${NC}"
fi
echo ""

echo -e "${YELLOW}Step 5: Checking sensor configurations...${NC}"
python3 tools/diagnose_sensor_db.py
echo ""

echo -e "${YELLOW}Step 6: Checking GeoIP database...${NC}"
GEOIP_PATHS=(
    "/var/lib/GeoIP/GeoLite2-Country.mmdb"
    "/usr/share/GeoIP/GeoLite2-Country.mmdb"
    "$(pwd)/GeoLite2-Country.mmdb"
)

GEOIP_FOUND=false
for path in "${GEOIP_PATHS[@]}"; do
    if [ -f "$path" ]; then
        echo -e "${GREEN}  ✅ GeoIP database found: $path${NC}"
        GEOIP_FOUND=true
        break
    fi
done

if [ "$GEOIP_FOUND" = false ]; then
    echo -e "${YELLOW}  ⚠️  GeoIP database not found${NC}"
    echo "  IP geolocation features will not work without this database."
    echo ""
    read -p "  Download free GeoIP database now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        bash download_geoip_db.sh
    else
        echo "  Skip GeoIP download - you can run './download_geoip_db.sh' later"
    fi
fi
echo ""

echo "======================================================================"
echo -e "${GREEN}Post-Installation Setup Complete!${NC}"
echo "======================================================================"
echo ""
echo "Next steps:"
echo "  1. Configure templates via Web UI: http://localhost:8080/templates"
echo "  2. Add device classifications: http://localhost:8080/devices"
echo "  3. Configure KIOSK mode rotation interval if needed"
echo "  4. Set up MCP server if using Claude Desktop integration"
echo ""
echo "Documentation:"
echo "  - Configuration Guide: docs/usage/CONFIG_GUIDE.md"
echo "  - Admin Manual: docs/usage/ADMIN_MANUAL.md"
echo "  - Architecture: docs/architecture/ARCHITECTURE_BEST_PRACTICES.md"
echo ""
