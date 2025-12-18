#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# Download GeoLite2 Country Database
# Note: MaxMind now requires a free account to download GeoLite2 databases

set -e

INSTALL_DIR="/var/lib/GeoIP"
DB_FILE="GeoLite2-Country.mmdb"

echo "=========================================="
echo "GeoLite2 Database Download Script"
echo "=========================================="
echo ""
echo "IMPORTANT: MaxMind now requires a free account to download GeoLite2 databases."
echo ""
echo "Options:"
echo ""
echo "1. Sign up for free account at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
echo "   After signup, download GeoLite2-Country.mmdb and place it in one of:"
echo "   - /var/lib/GeoIP/GeoLite2-Country.mmdb"
echo "   - /usr/share/GeoIP/GeoLite2-Country.mmdb"
echo "   - $(dirname $0)/GeoLite2-Country.mmdb"
echo ""
echo "2. Use alternative free database (db-ip.com):"
echo "   wget https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz"
echo "   gunzip dbip-country-lite-*.mmdb.gz"
echo "   sudo mkdir -p $INSTALL_DIR"
echo "   sudo mv dbip-country-lite-*.mmdb $INSTALL_DIR/GeoLite2-Country.mmdb"
echo ""
echo "3. Use geoipupdate tool (recommended for production):"
echo "   sudo apt-get install geoipupdate"
echo "   # Configure with your MaxMind account ID and license key"
echo "   # Edit /etc/GeoIP.conf"
echo "   sudo geoipupdate"
echo ""
echo "=========================================="
echo ""

read -p "Download db-ip.com free database now? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "Downloading db-ip.com free GeoIP database..."

    # Create directory if it doesn't exist
    sudo mkdir -p "$INSTALL_DIR"

    # Download current month's database
    CURRENT_MONTH=$(date +%Y-%m)
    DB_URL="https://download.db-ip.com/free/dbip-country-lite-${CURRENT_MONTH}.mmdb.gz"

    echo "Downloading from: $DB_URL"
    wget -O /tmp/dbip-country.mmdb.gz "$DB_URL" || {
        echo "Error: Download failed. This might be because:"
        echo "1. The database for $CURRENT_MONTH is not yet available"
        echo "2. Network connectivity issues"
        echo ""
        echo "Try downloading manually from: https://db-ip.com/db/download/ip-to-country-lite"
        exit 1
    }

    echo "Extracting database..."
    gunzip -f /tmp/dbip-country.mmdb.gz

    echo "Installing to $INSTALL_DIR/$DB_FILE"
    sudo mv /tmp/dbip-country.mmdb "$INSTALL_DIR/$DB_FILE"
    sudo chmod 644 "$INSTALL_DIR/$DB_FILE"

    echo ""
    echo "SUCCESS! GeoIP database installed to: $INSTALL_DIR/$DB_FILE"
    echo ""
    echo "Restart netmonitor service to use the new database:"
    echo "  sudo systemctl restart netmonitor"
else
    echo ""
    echo "No action taken. Follow the instructions above to manually install the database."
fi
