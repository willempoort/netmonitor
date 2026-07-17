#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# Setup script for PostgreSQL + TimescaleDB database

echo "========================================="
echo "NetMonitor Database Setup"
echo "PostgreSQL + TimescaleDB"
echo "========================================="
echo ""

# Check if running as sudo
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Please run with sudo: sudo ./setup_database.sh"
    exit 1
fi

# Database configuration
DB_NAME="netmonitor"
DB_USER="netmonitor"
DB_PASSWORD="netmonitor"

echo "📦 Step 1: Installing PostgreSQL + TimescaleDB..."
echo "-------------------------------------------"

apt-get update
apt-get install -y wget gnupg lsb-release postgresql postgresql-contrib

# Detect the PostgreSQL version that was just installed from the distro repos
PG_VERSION=$(psql --version | grep -oP '\d+' | head -1)
echo "Detected PostgreSQL version: $PG_VERSION"

# TimescaleDB's packagecloud repo has separate ubuntu/ and debian/ paths
. /etc/os-release
case "$ID" in
    debian) TIMESCALE_REPO_OS="debian" ;;
    ubuntu) TIMESCALE_REPO_OS="ubuntu" ;;
    *)
        echo "⚠️  Onbekende distributie ($ID) voor TimescaleDB-repo, val terug op ubuntu"
        TIMESCALE_REPO_OS="ubuntu"
        ;;
esac

# Add TimescaleDB repository met een signed-by keyring (apt-key is deprecated/
# verwijderd op recente Debian/Ubuntu releases)
if [ ! -f /etc/apt/sources.list.d/timescale_timescaledb.list ]; then
    echo "Adding TimescaleDB repository..."

    install -d -m 0755 /etc/apt/keyrings
    wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey \
        | gpg --dearmor -o /etc/apt/keyrings/timescaledb.gpg
    chmod 0644 /etc/apt/keyrings/timescaledb.gpg

    sh -c "echo 'deb [signed-by=/etc/apt/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/${TIMESCALE_REPO_OS}/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescale_timescaledb.list"

    apt-get update
fi

# Install TimescaleDB matching the detected PostgreSQL version
echo "Installing packages..."
apt-get install -y timescaledb-2-postgresql-$PG_VERSION

# Tune TimescaleDB
echo "Tuning TimescaleDB..."
timescaledb-tune --quiet --yes

# Apply NetMonitor recommended PostgreSQL settings
echo ""
echo "🔧 Applying NetMonitor recommended PostgreSQL settings..."

# Detect PostgreSQL version and config path
PG_VERSION=$(psql --version | grep -oP '\d+' | head -1)
PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"

if [ -f "$PG_CONF" ]; then
    # Calculate recommended values based on system RAM
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))

    # shared_buffers = 25% of RAM (max 8GB)
    SHARED_BUFFERS_MB=$((TOTAL_RAM_MB / 4))
    [ $SHARED_BUFFERS_MB -gt 8192 ] && SHARED_BUFFERS_MB=8192

    # effective_cache_size = 75% of RAM
    EFFECTIVE_CACHE_MB=$((TOTAL_RAM_MB * 3 / 4))

    echo "  System RAM: ${TOTAL_RAM_MB}MB"
    echo "  Recommended shared_buffers: ${SHARED_BUFFERS_MB}MB"
    echo "  Recommended effective_cache_size: ${EFFECTIVE_CACHE_MB}MB"

    # Apply settings via ALTER SYSTEM (persists across restarts)
    sudo -u postgres psql -c "ALTER SYSTEM SET maintenance_work_mem = '256MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET work_mem = '10MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET idle_in_transaction_session_timeout = '300000';"
    sudo -u postgres psql -c "ALTER SYSTEM SET idle_session_timeout = '600000';"

    echo "  ✓ maintenance_work_mem = 256MB"
    echo "  ✓ work_mem = 10MB"
    echo "  ✓ idle_in_transaction_session_timeout = 5 minutes"
    echo "  ✓ idle_session_timeout = 10 minutes"
else
    echo "  ⚠️  Could not find postgresql.conf at $PG_CONF"
fi

# Restart PostgreSQL
systemctl restart postgresql

echo ""
echo "✅ PostgreSQL + TimescaleDB installed successfully!"
echo ""

echo "📊 Step 2: Creating database and user..."
echo "-------------------------------------------"

# Create database and user
sudo -u postgres psql <<EOF
-- Create user
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';

-- Create database
CREATE DATABASE $DB_NAME OWNER $DB_USER;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;

-- Connect to database and enable TimescaleDB
\c $DB_NAME
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;

EOF

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Database setup complete!"
    echo ""
    echo "========================================="
    echo "Database Configuration"
    echo "========================================="
    echo "Host:      localhost"
    echo "Port:      5432"
    echo "Database:  $DB_NAME"
    echo "User:      $DB_USER"
    echo "Password:  $DB_PASSWORD"
    echo ""
    echo "⚠️  IMPORTANT: Change the password in production!"
    echo ""
    echo "📝 Configuration in config.yaml:"
    echo "-------------------------------------------"
    echo "database:"
    echo "  type: postgresql"
    echo "  postgresql:"
    echo "    host: localhost"
    echo "    port: 5432"
    echo "    database: $DB_NAME"
    echo "    user: $DB_USER"
    echo "    password: $DB_PASSWORD"
    echo ""
    echo "🚀 Next Steps:"
    echo "-------------------------------------------"
    echo "1. Install Python dependencies:"
    echo "   pip3 install -r requirements.txt"
    echo ""
    echo "2. Test the connection:"
    echo "   psql -U $DB_USER -d $DB_NAME -h localhost"
    echo "   (password: $DB_PASSWORD)"
    echo ""
    echo "3. Start NetMonitor:"
    echo "   sudo python3 netmonitor.py"
    echo ""
    echo "========================================="
    echo "✨ Setup Complete!"
    echo "========================================="
else
    echo ""
    echo "❌ Error creating database. Please check PostgreSQL logs."
    exit 1
fi
