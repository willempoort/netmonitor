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

# Add TimescaleDB repository
if [ ! -f /etc/apt/sources.list.d/timescale_timescaledb.list ]; then
    echo "Adding TimescaleDB repository..."
    apt-get update
    apt-get install -y wget gnupg lsb-release

    # Add TimescaleDB APT repository
    sh -c "echo 'deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescale_timescaledb.list"
    wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | apt-key add -

    apt-get update
fi

# Install PostgreSQL and TimescaleDB
echo "Installing packages..."
apt-get install -y postgresql postgresql-contrib timescaledb-2-postgresql-14

# Tune TimescaleDB
echo "Tuning TimescaleDB..."
timescaledb-tune --quiet --yes

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
