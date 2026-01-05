#!/bin/bash
# Fix corrupted template behavior parameters in the database

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_FILE="$SCRIPT_DIR/fix_corrupted_behaviors.sql"

echo "============================================================"
echo "Template Behavior Corruption Fix"
echo "============================================================"
echo ""

# Check if SQL file exists
if [ ! -f "$SQL_FILE" ]; then
    echo "❌ Error: SQL file not found: $SQL_FILE"
    exit 1
fi

# Try to read database config from config.yaml
CONFIG_FILE="$SCRIPT_DIR/../config.yaml"

if [ -f "$CONFIG_FILE" ]; then
    # Extract database credentials from config.yaml (nested under postgresql)
    DB_HOST=$(grep -A15 "^  postgresql:" "$CONFIG_FILE" | grep "host:" | awk '{print $2}' | tr -d '"')
    DB_PORT=$(grep -A15 "^  postgresql:" "$CONFIG_FILE" | grep "port:" | awk '{print $2}' | tr -d '"')
    DB_NAME=$(grep -A15 "^  postgresql:" "$CONFIG_FILE" | grep "database:" | awk '{print $2}' | tr -d '"')
    DB_USER=$(grep -A15 "^  postgresql:" "$CONFIG_FILE" | grep "user:" | awk '{print $2}' | tr -d '"')
    DB_PASS=$(grep -A15 "^  postgresql:" "$CONFIG_FILE" | grep "password:" | awk '{print $2}' | tr -d '"' | sed 's/#.*//' | xargs)

    if [ -z "$DB_HOST" ] || [ -z "$DB_NAME" ]; then
        echo "❌ Error: Could not read database config from $CONFIG_FILE"
        exit 1
    fi

    echo "📊 Database: $DB_NAME on $DB_HOST:$DB_PORT"
    echo ""

    # Run the SQL file
    export PGPASSWORD="$DB_PASS"
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$SQL_FILE"
    unset PGPASSWORD

    echo ""
    echo "✅ Done! Refresh the web UI to see the fixed behaviors."

else
    echo "❌ Error: Config file not found: $CONFIG_FILE"
    exit 1
fi
