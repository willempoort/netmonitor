#!/bin/bash
# Setup MCP read-only database user

echo "Setting up MCP read-only database user..."

# Get the absolute path of the netmonitor directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_FILE="${SCRIPT_DIR}/setup_mcp_db_user.sql"

# Verify SQL file exists
if [ ! -f "${SQL_FILE}" ]; then
    echo "❌ Error: SQL file not found at ${SQL_FILE}"
    exit 1
fi

echo "Using SQL file: ${SQL_FILE}"

# Execute SQL as postgres user
sudo -u postgres psql -d netmonitor -f "${SQL_FILE}"

echo ""
echo "✓ MCP database user created successfully"
echo ""
echo "User: mcp_readonly"
echo "Password: mcp_netmonitor_readonly_2024"
echo "Permissions: SELECT only (read-only)"
echo ""
echo "You can test the connection with:"
echo "psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'"
