#!/bin/bash
# Setup MCP read-only database user

echo "Setting up MCP read-only database user..."

# Execute SQL as postgres user
sudo -u postgres psql -d netmonitor -f /home/user/netmonitor/setup_mcp_db_user.sql

echo ""
echo "✓ MCP database user created successfully"
echo ""
echo "User: mcp_readonly"
echo "Password: mcp_netmonitor_readonly_2024"
echo "Permissions: SELECT only (read-only)"
echo ""
echo "You can test the connection with:"
echo "psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'"
