-- Setup read-only database user for MCP server
-- This user can only SELECT data, no modifications allowed

-- Create the user
CREATE USER mcp_readonly WITH PASSWORD 'mcp_netmonitor_readonly_2024';

-- Grant connection to database
GRANT CONNECT ON DATABASE netmonitor TO mcp_readonly;

-- Grant usage on schema
GRANT USAGE ON SCHEMA public TO mcp_readonly;

-- Grant SELECT on all existing tables
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;

-- Grant SELECT on all existing sequences (for id columns)
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_readonly;

-- Automatically grant SELECT on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mcp_readonly;

-- Verify grants
\du mcp_readonly
\dp alerts

-- Test connection (optional)
-- \c netmonitor mcp_readonly
-- SELECT COUNT(*) FROM alerts;
