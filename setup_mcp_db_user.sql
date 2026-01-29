-- Setup read-only database user for MCP server
-- This user can only SELECT data, no modifications allowed
-- Script is idempotent - safe to run multiple times

-- Create the user (skip if exists)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mcp_readonly') THEN
        CREATE USER mcp_readonly WITH PASSWORD 'mcp_netmonitor_readonly_2024';
        RAISE NOTICE 'Created user mcp_readonly';
    ELSE
        RAISE NOTICE 'User mcp_readonly already exists';
    END IF;
END
$$;

-- Grant connection to database
GRANT CONNECT ON DATABASE netmonitor TO mcp_readonly;

-- Grant usage on schema
GRANT USAGE ON SCHEMA public TO mcp_readonly;

-- Grant SELECT on ALL existing tables (including device tables)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;

-- Grant SELECT on all existing sequences (for id columns)
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_readonly;

-- Set default privileges for future tables created by different users
-- This ensures mcp_readonly gets SELECT on tables created by postgres, netmonitor, or root
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON TABLES TO mcp_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE netmonitor IN SCHEMA public GRANT SELECT ON TABLES TO mcp_readonly;

-- Also set for sequences
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON SEQUENCES TO mcp_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE netmonitor IN SCHEMA public GRANT SELECT ON SEQUENCES TO mcp_readonly;

-- Verify grants
\echo '=== User info ==='
\du mcp_readonly

\echo '=== Table permissions (sample) ==='
SELECT
    schemaname,
    tablename,
    has_table_privilege('mcp_readonly', schemaname || '.' || tablename, 'SELECT') as can_select
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename
LIMIT 15;

\echo '=== Setup complete ==='
\echo 'Test with: psql -h localhost -U mcp_readonly -d netmonitor -c "SELECT COUNT(*) FROM devices;"'
