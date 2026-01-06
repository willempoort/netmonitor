-- Check current database schema version and table existence

-- Show current schema version
SELECT
    'Current Schema Version' as info,
    schema_version as version,
    last_updated
FROM netmonitor_meta
LIMIT 1;

-- Check if sensor_configs table exists
SELECT
    'sensor_configs table' as table_name,
    CASE
        WHEN EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = 'sensor_configs'
        ) THEN 'EXISTS ✓'
        ELSE 'NOT FOUND ✗ (need schema upgrade)'
    END as status;

-- If sensor_configs exists, show count
SELECT
    'sensor_configs entries' as info,
    COUNT(*) as count,
    COUNT(DISTINCT parameter_path) as unique_parameters
FROM sensor_configs
WHERE 1=1; -- Will error if table doesn't exist

-- Show threat.* parameters if they exist
SELECT
    parameter_path,
    parameter_value::text,
    scope,
    updated_at
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%'
ORDER BY parameter_path
LIMIT 20;
