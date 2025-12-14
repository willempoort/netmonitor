-- Fix whitelist entries that are stored as JSON strings instead of arrays
-- This converts the string representations to proper JSONB arrays

-- Delete the malformed whitelist entries first
DELETE FROM sensor_configs WHERE parameter_path = 'whitelist';

-- Re-insert whitelist as proper JSONB array based on config.yaml format
-- Note: Adjust these IPs to match your actual network configuration
INSERT INTO sensor_configs (parameter_path, parameter_value, parameter_type, sensor_id, scope, description, updated_by, updated_at)
VALUES (
    'whitelist',
    '["127.0.0.1", "192.168.1.0/24"]'::jsonb,
    'list',
    NULL,
    'global',
    'Trusted IPs that should not trigger alerts',
    'system',
    NOW()
)
ON CONFLICT (sensor_id, parameter_path)
DO UPDATE SET
    parameter_value = EXCLUDED.parameter_value,
    parameter_type = 'list',
    updated_at = NOW(),
    updated_by = 'system';

-- Verify the fix
SELECT
    parameter_path,
    jsonb_typeof(parameter_value) AS jsonb_type,
    CASE
        WHEN jsonb_typeof(parameter_value) = 'array' THEN 'OK: Stored as array'
        ELSE 'ERROR: ' || jsonb_typeof(parameter_value)
    END AS status,
    parameter_value
FROM sensor_configs
WHERE parameter_path = 'whitelist';
