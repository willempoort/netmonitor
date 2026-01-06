-- Migration: Rename advanced_threats.* to threat.* in sensor_configs
-- This fixes the prefix mismatch between old and new configuration naming

-- Update all parameters that start with 'advanced_threats.' to 'threat.'
UPDATE sensor_configs
SET parameter_path = 'threat.' || substring(parameter_path from 19)
WHERE parameter_path LIKE 'advanced_threats.%';

-- Show what was updated
SELECT
    parameter_path,
    parameter_value,
    scope,
    sensor_id,
    updated_at
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%'
ORDER BY parameter_path;
