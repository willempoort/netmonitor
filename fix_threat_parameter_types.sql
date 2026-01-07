-- Fix parameter types for all threat.*.enabled parameters
-- Problem: Some old entries have parameter_type = 'str' instead of 'bool'
-- Solution: Update all threat.*.enabled to parameter_type = 'bool'

-- First, let's see what we have
SELECT parameter_path, parameter_value, parameter_type
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%.enabled'
ORDER BY parameter_path;

-- Update all threat.*.enabled to correct type
UPDATE sensor_configs
SET parameter_type = 'bool'
WHERE parameter_path LIKE 'threat.%.enabled'
  AND parameter_type != 'bool';

-- Verify the fix
SELECT
    COUNT(*) FILTER (WHERE parameter_type = 'bool') as bool_count,
    COUNT(*) FILTER (WHERE parameter_type = 'str') as str_count,
    COUNT(*) as total
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%.enabled';

-- Expected result: all should be 'bool', none should be 'str'
