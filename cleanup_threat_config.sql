-- Cleanup script for threat detection configuration
-- Removes old advanced_threats.* parameters and duplicate entries

BEGIN;

-- Show what we're going to delete
SELECT 'OLD PARAMETERS TO DELETE:' as action;
SELECT parameter_path, parameter_value::text, sensor_id, scope
FROM sensor_configs
WHERE parameter_path LIKE 'advanced_threats.%'
ORDER BY parameter_path;

-- Delete all old advanced_threats.* parameters
DELETE FROM sensor_configs
WHERE parameter_path LIKE 'advanced_threats.%';

SELECT 'DUPLICATE THREAT PARAMETERS:' as action;
-- Show duplicate threat.* parameters (same path, multiple entries)
SELECT parameter_path, COUNT(*) as count
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%'
GROUP BY parameter_path
HAVING COUNT(*) > 1
ORDER BY parameter_path;

-- Delete duplicate entries, keep only the most recent one
DELETE FROM sensor_configs
WHERE id IN (
    SELECT id
    FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY sensor_id, parameter_path
                   ORDER BY updated_at DESC
               ) as rn
        FROM sensor_configs
        WHERE parameter_path LIKE 'threat.%'
    ) t
    WHERE rn > 1
);

-- Show final clean state
SELECT 'FINAL CLEAN STATE:' as action;
SELECT parameter_path, parameter_value::text, sensor_id, scope, updated_at
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%'
ORDER BY parameter_path;

COMMIT;
