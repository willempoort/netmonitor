-- Check whitelist and blacklist in sensor_configs
SELECT
    parameter_path,
    jsonb_typeof(parameter_value) AS jsonb_type,
    CASE
        WHEN jsonb_typeof(parameter_value) = 'string' THEN 'ERROR: Stored as string!'
        WHEN jsonb_typeof(parameter_value) = 'array' THEN 'OK: Stored as array'
        ELSE 'OTHER: ' || jsonb_typeof(parameter_value)
    END AS status,
    parameter_value
FROM sensor_configs
WHERE parameter_path IN ('whitelist', 'blacklist')
   OR parameter_path LIKE '%whitelist%'
   OR parameter_path LIKE '%blacklist%'
ORDER BY parameter_path;
