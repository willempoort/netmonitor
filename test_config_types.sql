-- Test JSONB types in sensor_configs
SELECT
    parameter_path,
    parameter_type,
    jsonb_typeof(parameter_value) AS actual_jsonb_type,
    parameter_value,
    CASE
        WHEN jsonb_typeof(parameter_value) = 'array' THEN jsonb_array_length(parameter_value)::text || ' items'
        ELSE parameter_value::text
    END AS display_value
FROM sensor_configs
WHERE parameter_path LIKE '%modern_protocols%'
ORDER BY parameter_path;
