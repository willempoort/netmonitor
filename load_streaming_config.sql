-- Load streaming service and CDN configuration parameters into database
-- This inserts the new modern_protocols configuration

-- Insert brute_force exclusion flags
INSERT INTO sensor_configs (parameter_path, parameter_value, sensor_id, scope, description, updated_by, updated_at)
VALUES
    ('thresholds.brute_force.exclude_streaming', 'true'::jsonb, NULL, 'global', 'Default value from config.yaml', 'system', NOW()),
    ('thresholds.brute_force.exclude_cdn', 'true'::jsonb, NULL, 'global', 'Default value from config.yaml', 'system', NOW())
ON CONFLICT (parameter_path, COALESCE(sensor_id, '00000000-0000-0000-0000-000000000000'))
DO UPDATE SET
    parameter_value = EXCLUDED.parameter_value,
    updated_at = NOW(),
    updated_by = 'system';

-- Insert modern_protocols detection flags
INSERT INTO sensor_configs (parameter_path, parameter_value, sensor_id, scope, description, updated_by, updated_at)
VALUES
    ('thresholds.modern_protocols.quic_detection', 'true'::jsonb, NULL, 'global', 'Default value from config.yaml', 'system', NOW()),
    ('thresholds.modern_protocols.http3_detection', 'true'::jsonb, NULL, 'global', 'Default value from config.yaml', 'system', NOW())
ON CONFLICT (parameter_path, COALESCE(sensor_id, '00000000-0000-0000-0000-000000000000'))
DO UPDATE SET
    parameter_value = EXCLUDED.parameter_value,
    updated_at = NOW(),
    updated_by = 'system';

-- Insert streaming_services IP ranges as JSONB array
INSERT INTO sensor_configs (parameter_path, parameter_value, sensor_id, scope, description, updated_by, updated_at)
VALUES (
    'thresholds.modern_protocols.streaming_services',
    '["23.246.0.0/18","37.77.184.0/21","45.57.0.0/17","64.120.128.0/17","66.197.128.0/17","108.175.32.0/20","185.2.220.0/22","185.9.188.0/22","192.173.64.0/18","198.38.96.0/19","198.45.48.0/20","208.75.76.0/22","2620:10c:7000::/44","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16","216.58.192.0/19","2001:4860::/32","13.32.0.0/15","13.224.0.0/14","13.249.0.0/16","18.64.0.0/14","2600:9000::/28"]'::jsonb,
    NULL,
    'global',
    'Default value from config.yaml',
    'system',
    NOW()
)
ON CONFLICT (parameter_path, COALESCE(sensor_id, '00000000-0000-0000-0000-000000000000'))
DO UPDATE SET
    parameter_value = EXCLUDED.parameter_value,
    updated_at = NOW(),
    updated_by = 'system';

-- Insert cdn_providers IP ranges as JSONB array
INSERT INTO sensor_configs (parameter_path, parameter_value, sensor_id, scope, description, updated_by, updated_at)
VALUES (
    'thresholds.modern_protocols.cdn_providers',
    '["104.16.0.0/13","172.64.0.0/13","162.158.0.0/15","2606:4700::/32","23.32.0.0/11","23.192.0.0/11","95.100.0.0/15","2.16.0.0/13","184.24.0.0/13","2600:1400::/24"]'::jsonb,
    NULL,
    'global',
    'Default value from config.yaml',
    'system',
    NOW()
)
ON CONFLICT (parameter_path, COALESCE(sensor_id, '00000000-0000-0000-0000-000000000000'))
DO UPDATE SET
    parameter_value = EXCLUDED.parameter_value,
    updated_at = NOW(),
    updated_by = 'system';

-- Verify the inserts
SELECT
    parameter_path,
    CASE
        WHEN jsonb_typeof(parameter_value) = 'array' THEN 'Array with ' || jsonb_array_length(parameter_value) || ' items'
        ELSE parameter_value::text
    END as value,
    updated_at
FROM sensor_configs
WHERE parameter_path LIKE '%streaming%' OR parameter_path LIKE '%cdn%' OR parameter_path LIKE '%modern_protocols%'
ORDER BY parameter_path;
