-- NetMonitor: Initialize Database for Testing
-- This sets all threat detections to ENABLED for comprehensive testing

-- Fix permissions for netmonitor user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO netmonitor;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO netmonitor;

-- Create netmonitor_meta table if missing
CREATE TABLE IF NOT EXISTS netmonitor_meta (
    id SERIAL PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO netmonitor_meta (schema_version)
VALUES (13)
ON CONFLICT DO NOTHING;

GRANT ALL PRIVILEGES ON TABLE netmonitor_meta TO netmonitor;
GRANT USAGE, SELECT ON SEQUENCE netmonitor_meta_id_seq TO netmonitor;

-- FIX: Update parameter_type for all threat.*.enabled to 'bool'
-- (Some old entries may have 'str' instead of 'bool' - this fixes Web UI display)
UPDATE sensor_configs
SET parameter_type = 'bool'
WHERE parameter_path LIKE 'threat.%.enabled'
  AND parameter_type != 'bool';

-- Enable ALL threat detections globally for testing
UPDATE sensor_configs
SET parameter_value = 'true',
    updated_at = NOW(),
    updated_by = 'init_for_testing'
WHERE parameter_path LIKE 'threat.%.enabled'
  AND scope = 'global';

-- Set reasonable thresholds for testing (lower = more sensitive)
UPDATE sensor_configs
SET parameter_value = '3',  -- Lower from 5
    updated_at = NOW()
WHERE parameter_path = 'threat.lateral_movement.smb_targets_threshold';

UPDATE sensor_configs
SET parameter_value = '50',  -- Lower from 100 MB
    updated_at = NOW()
WHERE parameter_path = 'threat.data_exfiltration.megabytes_threshold';

UPDATE sensor_configs
SET parameter_value = '3',  -- Lower from 5
    updated_at = NOW()
WHERE parameter_path = 'threat.privilege_escalation.attempts_threshold';

-- Verify results
SELECT
    COUNT(*) FILTER (WHERE parameter_value = 'true') as enabled,
    COUNT(*) FILTER (WHERE parameter_value = 'false') as disabled,
    COUNT(*) as total
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%.enabled';

-- Verify parameter types are correct (all should be 'bool', none 'str')
SELECT
    COUNT(*) FILTER (WHERE parameter_type = 'bool') as bool_count,
    COUNT(*) FILTER (WHERE parameter_type = 'str') as str_count
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%.enabled';
