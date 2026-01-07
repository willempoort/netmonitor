# NetMonitor Testing Setup Guide

Quick setup guide for enabling all threat detections for comprehensive testing.

---

## Quick Start

### 1. Fix Database Permissions

If you get "permission denied" errors, run this as postgres user:

```bash
sudo -u postgres psql -d netmonitor -f init_database_for_testing.sql
```

This will:
- Grant all necessary permissions to `netmonitor` user
- Create `netmonitor_meta` table if missing
- **Fix parameter types** (threat.*.enabled from 'str' to 'bool')
- **Enable ALL 60 threat detections**
- Set more sensitive thresholds for easier testing

### 2. Verify Database Status

```bash
python3 check_database_status.py
```

Expected output:
```
✓ Database connection successful!
✓ Schema version: 13
✓ sensor_configs table exists (200+ parameters)
```

### 3. Enable Threats (Alternative Method)

If you prefer interactive enabling:

```bash
python3 enable_all_threats.py
```

This script:
- Shows current enabled/disabled count
- Lists all 60 threat types
- Asks for confirmation
- Enables all at once

---

## Why Are Threats Disabled by Default?

**Production Safety**: In production environments, enabling ALL threats at once can cause:
- High false positive rates (alerts for normal behavior)
- Performance impact (60 detections running simultaneously)
- Alert fatigue (too many alerts to triage)

**Best Practice Approach**:
1. Start with core threats (phishing, cryptomining, DDoS)
2. Tune thresholds based on network baseline
3. Gradually enable additional detections
4. Monitor false positive rate
5. Adjust per-sensor if needed

**For Testing**: Enable everything and adjust thresholds afterward.

---

## Manual SQL Commands

### Enable Specific Phases

```sql
-- Phase 1: Core Advanced Threats
UPDATE sensor_configs SET parameter_value = 'true'
WHERE parameter_path IN (
    'threat.cryptomining.enabled',
    'threat.phishing.enabled',
    'threat.tor.enabled',
    'threat.vpn.enabled',
    'threat.cloud_metadata.enabled',
    'threat.dns_anomaly.enabled'
);

-- Phase 6: OT/ICS (for industrial testing)
UPDATE sensor_configs SET parameter_value = 'true'
WHERE parameter_path LIKE 'threat.modbus_attack.enabled'
   OR parameter_path LIKE 'threat.dnp3_attack.enabled'
   OR parameter_path LIKE 'threat.iec104_attack.enabled';

-- Phase 9: Kill Chain (for advanced testing)
UPDATE sensor_configs SET parameter_value = 'true'
WHERE parameter_path IN (
    'threat.lateral_movement.enabled',
    'threat.data_exfiltration.enabled',
    'threat.privilege_escalation.enabled',
    'threat.persistence.enabled',
    'threat.credential_dumping.enabled'
);
```

### Enable ALL Threats

```sql
UPDATE sensor_configs
SET parameter_value = 'true'
WHERE parameter_path LIKE 'threat.%.enabled';
```

### Check Status

```sql
SELECT
    parameter_path,
    parameter_value as enabled
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%.enabled'
ORDER BY parameter_path;
```

### Count Enabled

```sql
SELECT
    COUNT(*) FILTER (WHERE parameter_value = 'true') as enabled,
    COUNT(*) FILTER (WHERE parameter_value = 'false') as disabled
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%.enabled';
```

---

## Tuning Thresholds for Testing

Lower thresholds = more sensitive = easier to trigger during testing:

```sql
-- Make lateral movement easier to trigger (3 targets instead of 5)
UPDATE sensor_configs
SET parameter_value = '3'
WHERE parameter_path = 'threat.lateral_movement.smb_targets_threshold';

-- Make data exfiltration easier to trigger (50 MB instead of 100 MB)
UPDATE sensor_configs
SET parameter_value = '50'
WHERE parameter_path = 'threat.data_exfiltration.megabytes_threshold';

-- Make Modbus attack easier to trigger (25 writes instead of 50)
UPDATE sensor_configs
SET parameter_value = '25'
WHERE parameter_path = 'threat.modbus_attack.write_ops_threshold';
```

---

## Troubleshooting

### Permission Denied Errors

**Problem**: `permission denied for table netmonitor_meta`

**Solution**:
```bash
sudo -u postgres psql -d netmonitor << 'EOF'
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO netmonitor;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO netmonitor;
EOF
```

### Threats Not Detecting

**Check 1**: Are they enabled?
```bash
python3 check_database_status.py
```

**Check 2**: Did sensors sync?
```bash
# Check sensor logs
sudo journalctl -u netmonitor-sensor -n 50

# Or sensor log file
tail -f /var/log/netmonitor/sensor.log
```

**Check 3**: Force sensor restart
```bash
sudo systemctl restart netmonitor-sensor
```

### Database Not Initializing

**Problem**: `sensor_configs table does not exist`

**Solution**: Run SOC server once to initialize database
```bash
python3 app.py
# Wait 10 seconds, then Ctrl+C
python3 check_database_status.py
```

### Web UI Shows "str" Instead of "bool"

**Problem**: Web UI shows threat.*.enabled parameters with type "str" instead of "bool"

**Cause**: Old database entries from earlier versions stored parameter_type as 'str'

**Solution**: Run the type fix script
```bash
# Quick fix (included in init_database_for_testing.sql)
sudo -u postgres psql -d netmonitor -f fix_threat_parameter_types.sql

# Or manual fix
sudo -u postgres psql -d netmonitor << 'EOF'
UPDATE sensor_configs
SET parameter_type = 'bool'
WHERE parameter_path LIKE 'threat.%.enabled'
  AND parameter_type != 'bool';
EOF
```

**Verify**:
```bash
sudo -u postgres psql -d netmonitor -c "
SELECT parameter_path, parameter_type
FROM sensor_configs
WHERE parameter_path = 'threat.phishing.enabled';
"
```

Expected output: `parameter_type = 'bool'`

---

## Testing Workflow

1. **Setup Database**:
   ```bash
   sudo -u postgres psql -d netmonitor -f init_database_for_testing.sql
   python3 check_database_status.py
   ```

2. **Restart Sensors**:
   ```bash
   sudo systemctl restart netmonitor-sensor
   ```

3. **Run Test Scenarios**:
   ```bash
   # See TEST_SCENARIOS.md for detailed tests
   bash test_lateral_movement.sh
   bash test_docker_escape.sh
   ```

4. **Monitor Alerts**:
   - Web UI: `http://soc-server/alerts`
   - Database: `SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10`
   - Logs: `tail -f /var/log/netmonitor/sensor.log`

5. **Tune Thresholds**:
   - If too many alerts: increase thresholds
   - If no alerts: lower thresholds or check sensor logs

---

## Quick Reference

| Task | Command |
|------|---------|
| Enable all threats | `sudo -u postgres psql -d netmonitor -f init_database_for_testing.sql` |
| Fix parameter types | `sudo -u postgres psql -d netmonitor -f fix_threat_parameter_types.sql` |
| Check status | `python3 check_database_status.py` |
| Interactive enable | `python3 enable_all_threats.py` |
| Restart sensors | `sudo systemctl restart netmonitor-sensor` |
| View alerts | `http://soc-server/alerts` |
| Check logs | `tail -f /var/log/netmonitor/sensor.log` |

---

For detailed test scenarios, see `TEST_SCENARIOS.md`.
For configuration guide, see `THREAT_DETECTION_GUIDE.md`.
