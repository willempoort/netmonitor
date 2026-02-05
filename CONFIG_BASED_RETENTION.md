# Config-Based Data Retention - Implementation

## Overview

Data retention policies are now dynamically loaded from `config.yaml` at startup, ensuring database policies always match configuration. Includes NIS2 compliance warnings when retention periods are below legal minimums.

**Implementation Date**: 2026-02-05
**Status**: ✅ Production Ready

---

## Key Features

### 1. Single Source of Truth

**Before**: Retention periods hardcoded in database.py and web_dashboard.py
**After**: All retention settings come from `config.yaml`

```yaml
# config.yaml
data_retention:
  alerts_days: 365      # Database & cleanup use this value
  metrics_days: 90      # Database & cleanup use this value
  audit_logs_days: 730  # For future audit log cleanup
```

### 2. Automatic Policy Updates

On database startup:
1. Reads retention config from `config.yaml`
2. Removes existing TimescaleDB retention policies
3. Creates new policies with config values
4. Logs warnings if below NIS2 minimum

```python
# Database automatically syncs with config
db = DatabaseManager(config=config)
# -> Retention policies updated from config.yaml
```

### 3. NIS2 Compliance Checks

**Minimum Requirements**:
- Alerts: 365 days (12 months)
- Audit logs: 730 days (24 months)

**Automatic Warnings**:
```
⚠️ COMPLIANCE WARNING: Alert retention (180 days) is below NIS2 minimum requirement (365 days)
```

### 4. API Endpoint for Frontend

New endpoint: `GET /api/data-retention/config`

Returns:
```json
{
  "success": true,
  "data": {
    "alerts_days": 365,
    "metrics_days": 90,
    "audit_days": 730,
    "nis2_compliant": {
      "alerts": true,
      "audit": true,
      "overall": true
    },
    "warnings": []
  }
}
```

---

## Files Modified

### 1. database.py

**Lines 21-25**: Added `config` parameter to `__init__`
```python
def __init__(self, ..., config=None):
    self.config = config  # Store config for retention policies
```

**Lines 123-199**: New methods
- `_update_retention_policies(cursor)` - Syncs DB policies with config
- `get_retention_config()` - Returns config + compliance status

**Line 988**: Use dynamic retention policies
```python
# Old: Hard-coded 90 days
SELECT add_retention_policy('alerts', INTERVAL '90 days', ...)

# New: From config
self._update_retention_policies(cursor)
```

### 2. web_dashboard.py

**Line 136**: Pass config to DatabaseManager
```python
db = DatabaseManager(..., config=config)
```

**Lines 2577-2650**: Updated cleanup endpoint to use config
```python
# Old: Hard-coded intervals
DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '365 days'

# New: Dynamic from config
retention = db.get_retention_config()
DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '{retention['alerts_days']} days'
```

**Lines 2652-2665**: New API endpoint
```python
@app.route('/api/data-retention/config', methods=['GET'])
def api_data_retention_config():
    return db.get_retention_config()
```

---

## Configuration Example

### NIS2 Compliant (Recommended)

```yaml
data_retention:
  enabled: true

  # NIS2 minimum: 365 days (12 months)
  alerts_days: 365

  # High volume data - shorter retention OK
  metrics_days: 90

  # NIS2 minimum: 730 days (24 months)
  audit_logs_days: 730

  # Transient data
  statistics_days: 30
  devices_inactive_days: 180
```

### Test Environment (Lower Retention)

```yaml
data_retention:
  enabled: true

  alerts_days: 30      # ⚠️ Below NIS2 minimum
  metrics_days: 7      # Fast cleanup for testing
  audit_logs_days: 30  # ⚠️ Below NIS2 minimum
```

**Result**: Logs show warnings but system continues to work:
```
⚠️ COMPLIANCE WARNING: Alert retention (30 days) is below NIS2 minimum (365 days)
✓ Retention policies updated successfully
```

---

## Testing

### Verify Config is Used

```bash
# Check what retention periods are loaded
python3 << 'EOF'
from config_loader import load_config
from database import DatabaseManager

config = load_config('config.yaml')
db = DatabaseManager(config=config)
retention = db.get_retention_config()

print(f"Alerts: {retention['alerts_days']} days")
print(f"Metrics: {retention['metrics_days']} days")
print(f"NIS2 Compliant: {retention['nis2_compliant']['overall']}")
EOF
```

### Test Policy Updates

```bash
# 1. Edit config.yaml - change alerts_days to 180
vim config.yaml

# 2. Restart dashboard
systemctl restart netmonitor-dashboard

# 3. Check logs for warnings
journalctl -u netmonitor-dashboard --since "1 minute ago" | grep COMPLIANCE
# Should show: ⚠️ COMPLIANCE WARNING: Alert retention (180 days)...

# 4. Verify cleanup uses new value
curl -X POST http://localhost:8080/api/data-retention/cleanup
# Will delete alerts older than 180 days (not 365)
```

### Test API Endpoint

```bash
curl http://localhost:8080/api/data-retention/config | jq
```

Expected output:
```json
{
  "success": true,
  "data": {
    "alerts_days": 365,
    "metrics_days": 90,
    "audit_days": 730,
    "nis2_compliant": {
      "alerts": true,
      "audit": true,
      "overall": true
    },
    "warnings": []
  }
}
```

---

## Frontend Integration (Future)

### Show Warning on Cleanup Button

The frontend can check compliance before cleanup:

```javascript
// Fetch retention config
const response = await fetch('/api/data-retention/config');
const {data} = await response.json();

// Show warning if not NIS2 compliant
if (!data.nis2_compliant.overall) {
    const warnings = data.warnings.filter(w => w).join('\n');
    if (!confirm(`⚠️ COMPLIANCE WARNING\n\n${warnings}\n\nContinue with cleanup?`)) {
        return;
    }
}

// Proceed with cleanup
await fetch('/api/data-retention/cleanup', {method: 'POST'});
```

### Display Current Settings

```javascript
// Show retention periods in dashboard
document.getElementById('alerts-retention').textContent = `${data.alerts_days} days`;
document.getElementById('metrics-retention').textContent = `${data.metrics_days} days`;

// Show compliance badge
if (data.nis2_compliant.overall) {
    badge.className = 'badge bg-success';
    badge.textContent = 'NIS2 Compliant';
} else {
    badge.className = 'badge bg-warning';
    badge.textContent = 'Below NIS2 Minimum';
}
```

---

## Benefits

### 1. Operational

- ✅ Change retention in one place (config.yaml)
- ✅ No code changes required
- ✅ Database auto-syncs on restart
- ✅ Test environments can use shorter retention

### 2. Compliance

- ✅ Automatic NIS2 compliance checking
- ✅ Warnings logged on startup
- ✅ Frontend can show warnings to users
- ✅ Audit trail of retention settings

### 3. Development

- ✅ Single source of truth
- ✅ Easier to test different scenarios
- ✅ No hardcoded values
- ✅ Config-driven behavior

---

## Migration Guide

### From Hardcoded to Config-Based

**Old Way**:
```python
# database.py
SELECT add_retention_policy('alerts', INTERVAL '90 days', ...)

# web_dashboard.py
DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '90 days'
```

**New Way**:
```yaml
# config.yaml
data_retention:
  alerts_days: 365
```

```python
# database.py - automatic
db = DatabaseManager(config=config)
# -> Policies updated from config

# web_dashboard.py - automatic
retention = db.get_retention_config()
# -> Cleanup uses config values
```

### No Manual Migration Needed

The system automatically:
1. Removes old hardcoded policies
2. Creates new config-based policies
3. Uses config values for cleanup

---

## Troubleshooting

### Policies Not Updated

**Symptom**: Old retention periods still in use

**Solution**:
```bash
# Force policy update
python3 << 'EOF'
from database import DatabaseManager
from config_loader import load_config

config = load_config('config.yaml')
db = DatabaseManager(config=config)

conn = db._get_connection()
cursor = conn.cursor()
db._update_retention_policies(cursor)
conn.commit()
db._return_connection(conn)

print("✓ Policies updated")
EOF
```

### Warnings Not Showing

**Symptom**: No compliance warnings in logs

**Check**:
```bash
# Verify config is loaded
journalctl -u netmonitor-dashboard | grep "Configuring retention"

# Should show:
# Configuring retention policies: alerts=365d, metrics=90d
```

### Config Not Found

**Symptom**: Using default values instead of config

**Check**:
```bash
# Verify config file exists
ls -l /opt/netmonitor/config.yaml

# Check logs for "No config provided"
journalctl -u netmonitor-dashboard | grep "No config provided"
```

---

## Summary

| Aspect | Before | After |
|--------|--------|-------|
| Retention Source | Hardcoded in code | config.yaml |
| Change Process | Edit code, restart | Edit config, restart |
| Compliance Check | Manual | Automatic |
| Frontend Warnings | No | Yes (via API) |
| Test Flexibility | Limited | Full |
| NIS2 Compliance | Hope for the best | Verified on startup |

---

**Last Updated**: 2026-02-05
**Status**: Production Ready ✅
**Breaking Changes**: None (backwards compatible)
**Config Required**: Yes (uses defaults if missing)
