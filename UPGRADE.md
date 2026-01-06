# NetMonitor Upgrade Guide

## Upgrading from Older Versions

NetMonitor now includes automatic database migration tools that handle upgrades seamlessly.

### Quick Upgrade (Recommended)

```bash
cd /opt/netmonitor

# Pull latest code
git fetch origin
git checkout <branch-name>  # e.g., main or claude/fix-ssh-port-detection-mrPfo
git pull

# Run auto-fix script (handles all migrations)
venv/bin/python3 check_database_status.py

# Restart services
sudo systemctl restart netmonitor netmonitor-dashboard

# Hard refresh browser (Ctrl+F5)
```

### What the Auto-Fix Script Does

The `check_database_status.py` script automatically detects and fixes:

1. **Missing `netmonitor_meta` table** (pre-v13 databases)
   - Auto-creates table with current schema version
   - No manual SQL needed!

2. **Old `advanced_threats.*` parameters** (pre-threat-detection refactor)
   - Deletes old `advanced_threats.cryptomining.enabled` etc.
   - Migrates to new `threat.cryptomining.enabled` format
   - Removes duplicate entries

3. **Duplicate configuration parameters**
   - Keeps most recent value
   - Cleans up database

### Manual Upgrade (Advanced)

If you prefer to see exactly what will be changed:

```bash
cd /opt/netmonitor

# Check current status (read-only)
sudo -u postgres psql netmonitor -c "
SELECT tablename FROM pg_tables
WHERE schemaname='public'
AND tablename IN ('netmonitor_meta', 'sensor_configs', 'schema_version');
"

# Check for old parameters
sudo -u postgres psql netmonitor -c "
SELECT parameter_path, COUNT(*)
FROM sensor_configs
WHERE parameter_path LIKE 'advanced_threats.%' OR parameter_path LIKE 'threat.%'
GROUP BY parameter_path;
"

# Run migrations manually (if needed)
sudo -u postgres psql netmonitor -f cleanup_threat_config.sql
```

### Upgrade Checklist

- [ ] Pull latest code from repository
- [ ] Run `check_database_status.py` (auto-fixes issues)
- [ ] Restart services
- [ ] Hard refresh browser (Ctrl+F5 or Cmd+Shift+R)
- [ ] Verify threat detection config in Web UI
- [ ] Check logs for errors: `journalctl -u netmonitor -n 100`

### Troubleshooting

**Issue: "netmonitor_meta table does not exist"**
- ✓ Fixed automatically by `check_database_status.py`
- Creates table with schema_version=13

**Issue: Parameters show wrong values in UI**
- ✓ Fixed automatically by `check_database_status.py`
- Removes old `advanced_threats.*` parameters
- Deduplicates `threat.*` parameters

**Issue: Toggles don't work in Advanced Threats tab**
- Hard refresh browser (Ctrl+F5)
- Check JavaScript console (F12) for errors
- Verify cache buster version: view-source, search for `config-management.js?v=4`

**Issue: "Database is not configured"**
- Check `config.yaml` has:
  ```yaml
  database:
    type: postgresql
    postgresql:
      host: localhost
      ...
  ```

### Version History

- **v13**: Current version with `netmonitor_meta` table
- **pre-v13**: Used `schema_version` table (migrated automatically)
- **pre-threat-detection**: Used `advanced_threats.*` (migrated automatically)

### Need Help?

```bash
# Check database status
venv/bin/python3 check_database_status.py

# View recent logs
journalctl -u netmonitor -n 100
journalctl -u netmonitor-dashboard -n 100

# Check what's running
systemctl status netmonitor netmonitor-dashboard
```

## After Upgrading

1. **Verify Web UI works**: http://localhost:8080
2. **Check threat detection**: Configuration → Advanced Threats tab
3. **Test toggles**: Enable/disable a threat type and save
4. **Check sensors**: Verify sensors sync new config (wait 5 min)

Done! 🎉
