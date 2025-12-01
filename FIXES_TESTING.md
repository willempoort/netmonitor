# Testing Guide for Recent Fixes

## Two Issues Fixed

### 1. User Dropdown Menu Not Working
### 2. SOC Server Config Not Syncing from Database

---

## Prerequisites

**You MUST restart services after pulling the latest code:**

```bash
# If using systemd (production):
sudo systemctl restart netmonitor-dashboard
sudo systemctl restart netmonitor

# OR if running manually:
# Kill existing processes first:
pkill -f web_dashboard.py
pkill -f netmonitor.py

# Then restart them
```

---

## Fix #1: User Dropdown Menu

### What Was Changed
- File: `web/templates/dashboard.html`
- Bootstrap JS now loads without `defer` attribute
- Added explicit dropdown initialization script
- Dropdowns are initialized on `DOMContentLoaded` event

### How to Test

1. **Clear browser cache** (important!):
   - Chrome/Edge: Ctrl+Shift+Del → Clear cached images and files
   - Firefox: Ctrl+Shift+Del → Cache
   - Or use Incognito/Private mode

2. **Navigate to dashboard**:
   ```
   http://localhost:8181
   ```

3. **Login** with your credentials

4. **Test dropdown**:
   - Look for your username in top-right corner
   - Click on username/role badge
   - Dropdown menu should appear with:
     - Profile Settings
     - Two-Factor Auth
     - User Management (if admin)
     - Logout

5. **Check browser console** (F12 → Console):
   - Should see: `Bootstrap dropdowns initialized: 1`
   - Should NOT see any JavaScript errors

### If Still Not Working

**Check these:**

1. **Browser cache** - Try hard refresh (Ctrl+F5)
2. **JavaScript errors** - Open browser console (F12) and look for red errors
3. **Bootstrap loaded** - In console, type: `typeof bootstrap` should return `"object"`
4. **Network issues** - Check Network tab (F12) - bootstrap.bundle.min.js should load (status 200)

**Debug commands in browser console:**
```javascript
// Check if Bootstrap is loaded
console.log(typeof bootstrap);  // Should be "object"

// Check if dropdown element exists
console.log(document.getElementById('userMenuButton'));  // Should show button element

// Try to manually initialize
var btn = document.getElementById('userMenuButton');
var dropdown = new bootstrap.Dropdown(btn);
dropdown.show();  // Should show dropdown
```

---

## Fix #2: SOC Server Config Sync

### What Was Changed
- File: `netmonitor.py`
- Added `_deep_merge_config()` function for proper config merging
- Added `_count_config_differences()` to track changes
- Improved logging with ✓ symbols
- Config syncs every 5 minutes automatically

### How to Test

**Step 1: Verify self-monitoring is enabled**
```bash
grep -A2 "^self_monitor:" config.yaml
```

Should show:
```yaml
self_monitor:
  enabled: true
  sensor_id: soc-server
```

If `enabled: false`, set it to `true` and restart.

**Step 2: Restart SOC server**
```bash
# If using systemd:
sudo systemctl restart netmonitor

# OR manually:
pkill -f netmonitor.py
python3 netmonitor.py &
```

**Step 3: Check startup logs**

Look for these messages in logs:
```bash
# View logs (systemd):
sudo journalctl -u netmonitor -n 50

# OR if running manually:
tail -f /var/log/netmonitor/netmonitor.log
```

Expected output:
```
INFO - SOC server self-monitoring enabled as sensor: soc-server
INFO - Config sync enabled (checking every 300s)
```

If you see these, config sync is ACTIVE.

**Step 4: Test config changes**

1. **Go to dashboard** → Configuration Management
2. **Edit a threshold** (e.g., port_scan unique_ports)
3. **Save changes**
4. **Wait up to 5 minutes** (or check every 30 seconds)
5. **Check logs** for:
   ```
   INFO - ✓ Config updated from database: X parameter(s) changed
   INFO -   Updated categories: port_scan, connection_flood
   ```

**Step 5: Verify config is applied**

After seeing the log message, check if the new threshold is active:

```bash
# Check detector's current config (requires manual inspection or logging)
# The detector should now use the database values instead of config.yaml
```

### If Config Still Not Syncing

**Diagnose the issue:**

1. **Check database connection**:
   ```bash
   psql -h localhost -U netmonitor -d netmonitor -c "SELECT COUNT(*) FROM config_parameters;"
   ```
   Should return a count (not an error).

2. **Check if config exists in database**:
   ```bash
   psql -h localhost -U netmonitor -d netmonitor -c "
   SELECT sensor_id, parameter_path, COUNT(*)
   FROM config_parameters
   WHERE sensor_id IS NULL OR sensor_id = 'soc-server'
   GROUP BY sensor_id, parameter_path;
   "
   ```

3. **Check self_monitor.enabled**:
   ```bash
   grep "self_monitor_enabled" /var/log/netmonitor/netmonitor.log
   ```

4. **Check for errors**:
   ```bash
   grep -i "error.*config" /var/log/netmonitor/netmonitor.log
   ```

### Manual Test Script

Run the diagnostic script:
```bash
cd /home/user/netmonitor
python3 test_config_sync.py
```

This will tell you:
- ✓ If self-monitoring is enabled
- ✓ If database connection works
- ✓ If config exists in database
- ✓ What will happen when SOC server starts

---

## Expected Behavior After Fixes

### User Dropdown
- **Before**: Clicking username does nothing
- **After**: Dropdown menu appears with options

### Config Sync
- **Before**: Only config.yaml values used, changes in dashboard ignored
- **After**:
  - Startup: config.yaml + database (database wins)
  - Every 5 min: Re-sync from database
  - Immediate effect: No restart needed

---

## Configuration Priority

For SOC server (sensor ID: `soc-server`):

1. **Highest**: Database sensor-specific config (WHERE sensor_id = 'soc-server')
2. **Medium**: Database global config (WHERE sensor_id IS NULL)
3. **Lowest**: config.yaml (fallback)

---

## Troubleshooting

### Problem: Dropdown still doesn't work after restart

**Solution:**
1. Clear browser cache completely
2. Try different browser
3. Check browser console for errors
4. Verify Bootstrap loads: Network tab should show bootstrap.bundle.min.js (200 OK)

### Problem: Config sync not happening

**Solution:**
1. Verify `self_monitor.enabled: true` in config.yaml
2. Restart netmonitor service
3. Check logs for "Config sync enabled"
4. Wait full 5 minutes after making dashboard changes
5. Check database has config: Run queries above

### Problem: See errors in logs

**Common errors:**

- `ModuleNotFoundError: psycopg2` → Install dependencies: `pip install -r requirements.txt`
- `Database connection failed` → Check PostgreSQL is running: `systemctl status postgresql`
- `Could not load config from database` → Check database config in config.yaml

---

## Verification Commands

**Check if dashboard is running:**
```bash
ps aux | grep web_dashboard
netstat -tuln | grep 8181
```

**Check if netmonitor is running:**
```bash
ps aux | grep netmonitor.py
```

**Check recent logs:**
```bash
tail -f /var/log/netmonitor/netmonitor.log | grep -E "Config|✓"
```

**Check database has data:**
```bash
psql -h localhost -U netmonitor -d netmonitor -c "
SELECT parameter_path, value
FROM config_parameters
WHERE sensor_id = 'soc-server'
LIMIT 5;
"
```

---

## Support

If issues persist after following this guide:

1. Collect logs:
   ```bash
   journalctl -u netmonitor -n 100 > netmonitor.log
   journalctl -u netmonitor-dashboard -n 100 > dashboard.log
   ```

2. Check browser console errors (screenshot)

3. Run diagnostic script: `python3 test_config_sync.py`

4. Provide output from all above
