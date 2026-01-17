# Troubleshooting: Empty Top Talkers

## Quick Diagnostic Command

Run this one-liner on the SOC server to diagnose why Top Talkers is empty:

```bash
sudo -u postgres psql -d netmonitor -c "
SELECT
    'Recent records (5min)' as check_type,
    COUNT(*)::text as result
FROM top_talkers
WHERE timestamp > NOW() - INTERVAL '5 minutes'
UNION ALL
SELECT
    'Active sensors (5min)',
    COUNT(DISTINCT sensor_id)::text
FROM top_talkers
WHERE timestamp > NOW() - INTERVAL '5 minutes'
UNION ALL
SELECT
    'Total records',
    COUNT(*)::text
FROM top_talkers;
"
```

**Expected output:**
```
       check_type        | result
-------------------------+--------
 Recent records (5min)   | 150
 Active sensors (5min)   | 2
 Total records           | 45234
```

**If you see zeros** → Continue with full diagnostic below.

---

## Full Diagnostic Script

For detailed analysis, run the full diagnostic script:

```bash
cd /opt/netmonitor
sudo ./tools/diagnose_top_talkers.sh
```

This script checks:
- ✅ Database table existence
- ✅ Recent data (last 5 minutes)
- ✅ Active sensors reporting data
- ✅ SOC server configuration
- ✅ Interface configuration
- ✅ Service status
- ✅ Log analysis

---

## Common Issues & Solutions

### Issue 1: "Recent records (5min) = 0"

**Cause**: No sensors are collecting Top Talkers data

**Check**:
```bash
# Check if SOC server self-monitoring is enabled
grep -A5 "self_monitor:" config.yaml

# Check netmonitor service
sudo systemctl status netmonitor
```

**Solution**:
1. Enable self-monitoring in `config.yaml`:
   ```yaml
   self_monitor:
     enabled: true
     interface: ens192  # Your network interface
   ```

2. Restart service:
   ```bash
   sudo systemctl restart netmonitor
   ```

---

### Issue 2: "Interface configuration is EMPTY"

**Cause**: No network interface selected in sensor settings

**Impact**: 🔴 **CRITICAL** - Sensor cannot monitor traffic!

**Check**:
```bash
# Check interface config in database
sudo -u postgres psql -d netmonitor -c "
SELECT sensor_id, parameter_value
FROM sensor_configs
WHERE parameter_path = 'interface';
"
```

**Solution**:
1. Open Dashboard → Sensors
2. Click gear icon (⚙️) on SOC server sensor
3. Select at least one network interface
4. Click "Save Settings"
5. Restart SOC server:
   ```bash
   sudo systemctl restart netmonitor
   ```

See: [INTERFACE_CONFIGURATION.md](INTERFACE_CONFIGURATION.md) for details.

---

### Issue 3: Interface exists but "NOT in PROMISC mode"

**Cause**: Interface not in promiscuous mode

**Impact**: ⚠️ Limited visibility - only sees traffic to/from sensor IP

**Check**:
```bash
ip link show ens192 | grep PROMISC
```

**Solution**:
```bash
# Enable promiscuous mode
sudo ip link set ens192 promisc on

# Verify
ip link show ens192
# Should show: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP>
```

**Note**: The netmonitor service should enable this automatically on startup.

---

### Issue 4: "netmonitor service is NOT running"

**Cause**: Service crashed or not started

**Check**:
```bash
sudo systemctl status netmonitor
sudo journalctl -u netmonitor -n 50
```

**Solution**:
```bash
# Start service
sudo systemctl start netmonitor

# Enable on boot
sudo systemctl enable netmonitor

# Check logs
sudo journalctl -u netmonitor -f
```

---

### Issue 5: Remote sensors not sending data

**Cause**: Remote sensors not connected or misconfigured

**Check**:
```bash
# List registered sensors
sudo -u postgres psql -d netmonitor -c "
SELECT sensor_id, hostname, status, last_seen
FROM sensors
ORDER BY last_seen DESC;
"
```

**Look for**:
- `status = 'offline'` → Sensor not connected
- `last_seen` > 5 minutes ago → Sensor not sending heartbeat

**Solution** (on remote sensor):
```bash
# Check sensor service
sudo systemctl status netmonitor-sensor

# Check sensor logs
sudo journalctl -u netmonitor-sensor -n 100

# Restart sensor
sudo systemctl restart netmonitor-sensor
```

---

### Issue 6: Database connection issues

**Cause**: PostgreSQL not running or connection refused

**Check**:
```bash
# Test database connection
sudo -u postgres psql -d netmonitor -c "SELECT NOW();"

# Check PostgreSQL status
sudo systemctl status postgresql
```

**Solution**:
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Restart netmonitor
sudo systemctl restart netmonitor
```

---

## Manual Data Verification

### Check if traffic is being captured

```bash
# Watch netmonitor logs
sudo journalctl -u netmonitor -f

# Look for lines like:
# "Packets processed: 1234"
# "Top talkers updated: 10 entries"
```

### Check raw database contents

```bash
# Show recent top talkers
sudo -u postgres psql -d netmonitor -c "
SELECT
    timestamp,
    sensor_id,
    ip_address::text,
    hostname,
    packet_count,
    byte_count,
    direction
FROM top_talkers
WHERE timestamp > NOW() - INTERVAL '5 minutes'
ORDER BY timestamp DESC
LIMIT 20;
"
```

### Check metrics collection

```bash
# Check if MetricsCollector is working
sudo -u postgres psql -d netmonitor -c "
SELECT
    sensor_id,
    timestamp,
    packets_processed,
    bytes_processed
FROM sensor_metrics
WHERE timestamp > NOW() - INTERVAL '5 minutes'
ORDER BY timestamp DESC
LIMIT 10;
"
```

---

## Expected Behavior

### Normal Operation

When Top Talkers is working correctly:

1. **Traffic Capture**:
   - Packets being sniffed on configured interface
   - Logs show: `"Starting packet capture..."`

2. **Data Collection** (every 60 seconds by default):
   - MetricsCollector tracks IP addresses
   - Top 20 talkers inserted into database

3. **Database Storage**:
   - `top_talkers` table receives new records every 60s
   - Old records automatically retained (TimescaleDB)

4. **Dashboard Display**:
   - Query last 5 minutes of data
   - Shows top 10 talkers sorted by bandwidth (Mbps)

### Timing

- **Metrics interval**: 60 seconds (configurable)
- **Dashboard refresh**: Every 5 seconds (auto-refresh)
- **Data retention**: Last 5 minutes for Top Talkers display

---

## Advanced Debugging

### Enable Debug Logging

Edit `config.yaml`:
```yaml
logging:
  level: DEBUG  # Change from INFO to DEBUG
```

Restart:
```bash
sudo systemctl restart netmonitor
```

Watch detailed logs:
```bash
sudo journalctl -u netmonitor -f
```

### Monitor Packet Capture

```bash
# Watch interface traffic (should match netmonitor interface)
sudo tcpdump -i ens192 -c 100

# Count packets per second
sudo tcpdump -i ens192 -nn | pv -l > /dev/null
```

### Check Database Performance

```bash
# Check table sizes
sudo -u postgres psql -d netmonitor -c "
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE tablename IN ('top_talkers', 'sensor_metrics', 'alerts')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

---

## Contact & Support

If Top Talkers remains empty after following this guide:

1. Run full diagnostic:
   ```bash
   sudo ./tools/diagnose_top_talkers.sh > top_talkers_diag.txt
   ```

2. Collect logs:
   ```bash
   sudo journalctl -u netmonitor --since "1 hour ago" > netmonitor.log
   ```

3. Report issue with:
   - Output of diagnostic script
   - Service logs
   - Your `config.yaml` (redact passwords!)

**GitHub Issues**: https://github.com/willempoort/netmonitor/issues

---

**Last Updated**: 2026-01-17
