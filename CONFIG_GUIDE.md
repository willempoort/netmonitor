# Configuration Guide - SOC Server vs Remote Sensors

## 📚 Overview

NetMonitor heeft **twee configuratie modes**:

1. **SOC Server Mode** - Centraal beheer met optionele self-monitoring
2. **Remote Sensor Mode** - Minimale configuratie, alles wordt vanuit de SOC server gepusht

---

## 🖥️ SOC Server Configuration (`config.yaml`)

### Doel
Volledige configuratie voor de SOC server inclusief:
- Self-monitoring toggle (optioneel lokaal monitoren)
- Detection thresholds (centraal beheerd, gepusht naar sensors)
- Dashboard instellingen
- Database connectie
- Threat intelligence feeds

### Self-Monitoring Instellingen

```yaml
# config.yaml (SOC Server)
self_monitor:
  # Enable/disable local network monitoring on the SOC server
  enabled: true  # Set to false for sensor-only setups

  # Sensor ID for the SOC server (appears in sensor list)
  sensor_id: soc-server

  # Hostname and location (optional, auto-detected if empty)
  hostname: ""
  location: "SOC Server - Main Location"

  # Network interface to monitor
  interface: lo  # or eth0, ens33, etc.
```

### Wanneer Self-Monitoring Gebruiken?

**✅ Enable self-monitoring (`enabled: true`) als:**
- Je weinig of geen remote sensors hebt
- De SOC server zelf ook netwerkverkeer moet monitoren
- Je een hybride setup wilt (server + sensors)

**✅ Disable self-monitoring (`enabled: false`) als:**
- Je ALLEEN remote sensors wilt gebruiken
- De SOC server alleen als centrale management server dient
- Je resources wilt besparen op de SOC server

### Gedrag per Mode

| Mode | Dashboard | Packet Capture | Sensor List | Alert Source |
|------|-----------|----------------|-------------|--------------|
| **enabled: true** | ✅ Running | ✅ Active | ✅ "soc-server" visible | SOC + Sensors |
| **enabled: false** | ✅ Running | ❌ Disabled | ❌ SOC not visible | Sensors only |

---

## 📡 Remote Sensor Configuration (`config-sensor-minimal.yaml`)

### Doel
**Minimale configuratie** voor remote sensors - bevat ALLEEN:
- Sensor identificatie
- SOC server connectie
- Network interface
- Lokale logging

### Minimal Sensor Config

```yaml
# config-sensor-minimal.yaml (Remote Sensor)
sensor:
  id: nano-dmz-01  # UNIQUE per sensor
  auth_token: ""   # Generate via setup_sensor_auth.py
  location: "DMZ Network"

server:
  url: https://soc.example.com
  verify_ssl: true
  heartbeat_interval: 30
  config_sync_interval: 300

interface: eth0

internal_networks:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
```

### ❌ Wat NIET in Sensor Config Hoeft

Remote sensors hebben **GEEN** thresholds, detection rules, of dashboard config nodig:

```yaml
# ❌ NIET NODIG in sensor config:
thresholds:        # ← Centrally managed
  port_scan: ...
  dns_tunnel: ...

dashboard:         # ← Only on SOC server
  enabled: true

database:          # ← Only on SOC server
  type: postgresql
```

### Automatische Config Sync

Remote sensors:
1. **Verbinden** met SOC server
2. **Downloaden** laatste detection config
3. **Toepassen** automatisch
4. **Synchroniseren** elke 5 minuten (config_sync_interval)

---

## 🔧 Configuration Management

### Centraal Beheer via Web UI

**All detection settings are managed centrally:**

1. Login to SOC Dashboard: `https://soc.example.com`
2. Navigate to: **Configuration** tab
3. Modify parameters in: **Detection Rules**
4. Changes are **automatically pushed** to all sensors within 5 minutes

### Global vs Sensor-Specific Config

| Scope | Effect | Use Case |
|-------|--------|----------|
| **Global** | All sensors | Default thresholds for all |
| **Sensor-Specific** | Single sensor override | Custom thresholds per location |

**Example:**
```bash
# Global: DNS tunnel threshold = 50
# Sensor override (nano-dmz-01): DNS tunnel threshold = 30 (stricter for DMZ)
```

### Configuration API

**Update global config:**
```bash
curl -X PUT https://soc.example.com/api/config/parameter \
  -H "Content-Type: application/json" \
  -d '{
    "parameter_path": "thresholds.http_anomaly.post_threshold",
    "value": 75,
    "scope": "global"
  }'
```

**Update sensor-specific:**
```bash
curl -X PUT https://soc.example.com/api/config/parameter \
  -H "Content-Type: application/json" \
  -d '{
    "parameter_path": "thresholds.dns_tunnel.query_length_threshold",
    "value": 30,
    "scope": "sensor",
    "sensor_id": "nano-dmz-01"
  }'
```

---

## 📊 Configuration Files Comparison

### SOC Server (`config.yaml`)

```yaml
# FULL configuration for SOC server
self_monitor:           # ✅ Self-monitoring toggle
  enabled: true
  sensor_id: soc-server
  interface: lo

thresholds:             # ✅ Detection config (pushed to sensors)
  port_scan: ...
  dns_tunnel: ...
  http_anomaly: ...

dashboard:              # ✅ Web dashboard
  enabled: true
  host: 0.0.0.0
  port: 8080

database:               # ✅ PostgreSQL + TimescaleDB
  type: postgresql
  postgresql: ...

threat_feeds:           # ✅ Threat intelligence
  enabled: true
  feeds: [...]

# 182 lines total
```

### Remote Sensor (`config-sensor-minimal.yaml`)

```yaml
# MINIMAL configuration for remote sensor
sensor:                 # ✅ Sensor ID and auth
  id: nano-dmz-01
  auth_token: "..."
  location: "DMZ"

server:                 # ✅ SOC server connection
  url: https://soc.example.com
  heartbeat_interval: 30

interface: eth0         # ✅ Network interface

internal_networks:      # ✅ Local network ranges
  - 10.0.0.0/8

logging:                # ✅ Local logging
  level: INFO

# 75 lines total (57% smaller!)
```

---

## 🚀 Quick Start Examples

### Scenario 1: SOC Server with Self-Monitoring

```yaml
# config.yaml
self_monitor:
  enabled: true          # ← Monitor local traffic
  sensor_id: soc-server
  interface: eth0

# Result:
# - SOC server appears in sensor list
# - Monitors local eth0 traffic
# - Dashboard shows SOC + remote sensor alerts
```

### Scenario 2: SOC Server as Management Only

```yaml
# config.yaml
self_monitor:
  enabled: false         # ← NO local monitoring

# Result:
# - SOC server NOT in sensor list
# - Only dashboard running (no packet capture)
# - Shows ONLY remote sensor alerts
```

### Scenario 3: Remote Sensor Setup

```bash
# 1. Copy minimal config
cp config-sensor-minimal.yaml config.yaml

# 2. Edit sensor ID (must be unique!)
nano config.yaml
# Change: id: nano-dmz-01

# 3. Set SOC server URL
# Change: url: https://soc.example.com

# 4. Generate auth token (optional)
python3 setup_sensor_auth.py

# 5. Start sensor
sudo systemctl start netmonitor
```

---

## 🔐 Authentication for Sensors

### Generate Sensor Token (SOC Server)

```bash
# On SOC server
python3 setup_sensor_auth.py

# Prompts:
# - Sensor ID: nano-dmz-01
# - Token name: DMZ Sensor
# - Expiration: 365 days
# - Permissions: alerts, metrics

# Output:
# Token: nm_1234567890abcdef...
```

### Use Token in Sensor Config

```yaml
# config.yaml (on remote sensor)
sensor:
  id: nano-dmz-01
  auth_token: "nm_1234567890abcdef..."  # ← Paste here

server:
  url: https://soc.example.com
```

---

## 📝 Configuration Migration

### Migrating from Full Config to Minimal (Remote Sensors)

```bash
# Backup current config
cp config.yaml config.yaml.backup

# Use minimal template
cp config-sensor-minimal.yaml config.yaml

# Edit only required fields:
nano config.yaml
# 1. Set sensor.id (unique!)
# 2. Set server.url
# 3. Set interface
# 4. Optional: add auth_token

# Restart sensor
sudo systemctl restart netmonitor
```

**Result:**
- ✅ Config file 57% smaller
- ✅ No manual threshold management
- ✅ Automatic updates from SOC server
- ✅ Easier maintenance

---

## 🎯 Best Practices

### SOC Server

1. **Keep thresholds in config.yaml** - Single source of truth
2. **Enable self-monitoring** - If server is on monitored network
3. **Use descriptive sensor_id** - E.g., "soc-server-hq" instead of "server1"
4. **Regular backups** - `config.yaml` contains all detection logic

### Remote Sensors

1. **Use minimal config** - Only connection settings
2. **Unique sensor IDs** - Naming convention: `<location>-<segment>-<number>`
3. **Sync intervals** - Default 5min is good, reduce for critical sensors
4. **Authentication** - Always use auth tokens in production

### Global Configuration Management

1. **Test in global scope first** - Then override for specific sensors if needed
2. **Document changes** - Use commit messages for threshold changes
3. **Monitor sensor sync** - Check `/api/sensors` for last_config_sync timestamps
4. **Version control** - Keep `config.yaml` in git

---

## 🆘 Troubleshooting

### SOC Server Not Appearing in Sensor List

**Problem:** `self_monitor.enabled: true` but server not visible

**Solution:**
```bash
# Check logs
sudo journalctl -u netmonitor -n 50

# Look for:
# "SOC server registered as sensor: soc-server"

# If missing, check database connection
# Verify: dashboard.enabled: true (required for DB)
```

### Remote Sensor Not Receiving Config Updates

**Problem:** Sensor using old thresholds

**Solution:**
```bash
# Check sensor logs
sudo journalctl -u netmonitor -n 50 | grep -i "config sync"

# Manually trigger sync (restart sensor)
sudo systemctl restart netmonitor

# Verify on SOC server dashboard:
# Sensors → Click sensor → Check "Last Config Sync" timestamp
```

### Sensor Shows Duplicate Detection Settings

**Problem:** Both local config.yaml AND server config active

**Solution:**
```bash
# Remove local thresholds from sensor config
# Keep ONLY these sections:
# - sensor
# - server
# - interface
# - internal_networks
# - logging

# Use minimal template:
cp config-sensor-minimal.yaml config.yaml
# (then edit as needed)

sudo systemctl restart netmonitor
```

---

## 📚 Additional Resources

- **Full Installation Guide**: `COMPLETE_INSTALLATION.md`
- **Remote Sensor Setup**: `REMOTE_SENSORS.md`
- **Detection Features**: `DETECTION_FEATURES.md`
- **Sensor Authentication**: `setup_sensor_auth.py`
