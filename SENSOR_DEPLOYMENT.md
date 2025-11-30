# NetMonitor Sensor Deployment Guide

This guide explains how to deploy NetMonitor sensors using the simplified configuration format.

## Overview

NetMonitor supports two deployment modes:

1. **SOC Server Mode**: Full configuration with dashboard, database, and management features
   - Script: `netmonitor.py`
   - Config: `config.yaml`
   - Purpose: Central SOC management server

2. **Sensor Mode**: Minimal configuration with only connection settings
   - Script: `sensor_client.py` ⭐
   - Config: `sensor.conf`
   - Purpose: Remote network sensors

This guide covers **Sensor Mode** deployment.

## Architecture

```
┌─────────────────┐
│   SOC Server    │
│  (config.yaml)  │
│                 │
│ ┌─────────────┐ │
│ │  Dashboard  │ │
│ │  Database   │ │
│ │  Detection  │ │
│ │  Settings   │ │
│ └─────────────┘ │
└────────┬────────┘
         │ HTTP/HTTPS
         │
    ┌────┴────┬────────────┬────────────┐
    │         │            │            │
┌───▼───┐ ┌──▼────┐   ┌───▼───┐   ┌───▼───┐
│Sensor │ │Sensor │   │Sensor │   │Sensor │
│  #1   │ │  #2   │   │  #3   │   │  #4   │
│(.conf)│ │(.conf)│   │(.conf)│   │(.conf)│
└───────┘ └───────┘   └───────┘   └───────┘
```

**Key Principles:**
- **Sensors**: Monitor network traffic, send alerts to SOC server
- **SOC Server**: Centralized management, configuration, and dashboard
- **Configuration**: Detection settings managed centrally, sensors only need connection info

---

## Quick Start

### Prerequisites

On each sensor machine:
```bash
# Install Python 3.8+
sudo apt-get update
sudo apt-get install -y python3 python3-pip

# Install system dependencies
sudo apt-get install -y tcpdump libpcap-dev
```

### Installation

1. **Clone repository on sensor**:
```bash
cd /opt
sudo git clone https://github.com/your-org/netmonitor.git
cd netmonitor
```

2. **Install Python dependencies**:
```bash
sudo pip3 install -r requirements.txt
```

3. **Run interactive setup**:
```bash
./setup_sensor.sh
```

The script will prompt for:
- Network interface to monitor
- SOC server URL
- Unique sensor ID
- Location description
- Optional authentication key

4. **Verify configuration**:
```bash
cat sensor.conf
```

5. **Install systemd service**:
```bash
sudo cp netmonitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable netmonitor
sudo systemctl start netmonitor
```

6. **Check status**:
```bash
sudo systemctl status netmonitor
sudo journalctl -u netmonitor -f
```

---

## Manual Configuration

If you prefer manual configuration, copy the template:

```bash
cp sensor.conf.template sensor.conf
```

Edit `sensor.conf`:

```bash
# Network interface to monitor
INTERFACE=eth0

# SOC Server URL (REQUIRED)
SOC_SERVER_URL=http://soc.example.com:8080

# Unique Sensor ID (REQUIRED)
SENSOR_ID=nano-office-vlan10-01

# Sensor Location Description (REQUIRED)
SENSOR_LOCATION=Main Office - VLAN 10 - Production Network

# Authentication Secret Key (OPTIONAL)
SENSOR_SECRET_KEY=your_secret_key_here

# Internal networks (comma-separated CIDR ranges)
INTERNAL_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Heartbeat interval (seconds)
HEARTBEAT_INTERVAL=30

# Config sync interval (seconds)
CONFIG_SYNC_INTERVAL=300

# Enable SSL verification (true/false)
SSL_VERIFY=true
```

---

## Configuration Fields

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `INTERFACE` | Network interface to monitor | `eth0`, `ens33`, `wlan0` |
| `SOC_SERVER_URL` | URL of SOC server dashboard | `http://soc.example.com:8080` |
| `SENSOR_ID` | Unique identifier for this sensor | `nano-office-01` |
| `SENSOR_LOCATION` | Human-readable location | `Building A - VLAN 10` |

### Optional Fields

| Field | Default | Description |
|-------|---------|-------------|
| `SENSOR_SECRET_KEY` | *(empty)* | Authentication token for secure communication |
| `INTERNAL_NETWORKS` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Internal network ranges |
| `HEARTBEAT_INTERVAL` | `30` | Status update frequency (seconds) |
| `CONFIG_SYNC_INTERVAL` | `300` | Configuration fetch frequency (seconds) |
| `SSL_VERIFY` | `true` | Verify SSL certificates |

---

## Deployment Scenarios

### Scenario 1: Office Network Monitoring

Deploy sensors on network segments:

**DMZ Sensor** (`sensor.conf`):
```bash
INTERFACE=eth1
SOC_SERVER_URL=http://soc.internal.example.com:8080
SENSOR_ID=nano-dmz-edge-01
SENSOR_LOCATION=DMZ - Edge Network - Public Servers
SENSOR_SECRET_KEY=abc123...
```

**Internal Office Sensor** (`sensor.conf`):
```bash
INTERFACE=eth0
SOC_SERVER_URL=http://soc.internal.example.com:8080
SENSOR_ID=nano-office-vlan10-01
SENSOR_LOCATION=Main Office - VLAN 10 - Workstations
SENSOR_SECRET_KEY=def456...
```

**Production Server Sensor** (`sensor.conf`):
```bash
INTERFACE=eth0
SOC_SERVER_URL=http://soc.internal.example.com:8080
SENSOR_ID=nano-datacenter-prod-01
SENSOR_LOCATION=Datacenter - Production VLAN
SENSOR_SECRET_KEY=ghi789...
```

### Scenario 2: Remote Site Monitoring

Deploy sensors at remote locations connecting to central SOC:

```bash
INTERFACE=eth0
SOC_SERVER_URL=https://soc.company.com:8443
SENSOR_ID=nano-branch-amsterdam-01
SENSOR_LOCATION=Amsterdam Branch Office - Main Network
SSL_VERIFY=true
SENSOR_SECRET_KEY=remote_site_key_123
```

---

## Authentication Setup

### Generate Authentication Key

On SOC server:
```bash
cd /opt/netmonitor
python3 setup_sensor_auth.py

# Follow prompts to generate sensor token
```

On sensor:
```bash
# Add generated token to sensor.conf
SENSOR_SECRET_KEY=generated_token_from_soc_server
```

### Disable Authentication (Testing Only)

For testing without authentication:
```bash
# Leave empty in sensor.conf
SENSOR_SECRET_KEY=

# On SOC server config.yaml, set:
sensor_auth:
  enabled: false
```

⚠️ **Not recommended for production!**

---

## Configuration Management

### How Detection Settings Work

1. **Sensor startup**: Loads minimal `sensor.conf` (connection info only)
2. **Initial sync**: Fetches detection thresholds from SOC server
3. **Periodic sync**: Updates configuration every 5 minutes (configurable)
4. **Dashboard changes**: SOC admin updates thresholds via web UI
5. **Auto-propagation**: All sensors receive new settings within 5 minutes

**Example flow:**
```
SOC Admin (Web UI)
    ↓
Updates port_scan.unique_ports = 15
    ↓
Saved to PostgreSQL database
    ↓ (within 5 minutes)
All sensors fetch new config
    ↓
Detection updated across all sensors
```

### Override Configuration Sync Interval

To sync more frequently:
```bash
# In sensor.conf
CONFIG_SYNC_INTERVAL=60  # Sync every minute
```

---

## Monitoring & Troubleshooting

### Check Sensor Status

```bash
# Service status
sudo systemctl status netmonitor

# Live logs
sudo journalctl -u netmonitor -f

# Recent errors
sudo journalctl -u netmonitor --since "10 minutes ago" -p err
```

### Common Issues

#### 1. Sensor not appearing in SOC dashboard

**Symptoms:**
- Service running but not visible in sensor list

**Diagnosis:**
```bash
# Check connectivity
curl -v http://soc.example.com:8080/api/sensors

# Check logs for registration errors
sudo journalctl -u netmonitor | grep -i "register\|connection"
```

**Solution:**
- Verify `SOC_SERVER_URL` is correct
- Check firewall allows outbound HTTP/HTTPS
- Verify sensor authentication key (if enabled)

#### 2. Configuration not syncing from SOC

**Symptoms:**
- Sensor uses outdated detection thresholds

**Diagnosis:**
```bash
# Check config sync logs
sudo journalctl -u netmonitor | grep -i "config sync\|database"
```

**Solution:**
- Verify `CONFIG_SYNC_INTERVAL` setting
- Check SOC server API is accessible
- Restart sensor: `sudo systemctl restart netmonitor`

#### 3. Permission errors (packet capture)

**Symptoms:**
```
PermissionError: Operation not permitted
```

**Solution:**
```bash
# Run as root (required for packet capture)
sudo systemctl start netmonitor

# Or give capabilities to Python
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

---

## Systemd Service Configuration

Edit `/etc/systemd/system/netmonitor.service`:

```ini
[Unit]
Description=NetMonitor Security Sensor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netmonitor
ExecStart=/usr/bin/python3 /opt/netmonitor/netmonitor.py -c sensor.conf
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/netmonitor

[Install]
WantedBy=multi-user.target
```

---

## Comparison: sensor.conf vs config.yaml

| Feature | sensor.conf (Sensor) | config.yaml (SOC Server) |
|---------|---------------------|--------------------------|
| **Size** | ~15 lines | ~300+ lines |
| **Purpose** | Connection settings only | Full configuration |
| **Detection thresholds** | ❌ (from SOC server) | ✅ (managed locally) |
| **Database** | ❌ | ✅ PostgreSQL + TimescaleDB |
| **Dashboard** | ❌ | ✅ Web UI on port 8080 |
| **Threat feeds** | ❌ | ✅ Multiple sources |
| **GeoIP** | ❌ | ✅ MaxMind GeoLite2 |
| **Self-monitoring** | ❌ | ✅ (optional) |
| **Use case** | Remote sensors | Central SOC server |

---

## Best Practices

### Sensor Naming Convention

Use descriptive, hierarchical sensor IDs:
```
{location}-{network}-{purpose}-{number}

Examples:
- nano-hq-dmz-edge-01
- nano-branch-nyc-office-01
- nano-dc-prod-db-01
- nano-wifi-guest-01
```

### Network Placement

**Optimal sensor placement:**
1. **Edge/DMZ**: Monitor external threats
2. **VLAN boundaries**: Monitor inter-VLAN traffic
3. **Critical servers**: Database, file servers
4. **User networks**: Office workstations
5. **Guest networks**: Visitor WiFi

### Security Hardening

1. **Use authentication**: Always set `SENSOR_SECRET_KEY`
2. **Enable SSL**: Use HTTPS for SOC server
3. **Limit sensor access**: Firewall rules to SOC server only
4. **Regular updates**: Keep NetMonitor updated
5. **Monitor sensors**: Alert if sensor goes offline

---

## Migration from config.yaml to sensor.conf

If you have an existing `config.yaml` sensor deployment:

1. **Backup existing config**:
```bash
cp config.yaml config.yaml.backup
```

2. **Run migration helper** (if available):
```bash
./migrate_to_sensor_conf.sh config.yaml
```

3. **Or manually create sensor.conf**:
```bash
./setup_sensor.sh
# Enter values from old config.yaml
```

4. **Test new configuration**:
```bash
# Test with sensor.conf
sudo python3 netmonitor.py -c sensor.conf

# If successful, update systemd service
sudo systemctl daemon-reload
sudo systemctl restart netmonitor
```

---

## Support

For issues or questions:
- Check logs: `sudo journalctl -u netmonitor -f`
- GitHub Issues: https://github.com/your-org/netmonitor/issues
- Documentation: https://docs.netmonitor.example.com
