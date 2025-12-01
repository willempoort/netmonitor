# NetMonitor SOC - Administrator Manual

**Complete Installation & Administration Guide**

Version: 2.0
Last Updated: November 2024

---

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [SOC Server Installation](#soc-server-installation)
5. [Sensor Deployment](#sensor-deployment)
6. [Configuration Management](#configuration-management)
7. [Maintenance & Troubleshooting](#maintenance--troubleshooting)
8. [Security Best Practices](#security-best-practices)
9. [Advanced Topics](#advanced-topics)

---

## System Overview

NetMonitor is a centralized Security Operations Center (SOC) platform for network monitoring and threat detection. The system consists of:

- **SOC Server**: Central dashboard and database (PostgreSQL + TimescaleDB)
- **Remote Sensors**: Lightweight packet capture agents deployed across your network
- **Web Dashboard**: Real-time monitoring interface on port 8080

### Key Capabilities

✅ **Real-time threat detection** - 13 built-in detection rules
✅ **Centralized management** - All configuration via dashboard
✅ **Distributed sensors** - Deploy anywhere in your network
✅ **Auto-synchronization** - Sensors pull config every 5 minutes
✅ **Professional UI** - Dark theme, WebSocket updates, gauges
✅ **Time-series database** - Optimized for metrics and alerts

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      SOC Server                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Web Dashboard│  │  PostgreSQL  │  │   Python     │      │
│  │   (Port 8080)│  │  TimescaleDB │  │   Backend    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└───────────────────────────┬─────────────────────────────────┘
                            │ API
                            │ (HTTP/WebSocket)
            ┌───────────────┼───────────────┐
            │               │               │
    ┌───────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
    │   Sensor 1   │ │  Sensor 2  │ │  Sensor 3  │
    │  (Building A)│ │   (DMZ)    │ │ (VLAN 10)  │
    └──────────────┘ └────────────┘ └────────────┘
```

### Communication Flow

1. **Sensors → SOC**: Send alerts, metrics, registration
2. **SOC → Sensors**: Provide config, thresholds, whitelist
3. **Admin → Dashboard**: Configure, monitor, manage
4. **Dashboard → Database**: Store alerts, metrics, config

---

## Requirements

### SOC Server Requirements

**Hardware:**
- CPU: 2+ cores
- RAM: 4 GB minimum, 8 GB recommended
- Disk: 20 GB+ (grows with time-series data)
- Network: 100 Mbps+

**Software:**
- OS: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- Python: 3.8+
- PostgreSQL: 12+
- TimescaleDB: 2.0+ (optional but recommended)

### Sensor Requirements

**Hardware:**
- CPU: 1+ core
- RAM: 512 MB minimum, 1 GB recommended
- Disk: 1 GB
- Network: Mirror/SPAN port access OR in-line deployment

**Software:**
- OS: Linux (any distribution)
- Python: 3.8+
- Root access (for packet capture)

**Tested Platforms:**
- Raspberry Pi (3B+, 4)
- NanoPi R2S
- x86/x64 Linux servers
- VMs (VMware, VirtualBox, KVM)

---

## SOC Server Installation

### Quick Start (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/your-org/netmonitor.git
cd netmonitor

# 2. Run complete installation script
sudo ./install_complete.sh

# 3. Access dashboard
# Open browser: http://your-server-ip:8080
```

The installation script will:
- ✅ Install system dependencies
- ✅ Set up Python venv
- ✅ Install PostgreSQL + TimescaleDB
- ✅ Create database and tables
- ✅ Install systemd service
- ✅ Start SOC server

### Manual Installation

See [COMPLETE_INSTALLATION.md](COMPLETE_INSTALLATION.md) for step-by-step manual installation.

### Post-Installation

**1. Verify Service Status:**
```bash
systemctl status netmonitor-soc
journalctl -u netmonitor-soc -f
```

**2. Check Dashboard:**
```bash
curl http://localhost:8080/api/stats
```

**3. Configure Firewall:**
```bash
# Allow dashboard access
sudo ufw allow 8080/tcp

# Allow sensor connections (if using auth)
sudo ufw allow from sensor-subnet to any port 8080
```

---

## Sensor Deployment

### Automated Setup (Recommended)

**On the sensor machine:**

```bash
# 1. Copy NetMonitor files to sensor
scp -r netmonitor/ user@sensor:/tmp/

# 2. Run setup script
ssh user@sensor
cd /tmp/netmonitor
sudo ./setup_sensor.sh
```

The script will prompt for:
1. **Network Interface** (required): e.g., `eth0`
2. **SOC Server URL** (required): e.g., `http://192.168.1.100:8080`
3. **Sensor ID** (optional): Auto-uses hostname if empty
4. **Location** (optional): Can be set via dashboard later
5. **Secret Key** (optional): For authentication

**What the script does:**
- ✅ Copies files to `/opt/netmonitor`
- ✅ Creates Python venv
- ✅ Generates `sensor.conf`
- ✅ Installs systemd service
- ✅ Starts sensor service
- ✅ Registers with SOC server

### Manual Sensor Setup

See [SENSOR_DEPLOYMENT.md](SENSOR_DEPLOYMENT.md) for manual sensor configuration.

### Sensor Configuration File

**Minimal `/opt/netmonitor/sensor.conf`:**

```bash
# Required settings
SOC_SERVER_URL=http://192.168.1.100:8080
INTERFACE=eth0

# Optional settings
SENSOR_ID=office-vlan10-01
SENSOR_LOCATION=Building A - VLAN 10
SENSOR_SECRET_KEY=your-secret-key-here
```

**All other settings** (detection rules, thresholds, whitelist, etc.) are managed centrally via the SOC dashboard!

### Verification

**Check sensor status:**
```bash
# On sensor machine
systemctl status netmonitor-sensor
journalctl -u netmonitor-sensor -f
```

**Check SOC dashboard:**
- Navigate to Dashboard → Sensors tab
- Sensor should appear with status "Online"
- Click on sensor to see metrics

---

## Configuration Management

### Centralized Configuration

**All configuration is now managed via the SOC Dashboard!**

#### Dashboard → Configuration Management

**What you can configure:**

1. **Detection Rules** (13 rules):
   - Port scan detection
   - Brute force detection
   - DNS tunneling detection
   - DDoS detection
   - Protocol anomalies
   - And more...

2. **Thresholds**:
   - CPU usage limits
   - Memory limits
   - Network bandwidth limits
   - Alert rate limits

3. **Alert Management**:
   - Email notifications
   - Webhook integrations
   - Retention policies

4. **Performance Settings**:
   - Batch intervals
   - Sync frequencies
   - Buffer sizes

**Configuration Scopes:**
- **Global**: Applies to all sensors
- **Sensor-specific**: Override for individual sensors

**How it works:**
1. Edit settings in dashboard
2. Click "Save Changes"
3. Sensors auto-sync within 5 minutes
4. Force immediate: restart sensor

#### Sensor Settings (Per-Sensor)

Edit sensor metadata:
1. Go to Dashboard → Sensors
2. Click **Settings** button (sliders icon)
3. Edit location or other settings
4. Sensor picks up changes automatically

### Whitelist Management

**Dashboard → Whitelist Management**

Add trusted IP ranges:
```
192.168.1.0/24  - Office network
10.0.0.0/8      - Internal networks
203.0.113.50    - Trusted external server
```

Whitelisted IPs/ranges won't trigger alerts.

---

## Maintenance & Troubleshooting

### Log Files

**SOC Server logs:**
```bash
journalctl -u netmonitor-soc -f
tail -f /var/log/netmonitor/soc.log
```

**Sensor logs:**
```bash
journalctl -u netmonitor-sensor -f
```

**PostgreSQL logs:**
```bash
tail -f /var/log/postgresql/postgresql-*.log
```

### Common Issues

**Sensor not appearing in dashboard:**
- Check sensor logs for connection errors
- Verify SOC_SERVER_URL is correct
- Check firewall allows port 8080
- Verify sensor service is running

**High CPU usage:**
- Check alert rate in dashboard
- Adjust detection thresholds
- Consider adding IPs to whitelist

**Database growing too large:**
```sql
-- Check database size
SELECT pg_size_pretty(pg_database_size('netmonitor'));

-- Enable TimescaleDB compression (if installed)
ALTER TABLE alerts SET (timescaledb.compress);
SELECT add_compression_policy('alerts', INTERVAL '7 days');
```

**Sensor offline but service running:**
- Check network connectivity
- Verify SOC server is accessible
- Check sensor logs for errors

### Service Management

**SOC Server:**
```bash
sudo systemctl start netmonitor-soc
sudo systemctl stop netmonitor-soc
sudo systemctl restart netmonitor-soc
sudo systemctl status netmonitor-soc
```

**Sensor:**
```bash
sudo systemctl start netmonitor-sensor
sudo systemctl stop netmonitor-sensor
sudo systemctl restart netmonitor-sensor
sudo systemctl status netmonitor-sensor
```

### Backup & Restore

**Backup database:**
```bash
# Full backup
sudo -u postgres pg_dump netmonitor > netmonitor_backup.sql

# Compressed backup
sudo -u postgres pg_dump netmonitor | gzip > netmonitor_backup.sql.gz
```

**Restore database:**
```bash
# Stop SOC server
sudo systemctl stop netmonitor-soc

# Restore
sudo -u postgres psql netmonitor < netmonitor_backup.sql

# Restart
sudo systemctl start netmonitor-soc
```

---

## Security Best Practices

### Network Security

1. **Firewall Rules:**
   - Only allow sensors to connect to SOC on port 8080
   - Restrict dashboard access to admin network
   - Use VPN for remote access

2. **Authentication:**
   - Enable sensor authentication (SENSOR_SECRET_KEY)
   - Use strong random keys: `openssl rand -hex 32`
   - Rotate keys periodically

3. **HTTPS:**
   - Use reverse proxy (nginx/Apache) for HTTPS
   - Get free SSL cert from Let's Encrypt
   - Example nginx config in [PRODUCTION.md](PRODUCTION.md)

### Access Control

1. **Dashboard Access:**
   - Implement authentication (future feature)
   - Use IP whitelist in firewall
   - Monitor access logs

2. **Database Security:**
   - Change default PostgreSQL password
   - Restrict network access to localhost
   - Regular security updates

3. **Sensor Security:**
   - Run as systemd service (not manual)
   - Keep sensors updated
   - Monitor sensor logs

### Monitoring

1. **Monitor the Monitor:**
   - Set up external monitoring for SOC server
   - Alert on service failures
   - Track disk space growth

2. **Regular Reviews:**
   - Review alerts weekly
   - Check for false positives
   - Update whitelist as needed

---

## Advanced Topics

### TimescaleDB Optimization

**Compression policies:**
```sql
-- Compress old alerts (saves 90% space)
ALTER TABLE alerts SET (timescaledb.compress);
SELECT add_compression_policy('alerts', INTERVAL '7 days');

-- Compress old metrics
ALTER TABLE sensor_metrics SET (timescaledb.compress);
SELECT add_compression_policy('sensor_metrics', INTERVAL '7 days');
```

**Retention policies:**
```sql
-- Auto-delete alerts older than 90 days
SELECT add_retention_policy('alerts', INTERVAL '90 days');

-- Auto-delete metrics older than 365 days
SELECT add_retention_policy('sensor_metrics', INTERVAL '365 days');
```

### High Availability

For production environments:
- Use PostgreSQL replication
- Deploy multiple SOC servers with load balancer
- Implement database failover
- See [PRODUCTION.md](PRODUCTION.md) for details

### Integration

**Email Alerts:**
- Configure SMTP in dashboard settings
- Set alert thresholds
- Email notifications on critical alerts

**Webhook Integration:**
- Send alerts to Slack, Teams, PagerDuty
- Configure in Alert Management
- JSON format for custom integrations

**AI Integration:**
- MCP server for Claude Desktop
- Query alerts via natural language
- See [mcp_server/README.md](mcp_server/README.md)

---

## Next Steps

After installation:

1. ✅ **Deploy sensors** across your network
2. ✅ **Configure detection rules** via dashboard
3. ✅ **Set up whitelist** for trusted IPs
4. ✅ **Monitor dashboard** for alerts
5. ✅ **Fine-tune thresholds** to reduce false positives

**For SOC Operators:**
See [USER_MANUAL.md](USER_MANUAL.md) for daily usage guide.

**For Detailed Topics:**
- [DASHBOARD.md](DASHBOARD.md) - Dashboard features
- [DETECTION_FEATURES.md](DETECTION_FEATURES.md) - Detection capabilities
- [CONFIG_GUIDE.md](CONFIG_GUIDE.md) - Configuration reference
- [PRODUCTION.md](PRODUCTION.md) - Production deployment

---

## Support & Documentation

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: All .md files in repository
- **Logs**: Always check logs first for troubleshooting

---

*Last updated: November 2024*
*NetMonitor SOC v2.0 - Centralized Security Operations*
