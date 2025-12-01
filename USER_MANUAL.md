# NetMonitor SOC - User Manual

**SOC Operator Guide for Daily Operations**

Version: 2.1
Last Updated: December 2024

---

## 📋 Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Monitoring Alerts](#monitoring-alerts)
4. [Managing Sensors](#managing-sensors)
5. [Configuration](#configuration)
6. [Whitelist Management](#whitelist-management)
7. [AI Integration (MCP Server)](#ai-integration-mcp-server)
8. [Common Tasks](#common-tasks)
9. [Best Practices](#best-practices)

---

## Getting Started

### Accessing the Dashboard

**URL:** `http://your-soc-server:8080`

The dashboard opens automatically to the main monitoring view with:
- Real-time alert feed
- Traffic visualizations
- System metrics
- Top talkers

### Dashboard Layout

```
┌────────────────────────────────────────────────────────────┐
│  NetMonitor SOC Dashboard                    🔔 🔄 ⚙️  │
├────────────────────────────────────────────────────────────┤
│  [Alerts] [Sensors] [Config] [Whitelist]                  │
├──────────────────┬─────────────────────────────────────────┤
│                  │  Real-Time Alert Feed                   │
│  System Metrics  │  ┌──────────────────────────────────┐  │
│  ┌─────────────┐ │  │ HIGH - Port Scan Detected        │  │
│  │ CPU: 45%    │ │  │ 192.168.1.100 → Multiple ports   │  │
│  │ RAM: 62%    │ │  └──────────────────────────────────┘  │
│  │ Alerts: 12  │ │  ┌──────────────────────────────────┐  │
│  └─────────────┘ │  │ MEDIUM - High Traffic            │  │
│                  │  │ 10.0.0.50 → 500 Mbps             │  │
│  Traffic Graphs  │  └──────────────────────────────────┘  │
│                  │                                         │
└──────────────────┴─────────────────────────────────────────┘
```

---

## Dashboard Overview

### Main Dashboard

**What you see:**

1. **Alert Feed** (center):
   - Real-time security alerts
   - Color-coded by severity (RED/ORANGE/YELLOW)
   - Auto-scrolls with new alerts
   - Click alert for details

2. **System Metrics** (left):
   - CPU usage gauge
   - Memory usage gauge
   - Packets/second counter
   - Alerts/minute counter

3. **Traffic Visualizations**:
   - Bandwidth graph (last hour)
   - Packets/second graph
   - Protocol distribution

4. **Top Talkers**:
   - IPs with most traffic
   - Shows hostname when available
   - Inbound/outbound breakdown

### Navigation Tabs

**🚨 Alerts Tab**
- Main alert monitoring view
- Filter by severity
- Search alerts
- Acknowledge alerts

**🖥️ Sensors Tab**
- View all deployed sensors
- Monitor sensor health
- Manage sensor settings
- Control sensor operations

**⚙️ Configuration Tab**
- Detection rule settings
- Threshold adjustments
- Alert management
- Performance tuning

**📋 Whitelist Tab**
- Manage trusted IPs
- Add/remove whitelist entries
- Scope: global or per-sensor

---

## Monitoring Alerts

### Alert Types

**Port Scan Detection** 🔴 HIGH
```
Source IP scanning multiple ports
Indicates: Reconnaissance activity
Action: Investigate source, block if malicious
```

**Brute Force Attack** 🔴 HIGH
```
Multiple failed login attempts
Indicates: Password guessing attack
Action: Block source IP, check target system
```

**DNS Tunneling** 🟠 MEDIUM
```
Suspicious DNS query patterns
Indicates: Data exfiltration or C2 communication
Action: Analyze DNS queries, investigate client
```

**DDoS Attack** 🔴 HIGH
```
Abnormally high traffic volume
Indicates: Denial of service attempt
Action: Activate DDoS mitigation, contact ISP
```

**Protocol Anomaly** 🟡 LOW
```
Unusual protocol behavior
Indicates: Misconfiguration or evasion attempt
Action: Investigate protocol usage
```

### Alert Workflow

**1. Alert Appears:**
- Dashboard shows alert in feed
- Sound notification (if enabled)
- Counter increments

**2. Investigate:**
- Click alert for details
- Check source/destination IPs
- Review traffic patterns
- Check logs

**3. Take Action:**
- **False Positive**: Add to whitelist
- **Real Threat**: Block IP, investigate further
- **Unclear**: Monitor for pattern

**4. Acknowledge:**
- Mark alert as reviewed
- Add notes (if available)
- Track in incident log

### Filtering Alerts

**By Severity:**
- Click severity badge to filter
- RED (High) / ORANGE (Medium) / YELLOW (Low)

**By Time:**
- Last hour / 6 hours / 24 hours / 7 days
- Custom date range

**By Source:**
- Filter by sensor
- Filter by source IP
- Filter by alert type

---

## Managing Sensors

### Sensor Overview

**Sensors Tab** shows all deployed sensors with:
- 🟢 Status (Online/Offline)
- Hostname
- Location
- IP address
- Performance metrics (CPU, RAM, Bandwidth)
- Last seen timestamp
- Action buttons

### Sensor Actions

**🔄 Update** (Blue button)
```
Updates sensor software from git
- Prompts for branch (optional)
- Pulls latest code
- Restarts sensor automatically
- ~30 seconds downtime
```

**⚡ Reboot** (Yellow button)
```
Reboots the entire sensor system
- Full system restart
- ~1-5 minutes downtime
- Use for system-level issues
- Requires confirmation (type sensor name)
```

**🎚️ Settings** (Cyan button)
```
Edit sensor configuration
- Location description
- Custom parameters
- Saved to central database
- Sensor picks up within 5 minutes
```

**🗑️ Delete** (Red button)
```
Permanently removes sensor
- Deletes all metrics
- Deletes all alerts
- Cannot be undone
- Use when decommissioning
```

### Managing Sensor Settings

**Advanced Sensor Configuration:**

Each sensor can be configured with detailed settings via the dashboard. Click the Settings icon (sliders 🎚️) next to any sensor to access the sensor settings modal.

**Available Settings:**

1. **Sensor Location**
   - Physical location or network segment description
   - Examples: "Office VLAN 10", "DMZ Gateway", "Branch Office Amsterdam"
   - Helps identify which part of your network the sensor monitors
   - Shows in dashboard for quick reference

2. **Internal Networks**
   - Define your internal network CIDR ranges
   - One range per line
   - Examples:
     ```
     10.0.0.0/8
     172.16.0.0/12
     192.168.0.0/16
     ```
   - Used for detection logic (internal vs external traffic)
   - Helps identify lateral movement and internal scanning

3. **Heartbeat Interval**
   - How often the sensor sends heartbeat signals to SOC
   - Range: 10-300 seconds
   - Default: 30 seconds
   - Lower = faster offline detection, higher network overhead
   - Higher = less network traffic, slower offline detection

4. **Config Sync Interval**
   - How often sensor checks for configuration updates
   - Range: 60-3600 seconds (1 minute to 1 hour)
   - Default: 300 seconds (5 minutes)
   - Lower = faster config updates, more database queries
   - Higher = less overhead, slower config propagation

**How to Configure:**

1. Navigate to **Sensors Tab**
2. Click the **Settings** icon (🎚️) next to the sensor
3. Sensor settings modal opens
4. Edit the desired settings:
   - Update location description
   - Add/modify internal network ranges
   - Adjust heartbeat interval
   - Adjust config sync interval
5. Click **"Save Settings"**
6. Settings are saved to central database
7. Sensor automatically picks up changes within the sync interval
8. For immediate application: use the Update or Reboot button

**Important Notes:**
- All settings are stored centrally in the SOC database
- Sensors automatically synchronize settings at their configured interval
- No need to manually edit sensor.conf files
- Changes apply to the specific sensor only (not global)
- Always test settings changes on one sensor before rolling out to all

### Monitoring Sensor Health

**Green Status**: Sensor is healthy
- Sending metrics regularly
- No performance issues
- Last seen < 2 minutes ago

**Red Status**: Sensor has issues
- No communication for > 5 minutes
- High CPU/RAM usage
- Network problems

**Actions for Offline Sensor:**
1. Check sensor logs: `journalctl -u netmonitor-sensor -f`
2. Verify network connectivity
3. Check SOC server accessibility
4. Restart sensor if needed

---

## Configuration

### Centralized Configuration Management

**Modern Approach:**

NetMonitor SOC uses a centralized configuration system. All sensor settings (except basic connection parameters) are managed through the dashboard and synchronized automatically.

**Sensor-Side Configuration (sensor.conf):**

Sensors only need minimal local configuration:
```ini
INTERFACE=eth0
SOC_SERVER_URL=http://soc.example.com:8080
SSL_VERIFY=true
SENSOR_SECRET_KEY=optional-secret-key
```

**Centrally Managed Settings:**
- Sensor location and description
- Internal network ranges (CIDR)
- Detection rule thresholds
- Heartbeat and sync intervals
- Alert severity levels
- Custom detection parameters

**How It Works:**
1. Configure settings via dashboard (Sensors → Settings or Configuration tab)
2. Settings stored in SOC database
3. Sensors poll for updates at configured sync interval (default: 5 minutes)
4. Sensors automatically apply new settings
5. No manual file editing required on sensor systems

**Benefits:**
- Consistent configuration across all sensors
- Easy bulk updates
- Version control and audit trail
- No need to SSH into sensor systems
- Per-sensor customization when needed

### Detection Rules

**Configuration → Detection Rules Tab**

**Available Rules:**
1. Port Scan Detection
2. Brute Force Detection
3. DNS Tunneling Detection
4. Large File Transfer Detection
5. DDoS Detection
6. Unusual Port Activity
7. Internal Scanning
8. Protocol Anomaly Detection
9. Beacon Detection
10. Data Exfiltration Detection
11. Malware Communication Detection
12. Lateral Movement Detection
13. Suspicious DNS Detection

**For Each Rule:**
- ☑️ Enable/Disable checkbox
- 📊 Threshold values
- 📝 Description and purpose
- 🌍 Scope: Global or per-sensor

### Adjusting Thresholds

**Example: Port Scan Detection**

```
Threshold: Number of unique ports before alert
Default: 10 ports
Too many alerts: Increase to 20-30
Missing scans: Decrease to 5-10
```

**Example: Brute Force Detection**

```
Threshold: Failed attempts before alert
Default: 5 attempts
Strong security: 3 attempts
Reduce noise: 10 attempts
```

### Configuration Workflow

1. **Navigate to Configuration tab**
2. **Select category** (Detection Rules / Thresholds / etc.)
3. **Adjust values** in the form
4. **Choose scope**:
   - Global: Applies to all sensors
   - Sensor-specific: Override for one sensor
5. **Click "Save Changes"**
6. **Wait for sync** (sensors update within 5 minutes)
7. **Force immediate**: Restart sensor

### Resetting Configuration

**Reset to Defaults:**
- Click "Reset to Best Practice Defaults"
- Confirms destructive action
- Reverts all settings to recommended values
- Use when configuration is misconfigured

---

## Whitelist Management

### Why Whitelist?

Prevent false positives from:
- Internal servers
- Trusted external services
- Backup systems
- Monitoring tools
- Admin workstations

### Adding Whitelist Entries

**Whitelist Tab → Add Entry**

**Single IP:**
```
IP/CIDR: 192.168.1.50
Description: Admin workstation
Scope: Global
```

**IP Range (CIDR):**
```
IP/CIDR: 10.0.0.0/8
Description: Internal network
Scope: Global
```

**Per-Sensor Whitelist:**
```
IP/CIDR: 203.0.113.100
Description: External backup server
Scope: Sensor-specific
Sensor: office-vlan10-01
```

### Managing Whitelist

**View Entries:**
- Global whitelist (applies to all)
- Sensor-specific entries
- Shows IP, description, scope

**Remove Entry:**
- Click delete button
- Confirms action
- Sensor picks up within 5 minutes

---

## AI Integration (MCP Server)

### Overview

NetMonitor SOC includes an MCP (Model Context Protocol) server that enables AI assistants like Claude to monitor and interact with your SOC platform through a modern HTTP API.

**What is MCP?**

MCP is a standardized protocol that allows AI assistants to access external systems securely. The NetMonitor MCP server exposes your SOC data and operations to AI tools while maintaining security and access control.

**What Can AI Do?**

- **Threat Analysis**: "Claude, analyze the last 24 hours of critical alerts and identify patterns"
- **Incident Response**: "What are the top 3 priority incidents I should handle first?"
- **Security Queries**: "Show me all port scan alerts from external sources this week"
- **Operational Insights**: "Which sensors have performance issues?"
- **Custom Reports**: "Generate a summary of all brute force attempts by source country"

**For SOC Operators:**

You typically don't need to interact with the MCP server directly - it's designed for administrators who want to integrate AI capabilities. However, if you're interested in using an AI assistant to help monitor your SOC:

1. Ask your administrator to create a **read_only** API token for you
2. Connect Claude or another AI assistant using the token
3. Ask questions in natural language about your security posture
4. Get AI-powered analysis and recommendations

**Example Workflow:**

```
You: "Claude, show me the sensors that are offline"
Claude: *queries MCP server*
        "Currently 2 sensors are offline:
        - office-vlan10-01 (last seen 15 minutes ago)
        - branch-dmz-03 (last seen 2 hours ago)"

You: "Analyze the recent DDoS alerts"
Claude: *retrieves and analyzes alerts*
        "I found 5 DDoS alerts in the past 6 hours, all targeting
        10.0.0.50. Pattern suggests volumetric attack.
        Recommendation: Enable rate limiting and contact ISP."
```

**Security Note:**

All MCP access is authenticated and logged. Your administrator controls what permissions each token has (read-only vs full access). AI assistants can only see data you have access to.

**Learn More:**

If you want to set up AI integration, refer to the [ADMIN_MANUAL.md](ADMIN_MANUAL.md) MCP Server section or contact your administrator.

---

## Common Tasks

### Investigating a Port Scan Alert

**1. Review Alert:**
```
Alert: Port Scan Detected
Source: 192.168.1.100
Ports: 22, 23, 80, 443, 3306, 3389, 8080
```

**2. Identify Source:**
- Is it internal or external?
- Known IP? Check inventory
- Hostname available?

**3. Determine Intent:**
- **Legitimate**: Admin tool, vulnerability scanner
  → Add to whitelist
- **Malicious**: Unauthorized scanning
  → Block IP, investigate system
- **Compromised**: Internal system infected
  → Isolate system, run antivirus

**4. Take Action:**
- Whitelist if legitimate
- Block and monitor if suspicious
- Incident response if compromised

### Adding a New Sensor

**1. Prepare Sensor:**
- Linux machine with network access
- Mirror port or in-line deployment
- SSH access

**2. Deploy:**
```bash
# On sensor machine
scp -r netmonitor/ user@sensor:/tmp/
ssh user@sensor
cd /tmp/netmonitor
sudo ./setup_sensor.sh
```

**3. Verify:**
- Check Sensors tab in dashboard
- Sensor appears as Online
- Metrics updating

**4. Configure:**
- Click Settings button
- Set location
- Configure internal networks
- Adjust heartbeat/sync intervals if needed
- Adjust sensor-specific config if needed

### Tuning Detection Rules

**Too Many Alerts:**
1. Review alert patterns
2. Identify common sources
3. Options:
   - Add legitimate sources to whitelist
   - Increase detection thresholds
   - Disable overly sensitive rules

**Missing Real Threats:**
1. Review known attack scenarios
2. Check if alerts generated
3. Options:
   - Decrease thresholds
   - Enable additional rules
   - Review whitelist (too broad?)

### Weekly Maintenance

**Monday Morning Checklist:**
- ✅ Review alerts from weekend
- ✅ Check sensor status (all online?)
- ✅ Review top talkers for anomalies
- ✅ Update whitelist if needed
- ✅ Check disk space on SOC server

---

## Best Practices

### Alert Management

**Do:**
- ✅ Review alerts daily
- ✅ Investigate unknowns immediately
- ✅ Keep whitelist up to date
- ✅ Document your decisions
- ✅ Track false positive patterns

**Don't:**
- ❌ Ignore low-severity alerts completely
- ❌ Disable rules without understanding
- ❌ Over-whitelist (defeats purpose)
- ❌ Forget to acknowledge reviewed alerts

### Configuration

**Do:**
- ✅ Start with defaults
- ✅ Adjust gradually based on experience
- ✅ Document changes
- ✅ Test in development first
- ✅ Use sensor-specific overrides when needed

**Don't:**
- ❌ Set thresholds too high (miss threats)
- ❌ Set thresholds too low (alert fatigue)
- ❌ Change multiple settings at once
- ❌ Disable all detection rules

### Sensor Management

**Do:**
- ✅ Deploy sensors strategically
- ✅ Monitor sensor health
- ✅ Keep sensors updated
- ✅ Use descriptive names/locations
- ✅ Document sensor placements

**Don't:**
- ❌ Deploy sensors without planning
- ❌ Ignore offline sensors
- ❌ Mix sensor versions significantly
- ❌ Overload sensors with traffic

### Sensor Configuration

**Do:**
- ✅ Use dashboard to adjust sensor settings (not manual sensor.conf editing)
- ✅ Always configure location and internal networks via dashboard
- ✅ Test configuration changes on one sensor first before rolling out to all
- ✅ Monitor sensor status after config changes
- ✅ Document why you made specific configuration choices
- ✅ Use appropriate heartbeat intervals (default 30s is good for most)
- ✅ Keep config sync interval at default (300s) unless you have specific needs

**Don't:**
- ❌ Manually edit sensor.conf files on sensor systems (except initial setup)
- ❌ Set heartbeat interval too low (< 15s causes unnecessary overhead)
- ❌ Set config sync interval too high (> 600s delays important updates)
- ❌ Copy sensor.conf between different sensors (each needs unique ID)
- ❌ Change multiple sensor settings simultaneously without testing
- ❌ Forget to define internal networks (critical for accurate detection)

---

## Keyboard Shortcuts

### Dashboard Navigation

- `Alt + 1`: Alerts tab
- `Alt + 2`: Sensors tab
- `Alt + 3`: Configuration tab
- `Alt + 4`: Whitelist tab
- `F5`: Refresh dashboard
- `Ctrl + F`: Search alerts

### Alert Actions

- `↑` `↓`: Navigate alerts
- `Enter`: View alert details
- `A`: Acknowledge alert
- `W`: Add to whitelist

*(Note: Shortcuts may vary by browser)*

---

## Troubleshooting

### Dashboard Not Updating

**Issue:** Real-time updates stopped
**Solution:**
1. Check browser console for errors
2. Refresh page (F5)
3. Check SOC server status
4. Verify WebSocket connection

### Sensor Offline

**Issue:** Sensor shows red status
**Solution:**
1. Check sensor logs
2. Verify network connectivity
3. Ping SOC server from sensor
4. Restart sensor service
5. Check firewall rules

### Too Many Alerts

**Issue:** Alert fatigue
**Solution:**
1. Review common alert sources
2. Add legitimate traffic to whitelist
3. Increase thresholds for noisy rules
4. Consider disabling rules temporarily
5. Analyze traffic patterns

### False Positives

**Issue:** Alerts on legitimate traffic
**Solution:**
1. Identify source of false positives
2. Add to whitelist (preferred)
3. Or adjust rule thresholds
4. Document why it's legitimate
5. Monitor for true pattern

---

## Getting Help

**For Technical Issues:**
- Check logs: `journalctl -u netmonitor-soc -f`
- Review [ADMIN_MANUAL.md](ADMIN_MANUAL.md)
- Contact system administrator

**For Security Questions:**
- Follow incident response procedures
- Escalate to security team
- Document findings

**For Feature Requests:**
- Discuss with admin team
- Submit via proper channels
- Provide use case details

---

## Quick Reference

### Alert Severity Levels

| Color | Severity | Action Required |
|-------|----------|----------------|
| 🔴 RED | HIGH | Immediate investigation |
| 🟠 ORANGE | MEDIUM | Review within 1 hour |
| 🟡 YELLOW | LOW | Review daily |

### Sensor Status Icons

| Icon | Meaning | Action |
|------|---------|--------|
| 🟢 Green | Online, healthy | None |
| 🔴 Red | Offline | Investigate |
| 🟡 Yellow | Degraded | Monitor |

### Common IP Ranges

| Range | Purpose |
|-------|---------|
| 10.0.0.0/8 | Private networks |
| 172.16.0.0/12 | Private networks |
| 192.168.0.0/16 | Private networks |
| 127.0.0.0/8 | Localhost |
| 0.0.0.0/8 | Invalid source |

---

## Next Steps

**Learn More:**
- [DETECTION_FEATURES.md](DETECTION_FEATURES.md) - All detection capabilities
- [DASHBOARD.md](DASHBOARD.md) - Dashboard features in detail
- [CONFIG_GUIDE.md](CONFIG_GUIDE.md) - Configuration reference

**For Administrators:**
- [ADMIN_MANUAL.md](ADMIN_MANUAL.md) - Installation and administration

---

*Last updated: December 2024*
*NetMonitor SOC v2.1 - Stay Vigilant, Stay Secure*
