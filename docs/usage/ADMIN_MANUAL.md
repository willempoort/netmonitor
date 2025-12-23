# NetMonitor SOC - Administrator Manual

**Complete Installation & Administration Guide**

Version: 2.2
Last Updated: December 2025

---

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [SOC Server Installation](#soc-server-installation)
5. [Sensor Deployment](#sensor-deployment)
6. [Configuration Management](#configuration-management)
7. [Device Classification Administration](#device-classification-administration)
8. [MCP Server](#mcp-server)
9. [Maintenance & Troubleshooting](#maintenance--troubleshooting)
10. [Web Dashboard Authentication & User Management](#web-dashboard-authentication--user-management)
11. [Security Best Practices](#security-best-practices)
12. [NIS2 Compliance](#nis2-compliance)
13. [Advanced Topics](#advanced-topics)

---

## System Overview

NetMonitor is a centralized Security Operations Center (SOC) platform for network monitoring and threat detection. The system consists of:

- **SOC Server**: Central dashboard and database (PostgreSQL + TimescaleDB)
- **Remote Sensors**: Lightweight packet capture agents deployed across your network
- **Web Dashboard**: Real-time monitoring interface on port 8080
- **MCP Server**: AI-powered REST API for security analysis and automation

### Key Capabilities

✅ **Real-time threat detection** - 13 built-in detection rules
✅ **Centralized management** - All configuration via dashboard
✅ **Distributed sensors** - Deploy anywhere in your network
✅ **Auto-synchronization** - Sensors pull config every 5 minutes
✅ **Professional UI** - Dark theme, WebSocket updates, gauges
✅ **Time-series database** - Optimized for metrics and alerts
✅ **AI Integration** - Model Context Protocol (MCP) server for Claude and other AI assistants
✅ **Enhanced sensor configuration** - Location, networks, and intervals via dashboard

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      SOC Server                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Web Dashboard│  │  PostgreSQL  │  │   Python     │      │
│  │   (Port 8080)│  │  TimescaleDB │  │   Backend    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────────────────────────────────────────┐       │
│  │         MCP HTTP API (Port 8000)                 │       │
│  │  AI-Powered Security Analysis & Automation       │       │
│  └──────────────────────────────────────────────────┘       │
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
5. **AI Assistants → MCP API**: Query, analyze, automate via AI

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

# Allow MCP API access (optional, if using MCP server)
sudo ufw allow 8000/tcp

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
- ✅ Generates minimal `sensor.conf` (only connection settings)
- ✅ Installs systemd service
- ✅ Starts sensor service
- ✅ Registers with SOC server

### Manual Sensor Setup

See [SENSOR_DEPLOYMENT.md](SENSOR_DEPLOYMENT.md) for manual sensor configuration.

### Minimal Sensor Configuration

**The sensor.conf is now minimal!** Only connection settings are required locally. All other settings (detection rules, thresholds, intervals, networks) are managed centrally via the SOC dashboard.

**Minimal `/opt/netmonitor/sensor.conf`:**

```bash
# Required settings
SOC_SERVER_URL=http://192.168.1.100:8080
INTERFACE=eth0

# Optional settings (can be set via dashboard)
SENSOR_ID=office-vlan10-01
SENSOR_LOCATION=Building A - VLAN 10
SENSOR_SECRET_KEY=your-secret-key-here
```

**Centralized Configuration:**
- Detection rules (port scans, brute force, DDoS, etc.)
- Thresholds (CPU, memory, bandwidth)
- Internal networks (CIDR ranges)
- Heartbeat interval (10-300 seconds)
- Config sync interval (60-3600 seconds)
- Whitelist entries

**Auto-Synchronization:**
- Sensors automatically pull configuration from SOC server
- Default sync interval: 5 minutes (300 seconds)
- Configurable via dashboard per sensor
- Changes propagate automatically without manual restarts

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
- Use settings button to configure sensor-specific parameters

---

## Configuration Management

### Centralized Configuration

**All configuration is now managed via the SOC Dashboard!**

Sensors maintain minimal local configuration (only connection settings). All operational parameters are synchronized from the central SOC server every 5 minutes.

#### Dashboard → Configuration Management

**What you can configure globally:**

1. **Detection Rules** (15+ rules):
   - Port scan detection
   - Brute force detection
   - DNS tunneling detection
   - DDoS detection
   - Protocol anomalies
   - **TLS/HTTPS analysis** (JA3 fingerprinting, certificate validation)
   - **PCAP forensics** (automatic capture around alerts)
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
3. Sensors auto-sync within 5 minutes (or configured interval)
4. Force immediate sync: restart sensor or wait for next sync cycle

#### Enhanced Sensor Settings Editor

Each sensor can be individually configured via the web dashboard with the following parameters:

**Access the Sensor Settings:**
1. Go to Dashboard → Sensors
2. Click **Settings** button (sliders icon) next to any sensor
3. Edit sensor-specific configuration
4. Click **Save Changes**

**Configurable Per-Sensor Parameters:**

1. **Sensor Location** (string):
   - Human-readable location description
   - Example: "Building A - Floor 3 - VLAN 10"
   - Helps identify sensor placement in alerts
   - Can be set during deployment or updated later

2. **Internal Networks** (CIDR notation):
   - Define internal IP ranges for this sensor
   - Comma-separated list of CIDR blocks
   - Example: `192.168.1.0/24,10.0.0.0/8,172.16.0.0/12`
   - Used for internal vs external traffic classification
   - Improves accuracy of threat detection

3. **Heartbeat Interval** (10-300 seconds):
   - How often sensor sends "I'm alive" messages
   - Default: 60 seconds
   - Lower = faster offline detection, higher network overhead
   - Higher = less network traffic, slower offline detection

4. **Config Sync Interval** (60-3600 seconds):
   - How often sensor pulls configuration from SOC
   - Default: 300 seconds (5 minutes)
   - Lower = faster config propagation, more API calls
   - Higher = less load on SOC server, slower updates

**Automatic Synchronization:**
- All changes made via dashboard are stored in database
- Sensors fetch their specific configuration on next sync cycle
- No manual intervention or sensor restarts required
- Configuration changes are logged for audit trail

**Example Workflow:**
```
1. Admin edits sensor "office-fw-01" in dashboard
2. Sets location to "Main Office - Firewall"
3. Sets INTERNAL_NETWORKS to "192.168.0.0/16,10.10.0.0/16"
4. Sets HEARTBEAT_INTERVAL to 30 seconds
5. Clicks "Save Changes"
6. Within 5 minutes (or configured interval):
   - Sensor fetches new configuration
   - Applies new settings automatically
   - Logs configuration update
7. Dashboard shows updated sensor metadata
```

#### SOC Server Self-Monitoring Config Sync

**The SOC server itself can also monitor its local network traffic!**

If `self_monitor.enabled: true` in `config.yaml`, the SOC server acts as both:
- **Server**: Receiving alerts from remote sensors
- **Sensor**: Monitoring its own network interface

**Automatic Config Reload (No Restart Required):**

When self-monitoring is enabled:
1. SOC server registers itself with sensor ID `soc-server` (configurable)
2. Loads initial configuration from `config.yaml` at startup
3. Merges with database configuration (database takes precedence)
4. **Background thread syncs config every 5 minutes**
5. Configuration changes apply immediately without restart

**How It Works:**
```
1. Admin edits detection thresholds in dashboard
2. Changes are saved to database
3. Within 5 minutes:
   - SOC server background thread runs
   - Fetches updated config from database
   - Deep merges with existing config (database overrides yaml)
   - Detector immediately uses new thresholds
   - Logs: "✓ Config updated from database: 3 parameter(s) changed"
4. New detection rules active immediately
```

**Log Output Examples:**
```
INFO - SOC server self-monitoring enabled as sensor: soc-server
INFO - Config sync enabled (checking every 300s)
INFO - ✓ Config updated from database: 3 parameter(s) changed
INFO -   Updated categories: port_scan, connection_flood
```

**Configuration Priority (Highest to Lowest):**
1. **Database sensor-specific** (for sensor ID `soc-server`)
2. **Database global** (applies to all sensors)
3. **config.yaml** (fallback/defaults)

**Benefits:**
- No need to restart SOC server after config changes
- Consistent config management across all sensors (including SOC server)
- Changes tested on SOC server before deploying to remote sensors
- Full audit trail of all configuration changes

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

## Device Classification Administration

Device Classification is a ML-based system that automatically discovers devices, learns their behavior patterns, and suppresses expected alerts. This section covers the administrative aspects.

### Database Tables

Device Classification uses the following database tables:

| Table | Purpose |
|-------|---------|
| `devices` | Discovered devices with IP, MAC, hostname, learned behavior |
| `device_templates` | Templates defining expected behavior per device type |
| `template_behaviors` | Behavior rules for each template |
| `service_providers` | Known streaming/CDN providers |

### Database Migration

If upgrading from a version without Device Classification, run the migration:

```bash
cd /opt/netmonitor
python3 migrate_device_classification.py
```

This creates the necessary tables and indexes.

### Built-in Templates

NetMonitor includes built-in templates that cannot be modified:

```bash
# View built-in templates in database
psql -U netmonitor -d netmonitor -c "SELECT name, category FROM device_templates WHERE is_builtin = true;"
```

Built-in templates include: IP Camera, Smart TV, Network Printer, Router/Firewall, DNS Server, Web Server, Workstation.

### Template Management via CLI

**List all templates:**
```bash
psql -U netmonitor -d netmonitor -c "SELECT id, name, category, is_builtin, (SELECT COUNT(*) FROM devices WHERE template_id = device_templates.id) as device_count FROM device_templates;"
```

**Create custom template via SQL:**
```sql
INSERT INTO device_templates (name, category, description, is_builtin)
VALUES ('Custom VoIP Phone', 'iot', 'Office VoIP telephones', false);
```

**Add behavior rule:**
```sql
INSERT INTO template_behaviors (template_id, behavior_type, parameters, action, description)
VALUES (
    (SELECT id FROM device_templates WHERE name = 'Custom VoIP Phone'),
    'allowed_ports',
    '{"ports": [5060, 5061]}',
    'allow',
    'SIP signaling ports'
);
```

### Service Provider Management

**List built-in providers:**
```bash
psql -U netmonitor -d netmonitor -c "SELECT name, category FROM service_providers WHERE is_builtin = true;"
```

**Add custom provider:**
```sql
INSERT INTO service_providers (name, category, ip_ranges, domains, description, is_builtin)
VALUES (
    'Zoom',
    'cloud',
    ARRAY['3.7.35.0/25', '3.21.137.128/25'],
    ARRAY['*.zoom.us', '*.zoomgov.com'],
    'Zoom video conferencing',
    false
);
```

### Device Discovery Configuration

Device discovery runs as part of the sensor and is controlled by these settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `ENABLE_DEVICE_DISCOVERY` | true | Enable/disable discovery |
| `OUI_DATABASE_PATH` | `/opt/netmonitor/oui.txt` | Path to OUI database |
| `DEVICE_LEARNING_MIN_PACKETS` | 100 | Packets needed for "Ready" status |

**Update OUI database:**
```bash
cd /opt/netmonitor
wget -O oui.txt https://standards-oui.ieee.org/oui/oui.txt
```

### Alert Suppression Logic

Device Classification suppresses alerts based on:

1. **Device Template Match**: If device has a template assigned
2. **Behavior Rule Match**: If traffic matches an "allow" rule
3. **Service Provider Match**: If destination is a known provider

**Never suppressed (regardless of rules):**
- CRITICAL severity alerts
- C2 (Command & Control) detection
- Known malware communication
- Threat intelligence matches

### API Endpoints

Device Classification exposes these API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all devices |
| `/api/devices/<ip>` | GET | Get device details |
| `/api/devices/<ip>/template` | PUT | Assign template |
| `/api/device-templates` | GET | List templates |
| `/api/device-templates` | POST | Create template |
| `/api/device-templates/<id>` | GET | Get template details |
| `/api/device-templates/<id>/behaviors` | POST | Add behavior rule |
| `/api/service-providers` | GET | List providers |
| `/api/device-classification/stats` | GET | Get statistics |

### MCP Tools for Device Classification

The MCP server includes these tools for AI integration:

| Tool | Scope | Description |
|------|-------|-------------|
| `get_devices` | read_only | List discovered devices |
| `get_device_templates` | read_only | List device templates |
| `get_service_providers` | read_only | List service providers |
| `get_device_learning_status` | read_only | Get learning status for device |
| `assign_device_template` | read_write | Assign template to device |
| `create_device_template` | read_write | Create new template |
| `save_device_learned_behavior` | read_write | Save learned behavior |

### Performance Considerations

**Database indexes:**
The migration creates indexes for optimal performance:
```sql
CREATE INDEX idx_devices_template ON devices(template_id);
CREATE INDEX idx_devices_sensor ON devices(sensor_id);
CREATE INDEX idx_template_behaviors_template ON template_behaviors(template_id);
```

**Cleanup old devices:**
```sql
-- Remove devices not seen in 30 days
DELETE FROM devices WHERE last_seen < NOW() - INTERVAL '30 days';
```

### Troubleshooting

**Devices not appearing:**
1. Check sensor is running with device discovery enabled
2. Verify network interface captures ARP/IP traffic
3. Check sensor logs: `journalctl -u netmonitor-sensor -f`

**Learning status stuck at "Not Started":**
1. Device may not be generating traffic
2. Check if device IP is in internal_networks range
3. Verify sensor is processing packets

**Alert suppression not working:**
1. Verify device has template assigned
2. Check behavior rules match the traffic
3. Ensure alert is not CRITICAL severity
4. Check service provider domains/IPs

**Debug device classification:**
```bash
# Check device in database
psql -U netmonitor -d netmonitor -c "SELECT * FROM devices WHERE ip_address = '192.168.1.100';"

# Check template behaviors
psql -U netmonitor -d netmonitor -c "
SELECT t.name, b.behavior_type, b.parameters, b.action
FROM device_templates t
JOIN template_behaviors b ON b.template_id = t.id
WHERE t.id = 1;
"
```

---

## MCP Server

The **Model Context Protocol (MCP) Server** is an HTTP REST API that provides AI assistants (like Claude) with complete access to the SOC platform for security analysis, automation, and management.

### Overview

The MCP server enables AI-powered security operations by exposing SOC functionality through a standardized API. AI assistants can query alerts, analyze threats, manage configurations, and execute security workflows using natural language.

**Key Features:**
- **Token-based authentication**: Secure Bearer token system
- **Permission scopes**: read_only, read_write, admin
- **Rate limiting**: Per-token request limits
- **23+ specialized tools**: Security analysis, reporting, management
- **Auto-documentation**: Swagger/OpenAPI interface
- **Audit logging**: Complete request history

### Architecture

```
┌──────────────────┐
│  AI Assistant    │
│  (Claude, etc)   │
└────────┬─────────┘
         │ HTTP REST API
         │ Bearer Token Auth
┌────────▼──────────────────────────────────────┐
│         MCP HTTP Server (Port 8000)           │
│  ┌─────────────────────────────────────────┐  │
│  │  Authentication & Authorization Layer   │  │
│  │  - Token validation                     │  │
│  │  - Permission checking                  │  │
│  │  - Rate limiting                        │  │
│  └─────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────┐  │
│  │  23+ MCP Tools                          │  │
│  │  - Security Analysis                    │  │
│  │  - Exports & Reporting                  │  │
│  │  - Configuration Management             │  │
│  │  - Sensor Management                    │  │
│  │  - Whitelist Management                 │  │
│  │  - AI-Powered Analysis                  │  │
│  └─────────────────────────────────────────┘  │
└────────┬──────────────────────────────────────┘
         │
┌────────▼─────────────────┐
│  PostgreSQL Database     │
│  - Alerts                │
│  - Sensors               │
│  - Configuration         │
│  - MCP Tokens            │
│  - Audit Logs            │
└──────────────────────────┘
```

### Installation

**1. Install MCP Server:**

```bash
cd /opt/netmonitor

# Ensure Python venv is activated
python3 -m venv venv
source venv/bin/activate

# Run installation script
sudo ./mcp_server/setup_http_api.sh
```

The setup script will:
- ✅ Install required Python dependencies (fastapi, uvicorn, etc.)
- ✅ Create systemd service (`netmonitor-mcp-http`)
- ✅ Configure firewall (optional)
- ✅ Start MCP server on port 8000

**2. Verify Installation:**

```bash
# Check service status
systemctl status netmonitor-mcp-http

# Test health endpoint
curl http://localhost:8000/health

# View API documentation
# Open browser: http://localhost:8000/docs
```

**3. Configure Firewall (if needed):**

```bash
# Allow MCP API access from specific network
sudo ufw allow from 192.168.1.0/24 to any port 8000

# Or allow from anywhere (not recommended for production)
sudo ufw allow 8000/tcp
```

### Token Management

The MCP server uses token-based authentication. Each token has:
- Unique token ID (UUID)
- Name/description
- Permission scope (read_only, read_write, admin)
- Rate limit (requests per minute)
- Creation and last-used timestamps

**Create Tokens:**

```bash
cd /opt/netmonitor

# Create read-only token for AI assistant
python3 mcp_server/manage_tokens.py create \
  --name "Claude Desktop" \
  --scope read_only \
  --rate-limit 60

# Create read-write token for automation
python3 mcp_server/manage_tokens.py create \
  --name "Security Automation" \
  --scope read_write \
  --rate-limit 120

# Create admin token for full access
python3 mcp_server/manage_tokens.py create \
  --name "Admin Console" \
  --scope admin \
  --rate-limit 300
```

**List Tokens:**

```bash
# View all tokens
python3 mcp_server/manage_tokens.py list

# View token statistics
python3 mcp_server/manage_tokens.py stats
```

**Revoke Tokens:**

```bash
# Revoke token by ID
python3 mcp_server/manage_tokens.py revoke <token_id>
```

### Permission Scopes

**read_only:**
- View alerts, metrics, sensors
- Export data (CSV, JSON)
- Analyze threats and IPs
- Read configuration
- Generate reports

**read_write:**
- Everything in read_only, plus:
- Modify configuration parameters
- Manage whitelist entries
- Send sensor commands
- Update sensor settings

**admin:**
- Everything in read_write, plus:
- Manage MCP tokens
- Access audit logs
- System administration
- Database operations

### API Endpoints

**Core Endpoints:**

```bash
# Health check
GET http://localhost:8000/health

# API documentation (Swagger UI)
GET http://localhost:8000/docs

# OpenAPI schema
GET http://localhost:8000/openapi.json

# List available tools
GET http://localhost:8000/mcp/tools
Authorization: Bearer <your_token>

# Execute a tool
POST http://localhost:8000/mcp/tools/execute
Authorization: Bearer <your_token>
Content-Type: application/json

{
  "tool_name": "analyze_ip",
  "parameters": {
    "ip_address": "203.0.113.45",
    "time_range_hours": 24
  }
}
```

### Tool Categories

The MCP server provides 23+ specialized tools organized into categories:

#### 1. Security Analysis Tools (read_only)

**analyze_ip:**
- Analyze specific IP address for threats
- Parameters: ip_address, time_range_hours
- Returns: Alert history, threat level, recommendations

**get_recent_threats:**
- Get recent high-severity threats
- Parameters: hours (default: 24), severity_min
- Returns: List of critical alerts with details

**get_threat_timeline:**
- Get timeline of threats by type
- Parameters: time_range_hours, group_by
- Returns: Threat distribution over time

**get_top_attackers:**
- Identify most active threat sources
- Parameters: limit, time_range_hours
- Returns: Ranked list of attacking IPs

**get_attack_patterns:**
- Analyze attack patterns and trends
- Parameters: time_range_hours
- Returns: Pattern analysis and statistics

#### 2. Exports & Reporting Tools (read_only)

**export_alerts_csv:**
- Export alerts to CSV format
- Parameters: time_range_hours, severity
- Returns: CSV file data

**export_traffic_stats_csv:**
- Export traffic statistics
- Parameters: sensor_id, time_range_hours
- Returns: CSV file with traffic metrics

**generate_security_report:**
- Generate comprehensive security report
- Parameters: time_range_hours
- Returns: PDF or HTML report

#### 3. Configuration Management Tools (read_write)

**get_config_parameters:**
- Retrieve configuration parameters
- Parameters: scope (global/sensor-specific)
- Returns: Current configuration values

**set_config_parameter:**
- Update configuration parameter
- Parameters: key, value, scope, sensor_id
- Returns: Confirmation and updated value

**get_detection_rules:**
- List all detection rules and status
- Returns: Detection rules with enabled/disabled state

**toggle_detection_rule:**
- Enable or disable detection rule
- Parameters: rule_name, enabled
- Returns: Updated rule status

#### 4. Sensor Management Tools (read_write)

**get_sensor_status:**
- Get status of all sensors
- Returns: Sensor list with online/offline status, metrics

**get_sensor_details:**
- Get detailed sensor information
- Parameters: sensor_id
- Returns: Full sensor configuration and stats

**send_sensor_command:**
- Send command to sensor
- Parameters: sensor_id, command
- Returns: Command execution result

**update_sensor_settings:**
- Update sensor-specific settings
- Parameters: sensor_id, settings (location, networks, intervals)
- Returns: Updated sensor configuration

#### 5. Whitelist Management Tools (read_write)

**get_whitelist_entries:**
- List all whitelist entries
- Returns: IP ranges and descriptions

**add_whitelist_entry:**
- Add IP/range to whitelist
- Parameters: ip_range, description
- Returns: Confirmation

**remove_whitelist_entry:**
- Remove whitelist entry
- Parameters: entry_id or ip_range
- Returns: Confirmation

**check_ip_whitelisted:**
- Check if IP is whitelisted
- Parameters: ip_address
- Returns: Boolean and matching entry

#### 6. AI-Powered Analysis Tools (read_only)

**analyze_threat_with_ollama:**
- AI analysis of threat using local Ollama
- Parameters: alert_id or threat_data
- Returns: AI-generated threat analysis and recommendations

**suggest_incident_response:**
- AI-suggested incident response playbook
- Parameters: threat_type, severity
- Returns: Step-by-step response procedure

**correlate_alerts:**
- AI-powered alert correlation
- Parameters: time_range_hours
- Returns: Related alerts and attack chains

#### 7. TLS Analysis Tools

**get_tls_metadata:** (read_only)
- Get recent TLS handshake metadata
- Parameters: limit, ip_filter, sni_filter
- Returns: JA3 fingerprints, SNI hostnames, certificate info

**get_tls_stats:** (read_only)
- Get TLS analyzer statistics
- Returns: Handshakes analyzed, malicious JA3 detected, etc.

**check_ja3_fingerprint:** (read_only)
- Check if JA3 fingerprint is known malicious
- Parameters: ja3_hash
- Returns: is_malicious, malware_family

**add_ja3_blacklist:** (read_write)
- Add JA3 fingerprint to malware blacklist
- Parameters: ja3_hash, malware_family
- Returns: Confirmation

#### 8. PCAP Forensics Tools

**get_pcap_captures:** (read_only)
- List all saved PCAP capture files
- Returns: Filename, size, created date

**get_pcap_stats:** (read_only)
- Get PCAP exporter statistics
- Returns: Buffer size, captures saved, pending captures

**get_packet_buffer_summary:** (read_only)
- Get summary of packets in ring buffer
- Returns: Count, time span, protocol breakdown

**export_flow_pcap:** (read_write)
- Export packets for specific flow to PCAP
- Parameters: src_ip, dst_ip, dst_port
- Returns: Filepath to saved PCAP

**delete_pcap_capture:** (read_write)
- Delete a PCAP capture file
- Parameters: filename
- Returns: Confirmation

### Usage Examples

**Example 1: Analyze Suspicious IP**

```bash
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "analyze_ip",
    "parameters": {
      "ip_address": "203.0.113.45",
      "time_range_hours": 24
    }
  }'
```

**Example 2: Export Recent Alerts**

```bash
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "export_alerts_csv",
    "parameters": {
      "time_range_hours": 48,
      "severity": "high"
    }
  }' > alerts.csv
```

**Example 3: Update Sensor Configuration**

```bash
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "update_sensor_settings",
    "parameters": {
      "sensor_id": "office-fw-01",
      "settings": {
        "location": "Main Office - Firewall",
        "internal_networks": "192.168.0.0/16,10.10.0.0/16",
        "heartbeat_interval": 30
      }
    }
  }'
```

**Example 4: Add Whitelist Entry**

```bash
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "add_whitelist_entry",
    "parameters": {
      "ip_range": "203.0.113.0/24",
      "description": "Trusted partner network"
    }
  }'
```

### Integration with Claude Desktop

To integrate with Claude Desktop:

1. **Create MCP token:**
   ```bash
   python3 mcp_server/manage_tokens.py create --name "Claude" --scope read_only
   ```

2. **Configure Claude Desktop:**
   Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "netmonitor": {
         "url": "http://your-soc-server:8000/mcp",
         "headers": {
           "Authorization": "Bearer <your_token>"
         }
       }
     }
   }
   ```

3. **Use in Claude:**
   - "Show me recent high-severity threats"
   - "Analyze IP address 203.0.113.45"
   - "Export alerts from the last 24 hours"
   - "What are the top attackers today?"

### Security Considerations

**Best Practices:**

1. **Token Security:**
   - Store tokens securely (environment variables, secrets manager)
   - Never commit tokens to version control
   - Rotate tokens periodically
   - Use minimal required scope (principle of least privilege)

2. **Network Security:**
   - Restrict MCP API access to trusted networks
   - Use firewall rules to limit access
   - Consider using VPN for remote access
   - Enable HTTPS in production (use reverse proxy)

3. **Rate Limiting:**
   - Configure appropriate rate limits per token
   - Monitor for unusual API usage patterns
   - Review audit logs regularly

4. **Audit Logging:**
   - All API requests are logged to database
   - Review logs for suspicious activity
   - Set up alerts for unusual patterns

**Production Deployment:**

For production use:
- Deploy behind reverse proxy (nginx/Apache) with HTTPS
- Use strong authentication (consider OAuth2)
- Implement IP whitelisting
- Enable request logging and monitoring
- Set up rate limiting and throttling
- Regular security audits of API access

### Troubleshooting

**MCP Server not starting:**
```bash
# Check service status
systemctl status netmonitor-mcp-http

# View logs
journalctl -u netmonitor-mcp-http -f

# Check port availability
netstat -tlnp | grep 8000
```

**Authentication errors:**
```bash
# Verify token exists
python3 mcp_server/manage_tokens.py list

# Check token permissions
python3 mcp_server/manage_tokens.py stats

# Test with curl
curl -H "Authorization: Bearer <token>" http://localhost:8000/mcp/tools
```

**Rate limiting issues:**
```bash
# Check current rate limits
python3 mcp_server/manage_tokens.py stats

# Increase rate limit for token
python3 mcp_server/manage_tokens.py update <token_id> --rate-limit 300
```

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

**MCP Server logs:**
```bash
journalctl -u netmonitor-mcp-http -f
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

**Sensor not syncing configuration:**
- Check CONFIG_SYNC_INTERVAL in sensor settings
- Verify sensor has network connectivity to SOC
- Check SOC server logs for sync errors
- Force sync by restarting sensor

**High CPU usage:**
- Check alert rate in dashboard
- Adjust detection thresholds
- Consider adding IPs to whitelist
- Review INTERNAL_NETWORKS settings per sensor

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
- Verify HEARTBEAT_INTERVAL is not too high

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

**MCP Server:**
```bash
sudo systemctl start netmonitor-mcp-http
sudo systemctl stop netmonitor-mcp-http
sudo systemctl restart netmonitor-mcp-http
sudo systemctl status netmonitor-mcp-http
```

### Backup & Restore

**Backup database:**
```bash
# Full backup
sudo -u postgres pg_dump netmonitor > netmonitor_backup.sql

# Compressed backup
sudo -u postgres pg_dump netmonitor | gzip > netmonitor_backup.sql.gz

# Include MCP tokens and audit logs
sudo -u postgres pg_dump netmonitor --table=mcp_tokens --table=mcp_audit_log >> netmonitor_backup.sql
```

**Restore database:**
```bash
# Stop services
sudo systemctl stop netmonitor-soc
sudo systemctl stop netmonitor-mcp-http

# Restore
sudo -u postgres psql netmonitor < netmonitor_backup.sql

# Restart services
sudo systemctl start netmonitor-soc
sudo systemctl start netmonitor-mcp-http
```

---

## Web Dashboard Authentication & User Management

NetMonitor v2.0+ includes comprehensive user authentication with multi-factor authentication (2FA) support.

### Initial Admin Setup

After installing the SOC server, create the first administrator account:

```bash
python3 setup_admin_user.py
```

The script will prompt you for:
- **Username** (minimum 3 characters)
- **Email** (optional but recommended for recovery)
- **Password** (minimum 12 characters, must include uppercase, lowercase, and digits)
- **2FA** (optional but strongly recommended)

**Example:**
```
NetMonitor - Admin User Setup
=====================================

[1/4] Connecting to database...
✓ Database connected

[2/4] Initializing authentication manager...
✓ Auth manager ready

[3/4] Enter administrator details
--------------------------------------
Username: admin
Email (optional): admin@example.com
Password: ****************
Confirm password: ****************

Enable 2FA now? (y/N): y

Summary:
  Username: admin
  Email:    admin@example.com
  Role:     admin
  2FA:      Enabled
--------------------------------------

Create this admin user? (y/N): y

✓ Admin user created successfully!
```

### Accessing the Dashboard

1. **Start the dashboard server:**
   ```bash
   python3 web_dashboard.py
   ```

2. **Open your browser:**
   ```
   http://localhost:8181/
   ```

3. **Log in with your credentials**

### User Roles

NetMonitor supports three role levels:

| Role | Permissions |
|------|-------------|
| **Admin** | Full access - User management, all configuration, sensor management |
| **Operator** | Sensor & alert management, configuration changes, acknowledge alerts |
| **Viewer** | Read-only access - View dashboard, alerts, and metrics only |

### Creating Additional Users

Administrators can create additional users via the dashboard:

1. **Access User Management:**
   - Click on your username in the top-right
   - Select "User Management" (admin only)

2. **Create New User:**
   - Click "Create New User"
   - Fill in details:
     - Username (required)
     - Email (optional)
     - Password (min 12 chars, required)
     - Role (admin/operator/viewer)
     - Enable 2FA (checkbox)

3. **Share credentials securely with the new user**

### Two-Factor Authentication (2FA)

2FA adds an extra security layer using time-based one-time passwords (TOTP).

#### Setting Up 2FA

1. **Access 2FA settings:**
   - Click your username → "Two-Factor Auth"

2. **Enable 2FA:**
   - Click "Enable 2FA"
   - Scan the QR code with an authenticator app:
     - **Google Authenticator** (iOS/Android)
     - **Microsoft Authenticator** (iOS/Android)
     - **Authy** (iOS/Android/Desktop)
     - **1Password** (with TOTP support)

3. **Save backup codes:**
   - 10 one-time recovery codes are generated
   - **CRITICAL**: Store these in a safe place!
   - Use if you lose access to your authenticator

#### Logging In with 2FA

1. Enter username and password
2. Enter the 6-digit code from your authenticator app
3. Or use a backup code if needed

#### Disabling 2FA

Administrators can disable 2FA for any user if they lose access to their authenticator:

1. Go to User Management
2. Contact the user to verify their identity
3. Access the user's 2FA settings
4. Click "Disable 2FA"

### Password Management

#### Password Requirements

- Minimum 12 characters
- Must contain:
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
- No common passwords or patterns

#### Changing Password

Users can change their own password:

1. Click username → "Profile Settings"
2. Enter current password
3. Enter new password (min 12 chars)
4. Click "Change Password"

#### Password Security Features

- **Argon2id hashing** - Industry-leading password security
- **Account lockout** - 5 failed attempts = 15 minute lockout
- **Rate limiting** - Max 5 login attempts per 15 minutes
- **No password recovery** - Admins must create new users

### Session Management

#### Session Security

- **Session timeout**: 30 minutes of inactivity
- **Secure cookies**: HTTP-only, SameSite=Lax
- **Session protection**: Strong (IP + user-agent validation)
- **One device policy**: Optional (can be enabled in production)

#### Logout

Always logout when finished:
- Click username → "Logout"
- Or close browser (session expires in 30 minutes)

### Security Audit Log

All authentication events are logged in `web_user_audit` table:

**Logged events:**
- Login success/failure
- 2FA verification success/failure
- Password changes
- User creation/deactivation
- 2FA enabled/disabled
- Account lockouts
- Rate limit violations

**Query audit log:**
```sql
SELECT
    username,
    event_type,
    ip_address,
    timestamp,
    details
FROM web_user_audit
ORDER BY timestamp DESC
LIMIT 100;
```

### Deactivating Users

Administrators can deactivate user accounts:

1. Go to User Management
2. Find the user
3. Click "Deactivate"
4. User can no longer log in

**Note**: Deactivation is permanent. To restore access, create a new account.

### Production Security Checklist

Before deploying to production:

- [ ] Set strong `FLASK_SECRET_KEY` environment variable
- [ ] Enable HTTPS (see Production section)
- [ ] Set `SESSION_COOKIE_SECURE = True` in web_dashboard.py
- [ ] Enforce 2FA for all admin accounts
- [ ] Use complex passwords (12+ characters)
- [ ] Review and configure session timeout
- [ ] Restrict dashboard access via firewall
- [ ] Enable database SSL connections
- [ ] Monitor audit logs regularly
- [ ] Back up user database
- [ ] Document admin credentials securely

### API Authentication

**Sensor API endpoints** (heartbeat, metrics, alerts) use token-based authentication (see Sensor Deployment section).

**Dashboard API endpoints** require web session authentication (login required).

**MCP API endpoints** use separate token authentication (see MCP Server section).

---

## Security Best Practices

### Network Security

1. **Firewall Rules:**
   - Only allow sensors to connect to SOC on port 8080
   - Restrict dashboard access to admin network
   - Restrict MCP API access to trusted hosts/networks
   - Use VPN for remote access

2. **Authentication:**
   - Enable sensor authentication (SENSOR_SECRET_KEY)
   - Use strong random keys: `openssl rand -hex 32`
   - Rotate keys periodically
   - Secure MCP tokens with appropriate scopes

3. **HTTPS:**
   - Use reverse proxy (nginx/Apache) for HTTPS
   - Get free SSL cert from Let's Encrypt
   - Terminate SSL at proxy for both dashboard and MCP API
   - Example nginx config in [PRODUCTION.md](PRODUCTION.md)

### Access Control

1. **Dashboard Access:**
   - Implement authentication (future feature)
   - Use IP whitelist in firewall
   - Monitor access logs

2. **MCP API Access:**
   - Use token-based authentication
   - Assign minimal required permissions
   - Implement rate limiting
   - Regular token rotation
   - Audit all API access

3. **Database Security:**
   - Change default PostgreSQL password
   - Restrict network access to localhost
   - Regular security updates
   - Encrypt sensitive data

4. **Sensor Security:**
   - Run as systemd service (not manual)
   - Keep sensors updated
   - Monitor sensor logs
   - Use authentication tokens

### Monitoring

1. **Monitor the Monitor:**
   - Set up external monitoring for SOC server
   - Alert on service failures
   - Track disk space growth
   - Monitor MCP API usage patterns

2. **Regular Reviews:**
   - Review alerts weekly
   - Check for false positives
   - Update whitelist as needed
   - Review MCP audit logs
   - Validate sensor configurations

---

## NIS2 Compliance

The **NIS2 Directive** (Network and Information Security Directive 2) is EU legislation requiring enhanced cybersecurity measures for essential and important entities. NetMonitor includes features specifically designed to help meet NIS2 requirements.

### NIS2 Requirements Overview

NetMonitor helps address these NIS2 requirements:

| NIS2 Requirement | NetMonitor Feature |
|------------------|-------------------|
| **Incident Detection** | 15+ detection rules, TLS analysis, threat intelligence |
| **Incident Reporting** | Alert system with severity levels, automated notifications |
| **Evidence Retention** | PCAP forensics with configurable retention |
| **Centralized Logging** | Sensor-to-SOC PCAP upload, audit logs |
| **Risk Management** | Device classification, behavior learning |
| **Supply Chain Security** | JA3 fingerprinting, certificate validation |

### Enabling NIS2 Features

**1. Enable PCAP Forensics (Required)**

PCAP capture is enabled by default. Verify settings in config.yaml:

```yaml
thresholds:
  pcap_export:
    enabled: true                # Must be true for NIS2
    alert_capture_enabled: true  # Capture packets around alerts
    upload_to_soc: true          # Centralize evidence
    max_age_hours: 720           # 30 days minimum retention
```

**2. Configure Sensor PCAP Upload**

For remote sensors, ensure PCAP data is centralized:

```yaml
# In sensor configuration or via dashboard
pcap_export:
  enabled: true
  upload_to_soc: true         # Upload to SOC server
  keep_local_copy: false      # Delete after successful upload
```

**3. Enable TLS Analysis**

Monitor encrypted traffic for compliance:

```yaml
thresholds:
  tls_analysis:
    enabled: true
    ja3_detection: true           # Identify client applications
    certificate_validation: true  # Detect rogue certificates
    detect_expired_certs: true    # Certificate hygiene
```

**4. Configure Audit Logging**

Enable comprehensive audit trails:

```bash
# Check MCP audit logs are enabled
psql -U netmonitor -d netmonitor -c "SELECT COUNT(*) FROM mcp_audit_log;"

# Check web user audit logs
psql -U netmonitor -d netmonitor -c "SELECT COUNT(*) FROM web_user_audit;"
```

### NIS2 Compliance Checklist

Use this checklist for NIS2 readiness:

**Incident Detection & Response:**
- [ ] All detection rules enabled (port scan, brute force, DDoS, etc.)
- [ ] TLS analysis enabled for encrypted traffic
- [ ] Threat intelligence feeds configured
- [ ] Alert notifications configured (email/webhook)
- [ ] Incident response procedures documented

**Evidence & Forensics:**
- [ ] PCAP forensics enabled on all sensors
- [ ] Sensor PCAP upload enabled (`upload_to_soc: true`)
- [ ] 30+ day retention configured (`max_age_hours: 720`)
- [ ] Sufficient storage provisioned (estimate 5GB/day/10 sensors)
- [ ] Backup procedures for PCAP files

**Access Control & Audit:**
- [ ] Admin accounts with strong passwords (12+ chars)
- [ ] 2FA enabled for all admin users
- [ ] MCP API tokens with minimal scope
- [ ] Audit logging enabled and reviewed
- [ ] User access logs retained

**Network Monitoring:**
- [ ] Sensors deployed at network boundaries
- [ ] Internal networks properly configured
- [ ] Device discovery enabled
- [ ] Whitelist maintained (reduce false positives)

### NIS2 Reporting

Generate compliance reports using MCP tools:

```bash
# Generate security report
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer <token>" \
  -d '{
    "tool_name": "generate_security_report",
    "parameters": {"time_range_hours": 720}
  }'

# Export alerts for incident timeline
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer <token>" \
  -d '{
    "tool_name": "export_alerts_csv",
    "parameters": {"time_range_hours": 720}
  }' > monthly_alerts.csv

# List PCAP evidence files
curl http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer <token>" \
  -d '{
    "tool_name": "get_pcap_captures",
    "parameters": {}
  }'
```

### Storage Planning for NIS2

Calculate storage requirements:

```
PCAP Storage = Alerts/day × Days × Average_PCAP_size

Example:
- 10 sensors × 50 HIGH/CRITICAL alerts/day = 500 alerts/day
- 30 days retention
- Average 2MB per PCAP
- Total: 500 × 30 × 2MB = 30GB

Recommended: Plan for 2x estimate = 60GB for PCAP storage
```

**Storage locations:**
- SOC server PCAPs: `/var/log/netmonitor/pcap/`
- Sensor uploads: `/var/log/netmonitor/pcap/sensors/<sensor_id>/`
- Database: PostgreSQL data directory

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

-- Auto-delete MCP audit logs older than 30 days
SELECT add_retention_policy('mcp_audit_log', INTERVAL '30 days');
```

### TLS/HTTPS Analysis Configuration

TLS analysis extracts metadata from encrypted traffic without decryption.

**Configuration in config.yaml or via Dashboard:**
```yaml
thresholds:
  tls_analysis:
    enabled: true                   # Master switch for TLS analysis
    ja3_detection: true             # Extract JA3 fingerprints (client ID)
    ja3s_detection: true            # Extract JA3S fingerprints (server ID)
    sni_extraction: true            # Extract Server Name Indication
    certificate_validation: true     # Validate certificate chains
    detect_weak_ciphers: true       # Alert on weak cipher suites
    detect_deprecated_tls: true     # Alert on SSL 3.0, TLS 1.0/1.1
    detect_expired_certs: true      # Alert on expired certificates
    detect_missing_sni: false       # Alert on missing SNI (can be noisy)
    ja3_blacklist:                  # Custom JA3 fingerprints to block
      "abc123...": "CustomMalware"
```

**Alert Types Generated:**
| Alert Type | Severity | Description |
|------------|----------|-------------|
| MALICIOUS_JA3_FINGERPRINT | CRITICAL | Known malware TLS fingerprint |
| TLS_WEAK_CIPHER_SELECTED | HIGH | Server selected weak cipher |
| TLS_EXPIRED_CERTIFICATE | HIGH | Expired SSL certificate |
| TLS_WEAK_CIPHER_OFFERED | MEDIUM | Client offers weak cipher |
| TLS_DEPRECATED_TLS_VERSION | MEDIUM | Old TLS version (1.0/1.1) |
| TLS_MISSING_SNI | LOW | No SNI extension (possible C2) |

**Built-in JA3 Blacklist:**
- Cobalt Strike: `72a589da586844d7f0818ce684948eea`
- Metasploit Meterpreter: `6734f37431670b3ab4292b8f60f29984`
- Empire: `e7d705a3286e19ea42f587b344ee6865`
- TrickBot: `51c64c77e60f3980eea90869b68c58a8`
- Emotet: `4d7a28d6f2263ed61de88ca66eb2e04b`

**Adding Custom JA3 via MCP:**
```bash
# Via AI assistant or API
add_ja3_blacklist --ja3_hash "your_hash" --malware_family "MalwareName"
```

### PCAP Forensics Configuration (NIS2 Compliant)

PCAP export saves packets for forensic analysis. This feature is designed to meet **NIS2 Directive** requirements for incident evidence retention.

**NIS2 Compliance Features:**
- ✅ Automatic packet capture around security alerts
- ✅ Centralized PCAP storage on SOC server
- ✅ Sensor PCAP upload for distributed environments
- ✅ Configurable retention policies
- ✅ Audit trail for forensic investigations

**Configuration in config.yaml or via Dashboard:**
```yaml
thresholds:
  pcap_export:
    enabled: true                   # Master switch for PCAP export
    output_dir: "/var/log/netmonitor/pcap"  # Where to save PCAPs
    buffer_size: 10000              # Ring buffer size (packets)
    alert_capture_enabled: true     # Auto-save packets around alerts
    pre_alert_packets: 100          # Packets to capture before alert
    post_alert_packets: 50          # Packets to capture after alert
    flow_buffer_size: 500           # Per-flow buffer size
    max_captures: 100               # Maximum stored PCAP files
    max_age_hours: 24               # Auto-delete PCAPs after 24 hours
    # NIS2 Sensor Options (for remote sensors)
    upload_to_soc: true             # Upload PCAP to SOC server (required for NIS2)
    keep_local_copy: false          # Keep local copy after upload (saves disk)
```

#### NIS2 Sensor PCAP Architecture

For distributed sensor deployments, PCAP data is automatically uploaded to the central SOC server:

```
┌─────────────────┐                      ┌─────────────────────────────┐
│  Remote Sensor  │                      │        SOC Server           │
│                 │                      │                             │
│  ┌───────────┐  │     Alert + PCAP     │  ┌───────────────────────┐  │
│  │ PCAP      │  │ ──────────────────── │  │ /var/log/netmonitor/  │  │
│  │ Exporter  │  │    (Base64 JSON)     │  │ pcap/sensors/         │  │
│  └───────────┘  │                      │  │   └── sensor_id/      │  │
│                 │                      │  │        └── alert.pcap │  │
└─────────────────┘                      │  └───────────────────────┘  │
                                         │                             │
                                         │  ┌───────────────────────┐  │
                                         │  │ Dashboard PCAP API    │  │
                                         │  │ GET /api/pcap/sensors │  │
                                         │  └───────────────────────┘  │
                                         └─────────────────────────────┘
```

**How Sensor PCAP Upload Works:**
1. Sensor detects HIGH/CRITICAL alert
2. Captures packets around alert (pre/post)
3. Base64 encodes PCAP data
4. Uploads with alert JSON to SOC server
5. SOC server stores in `/var/log/netmonitor/pcap/sensors/<sensor_id>/`
6. Optional: sensor deletes local copy after successful upload

**Sensor PCAP API Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/pcap/sensors` | GET | List all sensor PCAP files |
| `/api/pcap/sensors/<filename>` | GET | Download specific PCAP |
| `/api/pcap/sensors/<filename>` | DELETE | Delete specific PCAP |
| `/api/alerts/<alert_id>/pcap` | GET | Get PCAP for specific alert |

**Storage Considerations for NIS2:**
- Plan for 100KB-5MB per alert PCAP
- With 10 sensors × 100 alerts/day = ~5GB/day
- Configure retention based on compliance requirements
- NIS2 typically requires 30-90 days retention

**Recommended NIS2 Settings:**
```yaml
thresholds:
  pcap_export:
    enabled: true
    upload_to_soc: true       # Centralize all evidence
    keep_local_copy: false    # Save sensor disk space
    max_age_hours: 720        # 30 days retention (NIS2 minimum)
    max_captures: 5000        # Adjust based on storage
```

**How Alert-Triggered Capture Works:**
```
Timeline:
... [100 packets] [ALERT] [50 packets] ...
         ↓           ↓         ↓
    pre-alert    trigger  post-alert
         └─────────┬─────────┘
              PCAP file saved
```

**PCAP File Naming:**
```
alert_{type}_{src_ip}_to_{dst_ip}_{timestamp}.pcap

Examples:
alert_malicious_ja3_fingerprint_192_168_1_100_to_45_33_32_156_20231215_143022.pcap
alert_port_scan_10_0_0_50_20231214_091532.pcap
```

**Storage Requirements:**
- Average PCAP size: 100KB - 5MB per alert
- With 100 max captures × 5MB = 500MB max storage
- Auto-cleanup runs on capture and deletes old files

**Permissions:**
```bash
# Ensure output directory exists and is writable
sudo mkdir -p /var/log/netmonitor/pcap
sudo chown netmonitor:netmonitor /var/log/netmonitor/pcap
sudo chmod 750 /var/log/netmonitor/pcap
```

### High Availability

For production environments:
- Use PostgreSQL replication
- Deploy multiple SOC servers with load balancer
- Implement database failover
- Deploy redundant MCP API instances
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
- MCP HTTP API for Claude Desktop and other AI assistants
- Query alerts via natural language
- Automated security analysis and response
- Custom AI workflows via API
- See [mcp_server/README.md](mcp_server/README.md)

**SIEM Integration:**
- Export alerts via MCP API
- Real-time webhook forwarding
- Syslog integration (future)

---

## Next Steps

After installation:

1. ✅ **Deploy sensors** across your network
2. ✅ **Configure detection rules** via dashboard
3. ✅ **Configure sensor settings** (location, networks, intervals)
4. ✅ **Set up whitelist** for trusted IPs
5. ✅ **Monitor dashboard** for alerts
6. ✅ **Fine-tune thresholds** to reduce false positives
7. ✅ **Set up MCP server** for AI-powered analysis (optional)
8. ✅ **Create MCP tokens** for automation and AI assistants

**For SOC Operators:**
See [USER_MANUAL.md](USER_MANUAL.md) for daily usage guide.

**For Detailed Topics:**
- [DASHBOARD.md](DASHBOARD.md) - Dashboard features
- [DETECTION_FEATURES.md](DETECTION_FEATURES.md) - Detection capabilities
- [CONFIG_GUIDE.md](CONFIG_GUIDE.md) - Configuration reference
- [PRODUCTION.md](PRODUCTION.md) - Production deployment
- [mcp_server/README.md](mcp_server/README.md) - MCP server documentation

---

## Support & Documentation

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: All .md files in repository
- **Logs**: Always check logs first for troubleshooting
- **MCP API Docs**: http://your-server:8000/docs

---

*Last updated: December 2025*
*NetMonitor SOC v2.2 - Centralized Security Operations with NIS2 Compliance*
