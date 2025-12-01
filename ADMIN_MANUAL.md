# NetMonitor SOC - Administrator Manual

**Complete Installation & Administration Guide**

Version: 2.1
Last Updated: December 2024

---

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [SOC Server Installation](#soc-server-installation)
5. [Sensor Deployment](#sensor-deployment)
6. [Configuration Management](#configuration-management)
7. [MCP Server](#mcp-server)
8. [Maintenance & Troubleshooting](#maintenance--troubleshooting)
9. [Security Best Practices](#security-best-practices)
10. [Advanced Topics](#advanced-topics)

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

*Last updated: December 2024*
*NetMonitor SOC v2.1 - Centralized Security Operations with AI Integration*
