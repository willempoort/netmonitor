# NetMonitor MCP Server - Complete Installation Guide

**AI-powered Security Operations Center via Model Context Protocol**

---

## 📋 Overzicht

De NetMonitor MCP server geeft AI assistenten zoals Claude Desktop volledige toegang tot je Security Operations Center data via het Model Context Protocol. Met **23+ tools** voor security analysis, configuration management, sensor control, en whitelist beheer.

**Belangrijkste Features:**
- 🔍 **Security Analysis**: Threat intelligence, IP analysis, attack timelines
- 🎛️ **Configuration Management**: Wijzig sensor parameters, detection rules, thresholds
- 👥 **Sensor Management**: Remote command & control voor distributed sensors
- 🚫 **Whitelist Management**: Centraal beheer van whitelisted IPs/CIDRs/domains
- 🤖 **AI Analysis**: Ollama integration voor deep threat analysis
- 📊 **Exports & Reporting**: CSV exports, statistieken, dashboards

---

## 🚀 Quick Start

**Wat je nodig hebt:**
- NetMonitor SOC server (draaiend met PostgreSQL)
- Claude Desktop (op Mac/Linux/Windows)
- Python 3.8+ met MCP SDK

**In 3 stappen:**
1. Installeer dependencies: `pip install -r requirements.txt`
2. Configureer Claude Desktop met MCP server
3. Test: "Show me the dashboard summary"

---

## 📦 Requirements

### Server Requirements
- **PostgreSQL 12+** met TimescaleDB (optioneel)
- **Python 3.8+**
- **NetMonitor SOC** (geïnstalleerd en draaiend)
- **Database User**: `mcp_readonly` (automatisch aangemaakt)

### Client Requirements
- **Claude Desktop** (laatste versie)
- **SSH toegang** tot server (voor remote/network mode)

### Python Dependencies
```bash
cd mcp_server
pip install -r requirements.txt
```

**Vereiste packages:**
- `mcp>=0.9.0` - Model Context Protocol SDK
- `psycopg2-binary>=2.9.0` - PostgreSQL adapter
- `pyyaml>=6.0` - YAML config parser
- `requests>=2.31.0` - HTTP client
- `starlette>=0.27.0` - Web framework (network mode)
- `sse-starlette>=1.6.0` - Server-Sent Events (network mode)
- `uvicorn>=0.23.0` - ASGI server (network mode)

---

## 🔧 Installatie

### Methode 1: Lokale Setup (Aanbevolen voor beginners)

**Gebruik wanneer:**
- Claude Desktop en NetMonitor op DEZELFDE machine draaien
- Je simple stdio transport wilt (geen netwerk complexiteit)

**Setup:**

1. **Configureer Claude Desktop**

   **macOS:**
   ```bash
   nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

   **Linux:**
   ```bash
   mkdir -p ~/.config/Claude
   nano ~/.config/Claude/claude_desktop_config.json
   ```

2. **Voeg MCP server toe:**
   ```json
   {
     "mcpServers": {
       "netmonitor-soc": {
         "command": "python3",
         "args": [
           "/opt/netmonitor/mcp_server/server.py"
         ],
         "env": {
           "NETMONITOR_DB_HOST": "localhost",
           "NETMONITOR_DB_PORT": "5432",
           "NETMONITOR_DB_NAME": "netmonitor",
           "NETMONITOR_DB_USER": "mcp_readonly",
           "NETMONITOR_DB_PASSWORD": "mcp_netmonitor_readonly_2024"
         }
       }
     }
   }
   ```

   **⚠️ Pas het pad aan** naar waar je netmonitor staat!

3. **Herstart Claude Desktop**

4. **Test:**
   ```
   Show me the dashboard summary
   ```

---

### Methode 2: Network Setup (voor remote servers)

**Gebruik wanneer:**
- Claude Desktop op Mac, NetMonitor op Linux server
- Je meerdere clients wilt verbinden
- Je centraal logging wilt

#### Optie A: SSH Tunnel (Simpelst)

**Voordelen:**
- ✅ Geen firewall changes
- ✅ Encrypted verbinding
- ✅ Eenvoudig te debuggen

**Setup:**

1. **Start MCP server op NetMonitor server:**
   ```bash
   cd /opt/netmonitor/mcp_server
   python3 server.py --transport sse --host 127.0.0.1 --port 3000
   ```

2. **Maak SSH tunnel (op Mac/client):**
   ```bash
   ssh -N -L 3000:localhost:3000 user@soc.poort.net \
       -o ServerAliveInterval=60 \
       -o ServerAliveCountMax=3
   ```

3. **Configureer Claude Desktop:**
   ```json
   {
     "mcpServers": {
       "netmonitor-soc": {
         "command": "python3",
         "args": [
           "/opt/netmonitor/mcp_server/mcp_sse_bridge.py",
           "--url",
           "http://localhost:3000/sse"
         ]
       }
     }
   }
   ```

   **⚠️ Let op:** Je hebt `mcp_sse_bridge.py` lokaal nodig op de client!

4. **Test de verbinding:**
   ```
   Which sensors are online?
   ```

#### Optie B: Direct SSE (met firewall)

**Setup:**

1. **Start MCP server (bind op 0.0.0.0):**
   ```bash
   python3 server.py --transport sse --host 0.0.0.0 --port 3000
   ```

2. **Open firewall:**
   ```bash
   sudo ufw allow from 192.168.1.0/24 to any port 3000
   ```

3. **Gebruik bridge op client:**
   ```json
   {
     "mcpServers": {
       "netmonitor-soc": {
         "command": "python3",
         "args": [
           "/path/to/mcp_sse_bridge.py",
           "--url",
           "http://soc.poort.net:3000/sse"
         ]
       }
     }
   }
   ```

---

## 🛠️ Beschikbare Tools

De MCP server biedt **23 tools** verdeeld over 6 categorieën:

### 🔍 Security Analysis (Read-Only)
| Tool | Description |
|------|-------------|
| `analyze_ip` | Gedetailleerde IP analyse met threat intelligence |
| `get_recent_threats` | Recent gedetecteerde threats met filters |
| `get_threat_timeline` | Chronologische attack timeline |
| `get_traffic_trends` | Traffic trends en patronen |
| `get_top_talkers_stats` | Top communicerende hosts |
| `get_alert_statistics` | Alert statistieken gegroepeerd |

### 📊 Exports & Reporting
| Tool | Description |
|------|-------------|
| `export_alerts_csv` | Export alerts naar CSV |
| `export_traffic_stats_csv` | Export traffic statistieken |
| `export_top_talkers_csv` | Export top talkers |
| `get_dashboard_summary` | Complete SOC overzicht |

### 🎛️ Configuration Management (Read & Write)
| Tool | Description |
|------|-------------|
| `set_config_parameter` | Wijzig sensor parameters (detection rules, thresholds, etc.) |
| `get_config_parameters` | Haal configuratie op (global of sensor-specific) |
| `reset_config_to_defaults` | Reset naar best practice defaults |

### 👥 Sensor Management (Read & Write)
| Tool | Description |
|------|-------------|
| `get_sensor_status` | Status van alle sensors (online/offline, metrics) |
| `get_sensor_details` | Gedetailleerde sensor informatie |
| `send_sensor_command` | Stuur remote commands naar sensors |
| `get_sensor_alerts` | Alerts van specifieke sensor |
| `get_sensor_command_history` | Command history per sensor |
| `get_bandwidth_summary` | Bandwidth usage per sensor |

### 🚫 Whitelist Management (Read & Write)
| Tool | Description |
|------|-------------|
| `add_whitelist_entry` | Voeg IP/CIDR/domain toe aan whitelist |
| `get_whitelist_entries` | Haal whitelist op (met filtering) |
| `remove_whitelist_entry` | Verwijder whitelist entry |

### 🤖 AI-Powered Analysis (Ollama Integration)
| Tool | Description |
|------|-------------|
| `analyze_threat_with_ollama` | Deep threat analysis met lokale LLM |
| `suggest_incident_response` | AI-gegenereerde response suggesties |
| `explain_ioc` | Uitleg over Indicators of Compromise |
| `get_ollama_status` | Ollama server status |

---

## 💡 Gebruik Voorbeelden

### Security Analysis
```
"What's the current threat situation?"
"Analyze IP 192.168.1.50 from the last 24 hours"
"Show me the attack timeline for suspicious IPs"
"Who are the top 10 talkers in my network?"
```

### Configuration Management
```
"Set config parameter detection_rules.port_scan.enabled to false"
"Show me all config parameters for sensor npr2s-01"
"What's the current config_sync_interval?"
"Reset config to best practice defaults"
```

### Sensor Management
```
"Show me sensor status"
"Send command restart_monitoring to sensor npr2s-01"
"Get sensor command history for npr2s-02"
"Which sensors are offline?"
"Show bandwidth usage for all sensors"
```

### Whitelist Management
```
"Add 10.100.0.140 to whitelist with description Sonos speaker"
"Show me all whitelist entries"
"Get whitelist entries for scope global"
"Remove whitelist entry 15"
```

### AI Analysis (met Ollama)
```
"Analyze alert 12345 with AI and give me recommendations"
"Suggest incident response for the recent port scan"
"Explain what a SYN flood attack is"
```

---

## 🧪 Testen & Verificatie

### Test 1: MCP Server Geladen
```
What MCP servers are available?
```
**Verwacht:** "netmonitor-soc" in de lijst

### Test 2: Dashboard Resource
```
Show me the dashboard summary
```
**Verwacht:** Security statistieken (alerts, severity, top threats)

### Test 3: IP Analysis
```
Analyze IP 8.8.8.8
```
**Verwacht:** IP details, threat score, geolocation

### Test 4: Sensor Status
```
Which sensors are online?
```
**Verwacht:** Lijst met sensors en hun status

### Test 5: Whitelist Management
```
Show me all whitelist entries
```
**Verwacht:** Lijst met whitelisted IPs/CIDRs

### Test 6: Configuration
```
What's the current port scan detection threshold?
```
**Verwacht:** Detection rule configuratie

---

## 🐛 Troubleshooting

### Claude Desktop toont MCP server niet

**Diagnose:**
1. Check config file locatie:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Valideer JSON syntax:
   ```bash
   python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

3. Check MCP server logs:
   ```bash
   tail -f /tmp/mcp_netmonitor.log
   ```

**Oplossingen:**
- Herstart Claude Desktop volledig (quit + reopen)
- Check of pad naar `server.py` correct is
- Verify database credentials

---

### Database Connectie Errors

**Test connectie:**
```bash
PGPASSWORD='mcp_netmonitor_readonly_2024' \
  psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'
```

**Als dit WERKT maar MCP niet:**
- PostgreSQL moet luisteren op juiste interface
- Check `pg_hba.conf` voor host-based authentication
- Firewall kan PostgreSQL port (5432) blokkeren

**Als dit NIET werkt:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check database user
sudo -u postgres psql -c "\du mcp_readonly"

# Re-create user indien nodig
cd /opt/netmonitor
sudo ./setup_mcp_user.sh
```

---

### Permission Errors

**MCP server executable:**
```bash
chmod +x /opt/netmonitor/mcp_server/server.py
```

**Python dependencies:**
```bash
cd /opt/netmonitor/mcp_server
pip3 install -r requirements.txt --user
```

---

### SSH Tunnel Problemen

**Tunnel blijft niet verbonden:**

Maak persistent tunnel script:
```bash
#!/bin/bash
# ~/scripts/mcp-tunnel.sh

while true; do
    echo "Starting SSH tunnel..."
    ssh -N -L 3000:localhost:3000 user@soc.poort.net \
        -o ServerAliveInterval=60 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes

    echo "Tunnel disconnected, reconnecting in 5 seconds..."
    sleep 5
done
```

**Port al in gebruik:**
```bash
# Check wat poort gebruikt
lsof -i :3000

# Kill process
kill $(lsof -t -i:3000)
```

---

### Network Mode: SSE Errors

**"Connection refused" bij bridge:**
- Check of MCP server draait op server (port 3000)
- Test direct: `curl http://localhost:3000/health`
- Check firewall: `sudo ufw status`

**Bridge script werkt niet:**
- Verify Python dependencies op CLIENT
- Check bridge log output
- Test SSE endpoint: `curl http://soc.poort.net:3000/sse`

---

### Tools Werken Niet

**"Unknown tool" error:**
- MCP server mogelijk oude versie
- Pull latest: `git pull origin main`
- Restart Claude Desktop

**"Permission denied" bij write operations:**
- MCP server heeft read-only toegang by design
- Write operations (config, whitelist, commands) gaan via dashboard API
- Check of dashboard API draait: `curl http://localhost:8080/api/status`

---

## 🔒 Security Best Practices

### 1. Database Access
- MCP gebruikt `mcp_readonly` user (read-only)
- Write operations gaan via authenticated dashboard API
- Database credentials NIET in git committen

### 2. Network Mode
- **Altijd SSH tunnel gebruiken voor productie**
- Direct SSE alleen binnen trusted network
- Bind SSE server op `127.0.0.1` indien mogelijk
- Gebruik firewall rules voor IP whitelisting

### 3. Credentials Management
- Store database password in environment vars
- Gebruik `.env` files (niet in git)
- Roteer passwords regelmatig
- Gebruik sterke passwords (min. 16 chars)

### 4. API Access
- Dashboard API moet authenticated zijn
- MCP server roept localhost API aan (trusted)
- Externe API calls via HTTPS

---

## 📈 Performance Tips

### Database Queries
- MCP server gebruikt connection pooling
- Read-only queries zijn geoptimaliseerd
- Grote exports gebruiken streaming

### Network Mode
- SSH tunnel heeft lagere latency dan direct SSE
- Gebruik compression voor grote datasets
- Cache frequent queries in bridge

### Sensor Management
- Batch commands waar mogelijk
- Monitor command queue (max 100 per sensor)
- Gebruik heartbeat_interval voor health checks

---

## 🔄 Updates & Maintenance

### MCP Server Update
```bash
cd /opt/netmonitor
git pull origin main
cd mcp_server
pip3 install -r requirements.txt --upgrade
```

**Herstart MCP server:**
- **Stdio mode:** Restart Claude Desktop
- **SSE mode:** Restart server process

### Database Schema Updates
Na NetMonitor updates:
```bash
# Check of nieuwe tables/columns er zijn
psql -U postgres -d netmonitor -c "\dt"

# Herstart MCP server om nieuwe schema te laden
```

### Tool Additions
Nieuwe tools worden automatisch gedetecteerd bij server restart. Check beschikbare tools:
```
List all available MCP tools
```

---

## 🎯 Advanced Configuration

### Custom Database Connection
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": ["/opt/netmonitor/mcp_server/server.py"],
      "env": {
        "NETMONITOR_DB_HOST": "db.example.com",
        "NETMONITOR_DB_PORT": "5433",
        "NETMONITOR_DB_NAME": "custom_db",
        "NETMONITOR_DB_USER": "custom_user",
        "NETMONITOR_DB_PASSWORD": "secure_password",
        "NETMONITOR_DB_SSLMODE": "require"
      }
    }
  }
}
```

### SSE Server Tuning
```bash
# Start met custom configuratie
python3 server.py \
    --transport sse \
    --host 127.0.0.1 \
    --port 3000 \
    --workers 4
```

### Logging
```bash
# Enable debug logging
export NETMONITOR_LOG_LEVEL=DEBUG
python3 server.py
```

---

## 📚 Zie Ook

- **README.md** - Tool overzicht en use cases
- **MCP_SETUP.md** - Scenario's en deployment opties (in parent directory)
- **PRODUCTION.md** - Production deployment guide (in parent directory)
- **DASHBOARD.md** - Web dashboard documentation (in parent directory)

---

## 🆘 Support

**Bij problemen:**
1. Check logs: `/tmp/mcp_netmonitor.log`
2. Test database connectie
3. Verify Claude Desktop config
4. Test tools handmatig via API

**Debug commands:**
```bash
# Test MCP server standalone
cd /opt/netmonitor/mcp_server
export NETMONITOR_DB_HOST=localhost
export NETMONITOR_DB_USER=mcp_readonly
export NETMONITOR_DB_PASSWORD=mcp_netmonitor_readonly_2024
export NETMONITOR_DB_NAME=netmonitor
python3 server.py

# Test database
psql -U mcp_readonly -d netmonitor -h localhost -c "SELECT version();"

# Test dashboard API
curl http://localhost:8080/api/status
curl http://localhost:8080/api/sensors
```

---

## ✨ Klaar voor gebruik!

Je hebt nu een volledig functionele AI-powered SOC met:
- ✅ 23+ MCP tools
- ✅ Real-time security data
- ✅ Configuration management
- ✅ Sensor control
- ✅ Whitelist beheer
- ✅ AI-powered analysis

**Start met:**
```
Show me the current security situation and any critical threats
```

🎉 **Veel succes met je AI-enhanced Security Operations Center!**
