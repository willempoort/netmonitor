# NetMonitor MCP Server

MCP (Model Context Protocol) server voor NetMonitor Security Operations Center. Geeft AI assistenten zoals Claude read-only toegang tot security monitoring data.

## 📋 Overzicht

De MCP server biedt:
- **3 Tools** voor actieve security analysis
- **1 Resource** voor real-time dashboard context
- **Read-only** database toegang (extra security layer)
- **Gestructureerde** threat intelligence data

## 🛠️ Tools

### 1. analyze_ip

Analyseer een specifiek IP adres voor gedetailleerde threat intelligence.

**Parameters:**
- `ip_address` (required): IP adres om te analyseren
- `hours` (optional, default: 24): Lookback periode in uren

**Returns:**
- IP informatie (hostname, country, internal/external)
- Alert count en threat types
- Severity breakdown
- Threat score (0-100)
- Risk level en recommendation
- Recent alerts

**Voorbeeld gebruik in Claude:**
```
User: "Analyze IP 185.220.101.50"

Claude roept aan: analyze_ip("185.220.101.50", hours=24)

Response:
{
  "ip_address": "185.220.101.50",
  "country": "Russia (RU)",
  "is_internal": false,
  "alert_count": 15,
  "threat_types": ["PORT_SCAN", "CONNECTION_FLOOD"],
  "threat_score": 85,
  "risk_level": "CRITICAL",
  "recommendation": "URGENT: Block this IP immediately and investigate affected systems"
}
```

### 2. get_recent_threats

Haal recente threats op uit het monitoring systeem.

**Parameters:**
- `hours` (optional, default: 24): Lookback periode
- `severity` (optional): Filter op CRITICAL, HIGH, MEDIUM, LOW, INFO
- `threat_type` (optional): Filter op threat type (PORT_SCAN, BEACONING_DETECTED, etc.)
- `limit` (optional, default: 50): Max aantal resultaten

**Returns:**
- Total aantal alerts
- Statistics (by severity, by type)
- Unique source IPs
- Alert lijst

**Voorbeeld gebruik:**
```
User: "Show me all CRITICAL threats in the last 6 hours"

Claude roept aan: get_recent_threats(hours=6, severity="CRITICAL")

Response:
{
  "total_alerts": 8,
  "statistics": {
    "by_severity": {"CRITICAL": 8},
    "by_type": {"BEACONING_DETECTED": 5, "PORT_SCAN": 3}
  },
  "alerts": [...]
}
```

### 3. get_threat_timeline

Krijg chronologische tijdlijn van threats voor attack chain analysis.

**Parameters:**
- `source_ip` (optional): Filter op source IP
- `hours` (optional, default: 24): Lookback periode

**Returns:**
- Chronologische timeline van events
- Attack phases (reconnaissance, exploitation, etc.)
- Timeline summary

**Voorbeeld gebruik:**
```
User: "Show me the attack timeline from 192.168.1.50"

Claude roept aan: get_threat_timeline(source_ip="192.168.1.50", hours=24)

Response:
{
  "total_events": 12,
  "timeline": [
    {
      "sequence": 1,
      "timestamp": "2024-11-11 10:23:15",
      "threat_type": "PORT_SCAN",
      "description": "Scanned 127 ports..."
    },
    ...
  ],
  "attack_phases": {
    "reconnaissance": [1, 2, 3],
    "exploitation": [4, 5],
    "persistence": [6]
  }
}
```

## 📚 Resources

### dashboard://summary

Real-time security dashboard overzicht.

**Format:** Plain text, human-readable

**Content:**
- Total alerts (24h)
- Alerts by severity
- Top threat types
- Top source IPs

**Voorbeeld:**
```
=== NetMonitor Security Dashboard Summary ===

Period: Last 24 hours
Generated: 2024-11-11 13:30:00

TOTAL ALERTS: 127

ALERTS BY SEVERITY:
  CRITICAL: 8
  HIGH: 23
  MEDIUM: 45
  LOW: 35
  INFO: 16

TOP THREAT TYPES:
  PORT_SCAN: 67
  BEACONING_DETECTED: 23
  CONNECTION_FLOOD: 15

TOP SOURCE IPs:
  185.220.101.50: 15 alerts
  192.168.1.45: 12 alerts
```

## 🔧 Installatie

### Setup Guides

De MCP server ondersteunt twee deployment modes:

#### 🌐 Netwerk Setup (Aanbevolen voor remote access)
**Claude Desktop op Mac → MCP Server op Linux**

Volg: **[MCP_NETWORK_SETUP.md](../MCP_NETWORK_SETUP.md)**

Features:
- SSE/HTTP transport over netwerk
- Always-on systemd service
- Meerdere clients kunnen verbinden
- Geschikt voor Mac ↔ Linux setup

#### 💻 Lokale Setup (Voor testing)
**Alles op dezelfde machine**

Volg: **[MCP_SETUP.md](../MCP_SETUP.md)** of **[INSTALLATION.md](INSTALLATION.md)**

Features:
- stdio transport (lokaal)
- Claude Desktop managed proces
- Simpelste setup voor development

---

### Quick Start (Netwerk)

1. **Setup Virtual Environment:**
```bash
cd /path/to/netmonitor
./setup_venv.sh
```

2. **Install MCP Service:**
```bash
sudo ./install_mcp_service.sh
# (Dit checkt/maakt automatisch de venv en installeert de service)
```

3. **Configure Claude Desktop (on Mac):**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "url": "http://soc.poort.net:3000/sse",
      "transport": "sse"
    }
  }
}
```

4. **Restart Claude Desktop**

⚠️ **Waarom venv?** Zie [VENV_SETUP.md](../VENV_SETUP.md) voor uitleg over virtual environments.

Zie de volledige guides voor gedetailleerde instructies!

## 📖 Gebruik Voorbeelden

### Incident Investigation

```
You: "Analyze the port scan from 185.220.101.50"

Claude:
*calls analyze_ip("185.220.101.50")*
*calls get_threat_timeline(source_ip="185.220.101.50")*

This IP from Russia has conducted extensive reconnaissance:
- Scanned 127 ports on your web server
- 15 alerts in last 24 hours
- Attack timeline shows progression:
  1. Initial port scan (10:23)
  2. Connection flood attempts (10:25)
  3. Continued scanning (10:30 - 12:15)

RECOMMENDATION: Block this IP immediately. This is likely automated scanning from a botnet.
```

### Real-time Monitoring

```
You: "What's the current threat situation?"

Claude:
*reads dashboard://summary resource*
*calls get_recent_threats(hours=1)*

Current Security Status:
- 8 alerts in the last hour
- 2 CRITICAL alerts requiring immediate attention:
  1. Beaconing detected from 192.168.1.45 (internal host!)
  2. Port scan from 185.220.x.x

⚠️ PRIORITY: Internal host 192.168.1.45 is showing beaconing behavior.
This could indicate malware infection. Recommend immediate investigation.
```

### Threat Hunting

```
You: "Find any suspicious activity in the last 12 hours"

Claude:
*calls get_recent_threats(hours=12, limit=100)*
*analyzes patterns*

Found concerning pattern:
1. Internal host 192.168.1.50 started scanning at 14:23
2. Attempted connections to multiple internal hosts (lateral movement)
3. High outbound traffic detected at 14:45

This looks like:
- Initial compromise of 192.168.1.50
- Attempted lateral movement
- Possible data exfiltration

Timeline suggests active breach. Recommend:
1. Isolate 192.168.1.50 immediately
2. Check firewall logs for data exfiltration
3. Scan other hosts for similar behavior
```

### Historical Analysis

```
You: "Generate a security report for the last week"

Claude:
*calls get_recent_threats(hours=168, limit=500)*
*calls analyze_ip() for top attackers*

Weekly Security Report (Nov 4-11, 2024):

Summary:
- Total alerts: 1,247 (up 23% from previous week)
- Average per day: 178 alerts
- Peak activity: Thursday 14:00-16:00 (237 alerts)

Top Threats:
1. Port Scans: 845 (68%) - mostly from Russia/China
2. Beaconing: 156 (12%) - concerning internal activity
3. Connection Floods: 98 (8%)

Geographic Distribution:
- Russia: 35% (mostly port scans)
- China: 28% (port scans + connection floods)
- USA: 15% (legitimate traffic + some scans)

Recommendations:
1. Implement rate limiting on public-facing ports
2. Investigate internal beaconing sources (possible malware)
3. Update firewall rules to block repeat offenders
4. Consider GeoIP blocking for non-business countries
```

## 🔐 Security

- **Read-only access**: MCP server kan database NIET wijzigen
- **No write operations**: Geen DELETE, UPDATE, INSERT, of DROP
- **Separate user**: Dedicated `mcp_readonly` database user
- **Local only**: MCP server draait lokaal, niet remote accessible
- **Audit trail**: Alle queries worden gelogd

## 🐛 Troubleshooting

### MCP Server start niet

Check logs:
```bash
tail -f /tmp/mcp_netmonitor.log
```

### Database connectie problemen

Test connectie:
```bash
PGPASSWORD='mcp_netmonitor_readonly_2024' \
  psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'
```

### Claude Desktop herkent MCP server niet

1. Check config file locatie (macOS vs Linux)
2. Herstart Claude Desktop
3. Check MCP server logs
4. Verify Python path is correct

## 📊 Performance

- Queries zijn geoptimeerd met indexes
- TimescaleDB time_bucket() voor aggregaties
- Limit op aantal resultaten (default 50)
- Read-only connection pool

## 🚀 Toekomstige Uitbreidingen

**Fase 2 - Extra Tools:**
- `correlate_alerts` - Find related activity
- `search_alerts` - Search in descriptions/metadata
- `get_attack_statistics` - Threat landscape analysis
- `get_top_attackers` - Top attacking IPs
- `find_lateral_movement` - Detect lateral movement patterns

**Fase 3 - Ollama 24/7 Monitoring:**
- Continuous threat monitoring
- Automated alerting
- Daily/weekly reports
- Proactive threat hunting

## 📝 Licentie

Part of NetMonitor Security Operations Center
