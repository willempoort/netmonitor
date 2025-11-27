# NetMonitor MCP Server

**Modern HTTP REST API voor AI-powered Security Operations**

---

## 📋 Overzicht

De MCP (Model Context Protocol) server geeft AI assistenten zoals Claude volledige toegang tot je Security Operations Center via een moderne HTTP REST API met token authenticatie.

**Waarom HTTP API?**
- 🔐 **Token Authenticatie** - Veilige Bearer tokens per client
- 🚦 **Rate Limiting** - Bescherming tegen misbruik
- 👥 **Multi-Client** - Meerdere AI's tegelijk
- 📊 **Audit Trail** - Volledige request logging
- 🔒 **Permissions** - read_only, read_write, admin scopes
- 📚 **Auto-Docs** - OpenAPI/Swagger UI

---

## ⚡ Quick Start

```bash
# 1. Maak virtual environment
cd /opt/netmonitor
python3 -m venv venv
source venv/bin/activate

# 2. Run setup
sudo ./mcp_server/setup_http_api.sh

# 3. Start server
sudo systemctl start netmonitor-mcp-http

# 4. Test
curl http://localhost:8000/health
```

**Klaar!** De API draait op `http://localhost:8000`

**Documentatie:** http://localhost:8000/docs

---

## 🎯 Tool Categorieën

De MCP server biedt **23+ tools** verdeeld over 6 categorieën:

### 🔍 Security Analysis (read_only)
Real-time threat intelligence en security monitoring:
- `analyze_ip` - Gedetailleerde IP analyse met threat scoring
- `get_recent_threats` - Recent gedetecteerde threats met filters
- `get_threat_timeline` - Chronologische attack timeline
- `get_traffic_trends` - Traffic trends en patronen
- `get_top_talkers_stats` - Top communicerende hosts
- `get_alert_statistics` - Alert statistieken gegroepeerd

### 📊 Exports & Reporting (read_only)
Data export en rapportage:
- `export_alerts_csv` - Export alerts naar CSV
- `export_traffic_stats_csv` - Export traffic statistieken
- `export_top_talkers_csv` - Export top talkers
- `get_dashboard_summary` - Complete SOC overzicht

### 🎛️ Configuration Management (read_write)
Sensor configuratie beheer:
- `set_config_parameter` - Wijzig sensor parameters
- `get_config_parameters` - Haal configuratie op
- `reset_config_to_defaults` - Reset naar defaults

### 👥 Sensor Management (read_write)
Remote command & control voor sensors:
- `get_sensor_status` - Status van alle sensors
- `get_sensor_details` - Gedetailleerde sensor informatie
- `send_sensor_command` - Stuur remote commands
- `get_sensor_alerts` - Alerts van specifieke sensor
- `get_sensor_command_history` - Command history
- `get_bandwidth_summary` - Bandwidth usage

### 🚫 Whitelist Management (read_write)
Centraal beheer van whitelists:
- `add_whitelist_entry` - Voeg IP/CIDR/domain toe
- `get_whitelist_entries` - Haal whitelist op
- `remove_whitelist_entry` - Verwijder entry

### 🤖 AI-Powered Analysis (read_only)
Ollama integration voor deep analysis:
- `analyze_threat_with_ollama` - AI threat analyse
- `suggest_incident_response` - AI response suggesties
- `explain_ioc` - IOC uitleg via AI
- `get_ollama_status` - Ollama beschikbaarheid

**Volledige lijst:** `curl -H "Authorization: Bearer TOKEN" http://localhost:8000/mcp/tools`

---

## 🔑 Token Management

### Token Aanmaken

```bash
# Read-only token (voor AI monitoring)
python3 mcp_server/manage_tokens.py create \
    --name "Claude Desktop" \
    --scope read_only

# Read-write token (voor automation)
python3 mcp_server/manage_tokens.py create \
    --name "Admin Tool" \
    --scope read_write \
    --expires-days 90

# Admin token (voor beheer)
python3 mcp_server/manage_tokens.py create \
    --name "Super Admin" \
    --scope admin \
    --rate-minute 200
```

### Token Beheer

```bash
# Lijst tokens
python3 mcp_server/manage_tokens.py list

# Token details
python3 mcp_server/manage_tokens.py show 1

# Usage stats
python3 mcp_server/manage_tokens.py stats

# Revoke token
python3 mcp_server/manage_tokens.py revoke 3
```

---

## 🛠️ API Gebruik

### Health Check

```bash
curl http://localhost:8000/health
```

### List Available Tools

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/mcp/tools
```

### Execute Tool

```bash
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "analyze_ip",
    "parameters": {
      "ip_address": "185.220.101.50",
      "hours": 24
    }
  }'
```

**Response:**
```json
{
  "success": true,
  "tool_name": "analyze_ip",
  "data": {
    "ip_address": "185.220.101.50",
    "country": "Russia (RU)",
    "threat_score": 85,
    "risk_level": "CRITICAL",
    "recommendation": "Block this IP immediately"
  },
  "execution_time_ms": 142,
  "timestamp": "2024-11-27T14:35:22"
}
```

---

## 🤖 Client Libraries

### Python Client

```python
import requests

class MCPClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def execute_tool(self, tool_name, parameters):
        response = requests.post(
            f"{self.base_url}/mcp/tools/execute",
            headers=self.headers,
            json={
                "tool_name": tool_name,
                "parameters": parameters
            }
        )
        return response.json()

# Gebruik
client = MCPClient("http://localhost:8000", "YOUR_TOKEN")
result = client.execute_tool("get_sensor_status", {})
print(result)
```

### JavaScript/Node.js Client

```javascript
const axios = require('axios');

class MCPClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    }

    async executeTool(toolName, parameters) {
        const response = await axios.post(
            `${this.baseUrl}/mcp/tools/execute`,
            { tool_name: toolName, parameters },
            { headers: this.headers }
        );
        return response.data;
    }
}

// Gebruik
const client = new MCPClient('http://localhost:8000', 'YOUR_TOKEN');
const result = await client.executeTool('analyze_ip', { ip_address: '8.8.8.8' });
console.log(result);
```

---

## 📚 Documentatie

### API Documentation
- **Quick Start**: `HTTP_API_QUICKSTART.md`
- **Volledige Docs**: `../MCP_HTTP_API.md`
- **Installation**: `INSTALLATION.md`

### Live Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

---

## 🔐 Security

### Permission Scopes

| Scope | Kan wat? | Voor wie? |
|-------|----------|-----------|
| `read_only` | Monitoring, stats, exports | AI assistenten, dashboards |
| `read_write` | + Config wijzigen, commands | Admin tools, automation |
| `admin` | + Token management | Super admins |

### Rate Limiting

Elk token heeft configureerbare limieten:
- Per minute (default: 60)
- Per hour (default: 1000)
- Per day (default: 10000)

### Audit Logging

Alle requests worden gelogd:
- Timestamp, endpoint, method
- IP address, user agent
- Response status, execution time

**Query logs:**
```sql
SELECT * FROM mcp_api_token_usage
ORDER BY timestamp DESC
LIMIT 100;
```

---

## 🚦 Service Management

### Start/Stop Service

```bash
# Start
sudo systemctl start netmonitor-mcp-http

# Stop
sudo systemctl stop netmonitor-mcp-http

# Restart
sudo systemctl restart netmonitor-mcp-http

# Status
sudo systemctl status netmonitor-mcp-http

# Logs
sudo journalctl -u netmonitor-mcp-http -f
```

### Enable Auto-Start

```bash
sudo systemctl enable netmonitor-mcp-http
```

---

## 🐛 Troubleshooting

### Server Issues

```bash
# Check logs
sudo journalctl -u netmonitor-mcp-http -n 50

# Check database
psql -U netmonitor -d netmonitor -c "SELECT 1;"

# Check port
lsof -i :8000
```

### Token Issues

```bash
# List tokens
python3 mcp_server/manage_tokens.py list

# Show token details
python3 mcp_server/manage_tokens.py show 1

# Test authentication
curl -v \
    -H "Authorization: Bearer YOUR_TOKEN" \
    http://localhost:8000/mcp/tools
```

---

## 🔄 Updates

```bash
cd /opt/netmonitor
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r mcp_server/requirements.txt --upgrade

# Restart service
sudo systemctl restart netmonitor-mcp-http
```

---

## 📦 Project Structure

```
mcp_server/
├── http_server.py              # Main FastAPI HTTP server
├── token_auth.py               # Token authentication & validation
├── manage_tokens.py            # CLI tool for token management
├── database_client.py          # Database operations
├── ollama_client.py            # Ollama AI integration
├── schema_api_tokens.sql       # Database schema for tokens
├── setup_http_api.sh           # Setup script
├── requirements.txt            # Python dependencies
├── INSTALLATION.md             # Installation guide
├── HTTP_API_QUICKSTART.md      # Quick start guide
└── legacy_stdio_sse/           # Archived legacy implementation
    ├── README.md               # Legacy docs
    ├── server.py               # Old STDIO/SSE server
    ├── mcp_sse_bridge.py       # SSE bridge (deprecated)
    └── ...                     # Other legacy files
```

---

## ⚠️ Legacy STDIO/SSE

De oude STDIO/SSE implementatie is **verouderd** en gearchiveerd in:
```
mcp_server/legacy_stdio_sse/
```

**Waarom vervangen?**
- ❌ Geen authenticatie
- ❌ Geen rate limiting
- ❌ Geen permission control
- ❌ Moeilijk te debuggen
- ❌ Één client per instance

**Gebruik de HTTP API** voor:
- ✅ Token authenticatie
- ✅ Multiple clients
- ✅ Rate limiting
- ✅ Permission scopes
- ✅ Audit logging
- ✅ Auto-generated docs

---

## 🎯 Use Cases

### 1. AI Security Monitoring

```python
# Claude Desktop met read_only token
client = MCPClient(url, "read_only_token")

# Monitor threats
threats = client.execute_tool("get_recent_threats", {
    "severity": "CRITICAL",
    "hours": 1
})

# Analyze suspicious IPs
for alert in threats['data']['alerts']:
    analysis = client.execute_tool("analyze_ip", {
        "ip_address": alert['source_ip']
    })
    print(f"{alert['source_ip']}: {analysis['data']['risk_level']}")
```

### 2. Automated Incident Response

```python
# Script met read_write token
client = MCPClient(url, "read_write_token")

# Check for critical threats
threats = client.execute_tool("get_recent_threats", {
    "severity": "CRITICAL"
})

# Auto-block high-risk IPs
for alert in threats['data']['alerts']:
    if alert['threat_score'] > 90:
        client.execute_tool("add_whitelist_entry", {
            "ip_address": alert['source_ip'],
            "action": "block",
            "description": "Auto-blocked: threat score > 90"
        })
```

### 3. Custom Dashboard

```javascript
// Web dashboard met real-time updates
const mcp = new MCPClient(API_URL, API_TOKEN);

async function updateDashboard() {
    const summary = await mcp.executeTool('get_dashboard_summary', {});
    const sensors = await mcp.executeTool('get_sensor_status', {});

    renderDashboard(summary.data, sensors.data);
}

setInterval(updateDashboard, 30000); // Update every 30s
```

---

## 🆘 Support

**Bij problemen:**

1. Check logs: `sudo journalctl -u netmonitor-mcp-http -f`
2. Check health: `curl http://localhost:8000/health`
3. Verify token: `python3 mcp_server/manage_tokens.py list`
4. Test database: `psql -U netmonitor -d netmonitor -c "SELECT 1;"`

**Debug mode:**
```bash
cd /opt/netmonitor
source venv/bin/activate
LOG_LEVEL=DEBUG python3 mcp_server/http_server.py
```

---

## ✨ Features Roadmap

- [ ] WebSocket support voor real-time updates
- [ ] Prometheus metrics endpoint
- [ ] GraphQL API optie
- [ ] Token rotation mechanisme
- [ ] IP whitelisting per token
- [ ] Webhook notifications
- [ ] Multi-user RBAC
- [ ] Query result caching

---

**Veel succes met de NetMonitor MCP HTTP API!** 🚀
