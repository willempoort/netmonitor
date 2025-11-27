# MCP HTTP API - Quick Start

**Van STDIO naar moderne HTTP API met token authenticatie in 5 minuten**

---

## ⚡ Ultra Quick Start

```bash
# 0. Maak virtual environment (indien nog niet gedaan)
cd /opt/netmonitor
python3 -m venv venv
source venv/bin/activate

# 1. Setup (één keer) - installeert automatisch dependencies
sudo ./mcp_server/setup_http_api.sh

# 2. Start server
sudo systemctl start netmonitor-mcp-http

# 3. Kopieer token uit setup output
# Token: a1b2c3d4e5f6g7h8...

# 4. Test
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/mcp/tools
```

✅ **Klaar!** Je hebt nu een moderne HTTP-based MCP API draaiend.

---

## 🎯 Wat is er veranderd?

### ❌ Oude manier (STDIO/SSE)

```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": ["/path/to/server.py"],
      "transport": "stdio"
    }
  }
}
```

**Problemen:**
- Geen authenticatie
- Geen rate limiting
- Moeilijk te debuggen
- Geen audit trail
- Één client per server
- Geen permissions

### ✅ Nieuwe manier (HTTP API)

```bash
curl -H "Authorization: Bearer TOKEN" \
     -X POST http://localhost:8000/mcp/tools/execute \
     -d '{"tool_name": "analyze_ip", "parameters": {"ip_address": "8.8.8.8"}}'
```

**Voordelen:**
- ✅ Token authenticatie
- ✅ Rate limiting per token
- ✅ Multiple clients
- ✅ Permission scopes (read/write/admin)
- ✅ Volledige audit logging
- ✅ Auto-documentatie (Swagger)
- ✅ CORS support voor web apps
- ✅ Eenvoudig te testen met cURL

---

## 📋 Wat krijg je?

### 1. Database Schema

```sql
-- API tokens met permissions
CREATE TABLE mcp_api_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    scope VARCHAR(50),  -- read_only, read_write, admin
    rate_limit_per_minute INTEGER,
    created_at TIMESTAMP,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Usage logging
CREATE TABLE mcp_api_token_usage (
    id BIGSERIAL PRIMARY KEY,
    token_id INTEGER,
    timestamp TIMESTAMP,
    endpoint VARCHAR(255),
    status_code INTEGER,
    response_time_ms INTEGER
);
```

### 2. HTTP API Server

- **FastAPI** - Modern async Python framework
- **OpenAPI/Swagger** - Auto-documentatie
- **Bearer Token** - Veilige authenticatie
- **Rate Limiting** - Per token configureerbaar
- **CORS** - Web client support
- **Audit Logging** - Alle requests gelogd

### 3. Token Management CLI

```bash
# Maak tokens
python3 mcp_server/manage_tokens.py create --name "Client A" --scope read_only

# Lijst tokens
python3 mcp_server/manage_tokens.py list

# Token details
python3 mcp_server/manage_tokens.py show 1

# Statistieken
python3 mcp_server/manage_tokens.py stats

# Intrekken
python3 mcp_server/manage_tokens.py revoke 3
```

### 4. Systemd Service

```bash
sudo systemctl start netmonitor-mcp-http
sudo systemctl status netmonitor-mcp-http
sudo systemctl enable netmonitor-mcp-http  # Auto-start bij boot
```

---

## 🔑 Token Scopes

| Scope | Kan wat? | Voor wie? |
|-------|----------|-----------|
| **read_only** | Monitoring, statistics, exports | AI assistenten, dashboards |
| **read_write** | Alles van read_only + config wijzigen | Admin tools, automation |
| **admin** | Alles + token management | Super admins |

**Voorbeelden:**

```bash
# Monitoring token (Claude Desktop)
python3 mcp_server/manage_tokens.py create \
    --name "Claude Desktop" \
    --scope read_only \
    --description "Security monitoring via Claude"

# Automation token (scripts)
python3 mcp_server/manage_tokens.py create \
    --name "Incident Response Bot" \
    --scope read_write \
    --expires-days 90

# Admin token (beheer)
python3 mcp_server/manage_tokens.py create \
    --name "Super Admin" \
    --scope admin \
    --rate-minute 200
```

---

## 🛠️ API Gebruik

### Health Check

```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-11-27T14:30:00",
  "database": "connected",
  "ollama": "available"
}
```

### List Tools

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/mcp/tools
```

Response:
```json
[
  {
    "name": "analyze_ip",
    "description": "Analyze a specific IP address...",
    "input_schema": {...},
    "scope_required": "read_only"
  },
  ...
]
```

### Execute Tool

```bash
curl -X POST \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "tool_name": "analyze_ip",
       "parameters": {
         "ip_address": "185.220.101.50",
         "hours": 24
       }
     }' \
     http://localhost:8000/mcp/tools/execute
```

Response:
```json
{
  "success": true,
  "tool_name": "analyze_ip",
  "data": {
    "ip_address": "185.220.101.50",
    "country": "Russia (RU)",
    "threat_score": 85,
    "risk_level": "CRITICAL"
  },
  "execution_time_ms": 142,
  "timestamp": "2024-11-27T14:35:22"
}
```

---

## 📊 API Documentatie

**Swagger UI** (interactief):
```
http://localhost:8000/docs
```

**ReDoc** (leesbaar):
```
http://localhost:8000/redoc
```

**OpenAPI JSON**:
```
http://localhost:8000/openapi.json
```

---

## 🤖 AI Client Voorbeeld

### Python Client

```python
import requests

class MCPClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token

    def analyze_ip(self, ip_address, hours=24):
        """Analyseer een IP adres"""
        response = requests.post(
            f"{self.base_url}/mcp/tools/execute",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "tool_name": "analyze_ip",
                "parameters": {
                    "ip_address": ip_address,
                    "hours": hours
                }
            }
        )
        return response.json()

# Gebruik
client = MCPClient(
    base_url="http://localhost:8000",
    token="YOUR_TOKEN_HERE"
)

result = client.analyze_ip("8.8.8.8")
print(f"Threat score: {result['data']['threat_score']}")
```

### JavaScript/Node.js Client

```javascript
const axios = require('axios');

class MCPClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.token = token;
        this.headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    }

    async analyzeIP(ipAddress, hours = 24) {
        const response = await axios.post(
            `${this.baseUrl}/mcp/tools/execute`,
            {
                tool_name: 'analyze_ip',
                parameters: { ip_address: ipAddress, hours }
            },
            { headers: this.headers }
        );
        return response.data;
    }
}

// Gebruik
const client = new MCPClient('http://localhost:8000', 'YOUR_TOKEN');
const result = await client.analyzeIP('8.8.8.8');
console.log(`Threat score: ${result.data.threat_score}`);
```

---

## 🔧 Configuratie

### Environment Variables

```bash
# Database (verplicht)
export NETMONITOR_DB_HOST=localhost
export NETMONITOR_DB_PORT=5432
export NETMONITOR_DB_NAME=netmonitor
export NETMONITOR_DB_USER=netmonitor
export NETMONITOR_DB_PASSWORD=your_password

# CORS (optioneel)
export CORS_ORIGINS=http://localhost:3000,https://app.example.com

# Server (optioneel)
export MCP_HTTP_HOST=0.0.0.0
export MCP_HTTP_PORT=8000
```

### Systemd Service Edit

```bash
sudo systemctl edit netmonitor-mcp-http
```

```ini
[Service]
Environment="CORS_ORIGINS=https://trusted-domain.com"
Environment="MCP_HTTP_PORT=8080"
```

---

## 🚦 Rate Limiting

Elke token heeft eigen rate limits:

```bash
# Token met custom limits
python3 mcp_server/manage_tokens.py create \
    --name "High Volume Client" \
    --rate-minute 120 \
    --rate-hour 5000 \
    --rate-day 50000
```

**Default limits:**
- 60 requests/minuut
- 1000 requests/uur
- 10000 requests/dag

**Response bij overschrijding:**
```
HTTP/1.1 429 Too Many Requests
{
  "detail": "Rate limit exceeded"
}
```

---

## 📈 Monitoring

### Server Status

```bash
# Systemd status
sudo systemctl status netmonitor-mcp-http

# Logs
sudo journalctl -u netmonitor-mcp-http -f

# Log file
tail -f /tmp/mcp_http_server.log
```

### Token Usage

```bash
# Statistieken
python3 mcp_server/manage_tokens.py stats

# Details per token
python3 mcp_server/manage_tokens.py show 1
```

### Database Queries

```sql
-- Recent requests
SELECT
    t.name,
    u.timestamp,
    u.endpoint,
    u.status_code,
    u.response_time_ms
FROM mcp_api_token_usage u
JOIN mcp_api_tokens t ON t.id = u.token_id
ORDER BY u.timestamp DESC
LIMIT 100;

-- Requests per token (laatste uur)
SELECT
    t.name,
    COUNT(*) as requests,
    AVG(u.response_time_ms) as avg_time_ms
FROM mcp_api_token_usage u
JOIN mcp_api_tokens t ON t.id = u.token_id
WHERE u.timestamp > NOW() - INTERVAL '1 hour'
GROUP BY t.name
ORDER BY requests DESC;
```

---

## 🐛 Troubleshooting

### Server start niet

```bash
# Check logs
sudo journalctl -u netmonitor-mcp-http -n 50 --no-pager

# Test database
psql -h localhost -U netmonitor -d netmonitor -c "SELECT 1;"

# Check port
lsof -i :8000
```

### Authentication fails

```bash
# Verify token
python3 mcp_server/manage_tokens.py list

# Test met curl
curl -v \
    -H "Authorization: Bearer YOUR_TOKEN" \
    http://localhost:8000/mcp/tools
```

### Rate limit issues

```bash
# Check usage
python3 mcp_server/manage_tokens.py stats

# Verhoog limit (via database)
psql -U netmonitor -d netmonitor -c "
UPDATE mcp_api_tokens
SET rate_limit_per_minute = 200
WHERE id = 1;
"
```

---

## 🎓 Use Cases

### 1. AI Security Assistant

```bash
# Claude Desktop kan nu:
# - Dashboard bekijken
# - IPs analyseren
# - Alerts ophalen
# - Config NIET wijzigen (read_only scope)

TOKEN="read_only_token"
```

### 2. Automated Response

```python
# Script dat automatisch reageert op threats
from mcp_client import MCPClient

client = MCPClient(url, token="read_write_token")

# Monitor threats
threats = client.get_recent_threats(severity="CRITICAL")

# Auto-block dangerous IPs
for threat in threats['data']['alerts']:
    if threat['threat_score'] > 90:
        client.add_to_blacklist(threat['source_ip'])
```

### 3. Custom Dashboard

```javascript
// Web dashboard met MCP API
const mcp = new MCPClient(API_URL, API_TOKEN);

async function loadDashboard() {
    const summary = await mcp.getDashboardSummary();
    const threats = await mcp.getRecentThreats({ hours: 1 });

    renderDashboard(summary, threats);
}

setInterval(loadDashboard, 30000); // Update elke 30 sec
```

---

## 📚 Meer Informatie

- **Volledige documentatie**: [MCP_HTTP_API.md](../MCP_HTTP_API.md)
- **API Docs**: http://localhost:8000/docs
- **Tool lijst**: http://localhost:8000/mcp/tools

---

## ✨ Volgende Stappen

1. ✅ Setup gedaan met `setup_http_api.sh`
2. ✅ Server draait op http://localhost:8000
3. ✅ Token aangemaakt

**Nu:**

4. Test API met cURL/Postman
5. Bekijk documentatie op /docs
6. Integreer in je AI client
7. Setup production deployment met nginx/HTTPS
8. Monitor usage via stats

**Succes!** 🚀
