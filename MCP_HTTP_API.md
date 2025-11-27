# NetMonitor MCP HTTP API

**Moderne HTTP-based MCP server met token authenticatie**

---

## 📋 Overzicht

De MCP HTTP API is een moderne, veilige implementatie van het Model Context Protocol via HTTP REST API. In plaats van de verouderde STDIO of SSE transports, biedt deze API:

- ✅ **RESTful HTTP endpoints** - Standaard HTTP API
- 🔐 **Token-based authenticatie** - Unieke API tokens per AI setup
- 🚦 **Rate limiting** - Configureerbaar per token
- 📊 **Audit logging** - Complete request tracking
- 🔒 **Permission scopes** - read_only, read_write, admin
- 📚 **Auto-documentatie** - OpenAPI/Swagger docs
- 🌐 **CORS support** - Voor web-based clients

---

## 🏗️ Architectuur

```
┌─────────────────────┐
│   AI Client         │
│  (Claude, etc)      │
└──────────┬──────────┘
           │ HTTP + Bearer Token
           ▼
┌──────────────────────────────┐
│  MCP HTTP API Server         │
│  - Token validatie           │
│  - Permission check          │
│  - Rate limiting             │
│  - Request logging           │
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│   MCP Tools                  │
│  - analyze_ip                │
│  - get_recent_threats        │
│  - set_config_parameter      │
│  - etc.                      │
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│   PostgreSQL Database        │
│  - Security data             │
│  - API tokens                │
│  - Usage logs                │
└──────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Installatie

```bash
cd /opt/netmonitor

# Installeer dependencies
pip install -r mcp_server/requirements.txt

# Setup database schema en eerste token
sudo ./mcp_server/setup_http_api.sh
```

De setup script:
- ✅ Creëert database schema voor API tokens
- ✅ Genereert eerste admin token
- ✅ Installeert systemd service (optioneel)

### 2. Start de server

**Met systemd (aanbevolen):**
```bash
sudo systemctl start netmonitor-mcp-http
sudo systemctl status netmonitor-mcp-http

# Logs bekijken
sudo journalctl -u netmonitor-mcp-http -f
```

**Handmatig (voor development):**
```bash
cd /opt/netmonitor
python3 mcp_server/http_server.py --host 0.0.0.0 --port 8000
```

### 3. Test de API

```bash
# Health check
curl http://localhost:8000/health

# List tools (met token)
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     http://localhost:8000/mcp/tools

# Bekijk API docs
open http://localhost:8000/docs
```

---

## 🔑 Token Management

### Token aanmaken

```bash
cd /opt/netmonitor

# Read-only token (voor monitoring)
python3 mcp_server/manage_tokens.py create \
    --name "Claude Desktop - Monitoring" \
    --scope read_only \
    --description "Token voor security monitoring via Claude"

# Read-write token (voor configuratie)
python3 mcp_server/manage_tokens.py create \
    --name "Admin Tool" \
    --scope read_write \
    --expires-days 90

# Admin token (volledige toegang)
python3 mcp_server/manage_tokens.py create \
    --name "Super Admin" \
    --scope admin \
    --rate-minute 120
```

**Output:**
```
✅ API Token created successfully!

🔑 Token: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2

⚠️  IMPORTANT: Save this token now - it cannot be retrieved later!

   Name:        Claude Desktop - Monitoring
   Scope:       read_only
   Created:     2024-11-27 14:30:00

📋 Usage example:
   curl -H 'Authorization: Bearer a1b2c3d4...' http://localhost:8000/mcp/tools
```

### Tokens beheren

```bash
# Lijst alle tokens
python3 mcp_server/manage_tokens.py list

# Token details bekijken
python3 mcp_server/manage_tokens.py show 1

# Usage statistieken
python3 mcp_server/manage_tokens.py stats

# Token intrekken
python3 mcp_server/manage_tokens.py revoke 3
```

---

## 🛠️ API Endpoints

### Public Endpoints (geen auth vereist)

| Endpoint | Method | Beschrijving |
|----------|--------|--------------|
| `/` | GET | API info en versie |
| `/health` | GET | Health check |
| `/docs` | GET | OpenAPI/Swagger documentatie |
| `/redoc` | GET | ReDoc documentatie |

### Protected Endpoints (auth vereist)

| Endpoint | Method | Scope | Beschrijving |
|----------|--------|-------|--------------|
| `/mcp/tools` | GET | any | Lijst alle beschikbare tools |
| `/mcp/resources` | GET | any | Lijst alle resources |
| `/mcp/resources/dashboard/summary` | GET | any | Dashboard summary resource |
| `/mcp/tools/execute` | POST | varies | Voer een tool uit |
| `/admin/tokens` | GET | admin | Lijst alle tokens |
| `/admin/tokens/{id}/stats` | GET | admin | Token statistieken |

---

## 🔐 Authenticatie

Alle protected endpoints vereisen een Bearer token in de Authorization header:

```http
GET /mcp/tools HTTP/1.1
Host: localhost:8000
Authorization: Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

### Permission Scopes

| Scope | Toegang |
|-------|---------|
| `read_only` | Alleen lezen - monitoring, statistics, exports |
| `read_write` | Lezen + schrijven - configuratie wijzigen, commands sturen |
| `admin` | Volledige toegang + token management |

**Voorbeelden:**

```bash
# read_only kan:
- analyze_ip
- get_recent_threats
- get_sensor_status
- export_alerts_csv

# read_write kan alles van read_only + :
- set_config_parameter
- send_sensor_command
- add_whitelist_entry
- remove_whitelist_entry

# admin kan alles + :
- Token management
- Gebruikers beheren (toekomstig)
```

---

## 📊 Tool Execution

### Request Format

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

### Response Format

```json
{
  "success": true,
  "tool_name": "analyze_ip",
  "data": {
    "ip_address": "185.220.101.50",
    "country": "Russia (RU)",
    "is_internal": false,
    "alert_count": 15,
    "threat_types": ["PORT_SCAN", "CONNECTION_FLOOD"],
    "threat_score": 85,
    "risk_level": "CRITICAL",
    "recommendation": "URGENT: Block this IP immediately"
  },
  "execution_time_ms": 142,
  "timestamp": "2024-11-27T14:35:22.123456"
}
```

### Error Response

```json
{
  "success": false,
  "tool_name": "analyze_ip",
  "error": "Invalid IP address format",
  "execution_time_ms": 5,
  "timestamp": "2024-11-27T14:35:22.123456"
}
```

---

## 🚦 Rate Limiting

Elke token heeft configureerbare rate limits:

```bash
# Token met custom rate limits
python3 mcp_server/manage_tokens.py create \
    --name "High Volume Client" \
    --rate-minute 120 \
    --rate-hour 5000 \
    --rate-day 50000
```

**Default limits:**
- Per minute: 60 requests
- Per hour: 1000 requests
- Per day: 10000 requests

**Bij overschrijding:**
```json
HTTP/1.1 429 Too Many Requests
{
  "detail": "Rate limit exceeded"
}
```

---

## 📈 Monitoring & Logging

### Request Logging

Alle requests worden gelogd in de database:

```sql
SELECT
    t.name as token_name,
    u.timestamp,
    u.endpoint,
    u.method,
    u.status_code,
    u.response_time_ms,
    u.ip_address
FROM mcp_api_token_usage u
JOIN mcp_api_tokens t ON t.id = u.token_id
ORDER BY u.timestamp DESC
LIMIT 100;
```

### Usage Statistics

```bash
# Bekijk statistieken voor alle tokens
python3 mcp_server/manage_tokens.py stats

# Detailleerde stats voor specifiek token
python3 mcp_server/manage_tokens.py show 1
```

### Server Logs

```bash
# Systemd logs
sudo journalctl -u netmonitor-mcp-http -f

# Log file
tail -f /tmp/mcp_http_server.log
```

---

## 🔧 Configuratie

### Environment Variables

```bash
# Database
export NETMONITOR_DB_HOST=localhost
export NETMONITOR_DB_PORT=5432
export NETMONITOR_DB_NAME=netmonitor
export NETMONITOR_DB_USER=netmonitor
export NETMONITOR_DB_PASSWORD=your_password

# CORS (comma-separated origins)
export CORS_ORIGINS=http://localhost:3000,https://app.example.com

# Ollama (optioneel)
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=llama3.2
```

### Server Opties

```bash
python3 mcp_server/http_server.py --help

usage: http_server.py [-h] [--host HOST] [--port PORT]

Options:
  --host HOST  Host to bind to (default: 0.0.0.0)
  --port PORT  Port to listen on (default: 8000)
```

---

## 🤖 AI Client Configuratie

### Voorbeeld: Custom AI Client

```python
import requests

class MCPClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def list_tools(self):
        """Lijst alle beschikbare tools"""
        resp = requests.get(
            f"{self.base_url}/mcp/tools",
            headers=self.headers
        )
        return resp.json()

    def execute_tool(self, tool_name, parameters):
        """Voer een tool uit"""
        resp = requests.post(
            f"{self.base_url}/mcp/tools/execute",
            headers=self.headers,
            json={
                "tool_name": tool_name,
                "parameters": parameters
            }
        )
        return resp.json()

# Gebruik
client = MCPClient(
    base_url="http://localhost:8000",
    token="a1b2c3d4e5f6..."
)

# Lijst tools
tools = client.list_tools()
print(f"Available tools: {[t['name'] for t in tools]}")

# Analyseer IP
result = client.execute_tool("analyze_ip", {
    "ip_address": "8.8.8.8",
    "hours": 24
})

print(f"Threat score: {result['data']['threat_score']}")
```

### Voorbeeld: cURL Client

```bash
#!/bin/bash
# mcp_client.sh - Simple bash client for MCP API

TOKEN="your_token_here"
BASE_URL="http://localhost:8000"

# Get dashboard summary
curl -s -H "Authorization: Bearer $TOKEN" \
     "$BASE_URL/mcp/resources/dashboard/summary" | jq .

# Analyze IP
curl -s -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"tool_name": "analyze_ip", "parameters": {"ip_address": "8.8.8.8"}}' \
     "$BASE_URL/mcp/tools/execute" | jq .
```

---

## 🐛 Troubleshooting

### Server start niet

```bash
# Check logs
sudo journalctl -u netmonitor-mcp-http -n 50

# Test database connectie
psql -h localhost -U netmonitor -d netmonitor -c "SELECT 1;"

# Check of port beschikbaar is
lsof -i :8000
```

### Token authenticatie faalt

```bash
# Verify token bestaat en enabled is
python3 mcp_server/manage_tokens.py list

# Check token details
python3 mcp_server/manage_tokens.py show <TOKEN_ID>

# Test met curl
curl -v -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/mcp/tools
```

### Rate limit problemen

```bash
# Check huidige usage
python3 mcp_server/manage_tokens.py stats

# Verhoog limits voor token
# (momenteel via database, CLI optie volgt)
psql -U netmonitor -d netmonitor -c "
UPDATE mcp_api_tokens
SET rate_limit_per_minute = 200
WHERE id = 1;
"
```

### Permission errors

```bash
# Check token scope
python3 mcp_server/manage_tokens.py show <TOKEN_ID>

# Tool vereist hogere scope
# read_only < read_write < admin
```

---

## 📚 API Referentie

Volledige API documentatie beschikbaar via:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

---

## 🔒 Security Best Practices

### 1. Token Management

✅ **DO:**
- Gebruik unieke tokens per client/AI
- Stel expiration dates in voor tijdelijke toegang
- Revoke tokens die niet meer gebruikt worden
- Monitor usage via stats

❌ **DON'T:**
- Deel tokens tussen verschillende clients
- Commit tokens naar git
- Gebruik tokens in frontend code (gebruik server-side proxy)
- Geef admin scope aan monitoring clients

### 2. Network Security

✅ **DO:**
- Gebruik HTTPS in productie (reverse proxy zoals nginx)
- Beperk CORS origins tot trusted domains
- Gebruik firewall rules voor IP whitelisting
- Monitor failed authentication attempts

❌ **DON'T:**
- Expose server direct op internet zonder HTTPS
- Gebruik `CORS_ORIGINS=*` in productie
- Disable rate limiting
- Skip audit logging

### 3. Database Security

✅ **DO:**
- Gebruik sterke database passwords
- Roteer passwords regelmatig
- Gebruik SSL voor database connecties in productie
- Backup token database regelmatig

❌ **DON'T:**
- Gebruik default passwords
- Store passwords in code
- Disable SSL in productie
- Geef MCP database user write access op security data

---

## 🚀 Production Deployment

### 1. Reverse Proxy Setup (nginx)

```nginx
# /etc/nginx/sites-available/mcp-api

upstream mcp_backend {
    server 127.0.0.1:8000;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting (nginx level)
        limit_req zone=api_limit burst=20 nodelay;
    }
}

# Rate limit zone
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
```

### 2. Systemd Service Hardening

```ini
[Service]
# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths=/var/log/netmonitor

# Resource limits
LimitNOFILE=65536
MemoryLimit=2G
```

### 3. Monitoring

```bash
# Prometheus metrics endpoint (toekomstig)
# /metrics endpoint voor monitoring

# Nagios/Icinga check
#!/bin/bash
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health)
if [ "$response" = "200" ]; then
    echo "OK - MCP API is healthy"
    exit 0
else
    echo "CRITICAL - MCP API returned $response"
    exit 2
fi
```

---

## 📖 Verschil met oude STDIO/SSE implementatie

| Feature | STDIO/SSE (oud) | HTTP API (nieuw) |
|---------|-----------------|------------------|
| **Transport** | STDIO pipes / Server-Sent Events | RESTful HTTP |
| **Authenticatie** | Geen (filesystem/SSH) | Bearer tokens |
| **Rate limiting** | Geen | Ja, per token |
| **Audit logging** | Minimaal | Volledig |
| **Permission control** | Filesystem only | Scope-based (read/write/admin) |
| **Multi-client** | Moeilijk | Eenvoudig (tokens) |
| **API docs** | Handmatig | Auto-generated (OpenAPI) |
| **Testing** | Complex | cURL/Postman |
| **Monitoring** | Logs only | Metrics + usage stats |
| **Web clients** | Niet mogelijk | CORS support |

---

## 🎯 Use Cases

### 1. AI Monitoring Dashboard

```javascript
// Frontend app met MCP API
const mcp = new MCPClient(API_URL, API_TOKEN);

async function refreshDashboard() {
    const summary = await mcp.getResource('dashboard://summary');
    const threats = await mcp.executeTool('get_recent_threats', {
        hours: 1,
        severity: 'CRITICAL'
    });

    updateUI(summary, threats);
}

setInterval(refreshDashboard, 30000); // Elke 30 sec
```

### 2. Automated Incident Response

```python
# Periodic security check
import schedule
from mcp_client import MCPClient

mcp = MCPClient(url, token)

def check_threats():
    threats = mcp.execute_tool('get_recent_threats', {
        'hours': 1,
        'severity': 'CRITICAL'
    })

    if threats['data']['total_alerts'] > 0:
        # Send alert
        send_slack_alert(threats)

        # Auto-block IPs
        for alert in threats['data']['alerts']:
            if alert['threat_score'] > 90:
                mcp.execute_tool('add_whitelist_entry', {
                    'ip_address': alert['source_ip'],
                    'action': 'block'
                })

schedule.every(5).minutes.do(check_threats)
```

### 3. Multi-tenant Security Platform

```python
# Verschillende tokens per klant
customers = {
    'company_a': {'token': 'token_a', 'scope': 'read_only'},
    'company_b': {'token': 'token_b', 'scope': 'read_write'},
    'admin_team': {'token': 'token_admin', 'scope': 'admin'}
}

# Elke klant heeft eigen access level
client_a = MCPClient(url, customers['company_a']['token'])
client_b = MCPClient(url, customers['company_b']['token'])

# Company A kan alleen lezen
threats_a = client_a.execute_tool('get_recent_threats')

# Company B kan ook configureren
client_b.execute_tool('set_config_parameter', {...})
```

---

## ✨ Toekomstige Features

- [ ] WebSocket support voor real-time updates
- [ ] Prometheus metrics endpoint
- [ ] GraphQL API optie
- [ ] Token rotation mechanisme
- [ ] IP whitelisting per token
- [ ] Webhook notifications
- [ ] Multi-user support met RBAC
- [ ] API key rotation schedules
- [ ] Custom rate limit rules
- [ ] Query result caching

---

## 📞 Support

**Bij problemen:**

1. Check server logs: `sudo journalctl -u netmonitor-mcp-http -f`
2. Check API health: `curl http://localhost:8000/health`
3. Verify token: `python3 mcp_server/manage_tokens.py list`
4. Test database: `psql -U netmonitor -d netmonitor -c "SELECT 1;"`

**Debug mode:**
```bash
# Start server met debug logging
LOG_LEVEL=DEBUG python3 mcp_server/http_server.py
```

---

## 📄 Licentie

Part of NetMonitor Security Operations Center
