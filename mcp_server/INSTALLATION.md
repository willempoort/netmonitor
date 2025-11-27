# NetMonitor MCP Server - Installation Guide

**Modern HTTP API met Token Authenticatie**

---

## 📋 Overzicht

De NetMonitor MCP server biedt AI assistenten zoals Claude **volledige SOC toegang** via een moderne HTTP REST API met token-based authenticatie.

**Belangrijkste Features:**
- 🔐 **Token Authenticatie** - Veilige Bearer tokens per client
- 🚦 **Rate Limiting** - Configureerbaar per token
- 👥 **Permission Scopes** - read_only, read_write, admin
- 📊 **Audit Logging** - Volledige request tracking
- 🔍 **23+ Tools** - Van monitoring tot configuratie management
- 📚 **Auto-Docs** - OpenAPI/Swagger documentatie

---

## 🚀 Quick Start (5 minuten)

```bash
# 1. Maak virtual environment
cd /opt/netmonitor
python3 -m venv venv
source venv/bin/activate

# 2. Run setup (installeert dependencies, maakt schema, genereert token)
sudo ./mcp_server/setup_http_api.sh

# 3. Start server
sudo systemctl start netmonitor-mcp-http

# 4. Test API
curl http://localhost:8000/health
```

**Klaar!** De HTTP API draait op `http://localhost:8000`

---

## 📦 Requirements

### Server Requirements
- **PostgreSQL 12+** met TimescaleDB (optioneel)
- **Python 3.8+** met virtual environment
- **NetMonitor SOC** geïnstalleerd en draaiend

### Python Dependencies

Automatisch geïnstalleerd door setup script:
- `fastapi` - Modern async web framework
- `uvicorn` - ASGI HTTP server
- `pydantic` - Data validation
- `slowapi` - Rate limiting
- `python-jose` - Token crypto
- `tabulate` - CLI formatting
- Plus alle MCP SDK dependencies

---

## 🔧 Gedetailleerde Installatie

### Stap 1: Virtual Environment

**⚠️ BELANGRIJK:** Gebruik altijd een virtual environment!

```bash
cd /opt/netmonitor

# Maak venv
python3 -m venv venv

# Activeer venv
source venv/bin/activate

# Verify
which python
# Should show: /opt/netmonitor/venv/bin/python
```

### Stap 2: Run Setup Script

```bash
sudo ./mcp_server/setup_http_api.sh
```

**Dit script doet:**

1. ✅ Creëert database schema voor API tokens
2. ✅ Installeert Python dependencies in venv
3. ✅ Genereert eerste admin token
4. ✅ Installeert systemd service

**Output:**
```
Step 1: Creating database schema for API tokens...
✅ Database schema created successfully

Step 2: Installing/updating Python dependencies...
Using virtual environment: /opt/netmonitor/venv
✅ Dependencies installed successfully

Step 3: Creating initial admin API token...
✅ API Token created successfully!

🔑 Token: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...

⚠️  IMPORTANT: Save this token now!

Step 4: Installing systemd service...
✅ Service enabled
```

**⚠️ Bewaar de token!** Je kunt hem niet meer ophalen.

### Stap 3: Start de Service

```bash
# Start server
sudo systemctl start netmonitor-mcp-http

# Check status
sudo systemctl status netmonitor-mcp-http

# Enable auto-start
sudo systemctl enable netmonitor-mcp-http

# View logs
sudo journalctl -u netmonitor-mcp-http -f
```

### Stap 4: Test de API

```bash
# Health check
curl http://localhost:8000/health

# List tools (met token)
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/mcp/tools

# Bekijk docs
open http://localhost:8000/docs
```

---

## 🔑 Token Management

### Token Aanmaken

```bash
cd /opt/netmonitor

# Read-only token (voor AI monitoring)
python3 mcp_server/manage_tokens.py create \
    --name "Claude Desktop" \
    --scope read_only \
    --description "Security monitoring via Claude"

# Read-write token (voor automation)
python3 mcp_server/manage_tokens.py create \
    --name "Incident Response Bot" \
    --scope read_write \
    --expires-days 90

# Admin token (voor beheer)
python3 mcp_server/manage_tokens.py create \
    --name "Admin Console" \
    --scope admin \
    --rate-minute 200
```

### Token Beheren

```bash
# Lijst alle tokens
python3 mcp_server/manage_tokens.py list

# Token details
python3 mcp_server/manage_tokens.py show 1

# Usage statistieken
python3 mcp_server/manage_tokens.py stats

# Token intrekken
python3 mcp_server/manage_tokens.py revoke 3
```

---

## 🛠️ Beschikbare Tools

De MCP API biedt **23+ tools** verdeeld over categorieën:

### 🔍 Security Analysis (read_only)
- `analyze_ip` - IP threat intelligence
- `get_recent_threats` - Recent security alerts
- `get_threat_timeline` - Attack timeline
- `get_alert_statistics` - Alert statistieken

### 🎛️ Sensor Management (read_only)
- `get_sensor_status` - Live sensor status
- `get_sensor_details` - Gedetailleerde info
- `get_sensor_alerts` - Alerts per sensor

### ⚙️ Configuration (read_write)
- `set_config_parameter` - Wijzig configuratie
- `get_config_parameters` - Lijst parameters
- `reset_config_to_defaults` - Reset naar defaults

### 👥 Sensor Control (read_write)
- `send_sensor_command` - Remote commands
- `get_sensor_command_history` - Command log

### 🚫 Whitelist Management (read_write)
- `add_whitelist_entry` - Voeg IP/CIDR toe
- `get_whitelist_entries` - Lijst whitelist
- `remove_whitelist_entry` - Verwijder entry

### 📊 Exports & Reporting (read_only)
- `export_alerts_csv` - Export naar CSV
- `get_dashboard_summary` - Dashboard data

**Volledige lijst:** `http://localhost:8000/mcp/tools`

---

## 💡 Gebruik Voorbeelden

### Via cURL

```bash
# Analyze IP
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

# Get recent threats
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "get_recent_threats",
    "parameters": {
      "severity": "CRITICAL",
      "hours": 1
    }
  }'
```

### Via Python

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
result = client.execute_tool("analyze_ip", {"ip_address": "8.8.8.8"})
print(result)
```

---

## 🧪 Testing & Verificatie

### Test 1: Health Check
```bash
curl http://localhost:8000/health
```
**Verwacht:** `{"status": "healthy", ...}`

### Test 2: Authentication
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/mcp/tools
```
**Verwacht:** JSON array met tools

### Test 3: Tool Execution
```bash
curl -X POST http://localhost:8000/mcp/tools/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "get_sensor_status", "parameters": {}}'
```
**Verwacht:** JSON met sensor status

### Test 4: API Documentation
```
http://localhost:8000/docs
```
**Verwacht:** Swagger UI met alle endpoints

---

## 🐛 Troubleshooting

### Server start niet

```bash
# Check logs
sudo journalctl -u netmonitor-mcp-http -n 50

# Check database
psql -h localhost -U netmonitor -d netmonitor -c "SELECT 1;"

# Check port
lsof -i :8000
```

### Token authenticatie faalt

```bash
# Verify token bestaat
python3 mcp_server/manage_tokens.py list

# Check token details
python3 mcp_server/manage_tokens.py show 1

# Test met verbose
curl -v \
    -H "Authorization: Bearer YOUR_TOKEN" \
    http://localhost:8000/mcp/tools
```

### Dependencies ontbreken

```bash
# Re-run setup
cd /opt/netmonitor
source venv/bin/activate
pip install -r mcp_server/requirements.txt

# Of run setup opnieuw
sudo ./mcp_server/setup_http_api.sh
```

### Database schema errors

```bash
# Re-create schema
cd /opt/netmonitor
psql -U netmonitor -d netmonitor \
     -f mcp_server/schema_api_tokens.sql
```

---

## 🔒 Security Best Practices

### 1. Token Management

✅ **DO:**
- Gebruik unieke tokens per client
- Stel expiration dates in
- Revoke ongebruikte tokens
- Monitor usage via stats

❌ **DON'T:**
- Deel tokens tussen clients
- Commit tokens naar git
- Geef admin scope aan monitoring clients

### 2. Network Security

✅ **DO:**
- Gebruik HTTPS in productie (nginx reverse proxy)
- Beperk CORS origins
- Gebruik firewall rules
- Monitor failed auth attempts

❌ **DON'T:**
- Expose direct op internet zonder HTTPS
- Gebruik `CORS_ORIGINS=*` in productie
- Disable rate limiting

### 3. Production Deployment

Voor productie, gebruik een reverse proxy:

```nginx
# /etc/nginx/sites-available/mcp-api

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 🔄 Updates & Maintenance

### MCP Server Update

```bash
cd /opt/netmonitor
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r mcp_server/requirements.txt --upgrade

# Restart service
sudo systemctl restart netmonitor-mcp-http
```

### Database Schema Updates

Na NetMonitor updates:
```bash
# Check for schema changes
psql -U netmonitor -d netmonitor -c "\dt mcp_*"

# Apply updates if needed
psql -U netmonitor -d netmonitor -f mcp_server/schema_api_tokens.sql
```

---

## 📚 Meer Informatie

### Documentatie
- **API Documentatie**: `../MCP_HTTP_API.md` (root directory)
- **Quick Start**: `HTTP_API_QUICKSTART.md` (deze directory)
- **Live API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Legacy STDIO/SSE

⚠️ De oude STDIO/SSE implementatie is **verouderd** en gearchiveerd in:
```
mcp_server/legacy_stdio_sse/
```

Gebruik de moderne HTTP API in plaats daarvan voor:
- ✅ Betere beveiliging (tokens)
- ✅ Multiple clients
- ✅ Rate limiting
- ✅ Audit logging
- ✅ Permission control

---

## 🆘 Support

**Bij problemen:**

1. Check server logs: `sudo journalctl -u netmonitor-mcp-http -f`
2. Check API health: `curl http://localhost:8000/health`
3. Verify token: `python3 mcp_server/manage_tokens.py list`
4. Test database: `psql -U netmonitor -d netmonitor -c "SELECT 1;"`

**Debug mode:**
```bash
# Start server handmatig met debug logging
cd /opt/netmonitor
source venv/bin/activate
LOG_LEVEL=DEBUG python3 mcp_server/http_server.py
```

---

## ✨ Volgende Stappen

1. ✅ Installatie gedaan
2. ✅ Server draait
3. ✅ Token aangemaakt

**Nu:**

4. Test de API met cURL of Postman
5. Bekijk documentatie op `/docs`
6. Integreer in je AI client
7. Setup production met nginx/HTTPS
8. Monitor usage via token stats

**Veel succes met de MCP HTTP API!** 🚀
