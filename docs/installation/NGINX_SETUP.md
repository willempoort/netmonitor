# Nginx Configuration Guide voor NetMonitor

NetMonitor draait met **twee backend services** op verschillende poorten:

## 🔌 Backend Services

| Service | Poort | Technologie | Doel |
|---------|-------|-------------|------|
| **Web Dashboard** | 8080 | Flask + eventlet + SocketIO | Web UI voor mensen |
| **MCP HTTP API** | 8000 | FastAPI + Uvicorn | AI/MCP clients (Claude, Open WebUI) |

## 📁 Nginx Configuratie Bestand

### `nginx-netmonitor.conf.example`

Er is één template, voor de volledige setup met beide services. Het bevat
altijd de MCP-routing, ongeacht of je de MCP HTTP API (nog) geïnstalleerd
hebt - draait er niets op poort 8000, dan geven de `/mcp/*`-locaties
gewoon een 502 totdat je 'm alsnog activeert.

**Features:**
- ✅ Routeert `/mcp/*` naar MCP API (poort 8000)
- ✅ Routeert `/api/*` en `/` naar Web Dashboard (poort 8080)
- ✅ Ondersteunt WebSocket voor SocketIO
- ✅ CORS headers voor MCP API
- ✅ SSL/TLS met Let's Encrypt
- ✅ Security headers

**Routing:**
```
https://soc.example.com/             → Web Dashboard (8080)
https://soc.example.com/api/*        → Web Dashboard (8080)
https://soc.example.com/socket.io/*  → Web Dashboard (8080)
https://soc.example.com/mcp/*        → MCP HTTP API (8000)
```

**Installatie:**
```bash
sudo cp nginx-netmonitor.conf.example /etc/nginx/sites-available/netmonitor
sudo ln -sf /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/netmonitor
sudo nginx -t
sudo systemctl reload nginx
```

Wil je specifiek Gunicorn i.p.v. eventlet als WSGI-server? Zie de
gearchiveerde `archive/nginx/nginx-netmonitor-gunicorn.conf` en
`docs/installation/GUNICORN_SETUP.md` - dat is een losstaande, minder
gebruikelijke opstelling.

## 🚀 Setup Instructies

### Stap 1: Kopieer de Configuratie

```bash
sudo cp nginx-netmonitor.conf.example /etc/nginx/sites-available/netmonitor
```

### Stap 2: Pas Domeinnaam Aan

```bash
sudo nano /etc/nginx/sites-available/netmonitor
```

Wijzig **alle** voorkomens van `soc.example.com` naar je eigen domein:
```nginx
server_name soc.jouwdomein.com;
```

### Stap 3: SSL Certificaat

**Optie A: Let's Encrypt (aanbevolen)**
```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d soc.jouwdomein.com
```

**Optie B: Bestaand certificaat**

Pas de paden aan in de nginx config:
```nginx
ssl_certificate /pad/naar/fullchain.pem;
ssl_certificate_key /pad/naar/privkey.pem;
```

### Stap 4: Verifieer Backend Services Draaien

**Check Web Dashboard (8080):**
```bash
curl http://localhost:8080/api/status
```

**Check MCP API (8000):**
```bash
curl http://localhost:8000/health
# Of met de MCP path:
curl http://localhost:8000/docs
```

### Stap 5: Test Nginx Configuratie

```bash
# Test syntax
sudo nginx -t

# Als OK, reload
sudo systemctl reload nginx
```

### Stap 6: Test via Nginx

**Test Dashboard:**
```bash
curl https://soc.jouwdomein.com/api/status
```

**Test MCP API:**
```bash
curl https://soc.jouwdomein.com/mcp/health
curl https://soc.jouwdomein.com/mcp/docs
```

## 🔐 Authenticatie per Service

### Web Dashboard (8080)
- **Login UI**: Flask-Login met session cookies
- **Sensors**: Token authenticatie via `Authorization` header
- **2FA**: TOTP support

### MCP HTTP API (8000)
- **Token authenticatie**: `X-API-Key` of `Authorization: Bearer <token>` header
- **Geen cookies**: Stateless API
- **Tokens beheren**: `python3 mcp_server/manage_tokens.py`

## 🧪 Testing

### Test Web Dashboard Access

```bash
# Via nginx
curl https://soc.jouwdomein.com/

# Should redirect to /login (302)
```

### Test MCP API Access

```bash
# Health check (no auth required)
curl https://soc.jouwdomein.com/mcp/health

# API docs (no auth required)
curl https://soc.jouwdomein.com/mcp/docs

# List tools (auth required)
curl -H "X-API-Key: your-token-here" \
  https://soc.jouwdomein.com/mcp/tools
```

### Test WebSocket (SocketIO)

```bash
# Install websocat
sudo apt install websocat

# Test WebSocket connection
websocat wss://soc.jouwdomein.com/socket.io/?transport=websocket
```

## 🔧 Troubleshooting

### 502 Bad Gateway

**Oorzaak**: Backend service niet bereikbaar.

**Check:**
```bash
# Is dashboard running?
sudo systemctl status netmonitor.service
sudo lsof -i :8080

# Is MCP API running?
sudo systemctl status netmonitor-mcp-streamable.service
sudo lsof -i :8000
```

### WebSocket Connection Failed

**Check nginx error log:**
```bash
sudo tail -f /var/log/nginx/netmonitor_error.log
```

**Verify headers:**
```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

### MCP API Returns 404

**Check routing:**
```bash
# Dit zou naar MCP API moeten gaan:
curl https://soc.jouwdomein.com/mcp/health

# Dit zou naar dashboard moeten gaan:
curl https://soc.jouwdomein.com/api/status
```

**Check rewrite rule:**
```nginx
location /mcp/ {
    rewrite ^/mcp/(.*) /$1 break;  # /mcp/health → /health
    proxy_pass http://netmonitor_mcp_api;
}
```

### CORS Errors (MCP API)

**Verify CORS headers in nginx:**
```nginx
add_header Access-Control-Allow-Origin "*" always;
add_header Access-Control-Allow-Headers "Authorization, Content-Type, X-API-Key" always;
```

**Or configure in FastAPI** (`mcp_server/streamable_http_server.py`):
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## 📊 Monitoring

### Access Logs

```bash
# All requests
sudo tail -f /var/log/nginx/netmonitor_access.log

# MCP API requests only
sudo tail -f /var/log/nginx/netmonitor_access.log | grep "GET /mcp/"

# Dashboard requests only
sudo tail -f /var/log/nginx/netmonitor_access.log | grep -v "/mcp/"
```

### Error Logs

```bash
sudo tail -f /var/log/nginx/netmonitor_error.log
```

### Backend Service Logs

```bash
# Dashboard
sudo journalctl -u netmonitor.service -f

# MCP API
sudo journalctl -u netmonitor-mcp-streamable.service -f
```

## 🔀 Service Port Mapping

| External URL | Nginx Upstream | Backend Service | Port |
|--------------|----------------|-----------------|------|
| `/` | `netmonitor_dashboard` | web_dashboard.py | 8080 |
| `/api/*` | `netmonitor_dashboard` | web_dashboard.py | 8080 |
| `/api/sensors/*` | `netmonitor_dashboard` | web_dashboard.py | 8080 |
| `/socket.io/*` | `netmonitor_dashboard` | web_dashboard.py | 8080 |
| `/mcp/*` | `netmonitor_mcp_api` | streamable_http_server.py | 8000 |

## 🌐 Firewall Configuration

```bash
# Allow HTTPS
sudo ufw allow 443/tcp

# Allow HTTP (voor Let's Encrypt)
sudo ufw allow 80/tcp

# Block direct access to backend ports from outside
sudo ufw deny 8080/tcp
sudo ufw deny 8000/tcp

# Verify rules
sudo ufw status
```

Backend services blijven bereikbaar op localhost voor nginx.

## ✅ Verificatie Checklist

- [ ] Beide backend services draaien (check met `lsof -i :8080` en `lsof -i :8000`)
- [ ] Nginx configuratie syntax correct (`nginx -t`)
- [ ] SSL certificaat geldig en fullchain gebruikt
- [ ] Domeinnaam correct ingesteld
- [ ] Web dashboard bereikbaar via browser
- [ ] MCP API health endpoint bereikbaar
- [ ] WebSocket connecties werken
- [ ] CORS headers aanwezig voor MCP API
- [ ] Logs worden geschreven
- [ ] Firewall regels correct

**Alles OK?** 🎉 Je NetMonitor is klaar voor productie!
