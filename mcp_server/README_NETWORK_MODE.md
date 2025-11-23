# MCP Server Network Mode (SSE)

Dit document beschrijft hoe je de NetMonitor MCP server in network mode (SSE) kunt draaien, zodat Claude Desktop op je lokale machine kan verbinden met de server op `soc.poort.net`.

## Architectuur

```
[Je Desktop]                    [soc.poort.net]
     ↓                                ↓
Claude Desktop  ←→ (SSE) ←→  MCP Server ←→ PostgreSQL
                                  ↓
                              Ollama (optioneel)
```

## 1. MCP Server starten in SSE mode

Op de SOC server (`soc.poort.net`):

```bash
cd /home/user/netmonitor/mcp_server

# Start MCP server in SSE mode (network accessible)
python server.py --transport sse --host 0.0.0.0 --port 3000

# Of met systemd service:
sudo systemctl start netmonitor-mcp-sse
```

### Systemd Service Template

Maak `/etc/systemd/system/netmonitor-mcp-sse.service`:

```ini
[Unit]
Description=NetMonitor MCP Server (SSE Mode)
After=network.target postgresql.service

[Service]
Type=simple
User=netmonitor
WorkingDirectory=/home/user/netmonitor/mcp_server
Environment="NETMONITOR_DB_HOST=localhost"
Environment="NETMONITOR_DB_PORT=5432"
Environment="NETMONITOR_DB_NAME=netmonitor"
Environment="NETMONITOR_DB_USER=mcp_readonly"
Environment="NETMONITOR_DB_PASSWORD=mcp_netmonitor_readonly_2024"
Environment="OLLAMA_BASE_URL=http://localhost:11434"
ExecStart=/usr/bin/python3 /home/user/netmonitor/mcp_server/server.py --transport sse --host 0.0.0.0 --port 3000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable en start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable netmonitor-mcp-sse
sudo systemctl start netmonitor-mcp-sse
```

## 2. Firewall Configuration

Open poort 3000 voor externe toegang:

```bash
# UFW
sudo ufw allow 3000/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
```

## 3. Claude Desktop Configuration

Op je lokale desktop machine, configureer Claude Desktop om te verbinden met de remote MCP server.

### Locatie configuratie bestand:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### Configuratie:

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

## 4. Test de Verbinding

### Test 1: Health Check
```bash
curl http://soc.poort.net:3000/health
# Verwacht: "OK"
```

### Test 2: Claude Desktop
1. Herstart Claude Desktop
2. In een nieuw gesprek, type:
   ```
   Use the netmonitor-soc MCP server to get sensor status
   ```
3. Claude zal verbinden en sensor data ophalen

## 5. Ollama Configuratie

De MCP server kan optioneel verbinden met Ollama voor AI-analyse van threats.

### Optie A: Ollama op SOC Server

```bash
# Installeer Ollama op soc.poort.net
curl -fsSL https://ollama.com/install.sh | sh

# Download model
ollama pull llama3.2

# Ollama draait automatisch op localhost:11434
```

MCP server variabele:
```bash
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=llama3.2
```

### Optie B: Ollama op je Desktop (Remote Access)

Als je Ollama al op je desktop hebt draaien:

**Op je desktop:**
```bash
# Start Ollama met network binding
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# Of in ~/.ollama/config:
# OLLAMA_HOST=0.0.0.0:11434
```

**Op SOC server:**
```bash
# MCP server verbindt met jouw desktop Ollama
export OLLAMA_BASE_URL=http://[JE_DESKTOP_IP]:11434
export OLLAMA_MODEL=llama3.2
```

**Firewall (desktop):**
```bash
# Open poort 11434
sudo ufw allow from [SOC_SERVER_IP] to any port 11434
```

## 6. Beveiliging

⚠️ **Belangrijke beveiligingsoverwegingen:**

### SSL/TLS Toevoegen (Productie)

Voor productie gebruik, zet een reverse proxy met SSL voor de MCP server:

```nginx
# /etc/nginx/sites-available/mcp-server
server {
    listen 443 ssl;
    server_name mcp.soc.poort.net;

    ssl_certificate /etc/letsencrypt/live/soc.poort.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.poort.net/privkey.pem;

    location /sse {
        proxy_pass http://localhost:3000/sse;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_cache off;
    }

    location /health {
        proxy_pass http://localhost:3000/health;
    }
}
```

Claude Desktop config wordt dan:
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "url": "https://mcp.soc.poort.net/sse",
      "transport": "sse"
    }
  }
}
```

### IP Whitelisting

Beperk toegang tot alleen je desktop IP:

```bash
sudo ufw allow from [JE_DESKTOP_IP] to any port 3000
```

### VPN Optie

Beste beveiligingspraktijk: Gebruik VPN (WireGuard/OpenVPN) en bind MCP server alleen op VPN interface:

```bash
# MCP server alleen op WireGuard interface
python server.py --transport sse --host 10.8.0.1 --port 3000
```

## 7. Troubleshooting

### MCP Server start niet
```bash
# Check logs
journalctl -u netmonitor-mcp-sse -f

# Check of poort vrij is
sudo netstat -tlnp | grep 3000

# Test database connectie
psql -h localhost -U mcp_readonly -d netmonitor
```

### Claude Desktop kan niet verbinden
```bash
# Check of server draait
curl http://soc.poort.net:3000/health

# Check firewall
sudo ufw status

# Check Claude Desktop logs (macOS):
tail -f ~/Library/Logs/Claude/mcp*.log
```

### Ollama verbindt niet
```bash
# Check Ollama status
curl http://localhost:11434/api/tags

# Test vanuit MCP server
curl http://[OLLAMA_HOST]:11434/api/tags
```

## 8. Performance Optimalisatie

### Database Connection Pooling

De MCP server gebruikt readonly credentials met limited privileges. Voor betere performance bij veel MCP clients:

```python
# In mcp_server/database_client.py wordt al connection pooling gebruikt
# Default: min=2, max=10 connections
```

### Rate Limiting

Overweeg rate limiting voor productie:

```nginx
# In nginx config
limit_req_zone $binary_remote_addr zone=mcp:10m rate=10r/s;

location /sse {
    limit_req zone=mcp burst=20;
    proxy_pass http://localhost:3000/sse;
}
```

## 9. Monitoring

Check MCP server status:

```bash
# Health endpoint
watch -n 5 curl -s http://soc.poort.net:3000/health

# Systemd status
sudo systemctl status netmonitor-mcp-sse

# Logs
tail -f /tmp/mcp_netmonitor.log
```

## Vragen?

- MCP Protocol: https://modelcontextprotocol.io/
- Claude Desktop MCP: https://docs.anthropic.com/claude/docs/mcp
- Ollama: https://ollama.com/
