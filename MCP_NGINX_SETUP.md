# MCP API Nginx Setup voor Claude Desktop

## 🎯 Probleem

Claude Desktop werkt met:
- ✅ `http://servernaam:8000` (direct naar MCP API)
- ❌ `https://servernaam:443` (via nginx reverse proxy)
- ❌ `https://servernaam` (via nginx reverse proxy)

## 🔍 Oorzaak

Claude Desktop's HTTP Bridge Client bouwt URLs als:
```
{MCP_HTTP_URL}/mcp/tools
{MCP_HTTP_URL}/mcp/resources
```

Het probleem kan zijn:
1. SSL certificaat verificatie faalt
2. Nginx routing issues
3. CORS problemen

## ✅ Oplossingen

### Oplossing 1: Dedicated Subdomain (Aanbevolen)

**Voordelen:**
- ✅ Schone scheiding MCP API vs Web Dashboard
- ✅ Simpele nginx configuratie (geen URL rewriting)
- ✅ Dedicated SSL certificaat
- ✅ Geen conflicterende routes

**Setup:**

#### Stap 1: DNS Record Toevoegen

Voeg een A-record toe voor `mcp.poort.net`:
```
Type: A
Name: mcp
Value: [IP van soc.poort.net]
TTL: 300
```

#### Stap 2: Nginx Configuratie

```bash
# Kopieer configuratie
sudo cp nginx-mcp-subdomain.conf /etc/nginx/sites-available/mcp

# Enable site
sudo ln -sf /etc/nginx/sites-available/mcp /etc/nginx/sites-enabled/mcp

# Test configuratie
sudo nginx -t
```

#### Stap 3: SSL Certificaat (Let's Encrypt)

```bash
sudo certbot --nginx -d mcp.poort.net
```

#### Stap 4: Reload Nginx

```bash
sudo systemctl reload nginx
```

#### Stap 5: Test

```bash
# Health check
curl https://mcp.poort.net/health

# MCP endpoints
curl https://mcp.poort.net/mcp/tools
curl https://mcp.poort.net/docs
```

#### Stap 6: Update Claude Desktop Config

```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": ["/pad/naar/http_bridge_client.py"],
      "env": {
        "MCP_HTTP_URL": "https://mcp.poort.net",
        "MCP_HTTP_TOKEN": "your_token_here"
      }
    }
  }
}
```

**Bridge maakt nu:**
```
https://mcp.poort.net/mcp/tools ✅
https://mcp.poort.net/mcp/resources ✅
```

---

### Oplossing 2: Huidige Setup Debuggen

Als de `/mcp/` route op `soc.poort.net` niet werkt, check:

#### Test 1: Check Nginx Config Actief

```bash
# Is de dual config actief?
ls -la /etc/nginx/sites-enabled/

# Welke config wordt gebruikt?
sudo nginx -T | grep -A 5 "location /mcp"
```

#### Test 2: SSL Certificaat

```bash
# Test SSL verbinding
curl -v https://soc.poort.net/mcp/health

# Check certificaat
openssl s_client -connect soc.poort.net:443 -servername soc.poort.net </dev/null
```

**Als SSL errors:**
```bash
# Verifieer fullchain wordt gebruikt
sudo cat /etc/nginx/sites-enabled/netmonitor | grep ssl_certificate

# Herlaad als nodig
sudo systemctl reload nginx
```

#### Test 3: Bridge Client Logs

```bash
# Check bridge logs
tail -f /tmp/mcp_http_bridge.log
```

**Handmatig testen:**
```bash
export MCP_HTTP_URL="https://soc.poort.net"
export MCP_HTTP_TOKEN="your_token_here"
python3 http_bridge_client.py
```

#### Test 4: SSL Verificatie Uitschakelen (Temporary)

Edit `http_bridge_client.py`:
```python
# Regel 52 en 54, verander verify=True naar verify=False
response = requests.get(url, headers=self.headers, verify=False, timeout=30)
response = requests.post(url, headers=self.headers, json=data, verify=False, timeout=30)
```

**⚠️ Dit is alleen voor troubleshooting! Gebruik verify=True in productie.**

Als het werkt met `verify=False`:
→ Probleem is SSL certificaat
→ Installeer volledige certificate chain op server

---

### Oplossing 3: Direct SSL op MCP API (Poort 8000)

**Als je geen nginx wilt gebruiken voor MCP:**

#### Update MCP Server voor SSL

Edit `/opt/netmonitor/mcp_server/http_server.py` om SSL te ondersteunen, of draai achter een SSL tunnel.

**Nadelen:**
- ❌ Complexer om te beheren
- ❌ Twee SSL certificaten nodig
- ❌ Port 8000 moet publiek toegankelijk zijn

**Niet aanbevolen.**

---

## 🎯 Aanbevolen Architectuur

```
┌─────────────────┐
│  Claude Desktop │
└────────┬────────┘
         │ HTTPS (443)
         ▼
┌─────────────────────────────┐
│  Nginx Reverse Proxy        │
│                             │
│  mcp.poort.net  │ → Port 8000 (MCP API)
│  soc.poort.net  │ → Port 8080 (Dashboard)
└─────────────────────────────┘
```

**Routing:**
- `https://mcp.poort.net/*` → MCP HTTP API (8000)
- `https://soc.poort.net/*` → Web Dashboard (8080)

**Voordelen:**
- ✅ Schone scheiding
- ✅ Dedicated SSL per service
- ✅ Simpele nginx configuratie
- ✅ Geen URL rewriting complexiteit
- ✅ Makkelijk te debuggen

---

## 🔧 Troubleshooting Checklist

- [ ] DNS record voor `mcp.poort.net` bestaat
- [ ] Nginx config gekopieerd en enabled
- [ ] SSL certificaat aangemaakt (`certbot`)
- [ ] Nginx test passed (`nginx -t`)
- [ ] Nginx reloaded (`systemctl reload nginx`)
- [ ] MCP API draait op poort 8000 (`lsof -i :8000`)
- [ ] Health endpoint bereikbaar (`curl https://mcp.poort.net/health`)
- [ ] MCP endpoints bereikbaar (`curl https://mcp.poort.net/mcp/tools`)
- [ ] Bridge client config updated
- [ ] Claude Desktop herstart

---

## 📊 Verificatie

### Test MCP Endpoints

```bash
# Health (geen auth)
curl https://mcp.poort.net/health

# API info (geen auth)
curl https://mcp.poort.net/

# Tools lijst (auth required)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://mcp.poort.net/mcp/tools

# API docs
curl https://mcp.poort.net/docs
```

### Test Claude Desktop Verbinding

In Claude Desktop, type:
```
List available tools
```

Of:
```
Show me dashboard summary
```

Als MCP server correct verbonden is, zie je een lijst met NetMonitor tools.

---

## 🚀 Quick Start (Dedicated Subdomain)

```bash
# 1. DNS: Voeg A-record toe voor mcp.poort.net

# 2. Installeer nginx config
sudo cp nginx-mcp-subdomain.conf /etc/nginx/sites-available/mcp
sudo ln -sf /etc/nginx/sites-available/mcp /etc/nginx/sites-enabled/mcp

# 3. SSL certificaat
sudo certbot --nginx -d mcp.poort.net

# 4. Test en reload
sudo nginx -t && sudo systemctl reload nginx

# 5. Test endpoint
curl https://mcp.poort.net/health

# 6. Update Claude Desktop config
# MCP_HTTP_URL: "https://mcp.poort.net"

# 7. Herstart Claude Desktop
```

**Klaar!** 🎉

---

## 📞 Support

Als het nog steeds niet werkt:

1. **Check bridge logs:** `tail -f /tmp/mcp_http_bridge.log`
2. **Test handmatig:** Exporteer env vars en run bridge script
3. **Check nginx logs:** `tail -f /var/log/nginx/mcp_error.log`
4. **Verify SSL:** `openssl s_client -connect mcp.poort.net:443`
5. **Check firewall:** `sudo ufw status`

**Meest voorkomende problemen:**
- SSL certificaat niet volledig (gebruik fullchain.pem)
- DNS nog niet gepropageerd (wacht 5-10 minuten)
- Firewall blokkeert poort 443
- MCP API niet draaiend op poort 8000
