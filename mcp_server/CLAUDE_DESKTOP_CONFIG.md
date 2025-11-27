# Claude Desktop Configuration voor MCP HTTP API

## 📋 Overzicht

Dit voorbeeld toont hoe je Claude Desktop kunt verbinden met de MCP HTTP API server die draait op een remote server met HTTPS.

**Scenario:**
- MCP HTTP API server: `https://soc.poort.net:8000`
- Authenticatie: Bearer token
- Client: Claude Desktop (lokaal op je Mac/Windows/Linux)

---

## 🔧 Configuratie Methode

### Optie 1: HTTP Bridge Client (Aanbevolen)

Gebruik de meegeleverde bridge client die STDIO (verwacht door Claude Desktop) vertaalt naar HTTP API calls.

#### Stap 1: Installeer Dependencies op Client

```bash
# Op je lokale machine (waar Claude Desktop draait)
cd ~
mkdir -p mcp-clients/netmonitor
cd mcp-clients/netmonitor

# Kopieer bridge client van server
scp user@soc.poort.net:/opt/netmonitor/mcp_server/http_bridge_client.py .

# Installeer requests library
pip3 install requests
# Of met pipx (aanbevolen):
# pipx install requests
```

#### Stap 2: Haal API Token Op

```bash
# Op de MCP server (soc.poort.net)
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
    --name "Claude Desktop - <JOUW_NAAM>" \
    --scope read_only \
    --description "Token voor Claude Desktop op lokale machine"

# Kopieer de token uit de output
# Token: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

#### Stap 3: Configureer Claude Desktop

**macOS:**
```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Linux:**
```bash
mkdir -p ~/.config/Claude
nano ~/.config/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Configuratie:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": [
        "/Users/username/mcp-clients/netmonitor/http_bridge_client.py"
      ],
      "env": {
        "MCP_HTTP_URL": "https://soc.poort.net:8000",
        "MCP_HTTP_TOKEN": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2"
      }
    }
  }
}
```

**⚠️ Vervang:**
- `/Users/username/...` → Jouw pad naar `http_bridge_client.py`
- `MCP_HTTP_TOKEN` → Jouw API token

#### Stap 4: Herstart Claude Desktop

Sluit Claude Desktop volledig af en start opnieuw.

#### Stap 5: Test

In Claude Desktop:
```
Show me the security dashboard summary
```

Of:
```
What sensors are online?
```

---

## 🔐 SSL/TLS Certificaat (HTTPS)

Als je een self-signed certificaat gebruikt op `soc.poort.net`:

### Optie A: Vertrouw het Certificaat

**macOS:**
```bash
# Download certificaat
openssl s_client -connect soc.poort.net:8000 -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > soc_poort_net.crt

# Voeg toe aan keychain
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain soc_poort_net.crt
```

**Linux:**
```bash
# Download certificaat
openssl s_client -connect soc.poort.net:8000 -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > soc_poort_net.crt

# Voeg toe aan systeem
sudo cp soc_poort_net.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### Optie B: Disable SSL Verificatie (NIET AANBEVOLEN)

Alleen voor development/testing:

**Pas `http_bridge_client.py` aan:**
```python
# Zoek regel:
response = requests.get(url, headers=self.headers, verify=True, timeout=30)

# Wijzig naar:
response = requests.get(url, headers=self.headers, verify=False, timeout=30)
```

**⚠️ Gebruik dit alleen in een vertrouwd netwerk!**

---

## 🌐 Optie 2: Reverse Proxy met Let's Encrypt

**Beste oplossing voor productie:**

### Nginx Reverse Proxy

Op `soc.poort.net`:

```nginx
# /etc/nginx/sites-available/mcp-api

server {
    listen 443 ssl http2;
    server_name soc.poort.net;

    # Let's Encrypt certificaten
    ssl_certificate /etc/letsencrypt/live/soc.poort.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.poort.net/privkey.pem;

    # SSL configuratie
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location /mcp/ {
        proxy_pass http://127.0.0.1:8000/mcp/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts voor lange requests
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
    }

    location /health {
        proxy_pass http://127.0.0.1:8000/health;
    }

    location /docs {
        proxy_pass http://127.0.0.1:8000/docs;
    }
}
```

**Let's Encrypt installeren:**
```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d soc.poort.net
```

**Claude Desktop config blijft hetzelfde:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": ["/path/to/http_bridge_client.py"],
      "env": {
        "MCP_HTTP_URL": "https://soc.poort.net",
        "MCP_HTTP_TOKEN": "YOUR_TOKEN"
      }
    }
  }
}
```

---

## 🔧 Troubleshooting

### Bridge client start niet

**Check logs:**
```bash
tail -f /tmp/mcp_http_bridge.log
```

**Test handmatig:**
```bash
export MCP_HTTP_URL="https://soc.poort.net:8000"
export MCP_HTTP_TOKEN="your_token_here"
python3 http_bridge_client.py
```

### SSL certificaat errors

**Test connectie:**
```bash
curl -v https://soc.poort.net:8000/health
```

**Als self-signed certificaat:**
```bash
curl -k https://soc.poort.net:8000/health
# -k = insecure (skip SSL verificatie)
```

### Token authenticatie faalt

**Verify token:**
```bash
# Op de server
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py list
python3 mcp_server/manage_tokens.py show 1
```

**Test token:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://soc.poort.net:8000/mcp/tools
```

### Claude Desktop toont MCP server niet

**Check:**
1. JSON syntax: `python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json`
2. Pad naar script is correct en executable
3. Python dependencies zijn geïnstalleerd (`pip3 install requests`)
4. Herstart Claude Desktop volledig (Quit + reopen)

---

## 📊 Complete Configuratie Voorbeeld

### Productie Setup met Let's Encrypt

**Server setup (soc.poort.net):**
```bash
# 1. MCP HTTP API server draait op localhost:8000
sudo systemctl status netmonitor-mcp-http

# 2. Nginx reverse proxy met Let's Encrypt
sudo systemctl status nginx

# 3. Firewall
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp  # Voor Let's Encrypt renewal
```

**Client setup (lokale machine):**
```bash
# 1. Installeer bridge client
mkdir -p ~/mcp-clients/netmonitor
cd ~/mcp-clients/netmonitor
scp user@soc.poort.net:/opt/netmonitor/mcp_server/http_bridge_client.py .

# 2. Installeer requests
pip3 install requests

# 3. Test connectie
curl https://soc.poort.net/health
```

**Claude Desktop config:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": [
        "/Users/username/mcp-clients/netmonitor/http_bridge_client.py"
      ],
      "env": {
        "MCP_HTTP_URL": "https://soc.poort.net",
        "MCP_HTTP_TOKEN": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2"
      }
    }
  }
}
```

---

## 🔒 Security Checklist

- ✅ Gebruik HTTPS (niet HTTP)
- ✅ Gebruik valide SSL certificaat (Let's Encrypt)
- ✅ Gebruik unieke token per gebruiker
- ✅ Stel token expiration in
- ✅ Gebruik read_only scope voor Claude Desktop
- ✅ Monitor token usage via stats
- ✅ Revoke tokens die niet meer gebruikt worden
- ✅ Gebruik firewall rules om poort 8000 af te schermen
- ✅ Alleen HTTPS poort (443) toegankelijk

---

## 📚 Meer Informatie

- **HTTP API Docs:** `/opt/netmonitor/MCP_HTTP_API.md`
- **Quick Start:** `/opt/netmonitor/mcp_server/HTTP_API_QUICKSTART.md`
- **Live API Docs:** https://soc.poort.net:8000/docs
- **Token Management:** `python3 mcp_server/manage_tokens.py --help`

---

**Veel succes met de MCP HTTP API integratie!** 🚀
