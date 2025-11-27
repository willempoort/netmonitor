# NetMonitor MCP Server - Netwerk Setup (Mac → Linux)

## 🌐 Jouw Setup

**Client:** Claude Desktop op Mac
**Server:** soc.poort.net (Linux) - MCP Server + Database

Dit vereist **SSE/HTTP transport** over het netwerk.

---

## ⚠️ BELANGRIJK: Paths in deze Documentatie

In de voorbeelden hieronder gebruik ik `/home/user/netmonitor` als voorbeeld pad.

**Vervang dit met jouw eigen NetMonitor installatie pad!**

De installatie scripts (`install_mcp_service.sh` en `setup_mcp_user.sh`) detecteren automatisch de correcte directory, dus je hoeft geen paths aan te passen als je deze scripts gebruikt.

---

## 📋 Vereisten

### Op de Linux Server (soc.poort.net):
- Python 3.8+
- PostgreSQL met NetMonitor database
- Netwerk poort 3000 open (of andere poort naar keuze)

### Op je Mac:
- Claude Desktop geïnstalleerd

---

## 🚀 Installatie Stappen

### Stap 0: Virtual Environment Setup (BELANGRIJK!)

⚠️ **Eerst moet je een Python virtual environment maken!**

Zie: **[VENV_SETUP.md](VENV_SETUP.md)** voor uitleg waarom dit belangrijk is.

SSH naar je server en maak de venv:

```bash
ssh user@soc.poort.net
cd /path/to/netmonitor  # jouw NetMonitor directory
./setup_venv.sh
```

Dit script:
- Maakt een virtual environment in `./venv/`
- Installeert alle Python dependencies (inclusief MCP!)
- Neemt ~1-2 minuten

**Waarom venv?**
- MCP is niet beschikbaar via apt-get
- pipx is voor CLI tools, niet voor libraries
- venv isoleert dependencies proper
- Services kunnen venv gebruiken

### Stap 1: Test de MCP Server Handmatig (Optioneel)

Test eerst of de server werkt voordat je de service installeert:

```bash
cd /path/to/netmonitor

# Activeer de venv
source venv/bin/activate

# Ga naar MCP server directory
cd mcp_server

# Set environment variables
export NETMONITOR_DB_HOST=localhost
export NETMONITOR_DB_PORT=5432
export NETMONITOR_DB_NAME=netmonitor
export NETMONITOR_DB_USER=mcp_readonly
export NETMONITOR_DB_PASSWORD=mcp_netmonitor_readonly_2024

# Start in SSE mode
python3 server.py --transport sse --host 0.0.0.0 --port 3000
```

Je zou moeten zien:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:3000
```

Test de health endpoint:
```bash
# In een andere terminal:
curl http://localhost:3000/health
```

Zou moeten returnen: `OK`

### Stap 2: Installeer als Systemd Service

Het install script detecteert automatisch de venv en gebruikt deze voor de service:

```bash
cd /path/to/netmonitor
sudo ./install_mcp_service.sh
```

**Het script doet:**
- ✅ Checkt of venv bestaat (maakt deze aan als niet aanwezig)
- ✅ Genereert service file met venv Python path
- ✅ Installeert en start de service
- ✅ Configureert auto-start bij boot

**Check service status:**
```bash
sudo systemctl status netmonitor-mcp
```

**View logs:**
```bash
sudo journalctl -u netmonitor-mcp -f
```

### Stap 3: Configureer Firewall (indien nodig)

**Check of poort 3000 open is:**
```bash
sudo netstat -tlnp | grep 3000
```

**Als je een firewall gebruikt (ufw):**
```bash
# Check firewall status
sudo ufw status

# Open poort 3000 (alleen voor je Mac IP)
sudo ufw allow from <JE_MAC_IP> to any port 3000

# Of open voor alle IPs (minder veilig):
sudo ufw allow 3000/tcp
```

**Test vanaf je Mac:**
```bash
# Op je Mac, open Terminal:
curl http://soc.poort.net:3000/health
```

Zou `OK` moeten returnen.

### Stap 4: Configureer Claude Desktop op je Mac

**Voor macOS:**
```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Plak deze configuratie:**
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

**Sla op:** Cmd+O, Enter, Cmd+X

### Stap 5: Herstart Claude Desktop

Sluit Claude Desktop volledig af (Cmd+Q) en start opnieuw.

### Stap 6: Test de Verbinding

Open Claude Desktop en typ:
```
What MCP servers are available?
```

Je zou "netmonitor-soc" moeten zien.

Test een tool:
```
Show me the dashboard summary
```

Als het werkt, zie je security statistieken van je Linux server!

---

## 🔒 Security Overwegingen

### 1. **Onversleutelde HTTP**

De huidige setup gebruikt **HTTP** (niet HTTPS). Data wordt onversleuteld verzonden.

**Opties voor verbetering:**
- **SSL/TLS**: Gebruik HTTPS met zelf-getekend certificaat
- **SSH Tunnel**: Tunnel de verbinding via SSH
- **VPN**: Gebruik bestaande VPN verbinding

### 2. **Toegangscontrole**

Momenteel accepteert de server alle verbindingen op poort 3000.

**Aanbevelingen:**
- Gebruik firewall om alleen je Mac IP toe te staan
- Overweeg authentication toe te voegen (API key)
- Draai achter reverse proxy (nginx) met auth

### 3. **SSH Tunnel (Meest Veilig)**

Als alternatief, gebruik een SSH tunnel:

**Op je Mac:**
```bash
# Maak SSH tunnel
ssh -L 3000:localhost:3000 user@soc.poort.net -N

# Dit forward localhost:3000 op je Mac naar localhost:3000 op de server
```

**Claude Desktop config:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "url": "http://localhost:3000/sse",
      "transport": "sse"
    }
  }
}
```

**Voordeel:** All verkeer gaat via versleutelde SSH tunnel.

**Nadeel:** Je moet de tunnel handmatig open houden.

---

## 🐛 Troubleshooting

### Probleem: "Connection refused" in Claude Desktop

**Oorzaken:**
1. MCP server draait niet
2. Firewall blokkeert poort 3000
3. Server bindt alleen op localhost (niet 0.0.0.0)

**Oplossingen:**

1. **Check of server draait:**
```bash
ssh user@soc.poort.net
sudo systemctl status netmonitor-mcp
```

2. **Check of poort luistert:**
```bash
sudo netstat -tlnp | grep 3000
```

Zou moeten tonen: `0.0.0.0:3000` (niet `127.0.0.1:3000`)

3. **Test vanaf je Mac:**
```bash
curl http://soc.poort.net:3000/health
```

4. **Check firewall:**
```bash
sudo ufw status
```

### Probleem: "Timeout" errors

**Oorzaak:** Netwerk latency of server overload.

**Oplossing:**
- Check server logs: `sudo journalctl -u netmonitor-mcp -f`
- Check server resources: `top`, `htop`
- Check database performance: queries nemen te lang

### Probleem: MCP tools werken niet

**Check server logs:**
```bash
# Op de server:
sudo journalctl -u netmonitor-mcp -n 100
```

**Check database connectie:**
```bash
PGPASSWORD='mcp_netmonitor_readonly_2024' \
  psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'
```

### Probleem: "SSE dependencies not installed"

**Oplossing:**
```bash
cd /home/user/netmonitor/mcp_server
pip3 install starlette uvicorn sse-starlette --user
```

---

## 📊 Service Management

### Start Service
```bash
sudo systemctl start netmonitor-mcp
```

### Stop Service
```bash
sudo systemctl stop netmonitor-mcp
```

### Restart Service
```bash
sudo systemctl restart netmonitor-mcp
```

### Check Status
```bash
sudo systemctl status netmonitor-mcp
```

### View Logs
```bash
# Live logs
sudo journalctl -u netmonitor-mcp -f

# Last 100 lines
sudo journalctl -u netmonitor-mcp -n 100

# Errors only
sudo journalctl -u netmonitor-mcp -p err
```

### Enable Auto-start (boot)
```bash
sudo systemctl enable netmonitor-mcp
```

### Disable Auto-start
```bash
sudo systemctl disable netmonitor-mcp
```

---

## 🔄 Transport Modes

De MCP server ondersteunt twee modes:

### 1. **stdio** (Local Only)
- Voor lokale development
- Claude Desktop spawnt de Python process
- Communicatie via stdin/stdout

**Gebruik:**
```bash
python3 server.py --transport stdio
```

### 2. **sse** (Network)
- Voor remote access (jouw setup!)
- HTTP Server-Sent Events
- Claude Desktop verbindt via netwerk

**Gebruik:**
```bash
python3 server.py --transport sse --host 0.0.0.0 --port 3000
```

**Parameters:**
- `--host`: IP to bind to (0.0.0.0 = all interfaces)
- `--port`: Port number (default: 3000)

---

## ✅ Quick Start Checklist

- [ ] Virtual environment gemaakt: `./setup_venv.sh`
- [ ] MCP service geïnstalleerd: `sudo ./install_mcp_service.sh`
- [ ] Firewall poort 3000 open (of SSH tunnel)
- [ ] MCP service draait: `sudo systemctl status netmonitor-mcp`
- [ ] Health check werkt: `curl http://soc.poort.net:3000/health`
- [ ] Claude Desktop config updated met SSE URL
- [ ] Claude Desktop herstart
- [ ] Test: "Show me the dashboard summary" werkt

---

## 🎯 Volgende Stappen

Na succesvolle setup:

1. **Experimenteer met queries:**
   - "What's the current threat situation?"
   - "Analyze IP 192.168.1.50"
   - "Show me port scans from the last hour"

2. **Overweeg SSL/TLS:**
   - Voor production gebruik
   - Self-signed certificate voor intern gebruik
   - Let's Encrypt voor publieke domains

3. **Monitoring:**
   - Check server logs regelmatig
   - Monitor resource gebruik
   - Set up alerting voor service failures

4. **Later: Ollama Integration:**
   - Ollama kan ook verbinden via SSE
   - 24/7 monitoring en automated alerting
   - Beide kunnen tegelijk verbinden!

---

## 🔐 Security Hardening (Optioneel)

### 1. API Key Authentication

Voeg authentication toe aan de MCP server:

```python
# In server.py
API_KEY = os.environ.get('MCP_API_KEY', 'your-secret-key')

async def handle_sse(request):
    # Check API key
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {API_KEY}":
        return Response("Unauthorized", status_code=401)
    # ... rest of handler
```

### 2. Rate Limiting

Prevent abuse:
```bash
# Install nginx as reverse proxy
sudo apt-get install nginx

# Configure rate limiting in nginx.conf
```

### 3. HTTPS met Self-Signed Certificate

```bash
# Generate certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/mcp-selfsigned.key \
  -out /etc/ssl/certs/mcp-selfsigned.crt

# Update server.py to use SSL context
```

---

**Veel succes met je netwerk setup! 🚀**

Voor vragen of problemen, check de logs op de server met `journalctl`.
