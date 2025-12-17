# NetMonitor Service Installation Guide

## 📦 NetMonitor Componenten

NetMonitor bestaat uit **drie hoofdcomponenten**, elk met hun eigen systemd service:

### 1. **NetMonitor Main** (`netmonitor.service`)
- Packet sniffer en threat detector
- Detecteert: port scans, beaconing, connection floods, etc.
- Draait continu als daemon
- Schrijft alerts naar PostgreSQL database

### 2. **Feed Update** (`netmonitor-feed-update.service` + `.timer`)
- Update threat intelligence feeds (Tor exit nodes, malware IPs, etc.)
- Draait elk uur via systemd timer
- Type: oneshot (draait taak en stopt)

### 3. **MCP Server** (`netmonitor-mcp.service`)
- AI interface via Model Context Protocol
- Geeft Claude Desktop/Ollama toegang tot security data
- HTTP/SSE server op poort 3000
- Optioneel - alleen nodig voor AI integratie

---

## ⚠️ BELANGRIJK: Virtual Environment Vereist!

**Alle services gebruiken dezelfde Python virtual environment.**

Voordat je services installeert, moet je eerst de venv maken:

```bash
cd /path/to/netmonitor
./setup_venv.sh
```

Zie [VENV_SETUP.md](VENV_SETUP.md) voor details.

---

## 🚀 Installatie Methoden

### Methode 1: Alle Services Tegelijk (Aanbevolen)

Het **nieuwe** unified install script installeert alle services in één keer:

```bash
cd /path/to/netmonitor
sudo ./install_services.sh
```

**Wat het script doet:**
1. Checkt of venv bestaat (maakt aan indien nodig)
2. Valideert dat alle Python scripts aanwezig zijn
3. Genereert service files met correcte paths en venv Python
4. Vraagt per service of je deze wilt enablen/starten
5. Toont status van alle services

**Interactief:**
```
Enable and start netmonitor.service? (Y/n): y
Enable and start netmonitor-feed-update.timer? (Y/n): y
Enable and start netmonitor-mcp.service? (Y/n): n  # Skip MCP if not needed
```

### Methode 2: Alleen MCP Server (Backwards Compatible)

Voor alleen de MCP server (oude methode):

```bash
sudo ./install_mcp_service.sh
```

---

## 📋 Service Management

### NetMonitor Main Service

```bash
# Start/Stop
sudo systemctl start netmonitor
sudo systemctl stop netmonitor
sudo systemctl restart netmonitor

# Status en logs
sudo systemctl status netmonitor
sudo journalctl -u netmonitor -f

# Enable/Disable auto-start
sudo systemctl enable netmonitor   # Start bij boot
sudo systemctl disable netmonitor  # Niet auto-start
```

### Feed Update (Timer)

```bash
# Timer management
sudo systemctl start netmonitor-feed-update.timer
sudo systemctl stop netmonitor-feed-update.timer
sudo systemctl status netmonitor-feed-update.timer

# Manual feed update (buiten timer om)
sudo systemctl start netmonitor-feed-update.service

# Logs
sudo journalctl -u netmonitor-feed-update -f

# Check wanneer volgende update is
systemctl list-timers netmonitor-feed-update.timer
```

### MCP Server

```bash
# Start/Stop
sudo systemctl start netmonitor-mcp
sudo systemctl stop netmonitor-mcp
sudo systemctl restart netmonitor-mcp

# Status en logs
sudo systemctl status netmonitor-mcp
sudo journalctl -u netmonitor-mcp -f

# Test health endpoint
curl http://localhost:3000/health

# Enable/Disable auto-start
sudo systemctl enable netmonitor-mcp
sudo systemctl disable netmonitor-mcp
```

### Alle Services Tegelijk

```bash
# Status overview
sudo systemctl status netmonitor netmonitor-feed-update.timer netmonitor-mcp

# Stop alles
sudo systemctl stop netmonitor netmonitor-feed-update.timer netmonitor-mcp

# Start alles
sudo systemctl start netmonitor netmonitor-feed-update.timer netmonitor-mcp

# Restart alles
sudo systemctl restart netmonitor netmonitor-mcp

# Logs van alles
sudo journalctl -u netmonitor -u netmonitor-feed-update -u netmonitor-mcp -f
```

---

## 🔍 Troubleshooting

### Service start niet

**Check logs:**
```bash
sudo journalctl -u <service-name> -n 50
```

**Veelvoorkomende oorzaken:**

1. **Module not found error**
   - Oorzaak: Service gebruikt niet de venv Python
   - Oplossing: Herinstall services met `./install_services.sh`
   - Check: `systemctl cat <service> | grep ExecStart` moet venv path tonen

2. **Permission denied**
   - Oorzaak: User root heeft geen rechten op files
   - Oplossing: Check file ownership: `ls -la /path/to/netmonitor/*.py`

3. **Database connection failed** (alleen netmonitor en mcp)
   - Oorzaak: PostgreSQL draait niet of is niet bereikbaar
   - Oplossing: `sudo systemctl start postgresql`

4. **Port already in use** (alleen netmonitor-mcp)
   - Oorzaak: Poort 3000 al in gebruik
   - Check: `sudo netstat -tlnp | grep 3000`
   - Oplossing: Stop andere proces of wijzig poort in service file

### Venv probleem na system update

Als Python versie wijzigt na system update:

```bash
# Recreate venv
rm -rf venv/
./setup_venv.sh

# Reinstall all services
sudo ./install_services.sh
```

### Service gebruikt oude Python

Check welke Python gebruikt wordt:

```bash
systemctl cat netmonitor.service | grep ExecStart
```

Moet tonen: `/path/to/netmonitor/venv/bin/python3`

Als het `/usr/bin/python3` toont:
```bash
sudo ./install_services.sh  # Herinstall met correcte venv
```

---

## 🔄 Update Workflow

Als je NetMonitor code update (git pull, wijzigingen, etc.):

### Python code wijzigingen
```bash
# Restart alleen de betreffende service
sudo systemctl restart netmonitor
# of
sudo systemctl restart netmonitor-mcp
```

### Nieuwe Python dependencies
```bash
# Update venv
source venv/bin/activate
pip install nieuwe-package

# Restart services
sudo systemctl restart netmonitor netmonitor-mcp
```

### Service file wijzigingen
```bash
# Herinstall services
sudo ./install_services.sh

# Of handmatig:
sudo systemctl daemon-reload
sudo systemctl restart <service-name>
```

---

## 📊 Monitoring

### Check of alles draait

```bash
# Quick check
sudo systemctl is-active netmonitor
sudo systemctl is-active netmonitor-feed-update.timer
sudo systemctl is-active netmonitor-mcp

# Detailed status
sudo systemctl status netmonitor netmonitor-feed-update.timer netmonitor-mcp
```

### Live logs (alle services)

```bash
# Terminal 1: Main monitor
sudo journalctl -u netmonitor -f

# Terminal 2: Feed updates
sudo journalctl -u netmonitor-feed-update -f

# Terminal 3: MCP server
sudo journalctl -u netmonitor-mcp -f
```

### Check recent alerts

```bash
# Via database
psql -U netmonitor -d netmonitor -c "SELECT timestamp, threat_type, severity, source_ip FROM alerts ORDER BY timestamp DESC LIMIT 10;"

# Via dashboard
curl http://localhost:5000/api/threats/recent
```

---

## 🎯 Common Scenarios

### Scenario 1: Fresh Installation

```bash
# 1. Setup venv
./setup_venv.sh

# 2. Install all services
sudo ./install_services.sh
# → Enable alle drie services

# 3. Check status
sudo systemctl status netmonitor netmonitor-feed-update.timer netmonitor-mcp
```

### Scenario 2: Only Main Monitor (No AI)

```bash
# 1. Setup venv
./setup_venv.sh

# 2. Install services
sudo ./install_services.sh
# → Enable netmonitor: Y
# → Enable feed-update: Y
# → Enable mcp: N

# 3. MCP service bestaat maar is disabled
sudo systemctl list-unit-files | grep netmonitor
```

### Scenario 3: Add MCP Later

```bash
# MCP service al geïnstalleerd maar disabled
sudo systemctl enable netmonitor-mcp
sudo systemctl start netmonitor-mcp

# Of herinstall als venv niet bestaat was tijdens install
sudo ./install_services.sh
```

### Scenario 4: Development Setup

Als je NetMonitor in development draait (niet als service):

```bash
# Start services handmatig met venv
source venv/bin/activate

# Terminal 1: Main monitor
python3 netmonitor.py

# Terminal 2: Dashboard
python3 -m flask --app web.app run

# Terminal 3: MCP server (voor testing)
cd mcp_server
python3 server.py --transport sse --host 0.0.0.0 --port 3000

# Services zijn NIET nodig voor development
```

---

## 🆚 Old vs New Installation

### Oude Methode (Voor venv update)

```bash
# Elk service apart
sudo cp netmonitor.service /etc/systemd/system/
sudo cp netmonitor-feed-update.service /etc/systemd/system/
sudo cp netmonitor-feed-update.timer /etc/systemd/system/
sudo cp netmonitor-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmonitor
# etc...

# Probleem: Hardcoded paths, system Python
```

### Nieuwe Methode (Met venv)

```bash
# Unified script
sudo ./install_services.sh

# Voordelen:
# ✅ Automatische venv detectie
# ✅ Dynamische paths
# ✅ Interactieve setup
# ✅ Validatie van files
# ✅ Alle services in één keer
```

---

## 📝 Service File Locaties

Na installatie:

```
/etc/systemd/system/
├── netmonitor.service                    # Main monitor
├── netmonitor-feed-update.service        # Feed update
├── netmonitor-feed-update.timer          # Feed update timer
└── netmonitor-mcp.service                # MCP server
```

**BELANGRIJK:** Dit zijn gegenereerde files! Wijzig deze niet direct.

Om wijzigingen aan te brengen:
1. Wijzig de template files in de NetMonitor directory
2. Run `sudo ./install_services.sh` opnieuw

---

## 🔒 Security Notes

### Service User

Alle services draaien als `User=root` omdat:
- NetMonitor main heeft raw socket access nodig (packet capture)
- Consistent met andere system monitoring tools

### Security Hardening (netmonitor.service)

```
NoNewPrivileges=true   # Kan geen extra privileges krijgen
PrivateTmp=true        # Geïsoleerde /tmp directory
```

### Database Credentials (MCP)

MCP service heeft read-only database access via:
- User: `mcp_readonly`
- Password: in environment variable (visible in service file)

Voor production: overweeg systemd credential system of secrets management.

---

## ✅ Installation Checklist

- [ ] Virtual environment gemaakt: `./setup_venv.sh`
- [ ] Verified venv heeft MCP: `venv/bin/python3 -c "import mcp"`
- [ ] Services geïnstalleerd: `sudo ./install_services.sh`
- [ ] Main monitor draait: `systemctl is-active netmonitor`
- [ ] Feed timer actief: `systemctl is-active netmonitor-feed-update.timer`
- [ ] MCP server draait (indien enabled): `systemctl is-active netmonitor-mcp`
- [ ] MCP health check OK: `curl http://localhost:3000/health`
- [ ] Logs zijn clean: `journalctl -u netmonitor -n 20` geen errors
- [ ] Services enabled voor auto-start: `systemctl is-enabled <service>`

---

**Alle services gebruiken nu de venv - één unified Python environment! 🎉**
