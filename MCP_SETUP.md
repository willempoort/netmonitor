# NetMonitor MCP Server - Setup Guide

## ⚠️ BELANGRIJK: Kies Eerst Je Setup

### 🌐 Netwerk Setup (Mac → Linux Server)

**Als je Claude Desktop op een ANDERE machine draait dan waar NetMonitor staat:**

➡️ **Gebruik: [MCP_NETWORK_SETUP.md](MCP_NETWORK_SETUP.md)**

Bijvoorbeeld:
- Claude Desktop op **Mac** ← jouw situatie!
- NetMonitor op **Linux server** (soc.poort.net)

Dit vereist **SSE/HTTP transport** over het netwerk.

---

### 💻 Lokale Setup (Alles op 1 Machine)

**Als Claude Desktop en NetMonitor op DEZELFDE machine draaien:**

➡️ **Gebruik deze guide hieronder**

Bijvoorbeeld:
- Alles op Linux
- Alles op Mac
- Alles op Windows

Dit gebruikt **stdio transport** (lokaal proces).

---

## ⚠️ BELANGRIJK: Paths in deze Documentatie

In de voorbeelden hieronder gebruik ik `/home/user/netmonitor` als voorbeeld pad.

**Vervang dit met jouw eigen NetMonitor installatie pad!**

De installatie scripts (`install_mcp_service.sh` en `setup_mcp_user.sh`) detecteren automatisch de correcte directory, dus je hoeft geen paths aan te passen als je deze scripts gebruikt.

---

# Lokale Setup Guide

Er zijn **twee manieren** om de MCP server lokaal te gebruiken:

1. **Claude Desktop Managed** (Aanbevolen) - Automatisch beheerd door Claude Desktop
2. **Always-On Service** (Voor 24/7 Ollama monitoring) - Draait altijd als systemd service

---

## 🎯 Scenario 1: Claude Desktop Managed (AANBEVOLEN)

**Wanneer gebruiken:**
- Je gebruikt Claude Desktop voor incident investigation
- Je wilt de server alleen tijdens gebruik draaien
- Je hebt geen 24/7 monitoring nodig (nog niet)

**Voordelen:**
- ✅ Automatisch beheerd door Claude Desktop
- ✅ Start/stop automatisch
- ✅ Geen systemd service nodig
- ✅ Simpelste setup

### Setup Stappen:

#### Stap 1: Configureer Claude Desktop

**Voor Linux:**
```bash
# Maak config directory
mkdir -p ~/.config/Claude

# Maak config file
nano ~/.config/Claude/claude_desktop_config.json
```

**Plak deze inhoud:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": [
        "/home/user/netmonitor/mcp_server/server.py"
      ],
      "env": {
        "NETMONITOR_DB_HOST": "localhost",
        "NETMONITOR_DB_PORT": "5432",
        "NETMONITOR_DB_NAME": "netmonitor",
        "NETMONITOR_DB_USER": "mcp_readonly",
        "NETMONITOR_DB_PASSWORD": "mcp_netmonitor_readonly_2024"
      }
    }
  }
}
```

**Sla op:** Ctrl+O, Enter, Ctrl+X

#### Stap 2: Herstart Claude Desktop

Sluit Claude Desktop volledig af en start opnieuw.

#### Stap 3: Test

Open Claude Desktop en typ:
```
Show me the dashboard summary
```

Als het werkt zie je security statistieken!

### Verificatie:

**Check of MCP server geladen is:**
```
What MCP servers are available?
```

Je zou "netmonitor-soc" moeten zien.

**Test een tool:**
```
Get recent threats from the last hour
```

### Troubleshooting Scenario 1:

**Probleem: MCP server wordt niet geladen**

1. Check config file locatie:
```bash
cat ~/.config/Claude/claude_desktop_config.json
```

2. Check JSON syntax (moet valid zijn):
```bash
python3 -m json.tool ~/.config/Claude/claude_desktop_config.json
```

3. Check MCP server logs:
```bash
tail -f /tmp/mcp_netmonitor.log
```

4. Check database connectie:
```bash
PGPASSWORD='mcp_netmonitor_readonly_2024' \
  psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'
```

**Probleem: "Connection refused" errors**

PostgreSQL moet draaien en luisteren op localhost:
```bash
sudo systemctl status postgresql
sudo netstat -tlnp | grep 5432
```

---

## 🚀 Scenario 2: Always-On Service (OPTIONEEL)

**Wanneer gebruiken:**
- Je wilt 24/7 monitoring met Ollama (later)
- Je wilt de MCP server altijd beschikbaar hebben
- Je wilt niet afhankelijk zijn van Claude Desktop

**Voordelen:**
- ✅ Always-on (ook na reboot)
- ✅ Systemd beheerd (auto-restart bij crash)
- ✅ Centraal logging via journald
- ✅ Klaar voor Ollama integration

**Nadelen:**
- ❌ Complexer
- ❌ Gebruikt resources ook als niet in gebruik
- ❌ Nog niet nodig voor basis Claude Desktop gebruik

### Setup Stappen:

#### Stap 1: Installeer de service

```bash
cd /home/user/netmonitor
chmod +x install_mcp_service.sh
sudo ./install_mcp_service.sh
```

Dit script:
- Kopieert service file naar `/etc/systemd/system/`
- Enabled de service (auto-start bij boot)
- Start de service

#### Stap 2: Verificatie

**Check service status:**
```bash
sudo systemctl status netmonitor-mcp
```

Je zou "active (running)" moeten zien.

**Check logs:**
```bash
sudo journalctl -u netmonitor-mcp -f
```

Je zou "NetMonitor MCP Server initialized" moeten zien.

#### Stap 3: Test na reboot

```bash
sudo reboot
```

Na reboot:
```bash
sudo systemctl status netmonitor-mcp
```

Service zou automatisch moeten draaien!

### Service Management:

**Start:**
```bash
sudo systemctl start netmonitor-mcp
```

**Stop:**
```bash
sudo systemctl stop netmonitor-mcp
```

**Restart:**
```bash
sudo systemctl restart netmonitor-mcp
```

**Status:**
```bash
sudo systemctl status netmonitor-mcp
```

**Enable (auto-start bij boot):**
```bash
sudo systemctl enable netmonitor-mcp
```

**Disable (geen auto-start):**
```bash
sudo systemctl disable netmonitor-mcp
```

**Logs bekijken:**
```bash
# Live logs (follow)
sudo journalctl -u netmonitor-mcp -f

# Laatste 100 regels
sudo journalctl -u netmonitor-mcp -n 100

# Sinds vandaag
sudo journalctl -u netmonitor-mcp --since today

# Errors only
sudo journalctl -u netmonitor-mcp -p err
```

### Troubleshooting Scenario 2:

**Probleem: Service start niet**

1. Check service status details:
```bash
sudo systemctl status netmonitor-mcp -l
```

2. Check journald logs:
```bash
sudo journalctl -u netmonitor-mcp -n 50
```

3. Test handmatig:
```bash
cd /home/user/netmonitor/mcp_server
export NETMONITOR_DB_HOST=localhost
export NETMONITOR_DB_USER=mcp_readonly
export NETMONITOR_DB_PASSWORD=mcp_netmonitor_readonly_2024
export NETMONITOR_DB_NAME=netmonitor
python3 server.py
```

**Probleem: Service crasht steeds**

Check dependencies:
```bash
pip3 list | grep mcp
pip3 list | grep psycopg2
```

Herinstalleer indien nodig:
```bash
cd /home/user/netmonitor/mcp_server
pip3 install -r requirements.txt --user
```

**Probleem: Database connectie errors**

Check PostgreSQL:
```bash
sudo systemctl status postgresql
```

Test connectie:
```bash
PGPASSWORD='mcp_netmonitor_readonly_2024' \
  psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT 1;'
```

---

## 📊 Welke Setup Moet Ik Kiezen?

### Kies Scenario 1 (Claude Desktop Managed) als:
- ✅ Je Claude Desktop gebruikt voor security analysis
- ✅ Je geen 24/7 monitoring nodig hebt (nog niet)
- ✅ Je de simpelste setup wilt
- ✅ **Je bent net begonnen** ← DIT IS JOU!

### Kies Scenario 2 (Always-On Service) als:
- ✅ Je Ollama 24/7 monitoring wilt (later)
- ✅ Je de MCP server altijd beschikbaar wilt
- ✅ Je meerdere clients wilt verbinden
- ✅ Je centraal logging wilt

**Advies:** Start met **Scenario 1**. Je kunt later altijd upgraden naar Scenario 2 voor Ollama!

---

## 🔄 Upgraden van Scenario 1 naar 2

Als je later naar always-on wilt:

1. **Installeer de service:**
```bash
sudo /home/user/netmonitor/install_mcp_service.sh
```

2. **Claude Desktop blijft werken!**
   - Claude Desktop kan nog steeds zijn eigen MCP server instance starten
   - Of je kunt Claude Desktop configureren om te verbinden met de running service

3. **Ollama connecteren:**
   - Ollama kan verbinden met de always-on service
   - Geen conflicten met Claude Desktop

---

## ✅ Quick Start Checklist

**Voor nu (Scenario 1):**

- [ ] Claude Desktop geïnstalleerd
- [ ] Config file aangemaakt: `~/.config/Claude/claude_desktop_config.json`
- [ ] Config file bevat correcte MCP server configuratie
- [ ] Claude Desktop herstart
- [ ] Test: "Show me the dashboard summary" werkt
- [ ] Test: "Get recent threats" werkt

**Later (Scenario 2, optioneel):**

- [ ] Service geïnstalleerd met `install_mcp_service.sh`
- [ ] Service enabled: `sudo systemctl enable netmonitor-mcp`
- [ ] Service draait: `sudo systemctl status netmonitor-mcp`
- [ ] Auto-start getest na reboot

---

## 🆘 Nog Steeds Problemen?

1. **Check alle logs:**
```bash
# MCP server logs
tail -f /tmp/mcp_netmonitor.log

# Als service draait:
sudo journalctl -u netmonitor-mcp -f

# NetMonitor service logs
sudo journalctl -u netmonitor -f

# PostgreSQL logs
sudo journalctl -u postgresql -f
```

2. **Test elke component apart:**
```bash
# PostgreSQL
sudo systemctl status postgresql

# Database connectie
PGPASSWORD='mcp_netmonitor_readonly_2024' \
  psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'

# Python dependencies
pip3 list | grep -E 'mcp|psycopg2'

# MCP server handmatig
cd /home/user/netmonitor/mcp_server
python3 server.py
```

3. **Lees de uitgebreide docs:**
- `mcp_server/README.md` - Gebruik voorbeelden
- `mcp_server/INSTALLATION.md` - Gedetailleerde installatie

---

## 🎯 Volgende Stappen

Na succesvolle setup:

1. **Experimenteer met Claude Desktop**
   - "What's the current threat situation?"
   - "Analyze IP 192.168.1.50"
   - "Show me the attack timeline from suspicious IPs"

2. **Genereer wat test traffic**
   - Run een nmap scan
   - Check hoe Claude de data analyseert

3. **Geef feedback**
   - Wat werkt goed?
   - Welke features wil je nog meer?

4. **Later: Ollama 24/7 monitoring**
   - Upgrade naar Scenario 2
   - Configureer Ollama
   - Automated alerting!

---

**Veel succes! 🚀**
