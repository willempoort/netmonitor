# Python Virtual Environment Setup voor NetMonitor

## 🤔 Waarom een Virtual Environment?

Je hebt ontdekt dat MCP (Model Context Protocol) niet beschikbaar is via apt-get. Dit is normaal - veel Python packages zijn alleen via pip beschikbaar.

**Het probleem met system-wide pip:**
- `pip install` vereist vaak root rechten
- Kan conflicteren met system packages
- Moeilijk om dependencies te isoleren
- Services kunnen verkeerde versies gebruiken

**De oplossing: Virtual Environment (venv)**
- ✅ Geïsoleerde Python environment per project
- ✅ Geen root rechten nodig voor package installatie
- ✅ Geen conflicts met system packages
- ✅ Reproduceerbare dependency versies
- ✅ Services gebruiken altijd de juiste versies

---

## 🚀 Quick Start

### Stap 1: Maak de Virtual Environment

```bash
cd /path/to/netmonitor
./setup_venv.sh
```

Dit script:
1. Maakt een venv in `./venv/`
2. Installeert alle NetMonitor dependencies
3. Installeert MCP en dependencies voor de MCP server
4. Maakt een helper script `activate_venv.sh`

**Duur:** ~1-2 minuten (afhankelijk van internet snelheid)

### Stap 2: Installeer de MCP Service

```bash
sudo ./install_mcp_service.sh
```

Het install script:
- Detecteert automatisch de venv
- Biedt aan om venv te maken als deze niet bestaat
- Gebruikt de venv Python in de systemd service

### Stap 3: Verificatie

```bash
# Check service status
sudo systemctl status netmonitor-mcp

# Test MCP server
source venv/bin/activate
cd mcp_server
python3 server.py --help
```

---

## 📚 Virtual Environment Gebruik

### Activeren

**Voor development/testing:**
```bash
cd /path/to/netmonitor
source venv/bin/activate
# Nu gebruik je de venv Python
```

Of gebruik de helper:
```bash
source activate_venv.sh
```

Je ziet nu `(venv)` in je prompt:
```
(venv) user@host:~/netmonitor$
```

### Deactiveren

```bash
deactivate
```

### Packages Installeren

**Altijd binnen geactiveerde venv:**
```bash
source venv/bin/activate
pip install package-name
```

### Packages Verwijderen

```bash
source venv/bin/activate
pip uninstall package-name
```

### Lijst van Geïnstalleerde Packages

```bash
source venv/bin/activate
pip list
```

---

## 🔧 Troubleshooting

### Probleem: "mcp module not found"

**Oorzaak:** Je draait Python buiten de venv.

**Oplossing:**
```bash
# Check welke Python je gebruikt
which python3

# Zou moeten zijn: /path/to/netmonitor/venv/bin/python3
# Als het /usr/bin/python3 is, activeer dan de venv:
source venv/bin/activate
```

### Probleem: "Permission denied" tijdens setup

**Oorzaak:** Mogelijk een rechten probleem.

**Oplossing:**
```bash
# Run als normale user (NIET met sudo):
./setup_venv.sh

# Als de directory root ownership heeft:
sudo chown -R $USER:$USER /path/to/netmonitor
./setup_venv.sh
```

### Probleem: Service start niet

**Check logs:**
```bash
sudo journalctl -u netmonitor-mcp -n 50
```

**Veelvoorkomende oorzaken:**
1. Venv Python path incorrect in service file
2. Dependencies niet geïnstalleerd in venv
3. Database niet bereikbaar

**Oplossing:**
```bash
# Recreate venv
rm -rf venv/
./setup_venv.sh

# Reinstall service
sudo ./install_mcp_service.sh
sudo systemctl restart netmonitor-mcp
```

### Probleem: Venv werkt niet na system upgrade

**Oorzaak:** Python versie gewijzigd na system update.

**Oplossing:**
```bash
# Recreate venv met nieuwe Python
rm -rf venv/
./setup_venv.sh
sudo ./install_mcp_service.sh  # Reinstall service
```

---

## 🔍 Wat zit er in de venv?

### Core Dependencies (voor NetMonitor)
- `scapy` - Packet capturing en analyse
- `psycopg2-binary` - PostgreSQL database connector
- `flask` - Web framework voor dashboard
- `python-dateutil` - Date/time utilities

### MCP Server Dependencies
- `mcp>=1.0.0` - Model Context Protocol library
- `starlette` - ASGI web framework
- `uvicorn` - ASGI server
- `sse-starlette` - Server-Sent Events support

### Zie volledige lijst:
```bash
source venv/bin/activate
pip list
```

---

## 🗂️ Directory Structuur

```
netmonitor/
├── venv/                          # Virtual environment (DEZE NIET COMMITTEN)
│   ├── bin/
│   │   ├── python3               # Venv Python executable
│   │   ├── pip                   # Venv pip
│   │   └── activate              # Activation script
│   ├── lib/
│   │   └── python3.x/
│   │       └── site-packages/    # Installed packages
│   └── ...
├── setup_venv.sh                 # Setup script
├── activate_venv.sh              # Helper activation script
├── install_mcp_service.sh        # Service installer (uses venv)
└── ...
```

---

## 🎯 Best Practices

### DO ✅

1. **Activeer venv voor development:**
   ```bash
   source venv/bin/activate
   python3 script.py
   ```

2. **Gebruik venv Python voor manual testing:**
   ```bash
   venv/bin/python3 mcp_server/server.py --help
   ```

3. **Update requirements bij nieuwe dependencies:**
   ```bash
   source venv/bin/activate
   pip freeze > mcp_server/requirements.txt
   ```

4. **Voeg venv toe aan .gitignore:**
   ```
   venv/
   __pycache__/
   *.pyc
   ```

### DON'T ❌

1. **Niet venv committen naar git** - te groot, niet portable
2. **Niet global pip gebruiken** - kan system breken
3. **Niet sudo pip gebruiken** - security risk
4. **Niet apt en pip mixen** - dependency conflicts

---

## 🆚 Alternatieven (waarom we venv kiezen)

### pipx (jouw eerdere aanpak)
- ✅ Goed voor: CLI applicaties (zoals ansible, poetry)
- ❌ Slecht voor: Libraries die je importeert
- ❌ Problem: MCP is een library, geen applicatie

### apt-get python3-*
- ✅ Goed voor: System-level dependencies
- ❌ Slecht voor: Nieuwste versies (vaak outdated)
- ❌ Problem: MCP niet beschikbaar

### venv (onze keuze)
- ✅ Goed voor: Project-specific dependencies
- ✅ Werkt altijd met pip packages
- ✅ Geen root rechten nodig
- ✅ Services kunnen venv gebruiken
- ✅ Industry standard

### Docker (overkill voor deze use case)
- ✅ Ultieme isolatie
- ❌ Meer overhead
- ❌ Complexer setup
- ❌ Niet nodig voor dit project

---

## 📖 Meer Informatie

**Python venv documentatie:**
https://docs.python.org/3/library/venv.html

**Pip gebruikers guide:**
https://pip.pypa.io/en/stable/user_guide/

**Python packaging:**
https://packaging.python.org/

---

## ✅ Checklist

Gebruik deze checklist om te verifiëren dat alles correct is ingesteld:

- [ ] Venv gemaakt: `./setup_venv.sh` uitgevoerd zonder errors
- [ ] Venv bevat MCP: `venv/bin/python3 -c "import mcp; print('OK')"`
- [ ] Service gebruikt venv: `systemctl cat netmonitor-mcp | grep ExecStart` toont venv path
- [ ] Service draait: `systemctl status netmonitor-mcp` toont "active (running)"
- [ ] MCP server reageert: `curl http://localhost:3000/health` returns "OK"
- [ ] Logs zijn clean: `journalctl -u netmonitor-mcp -n 20` geen errors

---

**Klaar! Je NetMonitor gebruikt nu een proper geïsoleerde Python environment.** 🎉
