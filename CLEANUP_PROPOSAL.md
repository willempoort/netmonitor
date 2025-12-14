# NetMonitor Codebase Cleanup & Professionalisering

## Samenvatting Analyse

Na grondige analyse van de codebase zijn de volgende problemen geïdentificeerd:

### 🔴 Kritieke Issues

1. **Poort Inconsistentie**
   - Service draait op poort 8000 (gunicorn)
   - Documentatie en config.yaml vermelden poort 8080
   - Nginx configs wijzen naar poort 8080 (upstream netmonitor_dashboard)
   - **Status**: Dashboard werkt na reboot, dus draait op 8000
   - **Impact**: Verwarring en potentiële deployment failures

2. **Service File Verwarring**
   - `netmonitor.service` = Template met placeholders (NIET direct bruikbaar)
   - `netmonitor-gunicorn.service` = Actieve productie service
   - Onduidelijk welke service de dashboard start
   - Geen duidelijke documentatie over service architecture

3. **Documentatie Overload**
   - 33 markdown bestanden totaal
   - 22 markdown bestanden in root directory
   - Veel overlap en verouderde informatie
   - Geen master index of navigatie structuur

---

## 🎯 Voorgestelde Oplossingen

### Fase 1: Poort Standaardisatie (URGENT)

**Beslissing nodig:** Welke poort is de standaard?

**Optie A: Gebruik poort 8000 overal (AANBEVOLEN)**
- Gunicorn draait al op 8000
- Minder wijzigingen aan services
- MCP HTTP API gebruikt ook 8000 (maar via nginx /mcp path)

**Optie B: Gebruik poort 8080 overal**
- Consistent met oorspronkelijke documentatie
- Flask development server standaard
- Vereist wijzigingen aan gunicorn config en service

**Acties voor Optie A:**
```yaml
# config.yaml wijzigen
dashboard:
  port: 8000  # Was: 8080

# nginx configs updaten
upstream netmonitor_dashboard {
    server 127.0.0.1:8000;  # Was: 8080
}

# Alle documentatie updaten (README.md, DASHBOARD.md, etc.)
http://localhost:8000/kiosk  # Overal 8080 → 8000
```

**Acties voor Optie B:**
```python
# gunicorn_config.py
bind = "127.0.0.1:8080"  # Was: 8000

# netmonitor-gunicorn.service
--bind 127.0.0.1:8080 \  # Was: 8000

# wsgi.py
app.run(host='0.0.0.0', port=8080, debug=False)  # Was: 8000
```

---

### Fase 2: Documentatie Herstructurering

**Nieuwe Structuur:**

```
/netmonitor/
├── README.md                          # Quick start + links naar docs/
├── CHANGELOG.md                       # Version history
│
├── docs/                              # Alle documentatie hier
│   ├── INDEX.md                       # Master index van alle docs
│   │
│   ├── installation/                  # Installation guides
│   │   ├── QUICK_START.md            # Minimale setup (5 minuten)
│   │   ├── COMPLETE_INSTALLATION.md  # Volledige setup
│   │   ├── SERVICE_INSTALLATION.md   # Systemd services
│   │   ├── VENV_SETUP.md             # Python virtual env
│   │   └── SENSOR_DEPLOYMENT.md      # Remote sensors
│   │
│   ├── configuration/                 # Config guides
│   │   ├── CONFIG_GUIDE.md           # config.yaml reference
│   │   ├── ENV_CONFIGURATION.md      # Environment variables
│   │   ├── NGINX_SETUP.md            # Nginx configuratie
│   │   └── GUNICORN_SETUP.md         # Gunicorn configuratie
│   │
│   ├── usage/                         # Gebruikers handleidingen
│   │   ├── USER_MANUAL.md            # Eindgebruiker handleiding
│   │   ├── ADMIN_MANUAL.md           # Admin handleiding
│   │   ├── DASHBOARD.md              # Dashboard features
│   │   └── KIOSK_MODE.md             # Kiosk mode setup (nieuw)
│   │
│   ├── development/                   # Developer docs
│   │   ├── ARCHITECTURE.md           # System architecture (nieuw)
│   │   ├── DATABASE_SCHEMA.md        # Database design (nieuw)
│   │   ├── API_REFERENCE.md          # API endpoints (nieuw)
│   │   └── TESTING.md                # Test suite docs
│   │
│   ├── features/                      # Feature documentatie
│   │   ├── DETECTION_FEATURES.md     # Detection capabilities
│   │   ├── THREAT_FEEDS.md           # Threat intelligence
│   │   └── MCP_INTEGRATION.md        # AI integration
│   │
│   ├── troubleshooting/              # Problem solving
│   │   ├── COMMON_ISSUES.md          # FAQ (nieuw)
│   │   ├── DEBUGGING.md              # Debug procedures (nieuw)
│   │   └── PERFORMANCE.md            # Performance tuning (nieuw)
│   │
│   └── archived/                      # Verouderde docs
│       ├── legacy_stdio_mcp/
│       ├── old_installation_methods/
│       └── deprecated_features/
│
├── .claude/                           # Claude Code specifiek
│   ├── instructions.md
│   └── implementation-plans/
│       └── kiosk-mode-implementation-plan.md
│
└── scripts/                           # Install & utility scripts
    ├── install_complete.sh
    ├── install_services.sh
    └── setup/                         # Setup helpers
        ├── setup_http_api.sh
        └── setup_sensor_auth.py
```

**Te Archiveren Bestanden:**

```bash
# Verplaats naar docs/archived/
- MCP_NGINX_SETUP.md → docs/archived/legacy_stdio_mcp/
- mcp_server/legacy_stdio_sse/*.md → docs/archived/legacy_stdio_mcp/
- FIXES_TESTING.md → docs/archived/
- TEST_SUITE_SUMMARY.md → docs/development/TESTING.md (merge)

# Consolideren (merge meerdere docs)
- POSTGRESQL_SETUP.md + TIMESCALEDB_SETUP.md → docs/installation/DATABASE_SETUP.md
- PRODUCTION.md → docs/installation/PRODUCTION_DEPLOYMENT.md
- KIOSK-DEPLOYMENT.md → docs/usage/KIOSK_MODE.md
```

---

### Fase 3: Service Architecture Documentatie

**Nieuw bestand: docs/development/ARCHITECTURE.md**

Duidelijke uitleg van:

```
┌─────────────────────────────────────────────────────────────┐
│                    NetMonitor Architecture                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Nginx (Port 80/443)                                     │ │
│  │  - SSL Termination                                      │ │
│  │  - Reverse Proxy                                        │ │
│  │  - Static file serving                                  │ │
│  └──────┬────────────────────┬─────────────────────────────┘ │
│         │                    │                                │
│         ▼                    ▼                                │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Dashboard       │  │ MCP HTTP API    │                   │
│  │ (Port 8000)     │  │ (Port 8080)     │                   │
│  │                 │  │                 │                   │
│  │ Gunicorn        │  │ Uvicorn         │                   │
│  │  └─ Eventlet    │  │  └─ FastAPI     │                   │
│  │     workers     │  │                 │                   │
│  │  └─ SocketIO    │  │                 │                   │
│  │  └─ Flask app   │  │                 │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
│           │                    │                              │
│           └────────┬───────────┘                              │
│                    ▼                                          │
│         ┌─────────────────────┐                              │
│         │ SQLite Database     │                              │
│         │  - Sensors          │                              │
│         │  - Alerts           │                              │
│         │  - Metrics          │                              │
│         │  - Whitelist        │                              │
│         │  - Config           │                              │
│         └─────────────────────┘                              │
│                                                               │
└─────────────────────────────────────────────────────────────┘

Services (systemd):
├── netmonitor.service              # Main monitoring engine
├── netmonitor-gunicorn.service     # Web dashboard (Gunicorn)
├── netmonitor-mcp-http.service     # MCP HTTP API (Uvicorn)
└── netmonitor-feed-update.service  # Threat feed updates
```

---

### Fase 4: Nieuwe Master README

**Vereenvoudigde README.md:**

```markdown
# NetMonitor SOC - Security Operations Center

Professional network monitoring platform met real-time dashboard en AI integration.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/willempoort/netmonitor.git
cd netmonitor

# Install (automatic setup)
sudo bash install_complete.sh

# Access dashboard
https://soc.poort.net/
```

## 📚 Documentatie

**Voor nieuwe gebruikers:**
- [Quick Start Guide](docs/installation/QUICK_START.md) - 5 minuten setup
- [User Manual](docs/usage/USER_MANUAL.md) - Dashboard gebruik

**Voor administrators:**
- [Complete Installation](docs/installation/COMPLETE_INSTALLATION.md) - Volledige setup
- [Admin Manual](docs/usage/ADMIN_MANUAL.md) - Beheer & configuratie
- [Sensor Deployment](docs/installation/SENSOR_DEPLOYMENT.md) - Remote sensors

**Voor developers:**
- [Architecture](docs/development/ARCHITECTURE.md) - System design
- [API Reference](docs/development/API_REFERENCE.md) - REST API docs

**Alle documentatie:** [📖 Documentation Index](docs/INDEX.md)

## 🎯 Features

- ✅ Real-time web dashboard (Flask + SocketIO)
- ✅ Kiosk mode voor NOC displays
- ✅ AI integration via MCP HTTP API
- ✅ Remote sensor management
- ✅ Threat intelligence feeds
- ✅ Configuration as code

## 🔧 Architecture

```
Nginx → Gunicorn (Dashboard:8000) → SQLite
     └→ Uvicorn (MCP API:8080)    ↗
```

Zie [ARCHITECTURE.md](docs/development/ARCHITECTURE.md) voor details.

## 📦 Services

| Service | Poort | Beschrijving |
|---------|-------|--------------|
| Nginx | 80/443 | Reverse proxy + SSL |
| Dashboard | 8000 | Web UI (Gunicorn) |
| MCP API | 8080 | AI integration (Uvicorn) |

## 🐛 Troubleshooting

Zie [Common Issues](docs/troubleshooting/COMMON_ISSUES.md)

## 📝 License

MIT License - See LICENSE file
```

---

### Fase 5: Script Consolidatie

**Huidige scripts:**
- `install.sh` - Wat doet deze?
- `install_complete.sh` - Complete install
- `install_services.sh` - Service install

**Voorstel:**

```bash
scripts/
├── install.sh                 # Symlink → install_complete.sh
├── install_complete.sh        # Main installer (keep)
├── install_services.sh        # Service setup (keep)
│
├── setup/                     # Setup utilities
│   ├── setup_http_api.sh     # MCP HTTP API
│   ├── setup_nginx.sh        # Nginx config (nieuw)
│   ├── setup_ssl.sh          # SSL certificates (nieuw)
│   └── setup_sensor_auth.py  # Sensor tokens
│
├── utils/                     # Utility scripts (nieuw)
│   ├── check_services.sh     # Service health check
│   ├── backup_database.sh    # DB backup
│   └── update_feeds.sh       # Manual feed update
│
└── troubleshooting/          # Debug helpers (nieuw)
    ├── check_ports.sh        # Port conflicts
    ├── test_connectivity.sh  # Network tests
    └── collect_logs.sh       # Log collection
```

---

## 🎯 Implementatie Plan

### **Stap 1: Poort Fix (URGENT) - 30 minuten**

1. Besluit: Poort 8000 of 8080?
2. Update alle configs naar gekozen poort
3. Test lokaal: `curl http://localhost:POORT/kiosk`
4. Update nginx en reload
5. Test via nginx: `curl https://soc.poort.net/kiosk`

### **Stap 2: Documentatie Restructurering - 2 uur**

1. Create `docs/` directory structuur
2. Move bestanden naar juiste locaties
3. Create `docs/INDEX.md` master index
4. Update alle interne links
5. Archive legacy docs

### **Stap 3: README Vereenvoudiging - 30 minuten**

1. Backup huidige README.md
2. Create nieuwe simplified README
3. Ensure alle features gedocumenteerd in docs/
4. Add links naar relevante docs

### **Stap 4: Architecture Documentatie - 1 uur**

1. Create `docs/development/ARCHITECTURE.md`
2. Document service dependencies
3. Add port mapping table
4. Create system diagrams
5. Document database schema

### **Stap 5: Service Documentatie - 30 minuten**

1. Document elke systemd service
2. Add startup order
3. Add troubleshooting per service
4. Create service health check script

### **Stap 6: Testing & Validatie - 1 uur**

1. Test alle links in documentatie
2. Verify install scripts work
3. Test kiosk mode deployment
4. Update CHANGELOG.md

---

## 📊 Prioritering

| Taak | Priority | Impact | Effort |
|------|----------|--------|--------|
| Fix poort conflict | 🔴 URGENT | High | Low |
| Service documentatie | 🟡 High | High | Medium |
| Docs restructurering | 🟡 High | Medium | High |
| README simplificatie | 🟢 Medium | Medium | Low |
| Script consolidatie | 🟢 Low | Low | Medium |

---

## ✅ Succes Criteria

Na cleanup moet een nieuwe gebruiker:

1. **In 5 minuten** kunnen starten met Quick Start guide
2. **Duidelijk weten** welke poort de dashboard gebruikt
3. **Gemakkelijk vinden** welke documentatie ze nodig hebben
4. **Begrijpen** hoe de services samenwerken
5. **Troubleshooten** zonder code te moeten lezen

---

## 🤔 Vragen voor Beslissing

1. **Poort standaard:** 8000 of 8080? (Advies: 8000, minimal change)
2. **Legacy MCP docs:** Archiveren of verwijderen? (Advies: archiveren)
3. **Database migratie:** PostgreSQL docs behouden? (Advies: ja, in docs/installation/)
4. **Testing docs:** Merge in één document? (Advies: ja)

---

## 📝 Volgende Stappen

Wil je dat ik:

A. **Start met poort fix** - Los conflict nu op (30 min)
B. **Create docs structure** - Maak directory structuur en INDEX.md (1 uur)
C. **Generate ARCHITECTURE.md** - Volledige system documentatie (1 uur)
D. **All of the above** - Complete cleanup in één keer (4-5 uur)

Of heb je andere prioriteiten?
