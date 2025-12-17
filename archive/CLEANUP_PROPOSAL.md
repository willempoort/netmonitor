# NetMonitor Professionalisering & Cleanup Voorstel (HERZIEN)

---

## ✅ COMPLETION STATUS (December 2024)

**Dit document is gearchiveerd omdat de voorgestelde verbeteringen grotendeels zijn geïmplementeerd.**

### Wat is Afgerond: ✅

1. **✅ Service Architectuur Standaardisatie**
   - Template-based service generation: `services/*.service.template`
   - Environment variable based configuratie via `.env`
   - `install_services.sh` genereert services vanuit templates
   - Gunicorn implementatie **VOLLEDIG KLAAR**:
     - `wsgi.py` - WSGI entry point
     - `gunicorn_config.py` - Production configuratie
     - `netmonitor-dashboard.service.template` - Systemd service
     - `DASHBOARD_SERVER=embedded|gunicorn` switch in `.env`

2. **✅ Poort Allocatie Fix**
   - Dashboard standaard: 8080 (configureerbaar via `.env`)
   - MCP API standaard: 8000 (configureerbaar via `.env`)
   - Geen hardcoded poorten meer in service files
   - Alle poorten via environment variables

3. **✅ Environment Variable Standaardisatie**
   - Complete `.env.example` met alle variabelen
   - `EnvironmentFile=` directive in alle service templates
   - Consistent gebruik van `${VARIABLE:-default}` syntax
   - Alle paths, poorten, en configuratie via `.env`

4. **✅ Documentatie Restructurering**
   - Alle `.md` bestanden verplaatst naar `docs/` subdirectories:
     - `docs/installation/` - Setup en installatie guides
     - `docs/usage/` - User en admin manuals
     - `docs/deployment/` - Production deployment
     - `docs/features/` - Feature documentatie
     - `docs/testing/` - Test documentatie
     - `docs/architecture/` - Architectuur documentatie
   - `README.md` blijft in root als entry point
   - Overzichtelijke structuur per topic

5. **✅ Dashboard Server Keuze Gedocumenteerd**
   - Nieuw document: `docs/deployment/DASHBOARD_SERVER_COMPARISON.md`
   - Embedded Flask vs Gunicorn comparison
   - Performance metrics
   - Use case recommendations
   - Migration guide
   - **AANBEVELING: Gunicorn voor productie, Embedded voor development**

### Wat Niet Nodig Was: ℹ️

1. **Database Migration Scripts**
   - Geen schema changes nodig
   - Bestaande update mechanisme werkt prima
   - `init_database_defaults.py` handelt updates af

2. **Nginx Template Generation**
   - Bestaande nginx configs werken met standaard poorten
   - Handmatige configuratie geeft meer flexibiliteit
   - Documentatie is voldoende

### Implementatie Details:

**Hoe te Switchen naar Gunicorn:**
```bash
# 1. Edit .env
cd /opt/netmonitor
sudo nano .env
# Change: DASHBOARD_SERVER=gunicorn

# 2. Regenereer services
sudo ./install_services.sh

# 3. Restart
sudo systemctl stop netmonitor
sudo systemctl start netmonitor
sudo systemctl start netmonitor-dashboard
sudo systemctl enable netmonitor-dashboard
```

**Documentatie:**
- **Comparison Guide:** `docs/deployment/DASHBOARD_SERVER_COMPARISON.md`
- **Installation:** `docs/installation/COMPLETE_INSTALLATION.md`
- **Service Management:** `docs/installation/SERVICE_INSTALLATION.md`

---

## 🔍 Werkelijke Architectuur (Na Correcte Analyse)

### **Service Architectuur:**

```
┌─────────────────────────────────────────────────────────────┐
│                    NetMonitor Services                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. netmonitor.service (PRIMAIR)                             │
│     └─> Start: netmonitor.py                                 │
│         └─> Importeert DashboardServer from web_dashboard    │
│             └─> Start Flask in thread (poort uit config)     │
│                                                               │
│  2. netmonitor-gunicorn.service (ALTERNATIEF?)               │
│     └─> Start: gunicorn wsgi:application                     │
│         └─> Hardcoded poort 8000                             │
│         └─> Requires: netmonitor.service                     │
│         └─> Status: Mogelijk NIET in gebruik ❓              │
│                                                               │
│  3. netmonitor-mcp-http.service (AI INTEGRATION)             │
│     └─> Dynamisch aangemaakt door setup_http_api.sh         │
│         └─> Start: http_server.py                            │
│         └─> Hardcoded poort 8000 ⚠️ CONFLICT!               │
│         └─> PostgreSQL based                                 │
│                                                               │
│  4. netmonitor-feed-update.service                           │
│     └─> Threat feed updates                                  │
│                                                               │
│  5. netmonitor-sensor.service (REMOTE SENSORS)               │
│     └─> Start: sensor_client.py                              │
│         └─> Hardcoded /opt/netmonitor ✅                     │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔴 Kritieke Problemen Geïdentificeerd

### **1. POORT CONFLICT (8000)**

Twee services willen beide poort 8000:

```bash
# netmonitor-gunicorn.service (regel 23)
--bind 127.0.0.1:8000

# netmonitor-mcp-http.service (setup_http_api.sh regel 182)
ExecStart=$PYTHON $SCRIPT_DIR/http_server.py --host 0.0.0.0 --port 8000
```

**Impact:** Deze services kunnen NIET tegelijk draaien!

### **2. Geen Consistente .env Gebruik**

**.env.example heeft:**
```bash
DASHBOARD_PORT=8080
INSTALL_DIR=/opt/netmonitor
```

**Maar service files gebruiken:**
- Hardcoded poorten (8000)
- Hardcoded paths (/opt/netmonitor, /usr/local/bin/gunicorn)
- Geen EnvironmentFile= directive

### **3. Onduidelijke Service Status**

- Welke service start de dashboard? netmonitor.service OF netmonitor-gunicorn.service?
- Is netmonitor-gunicorn.service een legacy/alternatief?
- Documentatie is onduidelijk over service dependencies

### **4. Template vs Productie Verwarring**

`netmonitor.service` is een TEMPLATE met `__INSTALL_DIR__` placeholders:
```bash
ExecStart=__INSTALL_DIR__/venv/bin/python3 __INSTALL_DIR__/netmonitor.py
```

Dit werkt NIET as-is - moet gegenereerd worden door install script!

---

## 🎯 Professionalisering Voorstel

### **Fase 1: Service Architectuur Standaardisatie**

#### **1.1 Besluit: Welke Dashboard Setup?**

**Optie A: Embedded Flask (HUIDIGE netmonitor.service)**
```
✅ Voordelen:
- Eén service (netmonitor.service)
- Simpelere architectuur
- Dashboard start automatisch met monitoring

❌ Nadelen:
- Flask development server (niet production-grade)
- Moeilijker te scalen
```

**Optie B: Separate Gunicorn Service**
```
✅ Voordelen:
- Production-grade WSGI server
- Beter performance (eventlet workers)
- Separate restart mogelijk

❌ Nadelen:
- Twee services te managen
- Complexere setup
```

**AANBEVELING: Optie B (Separate Gunicorn)**
- Maar DAN verwijder dashboard code uit netmonitor.py
- Of disable dashboard in config als gunicorn service gebruikt wordt

#### **1.2 Poort Allocatie Standaard**

**Voorgestelde Standaard:**
```bash
# Web Dashboard
DASHBOARD_PORT=8080    # Flask/Gunicorn voor web UI

# MCP HTTP API
MCP_API_PORT=8000      # FastAPI/Uvicorn voor AI integration

# Nginx
NGINX_HTTP=80
NGINX_HTTPS=443
```

**Rationalisatie:**
- Verschillende poorten voor verschillende services ✅
- Geen conflicts ✅
- Consistent met documentatie (.env.example) ✅

---

### **Fase 2: Environment Variable Standaardisatie**

#### **2.1 .env Template Updaten**

**Nieuwe .env.example:**
```bash
# NetMonitor Environment Configuration
# Copy to .env and update values: cp .env.example .env

# ============================================================================
# Installation Configuration
# ============================================================================
# BELANGRIJK: Standaard installatie pad is /opt/netmonitor
# Als je hiervan afwijkt, ben je zelf verantwoordelijk voor pad aanpassingen
INSTALL_DIR=/opt/netmonitor

# ============================================================================
# Web Dashboard Configuration
# ============================================================================
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8080

# Dashboard Server Type (flask|gunicorn)
# flask   = Embedded Flask server (simpel, development)
# gunicorn = Production WSGI server (aanbevolen voor productie)
DASHBOARD_SERVER=gunicorn

# Flask Secret Key (generate: python3 -c "import secrets; print(secrets.token_hex(32))")
FLASK_SECRET_KEY=change-this-to-a-random-secret-key

# ============================================================================
# MCP HTTP API Configuration (AI Integration)
# ============================================================================
MCP_API_HOST=0.0.0.0
MCP_API_PORT=8000
MCP_API_WORKERS=4

# ============================================================================
# Database Configuration
# ============================================================================
# Database Type (sqlite|postgresql)
DB_TYPE=sqlite

# SQLite (default)
SQLITE_PATH=/var/lib/netmonitor/netmonitor.db

# PostgreSQL (optional - voor MCP HTTP API)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=netmonitor
DB_USER=netmonitor
DB_PASSWORD=netmonitor

# ============================================================================
# Logging Configuration
# ============================================================================
LOG_DIR=/var/log/netmonitor
LOG_LEVEL=INFO

# ============================================================================
# Runtime Directories
# ============================================================================
RUN_DIR=/var/run/netmonitor
DATA_DIR=/var/lib/netmonitor
CACHE_DIR=/var/cache/netmonitor

# ============================================================================
# Sensor Configuration (for remote sensors only)
# ============================================================================
SENSOR_ID=
SENSOR_NAME=
SOC_SERVER_URL=
SENSOR_TOKEN=
```

#### **2.2 Service Files met EnvironmentFile**

**Template: netmonitor.service.template**
```ini
[Unit]
Description=NetMonitor - Network Monitoring Engine
After=network.target
Documentation=https://github.com/willempoort/netmonitor

[Service]
Type=simple
User=root
WorkingDirectory=__INSTALL_DIR__

# Load environment variables
EnvironmentFile=-__INSTALL_DIR__/.env
EnvironmentFile=-/etc/netmonitor/netmonitor.env

# Start netmonitor (without embedded dashboard if DASHBOARD_SERVER=gunicorn)
ExecStart=__INSTALL_DIR__/venv/bin/python3 __INSTALL_DIR__/netmonitor.py --config __INSTALL_DIR__/config.yaml

# Restart on failure
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ReadWritePaths=/var/lib/netmonitor /var/log/netmonitor /var/run/netmonitor /var/cache/netmonitor

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netmonitor

[Install]
WantedBy=multi-user.target
```

**Template: netmonitor-dashboard.service.template**
```ini
[Unit]
Description=NetMonitor Web Dashboard (Gunicorn)
After=network.target netmonitor.service
Requires=netmonitor.service
Documentation=https://github.com/willempoort/netmonitor

[Service]
Type=notify
User=root
WorkingDirectory=__INSTALL_DIR__

# Load environment variables
EnvironmentFile=-__INSTALL_DIR__/.env
EnvironmentFile=-/etc/netmonitor/netmonitor.env

# Create runtime directory
RuntimeDirectory=netmonitor
RuntimeDirectoryMode=0755

# Ensure directories exist
ExecStartPre=/bin/mkdir -p ${LOG_DIR:-/var/log/netmonitor}
ExecStartPre=/bin/mkdir -p ${RUN_DIR:-/var/run/netmonitor}

# Start Gunicorn with eventlet workers for SocketIO
ExecStart=/usr/local/bin/gunicorn \
    --bind ${DASHBOARD_HOST:-0.0.0.0}:${DASHBOARD_PORT:-8080} \
    --workers ${DASHBOARD_WORKERS:-4} \
    --worker-class eventlet \
    --worker-connections 1000 \
    --timeout 30 \
    --graceful-timeout 30 \
    --access-logfile ${LOG_DIR:-/var/log/netmonitor}/dashboard_access.log \
    --error-logfile ${LOG_DIR:-/var/log/netmonitor}/dashboard_error.log \
    --log-level ${LOG_LEVEL:-info} \
    --pid ${RUN_DIR:-/var/run/netmonitor}/dashboard.pid \
    wsgi:application

# Restart on failure
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/netmonitor /var/log/netmonitor /var/run/netmonitor /var/cache/netmonitor

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netmonitor-dashboard

[Install]
WantedBy=multi-user.target
```

**Template: netmonitor-mcp-http.service.template**
```ini
[Unit]
Description=NetMonitor MCP HTTP API Server (AI Integration)
After=network.target postgresql.service
Wants=postgresql.service
Documentation=https://github.com/willempoort/netmonitor

[Service]
Type=simple
User=root
WorkingDirectory=__INSTALL_DIR__

# Load environment variables
EnvironmentFile=-__INSTALL_DIR__/.env
EnvironmentFile=-/etc/netmonitor/netmonitor.env

# Start MCP HTTP API
ExecStart=__INSTALL_DIR__/venv/bin/python3 __INSTALL_DIR__/mcp_server/http_server.py \
    --host ${MCP_API_HOST:-0.0.0.0} \
    --port ${MCP_API_PORT:-8000}

# Restart on failure
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netmonitor-mcp-http

[Install]
WantedBy=multi-user.target
```

---

### **Fase 3: Install Script Verbetering**

**install_services.sh verbeteren:**
```bash
#!/bin/bash
# NetMonitor Service Installation Script
# Generates service files from templates with correct paths

set -e

# Detect installation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$SCRIPT_DIR}"

echo "NetMonitor Service Installation"
echo "================================"
echo "Installation directory: $INSTALL_DIR"
echo ""

# Load .env if exists
if [ -f "$INSTALL_DIR/.env" ]; then
    echo "Loading configuration from .env..."
    source "$INSTALL_DIR/.env"
fi

# Set defaults
DASHBOARD_SERVER="${DASHBOARD_SERVER:-gunicorn}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"
MCP_API_PORT="${MCP_API_PORT:-8000}"

echo "Configuration:"
echo "  Dashboard server: $DASHBOARD_SERVER"
echo "  Dashboard port:   $DASHBOARD_PORT"
echo "  MCP API port:     $MCP_API_PORT"
echo ""

# Function to generate service file from template
generate_service() {
    local template="$1"
    local output="$2"

    if [ ! -f "$template" ]; then
        echo "⚠️  Template not found: $template"
        return 1
    fi

    echo "Generating $output from template..."
    sed -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" \
        "$template" > "$output"

    echo "✅ Generated: $output"
}

# Generate main netmonitor service
generate_service \
    "$INSTALL_DIR/netmonitor.service.template" \
    "/etc/systemd/system/netmonitor.service"

# Generate dashboard service (if using gunicorn)
if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    generate_service \
        "$INSTALL_DIR/netmonitor-dashboard.service.template" \
        "/etc/systemd/system/netmonitor-dashboard.service"
fi

# Reload systemd
systemctl daemon-reload
echo ""
echo "✅ Systemd daemon reloaded"

# Enable services
echo ""
echo "Enabling services..."
systemctl enable netmonitor.service

if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    systemctl enable netmonitor-dashboard.service
fi

echo ""
echo "=================================================="
echo "Installation Complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "  1. Review configuration: nano $INSTALL_DIR/.env"
echo "  2. Start services:"
echo "       sudo systemctl start netmonitor"
if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    echo "       sudo systemctl start netmonitor-dashboard"
fi
echo "  3. Check status:"
echo "       sudo systemctl status netmonitor"
if [ "$DASHBOARD_SERVER" = "gunicorn" ]; then
    echo "       sudo systemctl status netmonitor-dashboard"
fi
echo ""
```

---

### **Fase 4: Nginx Configuratie met .env**

**nginx-netmonitor.conf.template:**
```nginx
# NetMonitor Nginx Configuration Template
# This file should be processed to replace __DASHBOARD_PORT__ and __MCP_API_PORT__

upstream netmonitor_dashboard {
    server 127.0.0.1:__DASHBOARD_PORT__;  # Will be replaced with $DASHBOARD_PORT from .env
    keepalive 32;
}

upstream netmonitor_mcp_api {
    server 127.0.0.1:__MCP_API_PORT__;    # Will be replaced with $MCP_API_PORT from .env
    keepalive 32;
}

# ... rest of nginx config
```

**generate_nginx_config.sh:**
```bash
#!/bin/bash
# Generate Nginx config from template with correct ports

source /opt/netmonitor/.env

sed -e "s|__DASHBOARD_PORT__|${DASHBOARD_PORT:-8080}|g" \
    -e "s|__MCP_API_PORT__|${MCP_API_PORT:-8000}|g" \
    /opt/netmonitor/nginx-netmonitor.conf.template \
    > /etc/nginx/sites-available/netmonitor.conf

echo "✅ Nginx config generated with:"
echo "   Dashboard port: ${DASHBOARD_PORT:-8080}"
echo "   MCP API port:   ${MCP_API_PORT:-8000}"
```

---

### **Fase 5: Documentatie Restructurering**

**Nieuwe Structuur:**
```
/netmonitor/
├── README.md                    # Quick start + architectuur overzicht
├── .env.example                 # Template met ALLE variabelen
│
├── docs/
│   ├── INDEX.md                 # Master index
│   ├── ARCHITECTURE.md          # ⭐ System architecture (NIEUW)
│   │
│   ├── installation/
│   │   ├── QUICKSTART.md        # 5-minuten setup
│   │   ├── PRODUCTION.md        # Productie deployment
│   │   ├── SERVICES.md          # ⭐ Service management (NIEUW)
│   │   └── ENVIRONMENT.md       # ⭐ .env configuration (NIEUW)
│   │
│   ├── usage/
│   │   ├── USER_MANUAL.md
│   │   ├── ADMIN_MANUAL.md
│   │   ├── DASHBOARD.md
│   │   └── KIOSK_MODE.md
│   │
│   └── development/
│       ├── SERVICE_TEMPLATES.md  # ⭐ Template system (NIEUW)
│       └── CONTRIBUTING.md
│
├── services/                     # ⭐ Service templates (NIEUW)
│   ├── README.md
│   ├── netmonitor.service.template
│   ├── netmonitor-dashboard.service.template
│   ├── netmonitor-mcp-http.service.template
│   └── netmonitor-sensor.service.template
│
└── scripts/
    ├── install_complete.sh
    ├── install_services.sh       # ⭐ Verbeterd met templates
    └── generate_nginx_config.sh  # ⭐ NIEUW
```

---

## 📋 Implementatie Plan

### **Stap 1: .env Standaardisatie (30 min)**

1. Update .env.example met ALLE variabelen
2. Create .env op server (cp .env.example .env)
3. Set juiste waarden (poorten, paths, secrets)

### **Stap 2: Service Templates (1 uur)**

1. Create services/ directory
2. Move service files naar templates
3. Add EnvironmentFile directive
4. Test template generation

### **Stap 3: Install Script Update (30 min)**

1. Update install_services.sh
2. Add template processing
3. Add .env loading
4. Test complete installation

### **Stap 4: Poort Fix (30 min)**

1. Set DASHBOARD_PORT=8080 in .env
2. Set MCP_API_PORT=8000 in .env
3. Regenerate service files
4. Update nginx config
5. Restart services

### **Stap 5: Documentatie (2 uur)**

1. Create docs/ARCHITECTURE.md
2. Create docs/installation/SERVICES.md
3. Create docs/installation/ENVIRONMENT.md
4. Update README.md met architecture diagram

---

## ✅ Succes Criteria

Na cleanup:

1. **✅ Consistente configuratie:**
   - Alle poorten uit .env
   - Alle paths uit .env (of default /opt/netmonitor)
   - Geen hardcoded waarden in service files

2. **✅ Duidelijke service architectuur:**
   - Documentatie legt uit welke service wat doet
   - Template system maakt services reproduceerbaar
   - Geen port conflicts

3. **✅ Professionele deployment:**
   - install_services.sh genereert correcte files
   - .env based configuratie
   - Easy troubleshooting

4. **✅ Begrijpelijke docs:**
   - ARCHITECTURE.md legt alles uit
   - Duidelijke service dependencies
   - Template documentatie

---

## 🎯 Aanbevolen Aanpak

**Gefaseerd implementeren:**

1. **WEEK 1: Foundation**
   - .env.example update
   - Service templates maken
   - Install script verbeteren

2. **WEEK 2: Migration**
   - Poort standaardisatie
   - Service regeneratie
   - Testing

3. **WEEK 3: Documentation**
   - ARCHITECTURE.md schrijven
   - Docs herstructureren
   - README vereenvoudigen

---

## ❓ Beslissingen Nodig

1. **Dashboard Server:** Embedded Flask OF separate Gunicorn?
   - **Advies:** Separate Gunicorn (production-ready)

2. **Poort Allocatie:**
   - Dashboard: 8080 ✅
   - MCP API: 8000 ✅
   - **Akkoord?**

3. **Template Locatie:**
   - services/ directory OF root?
   - **Advies:** services/ directory (cleaner)

4. **Prioriteit:**
   - Alles in één keer OF gefaseerd?
   - **Advies:** Gefaseerd (minder risico)

---

Wil je dat ik nu start met:
- **A.** .env.example update en service templates (2 uur)
- **B.** Alleen poort fix voor kiosk mode (30 min)
- **C.** ARCHITECTURE.md documentatie eerst (1 uur)
- **D.** Anders?
