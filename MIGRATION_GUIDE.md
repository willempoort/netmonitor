# NetMonitor Migration Guide - Template-Based Services

**Van: Hardcoded services → Naar: Template-based .env configuratie**

Dit document beschrijft hoe je een bestaande NetMonitor installatie migreert naar het nieuwe template-based service systeem met .env configuratie.

---

## 📋 Overzicht

### **Wat verandert er?**

**Voor (Oud):**
- Hardcoded poorten en paths in service files
- Services direct in `/etc/systemd/system/` zonder templates
- Geen centrale configuratie
- Moeilijk reproduceerbaar

**Na (Nieuw):**
- Alle configuratie in `.env` file
- Service templates in `services/` directory
- `__INSTALL_DIR__` placeholder systeem
- Conditional service installation
- Reproduceerbare deployments

### **Waarom migreren?**

✅ **Configuration as Code** - Eén plek voor alle settings
✅ **Reproduceerbaar** - Easy deployment op nieuwe servers
✅ **Geen hardcoded waarden** - Alles configureerbaar
✅ **Professioneler** - Industry best practices
✅ **Makkelijker te onderhouden** - Duidelijke structuur

---

## ⚠️ Belangrijke Informatie

### **Best Practice: Clean Migration**

Voor een betrouwbare migratie raden we een **clean install aanpak** aan:

1. **Stop alle services** (geen data verlies - database blijft intact)
2. **Backup bestaande installatie** (`/opt/netmonitor` → `/opt/netmonitor.bak`)
3. **Nieuwe git clone** (verse installatie met nieuwe structuur)
4. **Migreer configuratie** (kopieer belangrijke settings)
5. **Regenerate services** (met nieuwe templates)
6. **Test en verify** (controleer of alles werkt)
7. **Cleanup** (verwijder backup als alles werkt)

**Waarom clean migration?**
- ✅ Geen conflicterende oude files
- ✅ Verse service templates
- ✅ Schone git history
- ✅ Easy rollback naar backup
- ✅ Vermijdt merge conflicts

### **Data Veiligheid**

**Data wordt NIET verwijderd:**
- ✅ Database: `/var/lib/netmonitor/netmonitor.db` (blijft intact)
- ✅ Logs: `/var/log/netmonitor/` (blijft intact)
- ✅ Config: `config.yaml` (backup en migrate)
- ✅ Threat feeds: `/var/cache/netmonitor/` (blijft intact)

**Alleen applicatie code wordt vervangen** - alle data blijft behouden!

---

## 🚀 Migratie Procedure

### **Stap 1: Pre-Migration Checklist**

Voer deze checks uit VOOR je begint:

```bash
# 1. Check welke services draaien
systemctl status netmonitor
systemctl status netmonitor-dashboard 2>/dev/null || echo "Not running"
systemctl status netmonitor-mcp-http 2>/dev/null || echo "Not running"
systemctl status netmonitor-feed-update.timer

# 2. Check huidige configuratie
cat /opt/netmonitor/config.yaml | grep -A5 "dashboard:"
ls -la /opt/netmonitor/.env 2>/dev/null || echo "No .env file (expected)"

# 3. Check database locatie
sudo sqlite3 /var/lib/netmonitor/netmonitor.db ".tables" 2>/dev/null || echo "Database not found"

# 4. Note current ports
sudo netstat -tlnp | grep -E ":(8000|8080)"

# 5. Check disk space (need ~500MB free)
df -h /opt
```

**Document je huidige setup:**
```bash
# Maak notities van:
# - Dashboard poort: _____
# - MCP API running? Y/N
# - Gunicorn of embedded Flask? _____
# - PostgreSQL of SQLite? _____
# - Custom config.yaml settings? _____
```

---

### **Stap 2: Backup Bestaande Installatie**

**2.1 Stop alle NetMonitor services:**

```bash
# Stop services (in volgorde)
sudo systemctl stop netmonitor-dashboard 2>/dev/null || true
sudo systemctl stop netmonitor-mcp-http 2>/dev/null || true
sudo systemctl stop netmonitor-feed-update.timer
sudo systemctl stop netmonitor

# Verify alles gestopt is
systemctl status netmonitor --no-pager
systemctl status netmonitor-dashboard --no-pager 2>/dev/null || true
```

**2.2 Backup service files:**

```bash
# Backup systemd service files
sudo mkdir -p /opt/netmonitor-migration-backup/services
sudo cp /etc/systemd/system/netmonitor*.service /opt/netmonitor-migration-backup/services/ 2>/dev/null || true
sudo cp /etc/systemd/system/netmonitor*.timer /opt/netmonitor-migration-backup/services/ 2>/dev/null || true

echo "✓ Service files backed up to /opt/netmonitor-migration-backup/services/"
ls -la /opt/netmonitor-migration-backup/services/
```

**2.3 Backup belangrijke configuratie:**

```bash
# Backup config.yaml en eventuele custom files
sudo cp /opt/netmonitor/config.yaml /opt/netmonitor-migration-backup/
sudo cp /opt/netmonitor/sensor.conf /opt/netmonitor-migration-backup/ 2>/dev/null || true
sudo cp /opt/netmonitor/.env /opt/netmonitor-migration-backup/ 2>/dev/null || true

# Backup nginx config
sudo cp /etc/nginx/sites-available/soc.conf /opt/netmonitor-migration-backup/ 2>/dev/null || true

echo "✓ Configuration backed up to /opt/netmonitor-migration-backup/"
ls -la /opt/netmonitor-migration-backup/
```

**2.4 Hernoem bestaande installatie:**

```bash
# Hernoem /opt/netmonitor naar backup
sudo mv /opt/netmonitor /opt/netmonitor.bak

# Verify
ls -la /opt/ | grep netmonitor

# Belangrijk: Database blijft in /var/lib/netmonitor/ (niet verplaatst!)
```

---

### **Stap 3: Nieuwe Installatie**

**3.1 Clone fresh repository:**

```bash
# Clone naar /opt/netmonitor (dezelfde locatie als voorheen)
cd /opt
sudo git clone https://github.com/willempoort/netmonitor.git

# Of als je de branch met nieuwe features wilt:
cd /opt
sudo git clone https://github.com/willempoort/netmonitor.git
cd netmonitor
sudo git checkout claude/implement-kiosk-mode-cOe95

# Verify nieuwe structuur
ls -la /opt/netmonitor/services/
```

**3.2 Restore virtual environment:**

**Optie A: Hergebruik oude venv (sneller)**
```bash
# Copy venv van backup
sudo cp -r /opt/netmonitor.bak/venv /opt/netmonitor/

# Verify
/opt/netmonitor/venv/bin/python3 --version
```

**Optie B: Nieuwe venv (schoner)**
```bash
cd /opt/netmonitor
sudo bash setup_venv.sh
```

---

### **Stap 4: Configuratie Migratie**

**4.1 Create .env from template:**

```bash
cd /opt/netmonitor
sudo cp .env.example .env
```

**4.2 Migrate settings naar .env:**

Open beide configs naast elkaar:
```bash
# Terminal 1: Oude config
cat /opt/netmonitor-migration-backup/config.yaml

# Terminal 2: Nieuwe .env
sudo nano /opt/netmonitor/.env
```

**Migreer deze settings:**

| Oude Locatie | Nieuwe .env Variable | Voorbeeld |
|--------------|---------------------|-----------|
| `config.yaml: dashboard.port` | `DASHBOARD_PORT` | `8080` |
| `config.yaml: dashboard.host` | `DASHBOARD_HOST` | `0.0.0.0` |
| Embedded Flask? | `DASHBOARD_SERVER` | `embedded` |
| Using Gunicorn? | `DASHBOARD_SERVER` | `gunicorn` |
| PostgreSQL database? | `DB_TYPE` | `postgresql` |
| PostgreSQL host | `DB_HOST` | `localhost` |
| PostgreSQL credentials | `DB_USER`, `DB_PASSWORD` | ... |
| MCP HTTP API running? | `MCP_API_ENABLED` | `true`/`false` |

**4.3 Generate Flask secret key:**

```bash
# Generate new secret key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Add to .env
sudo nano /opt/netmonitor/.env
# Set: FLASK_SECRET_KEY=<generated-key>
```

**4.4 Restore custom config.yaml settings:**

```bash
# Copy oude config als referentie
sudo cp /opt/netmonitor-migration-backup/config.yaml /opt/netmonitor/config.yaml.old

# Merge belangrijke custom settings naar nieuwe config.yaml
sudo nano /opt/netmonitor/config.yaml

# Belangrijke secties om te checken:
# - whitelist IP ranges
# - detection thresholds
# - alert settings
# - custom monitoring interfaces
```

---

### **Stap 5: Service Regeneratie**

**5.1 Genereer nieuwe service files:**

```bash
cd /opt/netmonitor
sudo bash install_services.sh
```

**Expected output:**
```
============================================
NetMonitor Service Installation
============================================

ℹ Installation directory: /opt/netmonitor
ℹ Loading configuration from .env...
✓ Configuration loaded from .env

Configuration Summary:
  Dashboard server: embedded
  Dashboard port:   8080
  MCP API enabled:  false
  MCP API port:     8000

ℹ Creating required directories...
✓ Created: /var/log/netmonitor
...

============================================
Generating Service Files from Templates
============================================

ℹ Generating netmonitor...
✓ netmonitor generated
ℹ Dashboard server mode is 'embedded' - dashboard runs within netmonitor.service
ℹ MCP HTTP API disabled (set MCP_API_ENABLED=true in .env to enable)
ℹ Generating netmonitor-feed-update...
✓ netmonitor-feed-update generated
...
```

**5.2 Review gegenereerde services:**

```bash
# Check gegenereerde service files
cat /etc/systemd/system/netmonitor.service

# Verify paths zijn correct
grep "WorkingDirectory" /etc/systemd/system/netmonitor.service
# Should show: WorkingDirectory=/opt/netmonitor

grep "EnvironmentFile" /etc/systemd/system/netmonitor.service
# Should show: EnvironmentFile=-/opt/netmonitor/.env
```

---

### **Stap 6: Services Starten**

**6.1 Start services:**

De installer heeft gevraagd welke services te enablen. Als je "n" koos, start ze nu:

```bash
# Start main service
sudo systemctl enable netmonitor
sudo systemctl start netmonitor

# Start feed update timer
sudo systemctl enable netmonitor-feed-update.timer
sudo systemctl start netmonitor-feed-update.timer

# Als je gunicorn gebruikt (DASHBOARD_SERVER=gunicorn in .env):
sudo systemctl enable netmonitor-dashboard
sudo systemctl start netmonitor-dashboard

# Als MCP HTTP API enabled (MCP_API_ENABLED=true in .env):
sudo systemctl enable netmonitor-mcp-http
sudo systemctl start netmonitor-mcp-http
```

**6.2 Check service status:**

```bash
# Check main service
sudo systemctl status netmonitor

# Check logs
sudo journalctl -u netmonitor -f --lines=50
```

---

### **Stap 7: Verificatie**

**7.1 Test Dashboard:**

```bash
# Check of dashboard luistert
sudo netstat -tlnp | grep :8080

# Test HTTP endpoint
curl -I http://localhost:8080

# Test in browser
firefox http://localhost:8080
# Of via nginx:
firefox https://soc.poort.net
```

**7.2 Test Kiosk Mode:**

```bash
# Test kiosk route
curl -I http://localhost:8080/kiosk

# Test kiosk API
curl http://localhost:8080/api/kiosk/metrics | jq .

# Test in browser
firefox http://localhost:8080/kiosk
# Of via nginx:
firefox https://soc.poort.net/kiosk
```

**7.3 Check Database:**

```bash
# Verify database toegankelijk is
sudo sqlite3 /var/lib/netmonitor/netmonitor.db "SELECT COUNT(*) FROM alerts;"

# Check sensor data
sudo sqlite3 /var/lib/netmonitor/netmonitor.db "SELECT sensor_id, hostname, last_seen FROM sensors;"
```

**7.4 Check Logs:**

```bash
# Geen errors in logs?
sudo journalctl -u netmonitor --since "5 minutes ago" | grep -i error

# Dashboard access logs
sudo tail -f /var/log/netmonitor/dashboard_access.log 2>/dev/null || \
sudo journalctl -u netmonitor | grep -i dashboard
```

**7.5 Functional Tests:**

- [ ] Dashboard laadt correct
- [ ] Login werkt
- [ ] Sensors zijn zichtbaar
- [ ] Alerts worden getoond
- [ ] Kiosk mode werkt (http://localhost:8080/kiosk)
- [ ] Metrics updaten real-time
- [ ] Feed update timer actief: `systemctl list-timers`

---

### **Stap 8: Nginx Update (Optioneel)**

Als je nginx gebruikt en kiosk mode wilt hebben:

```bash
# Check of kiosk routes al in nginx config zitten
grep -A5 "kiosk" /etc/nginx/sites-available/soc.conf

# Als niet, voeg toe (zie KIOSK-DEPLOYMENT.md):
sudo nano /etc/nginx/sites-available/soc.conf

# Voeg toe voor login routes:
# location ~ ^/(kiosk|api/kiosk/) {
#     proxy_pass http://netmonitor_dashboard;
#     ...
# }

# Test nginx config
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

---

### **Stap 9: Cleanup (Na Succesvolle Migratie)**

**Wacht minimaal 24-48 uur** voordat je de backup verwijdert!

**9.1 Monitor gedurende 1-2 dagen:**

```bash
# Daily checks:
systemctl status netmonitor
sudo journalctl -u netmonitor --since today | grep -i error
curl -s http://localhost:8080/api/kiosk/metrics | jq '.success'
```

**9.2 Als alles werkt, verwijder backup:**

```bash
# Alleen als je 100% zeker bent!
sudo rm -rf /opt/netmonitor.bak
sudo rm -rf /opt/netmonitor-migration-backup

# Keep service backup voor reference
# sudo tar czf /root/old-netmonitor-services.tar.gz /opt/netmonitor-migration-backup/services/
```

---

## 🔄 Rollback Procedure

Als de migratie mislukt, rollback naar oude situatie:

```bash
# 1. Stop nieuwe services
sudo systemctl stop netmonitor
sudo systemctl stop netmonitor-dashboard 2>/dev/null || true
sudo systemctl stop netmonitor-mcp-http 2>/dev/null || true

# 2. Restore oude service files
sudo cp /opt/netmonitor-migration-backup/services/* /etc/systemd/system/
sudo systemctl daemon-reload

# 3. Restore oude installatie
sudo rm -rf /opt/netmonitor
sudo mv /opt/netmonitor.bak /opt/netmonitor

# 4. Restore oude config
sudo cp /opt/netmonitor-migration-backup/config.yaml /opt/netmonitor/

# 5. Start oude services
sudo systemctl start netmonitor
sudo systemctl start netmonitor-feed-update.timer

# 6. Verify
sudo systemctl status netmonitor
curl http://localhost:8080
```

---

## 📊 Migratie Checklist

Print deze checklist en vink af tijdens migratie:

### **Pre-Migration**
- [ ] Backup gemaakt van services files
- [ ] Backup gemaakt van config.yaml
- [ ] Backup gemaakt van nginx config
- [ ] Gedocumenteerd: dashboard poort, MCP status, DB type
- [ ] Disk space gecontroleerd (>500MB vrij)

### **Migration**
- [ ] Alle services gestopt
- [ ] /opt/netmonitor → /opt/netmonitor.bak
- [ ] Nieuwe git clone gemaakt
- [ ] .env aangemaakt en geconfigureerd
- [ ] Flask secret key gegenereerd
- [ ] install_services.sh uitgevoerd
- [ ] Services gestart

### **Verification**
- [ ] Dashboard bereikbaar (http://localhost:8080)
- [ ] Kiosk mode werkt (http://localhost:8080/kiosk)
- [ ] Login werkt
- [ ] Database toegankelijk
- [ ] Sensors zichtbaar
- [ ] Alerts worden getoond
- [ ] Logs zijn clean (geen errors)
- [ ] Feed update timer actief

### **Post-Migration**
- [ ] 24 uur gemonitord zonder problemen
- [ ] Nginx config bijgewerkt (indien nodig)
- [ ] Backup verwijderd (na 48+ uur)
- [ ] Documentatie bijgewerkt

---

## ❓ Veelgestelde Vragen

### **Q: Verlies ik mijn alert history?**
A: Nee! Database blijft in `/var/lib/netmonitor/netmonitor.db` - alle data blijft intact.

### **Q: Kan ik de oude en nieuwe installatie tegelijk draaien?**
A: Nee, beide gebruiken dezelfde database en poorten. Migreer clean.

### **Q: Moet ik PostgreSQL opnieuw configureren?**
A: Nee, als je PostgreSQL gebruikte blijft die database intact. Alleen de connection settings moeten naar `.env`.

### **Q: Wat als ik custom modifications heb in Python files?**
A: Die moet je handmatig mergen. Maak eerst een lijst van je changes:
```bash
cd /opt/netmonitor.bak
git diff > /tmp/my-custom-changes.patch
# Review en apply handmatig naar nieuwe installatie
```

### **Q: Werkt de nieuwe installatie met mijn bestaande sensors?**
A: Ja! Sensor protocol is niet veranderd. Sensors blijven gewoon werken.

### **Q: Hoe lang duurt de migratie?**
A: ~30-45 minuten voor een standaard setup. Plan 1-2 uur voor custom setups.

### **Q: Kan ik migreren zonder downtime?**
A: Nee, migratie vereist service stop. Plan downtime van ~15-30 minuten.

---

## 🆘 Troubleshooting

### **Service start failed: "EnvironmentFile not found"**
```bash
# Check of .env bestaat
ls -la /opt/netmonitor/.env

# Als niet, create:
cd /opt/netmonitor
sudo cp .env.example .env
sudo nano .env  # Configure
sudo systemctl restart netmonitor
```

### **Dashboard niet bereikbaar**
```bash
# Check of service draait
sudo systemctl status netmonitor
sudo journalctl -u netmonitor --lines=50

# Check port
sudo netstat -tlnp | grep :8080

# Check logs
sudo tail -f /var/log/netmonitor/netmonitor.log
```

### **Database errors**
```bash
# Check database permissions
sudo ls -la /var/lib/netmonitor/netmonitor.db
sudo chown root:root /var/lib/netmonitor/netmonitor.db
sudo chmod 644 /var/lib/netmonitor/netmonitor.db
```

### **Kiosk 404 na migratie**
```bash
# Check web_dashboard.py heeft kiosk routes
grep -n "def kiosk_view" /opt/netmonitor/web_dashboard.py

# Als niet, checkout correct branch:
cd /opt/netmonitor
sudo git fetch origin
sudo git checkout claude/implement-kiosk-mode-cOe95
sudo systemctl restart netmonitor
```

---

## 📞 Support

Als je problemen hebt tijdens migratie:

1. **Check logs:** `sudo journalctl -u netmonitor -f`
2. **Rollback:** Gebruik rollback procedure hierboven
3. **GitHub Issues:** https://github.com/willempoort/netmonitor/issues
4. **Documentatie:** Zie `/opt/netmonitor/docs/` directory

---

## ✅ Migration Complete!

Na succesvolle migratie heb je:

✅ **Moderne service architectuur** met templates
✅ **Configuration as code** via .env
✅ **Reproduceerbare setup** voor nieuwe servers
✅ **Kiosk mode** voor NOC displays
✅ **Professionele basis** voor verdere ontwikkeling

Geniet van je ge-upgraded NetMonitor SOC! 🎉
