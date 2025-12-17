# Environment Configuration (.env)

NetMonitor gebruikt een `.env` bestand voor het opslaan van gevoelige configuratie zoals database wachtwoorden. Dit is veiliger dan hardcoded credentials in scripts.

## 🔐 Waarom .env?

**Voordelen:**
- Één centrale locatie voor credentials
- Niet opgenomen in Git (via `.gitignore`)
- Eenvoudig te wijzigen zonder scripts aan te passen
- Standaard practice in moderne applicaties

**Voor:**
- Database wachtwoord stond in `config.yaml` (in Git)
- Wachtwoord "netmonitor" was hardcoded in scripts
- Wachtwoord wijzigen betekende alle scripts aanpassen

**Nu:**
- Credentials in `.env` (NIET in Git)
- Scripts lezen automatisch uit `.env`
- Eenvoudig custom wachtwoord instellen

## 📝 Installatie

De `.env` file wordt automatisch gegenereerd tijdens installatie door `install_complete.sh`:

```bash
sudo bash install_complete.sh
```

Het script vraagt om een database wachtwoord en genereert:
- `/opt/netmonitor/.env` (chmod 600 voor security)
- Random secret key voor web dashboard
- Database credentials

## 🔧 Handmatige Setup (na installatie)

Als je het wachtwoord wilt wijzigen na installatie:

1. **Wijzig PostgreSQL wachtwoord:**
   ```bash
   sudo -u postgres psql -c "ALTER USER netmonitor WITH PASSWORD 'je_nieuwe_wachtwoord';"
   ```

2. **Update .env bestand:**
   ```bash
   nano /opt/netmonitor/.env
   ```

   Wijzig regel:
   ```
   DB_PASSWORD=je_nieuwe_wachtwoord
   ```

3. **Restart services:**
   ```bash
   sudo systemctl restart netmonitor
   sudo systemctl restart netmonitor-web
   ```

## 📋 .env Bestand Structuur

```bash
# PostgreSQL Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=netmonitor
DB_USER=netmonitor
DB_PASSWORD=je_wachtwoord_hier

# Web Dashboard Configuration
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8181
# Flask secret key (generate with: python3 -c "import secrets; print(secrets.token_hex(32))")
FLASK_SECRET_KEY=random_secret_key

# Installation Configuration
INSTALL_DIR=/opt/netmonitor

# Sensor Configuration (optional)
SENSOR_ID=
SENSOR_NAME=
SOC_SERVER_URL=
```

## 🔍 Hoe het werkt

### Python Scripts

Python scripts gebruiken `env_loader.py`:

```python
from env_loader import get_db_config

# Automatisch laden uit .env (met fallback naar config.yaml)
db_config = get_db_config()

db = DatabaseManager(**db_config)
```

**Prioriteit:**
1. `.env` bestand (als het bestaat)
2. `config.yaml` (fallback)
3. Default waarden

### Bash Scripts

Bash scripts laden `.env` met een helper functie:

```bash
# Load .env if it exists
load_env() {
    if [ -f .env ]; then
        export $(grep -v '^#' .env | grep -v '^$' | xargs)
    fi
}

load_env

# Gebruik variabelen
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME"
```

## 📚 Welke Scripts Gebruiken .env?

### Automatisch (via env_loader.py):
- ✅ `setup_admin_user.py`
- ✅ `show_2fa_qr.py`
- ✅ Alle Python scripts die database gebruiken

### Met load_env() functie:
- ✅ `get_2fa_secret.sh`
- ✅ `check_sensor_status.sh`
- ✅ Bash scripts die database query's doen

### Gegenereerd tijdens installatie:
- ✅ `install_complete.sh` - genereert `.env`
- ✅ Service files - lezen `INSTALL_DIR` uit `.env`

## ⚠️ Security Best Practices

1. **NOOIT committen:**
   - `.env` staat in `.gitignore`
   - Gebruik `.env.example` voor template

2. **Bestand permissies:**
   ```bash
   chmod 600 /opt/netmonitor/.env
   chown root:root /opt/netmonitor/.env
   ```

3. **Sterke wachtwoorden:**
   ```bash
   # Genereer random wachtwoord:
   openssl rand -base64 32
   ```

4. **Backup:**
   - Bewaar `.env` veilig (password manager)
   - NIET in Git, cloud backup, etc.

## 🔄 Migratie van Oude Setup

Als je al een bestaande NetMonitor installatie hebt:

1. **Maak .env aan:**
   ```bash
   cd /opt/netmonitor
   cp .env.example .env
   ```

2. **Kopieer credentials uit config.yaml:**
   ```bash
   DB_PASSWORD=$(grep -A5 "postgresql:" config.yaml | grep "password:" | awk '{print $2}')
   echo "DB_PASSWORD=$DB_PASSWORD" >> .env
   ```

3. **Optioneel: Wijzig wachtwoord:**
   - Volg stappen in "Handmatige Setup" hierboven

4. **Test:**
   ```bash
   python3 setup_admin_user.py
   # Moet "Using credentials from .env" tonen
   ```

## 🐛 Troubleshooting

### "Database connection failed"

1. **Check .env bestaat:**
   ```bash
   ls -la /opt/netmonitor/.env
   ```

2. **Verify credentials:**
   ```bash
   cat /opt/netmonitor/.env | grep DB_
   ```

3. **Test database login:**
   ```bash
   source /opt/netmonitor/.env
   psql -h $DB_HOST -U $DB_USER -d $DB_NAME
   # Voer wachtwoord in wanneer gevraagd
   ```

### "Using credentials from config.yaml"

Dit betekent `.env` niet gevonden is. Script valt terug op `config.yaml`:

```bash
# Controleer pad:
pwd
# Moet zijn: /opt/netmonitor

# .env aanmaken:
cp .env.example .env
nano .env  # Edit credentials
```

### Service start niet na wachtwoord wijziging

1. **Check .env permissions:**
   ```bash
   ls -la /opt/netmonitor/.env
   # Moet zijn: -rw------- root root
   ```

2. **Verify services kunnen .env lezen:**
   ```bash
   sudo systemctl status netmonitor
   sudo journalctl -u netmonitor -n 50
   ```

3. **Restart services:**
   ```bash
   sudo systemctl restart netmonitor
   sudo systemctl restart netmonitor-web
   ```

## 📖 Meer Informatie

- Zie `.env.example` voor template
- Zie `env_loader.py` voor implementatie details
- PostgreSQL docs: https://www.postgresql.org/docs/current/auth-password.html
