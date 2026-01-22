#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
#
# NetMonitor SOC - Complete Installation Script
# Version: 2.3.0
# Installs: PostgreSQL, TimescaleDB, NetMonitor, Web Auth, MCP API, Nginx
#
# Features:
# - Enforces root execution for automatic dependency installation
# - Reads existing .env values and uses them as defaults
# - Uses .env.example as template if .env doesn't exist
# - Supports Ubuntu 24.04 & Debian 12 (other distros need manual adaptation)
# - Checks for existing database and prompts to keep or overwrite
# - Configures all variables from .env including paths, ports, security settings
#
# Usage: sudo ./install_complete.sh
#
# Supported OS:
# - Ubuntu 24.04 LTS (fully tested)
# - Debian 12 (fully tested)
# - Other Ubuntu/Debian versions may work but are not tested
# - Other distributions require manual adaptation
#

# Don't use set -e globally - we handle errors manually for better user feedback
# set -e would exit immediately on any error, hiding the actual problem from users

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default Configuration (can be overridden from .env or user input)
# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default installation directory
INSTALL_DIR="${SCRIPT_DIR}"

# Logging
LOG_FILE="/tmp/netmonitor-install.log"

# Database defaults (will be loaded from .env or prompted)
DB_NAME="netmonitor"
DB_USER="netmonitor"
DB_PASS="netmonitor"

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "$1"
    echo "============================================================"
    echo -e "${NC}"
    echo "" >> $LOG_FILE 2>&1
    echo "============================================================" >> $LOG_FILE 2>&1
    echo "$1" >> $LOG_FILE 2>&1
    echo "============================================================" >> $LOG_FILE 2>&1
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    echo "[SUCCESS] $1" >> $LOG_FILE 2>&1
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    echo "[ERROR] $1" >> $LOG_FILE 2>&1
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    echo "[WARNING] $1" >> $LOG_FILE 2>&1
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
    echo "[INFO] $1" >> $LOG_FILE 2>&1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Dit script moet als root worden uitgevoerd!"
        echo "Run: sudo ./install_complete.sh"
        exit 1
    fi
}

check_os() {
    if [ ! -f /etc/os-release ]; then
        print_error "Kan OS niet detecteren"
        exit 1
    fi

    . /etc/os-release
    print_info "Gedetecteerd OS: $PRETTY_NAME"

    # Check for supported distros: Ubuntu 24.04 or Debian 12
    SUPPORTED=false

    if [[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]]; then
        SUPPORTED=true
        print_success "Ubuntu 24.04 gedetecteerd - volledig ondersteund"
    elif [[ "$ID" == "debian" && "$VERSION_ID" == "12" ]]; then
        SUPPORTED=true
        print_success "Debian 12 gedetecteerd - volledig ondersteund"
    elif [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
        print_warning "Dit script is getest op Ubuntu 24.04 en Debian 12"
        print_warning "Je versie: $PRETTY_NAME"
        print_warning "Het script zou moeten werken, maar is niet getest op deze versie"
    else
        print_warning "Dit script is alleen getest op Ubuntu 24.04 en Debian 12"
        print_warning "Je OS: $PRETTY_NAME"
        print_warning "Andere distributies vereisen mogelijk aanpassingen"
        print_warning "Voeg zelf ondersteuning toe voor jouw distributie indien nodig"
    fi

    if [ "$SUPPORTED" = false ]; then
        echo
        read -p "Toch doorgaan? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installatie geannuleerd"
            exit 0
        fi
    fi
}

parse_env_file() {
    local env_file="$1"

    if [ ! -f "$env_file" ]; then
        return 1
    fi

    # Parse .env file and export variables
    # This properly handles comments, empty lines, and quoted values
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        # Extract KEY=VALUE (handle quotes)
        if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"

            # Remove surrounding quotes if present
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"

            # Export the variable
            export "$key=$value"
        fi
    done < "$env_file"

    return 0
}

load_existing_env() {
    # Try to load existing .env first
    if [ -f "$INSTALL_DIR/.env" ]; then
        print_info "Bestaande .env gevonden, waarden worden geladen als defaults..."
        parse_env_file "$INSTALL_DIR/.env"
        return 0
    fi

    # If no .env exists, load defaults from .env.example
    if [ -f "$INSTALL_DIR/.env.example" ]; then
        print_info "Geen .env gevonden, gebruik .env.example als template..."
        parse_env_file "$INSTALL_DIR/.env.example"
        return 0
    fi

    print_warning "Geen .env of .env.example gevonden, gebruik hardcoded defaults"
    return 1
}

prompt_config() {
    print_header "CONFIGURATIE"

    # Load existing .env if present (or .env.example as fallback)
    load_existing_env

    # Database configuration
    echo
    print_info "PostgreSQL Database Configuratie:"

    read -p "Database host [${DB_HOST:-localhost}]: " DB_HOST_INPUT
    DB_HOST=${DB_HOST_INPUT:-${DB_HOST:-localhost}}

    read -p "Database port [${DB_PORT:-5432}]: " DB_PORT_INPUT
    DB_PORT=${DB_PORT_INPUT:-${DB_PORT:-5432}}

    read -p "Database naam [${DB_NAME:-netmonitor}]: " DB_NAME_INPUT
    DB_NAME=${DB_NAME_INPUT:-${DB_NAME:-netmonitor}}

    read -p "Database user [${DB_USER:-netmonitor}]: " DB_USER_INPUT
    DB_USER=${DB_USER_INPUT:-${DB_USER:-netmonitor}}

    read -sp "Database password [${DB_PASSWORD:-netmonitor}]: " DB_PASS_INPUT
    echo
    DB_PASS=${DB_PASS_INPUT:-${DB_PASSWORD:-netmonitor}}

    # Dashboard configuration
    echo
    print_info "Web Dashboard Configuratie:"

    read -p "Dashboard host [${DASHBOARD_HOST:-0.0.0.0}]: " DASH_HOST_INPUT
    DASHBOARD_HOST=${DASH_HOST_INPUT:-${DASHBOARD_HOST:-0.0.0.0}}

    read -p "Dashboard port [${DASHBOARD_PORT:-8080}]: " DASH_PORT_INPUT
    DASHBOARD_PORT=${DASH_PORT_INPUT:-${DASHBOARD_PORT:-8080}}

    read -p "Dashboard server mode [${DASHBOARD_SERVER:-embedded}] (embedded/gunicorn): " DASH_SERVER_INPUT
    DASHBOARD_SERVER=${DASH_SERVER_INPUT:-${DASHBOARD_SERVER:-embedded}}

    if [[ "$DASHBOARD_SERVER" == "gunicorn" ]]; then
        read -p "Dashboard workers [${DASHBOARD_WORKERS:-4}]: " DASH_WORKERS_INPUT
        DASHBOARD_WORKERS=${DASH_WORKERS_INPUT:-${DASHBOARD_WORKERS:-4}}
    fi

    # Network interface
    echo
    print_info "Beschikbare network interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print "  - " $2}' | sed 's/:$//'
    echo
    read -p "Welke interface wil je monitoren? [${MONITOR_INTERFACE:-eth0}]: " INTERFACE_INPUT
    INTERFACE=${INTERFACE_INPUT:-${MONITOR_INTERFACE:-eth0}}

    # Internal network
    read -p "Jouw interne netwerk CIDR [${INTERNAL_NETWORK:-192.168.1.0/24}]: " INTERNAL_NET_INPUT
    INTERNAL_NET=${INTERNAL_NET_INPUT:-${INTERNAL_NETWORK:-192.168.1.0/24}}

    # Installation directory
    echo
    print_info "Installatie Paden:"
    read -p "Installatie directory [${INSTALL_DIR:-/opt/netmonitor}]: " INSTALL_DIR_INPUT
    INSTALL_DIR=${INSTALL_DIR_INPUT:-${INSTALL_DIR:-/opt/netmonitor}}

    read -p "Data directory [${DATA_DIR:-/var/lib/netmonitor}]: " DATA_DIR_INPUT
    DATA_DIR=${DATA_DIR_INPUT:-${DATA_DIR:-/var/lib/netmonitor}}

    read -p "Log directory [${LOG_DIR:-/var/log/netmonitor}]: " LOG_DIR_INPUT
    LOG_DIR=${LOG_DIR_INPUT:-${LOG_DIR:-/var/log/netmonitor}}

    # Components
    echo
    print_info "Welke componenten wil je installeren?"
    read -p "PostgreSQL + TimescaleDB? (Y/n): " INSTALL_DB
    INSTALL_DB=${INSTALL_DB:-Y}

    read -p "NetMonitor Core? (Y/n): " INSTALL_CORE
    INSTALL_CORE=${INSTALL_CORE:-Y}

    # MCP API configuration
    MCP_DEFAULT="N"
    if [[ "${MCP_API_ENABLED}" == "true" ]]; then
        MCP_DEFAULT="y"
    fi
    read -p "MCP HTTP API Server? (y/N) [${MCP_DEFAULT}]: " INSTALL_MCP_INPUT
    INSTALL_MCP=${INSTALL_MCP_INPUT:-${MCP_DEFAULT}}

    if [[ $INSTALL_MCP =~ ^[Yy]$ ]]; then
        MCP_API_ENABLED="true"
        read -p "MCP API host [${MCP_API_HOST:-0.0.0.0}]: " MCP_HOST_INPUT
        MCP_API_HOST=${MCP_HOST_INPUT:-${MCP_API_HOST:-0.0.0.0}}

        read -p "MCP API port [${MCP_API_PORT:-8000}]: " MCP_PORT_INPUT
        MCP_API_PORT=${MCP_PORT_INPUT:-${MCP_API_PORT:-8000}}

        read -p "MCP API workers [${MCP_API_WORKERS:-4}]: " MCP_WORKERS_INPUT
        MCP_API_WORKERS=${MCP_WORKERS_INPUT:-${MCP_API_WORKERS:-4}}
    else
        MCP_API_ENABLED="false"
        MCP_API_HOST=${MCP_API_HOST:-0.0.0.0}
        MCP_API_PORT=${MCP_API_PORT:-8000}
        MCP_API_WORKERS=${MCP_API_WORKERS:-4}
    fi

    # Security settings
    echo
    print_info "Security Instellingen:"
    REQUIRE_2FA_DEFAULT="N"
    if [[ "${REQUIRE_2FA}" == "true" ]]; then
        REQUIRE_2FA_DEFAULT="Y"
    fi
    read -p "Verplicht 2FA voor dashboard login? (Y/n) [${REQUIRE_2FA_DEFAULT}]: " REQUIRE_2FA_INPUT
    REQUIRE_2FA_INPUT=${REQUIRE_2FA_INPUT:-${REQUIRE_2FA_DEFAULT}}
    if [[ $REQUIRE_2FA_INPUT =~ ^[Yy]$ ]]; then
        REQUIRE_2FA="true"
    else
        REQUIRE_2FA="false"
    fi

    # Nginx
    echo
    read -p "Nginx reverse proxy? (y/N): " INSTALL_NGINX
    INSTALL_NGINX=${INSTALL_NGINX:-N}

    if [[ $INSTALL_NGINX =~ ^[Yy]$ ]]; then
        read -p "Domain name [${NGINX_SERVER_NAME}] (bijv. soc.example.com): " DOMAIN_NAME_INPUT
        DOMAIN_NAME=${DOMAIN_NAME_INPUT:-${NGINX_SERVER_NAME}}
    fi

    echo
    print_success "Configuratie compleet!"
}

install_system_packages() {
    print_header "STAP 1/10: Systeem Packages Installeren"

    apt update >> $LOG_FILE 2>&1
    print_success "Package list updated"

    PACKAGES="git python3 python3-pip python3-venv build-essential libpcap-dev tcpdump curl wget"

    if [[ $INSTALL_DB =~ ^[Yy]$ ]]; then
        PACKAGES="$PACKAGES postgresql postgresql-contrib postgresql-server-dev-all"
    fi

    if [[ $INSTALL_NGINX =~ ^[Yy]$ ]]; then
        PACKAGES="$PACKAGES nginx certbot python3-certbot-nginx"
    fi

    print_info "Installeren: $PACKAGES"
    apt install -y $PACKAGES >> $LOG_FILE 2>&1
    print_success "Systeem packages geïnstalleerd"
}

install_timescaledb() {
    if [[ ! $INSTALL_DB =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 2/10: TimescaleDB Installeren"

    # Detect PostgreSQL version
    PG_VERSION=$(psql --version | grep -oP '\d+' | head -1)
    print_info "PostgreSQL version: $PG_VERSION"

    # Add TimescaleDB repo
    sh -c "echo 'deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescaledb.list"
    wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | apt-key add - >> $LOG_FILE 2>&1

    apt update >> $LOG_FILE 2>&1
    apt install -y timescaledb-2-postgresql-$PG_VERSION >> $LOG_FILE 2>&1

    # Tune PostgreSQL for TimescaleDB
    timescaledb-tune --quiet --yes >> $LOG_FILE 2>&1

    # Restart PostgreSQL
    systemctl restart postgresql
    print_success "TimescaleDB geïnstalleerd"
}

setup_database() {
    if [[ ! $INSTALL_DB =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 3/10: Database Setup"

    # Start PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    print_success "PostgreSQL gestart"

    # Check if database already exists
    DB_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null)

    if [ "$DB_EXISTS" = "1" ]; then
        print_warning "Database '$DB_NAME' bestaat al!"
        echo
        echo "Opties:"
        echo "  1) Behouden (gebruik bestaande database)"
        echo "  2) Overschrijven (VERWIJDERT ALLE DATA!)"
        echo "  3) Annuleren (stop installatie)"
        echo
        read -p "Keuze (1/2/3): " -n 1 -r DB_CHOICE
        echo

        case "$DB_CHOICE" in
            1)
                print_info "Bestaande database wordt behouden"
                # Check if user exists and update password if needed
                USER_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null)
                if [ "$USER_EXISTS" = "1" ]; then
                    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';" >> $LOG_FILE 2>&1
                    print_success "Database user password bijgewerkt"
                else
                    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" >> $LOG_FILE 2>&1
                    print_success "Database user aangemaakt"
                fi
                sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >> $LOG_FILE 2>&1
                ;;
            2)
                print_warning "Database wordt overschreven..."
                sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" >> $LOG_FILE 2>&1 || true
                sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;" >> $LOG_FILE 2>&1 || true
                sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" >> $LOG_FILE 2>&1
                sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" >> $LOG_FILE 2>&1
                sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >> $LOG_FILE 2>&1
                print_success "Database opnieuw aangemaakt"
                ;;
            3)
                print_info "Installatie geannuleerd door gebruiker"
                exit 0
                ;;
            *)
                print_error "Ongeldige keuze"
                exit 1
                ;;
        esac
    else
        # Create user and database (fresh install)
        sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;" >> $LOG_FILE 2>&1 || true
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" >> $LOG_FILE 2>&1
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" >> $LOG_FILE 2>&1
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >> $LOG_FILE 2>&1
        print_success "Database user en database aangemaakt"
    fi

    # Enable TimescaleDB extension
    sudo -u postgres psql -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;" >> $LOG_FILE 2>&1
    print_success "TimescaleDB extension enabled"
}

install_netmonitor() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 4/10: NetMonitor Installeren"

    # Already in /opt/netmonitor (current directory)
    cd $INSTALL_DIR

    # Create virtual environment
    print_info "Creating Python virtual environment..."
    python3 -m venv venv >> $LOG_FILE 2>&1
    print_success "Virtual environment aangemaakt"

    # Install Python packages
    print_info "Installeren Python dependencies (dit kan enkele minuten duren)..."
    source venv/bin/activate
    pip install --upgrade pip >> $LOG_FILE 2>&1
    pip install -r requirements.txt >> $LOG_FILE 2>&1
    print_success "Python dependencies geïnstalleerd"

    # Create directories
    mkdir -p /var/log/netmonitor
    mkdir -p /var/cache/netmonitor/feeds
    mkdir -p /var/lib/netmonitor
    print_success "Directories aangemaakt"
}

configure_netmonitor() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 5/10: NetMonitor Configureren"

    cd $INSTALL_DIR

    # Backup existing configs
    if [ -f config.yaml ]; then
        cp config.yaml config.yaml.backup.$(date +%Y%m%d_%H%M%S)
        print_info "Bestaande config.yaml backed up"
    fi

    if [ -f .env ]; then
        cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
        print_info "Bestaande .env backed up"
    fi

    # Create config.yaml from config.yaml.example if it doesn't exist
    if [ ! -f config.yaml ]; then
        if [ -f config.yaml.example ]; then
            cp config.yaml.example config.yaml
            print_info "config.yaml aangemaakt van config.yaml.example"
        else
            print_error "config.yaml.example niet gevonden!"
            return 1
        fi
    fi

    # Generate Flask secret key if not exists or empty
    if [ -z "$FLASK_SECRET_KEY" ] || [ "$FLASK_SECRET_KEY" = "change-this-to-a-random-secret-key-in-production" ]; then
        FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        print_info "Nieuwe Flask secret key gegenereerd"
    fi

    # Create/Update .env from .env.example
    print_info "Genereren/updaten van .env bestand..."

    if [ ! -f .env.example ]; then
        print_error ".env.example niet gevonden!"
        return 1
    fi

    # Start with .env.example as base
    cp .env.example .env.new

    # Update with configured values (all variables from prompt_config)
    # Installation paths
    sed -i "s|^INSTALL_DIR=.*|INSTALL_DIR=$INSTALL_DIR|" .env.new
    sed -i "s|^DATA_DIR=.*|DATA_DIR=$DATA_DIR|" .env.new
    sed -i "s|^LOG_DIR=.*|LOG_DIR=$LOG_DIR|" .env.new

    # Database configuration
    sed -i "s|^DB_HOST=.*|DB_HOST=$DB_HOST|" .env.new
    sed -i "s|^DB_PORT=.*|DB_PORT=$DB_PORT|" .env.new
    sed -i "s|^DB_NAME=.*|DB_NAME=$DB_NAME|" .env.new
    sed -i "s|^DB_USER=.*|DB_USER=$DB_USER|" .env.new
    sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=$DB_PASS|" .env.new
    sed -i "s|^DB_TYPE=.*|DB_TYPE=postgresql|" .env.new

    # Dashboard configuration
    sed -i "s|^DASHBOARD_SERVER=.*|DASHBOARD_SERVER=$DASHBOARD_SERVER|" .env.new
    sed -i "s|^DASHBOARD_HOST=.*|DASHBOARD_HOST=$DASHBOARD_HOST|" .env.new
    sed -i "s|^DASHBOARD_PORT=.*|DASHBOARD_PORT=$DASHBOARD_PORT|" .env.new

    if [ ! -z "$DASHBOARD_WORKERS" ]; then
        sed -i "s|^DASHBOARD_WORKERS=.*|DASHBOARD_WORKERS=$DASHBOARD_WORKERS|" .env.new
    fi

    # Security
    sed -i "s|^FLASK_SECRET_KEY=.*|FLASK_SECRET_KEY=$FLASK_SECRET_KEY|" .env.new
    sed -i "s|^REQUIRE_2FA=.*|REQUIRE_2FA=$REQUIRE_2FA|" .env.new

    # MCP API configuration
    sed -i "s|^MCP_API_ENABLED=.*|MCP_API_ENABLED=$MCP_API_ENABLED|" .env.new
    sed -i "s|^MCP_API_HOST=.*|MCP_API_HOST=$MCP_API_HOST|" .env.new
    sed -i "s|^MCP_API_PORT=.*|MCP_API_PORT=$MCP_API_PORT|" .env.new
    sed -i "s|^MCP_API_WORKERS=.*|MCP_API_WORKERS=$MCP_API_WORKERS|" .env.new

    # Nginx (if configured)
    if [ ! -z "$DOMAIN_NAME" ]; then
        sed -i "s|^NGINX_SERVER_NAME=.*|NGINX_SERVER_NAME=$DOMAIN_NAME|" .env.new
    fi

    # Add MONITOR_INTERFACE and INTERNAL_NETWORK (these are not in .env.example by default)
    # Check if they exist in .env.new, if not add them
    if ! grep -q "^MONITOR_INTERFACE=" .env.new; then
        echo "" >> .env.new
        echo "# Network monitoring configuration (added by install script)" >> .env.new
        echo "MONITOR_INTERFACE=$INTERFACE" >> .env.new
        echo "INTERNAL_NETWORK=$INTERNAL_NET" >> .env.new
    else
        sed -i "s|^MONITOR_INTERFACE=.*|MONITOR_INTERFACE=$INTERFACE|" .env.new
        sed -i "s|^INTERNAL_NETWORK=.*|INTERNAL_NETWORK=$INTERNAL_NET|" .env.new
    fi

    # Move new .env into place
    mv .env.new .env
    chmod 600 .env
    print_success ".env bestand aangemaakt/bijgewerkt (chmod 600 voor security)"

    # Update config.yaml with basic settings
    if [ -f config.yaml ]; then
        # Update monitor interface (main setting)
        sed -i "s/^interface:.*/interface: $INTERFACE/" config.yaml

        # Update self_monitor.interface as well
        sed -i "/^self_monitor:/,/^[a-z]/ s/interface: .*/interface: $INTERFACE/" config.yaml

        # Update database password in config.yaml
        sed -i "s|password: netmonitor|password: $DB_PASS|" config.yaml
        sed -i "s|password: .*  # PostgreSQL password|password: $DB_PASS  # PostgreSQL password|" config.yaml

        # Update database host, port, name, user
        sed -i "/postgresql:/,/user:/ s|host: .*|host: $DB_HOST|" config.yaml
        sed -i "/postgresql:/,/port:/ s|port: .*|port: $DB_PORT|" config.yaml
        sed -i "/postgresql:/,/database:/ s|database: .*|database: $DB_NAME|" config.yaml
        sed -i "/postgresql:/,/user:/ s|user: .*|user: $DB_USER|" config.yaml

        print_info "config.yaml bijgewerkt met database en interface instellingen"
    else
        print_warning "config.yaml niet gevonden na kopiëren - check handmatig"
    fi

    print_success "Configuratie bestanden bijgewerkt"
}

init_database_schema() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 6/10: Database Schema Initialiseren"

    cd $INSTALL_DIR
    source venv/bin/activate

    # Verify config.yaml exists
    if [ ! -f config.yaml ]; then
        print_error "config.yaml niet gevonden!"
        print_error "Run 'configure_netmonitor' eerst"
        return 1
    fi

    # Create a temporary Python script with better error handling
    cat > /tmp/init_db.py << 'PYTHON_EOF'
import sys
import os

# Add install dir to path
sys.path.insert(0, os.environ.get('INSTALL_DIR', '/opt/netmonitor'))

try:
    from database import DatabaseManager
    from config_loader import load_config

    print("Loading config.yaml...")
    config = load_config('config.yaml')

    if 'database' not in config or 'postgresql' not in config['database']:
        print("ERROR: Database configuration not found in config.yaml", file=sys.stderr)
        sys.exit(1)

    db_config = config['database']['postgresql']

    print(f"Connecting to database {db_config['database']} at {db_config['host']}:{db_config['port']}...")

    db = DatabaseManager(
        host=db_config['host'],
        port=db_config['port'],
        database=db_config['database'],
        user=db_config['user'],
        password=db_config['password']
    )

    print("Database schema created successfully")
    sys.exit(0)

except Exception as e:
    print(f"ERROR: Database initialization failed: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTHON_EOF

    # Run the Python script with visible output
    print_info "Database schema wordt aangemaakt..."

    INSTALL_DIR=$INSTALL_DIR python3 /tmp/init_db.py
    DB_INIT_STATUS=$?

    # Clean up temp script
    rm -f /tmp/init_db.py

    if [ $DB_INIT_STATUS -ne 0 ]; then
        print_error "Database schema initialisatie mislukt!"
        print_error "Check de error messages hierboven"
        print_error "Log file: $LOG_FILE"
        return 1
    fi

    print_success "Database schema geïnitialiseerd"
}

download_bootstrap_assets() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "Bootstrap Assets Lokaal Downloaden"

    cd $INSTALL_DIR
    mkdir -p web/static/css web/static/js web/static/fonts

    print_info "Bootstrap CSS downloaden..."
    curl -sL https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css -o web/static/css/bootstrap.min.css || {
        print_error "Bootstrap CSS download mislukt"
        return 1
    }

    print_info "Bootstrap JS (bundle with Popper) downloaden..."
    curl -sL https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js -o web/static/js/bootstrap.bundle.min.js || {
        print_error "Bootstrap JS download mislukt"
        return 1
    }
    # Verify it includes Popper
    if ! grep -q "Popper" web/static/js/bootstrap.bundle.min.js 2>/dev/null; then
        print_warning "Bootstrap bundle might not include Popper.js"
    fi

    print_info "Bootstrap Icons CSS downloaden..."
    curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css -o web/static/css/bootstrap-icons.css || {
        print_error "Bootstrap Icons CSS download mislukt"
        return 1
    }

    print_info "Bootstrap Icons fonts downloaden..."
    curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff -o web/static/fonts/bootstrap-icons.woff || {
        print_warning "Bootstrap Icons font download mislukt (optioneel)"
    }
    curl -sL https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff2 -o web/static/fonts/bootstrap-icons.woff2 || {
        print_warning "Bootstrap Icons font download mislukt (optioneel)"
    }

    print_info "Chart.js downloaden..."
    curl -sL https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js -o web/static/js/chart.umd.min.js || {
        print_error "Chart.js download mislukt"
        return 1
    }

    print_info "Socket.IO client downloaden..."
    curl -sL https://cdn.socket.io/4.6.0/socket.io.min.js -o web/static/js/socket.io.min.js || {
        print_error "Socket.IO download mislukt"
        return 1
    }

    # Fix Bootstrap Icons CSS paths naar lokale fonts (use absolute path from web root)
    # Change CDN URLs: https://cdn.jsdelivr.net/.../fonts/file.woff2 -> /static/fonts/file.woff2
    sed -i 's|https://cdn.jsdelivr.net/npm/bootstrap-icons@[^/]*/font/fonts/|/static/fonts/|g' web/static/css/bootstrap-icons.css
    # Change relative paths: ./fonts/ -> /static/fonts/ (crucial fix for icon display)
    sed -i 's|url("./fonts/bootstrap-icons|url("/static/fonts/bootstrap-icons|g' web/static/css/bootstrap-icons.css
    sed -i "s|url('./fonts/bootstrap-icons|url('/static/fonts/bootstrap-icons|g" web/static/css/bootstrap-icons.css

    print_success "Bootstrap assets lokaal gedownload"
}

init_database_defaults() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "Database Default Configuratie Laden"

    cd $INSTALL_DIR
    source venv/bin/activate

    print_info "Default threshold waarden uit config.yaml laden in database..."

    python3 init_database_defaults.py >> $LOG_FILE 2>&1

    if [ $? -eq 0 ]; then
        print_success "Default thresholds geladen in database"
    else
        print_warning "Fout bij laden defaults - check $LOG_FILE"
    fi
}

download_threat_feeds() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 7/11: Threat Feeds Downloaden"

    cd $INSTALL_DIR
    source venv/bin/activate

    python3 update_feeds.py >> $LOG_FILE 2>&1
    print_success "Threat feeds gedownload"
}

setup_admin_user() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 8/11: Admin User Setup"

    cd $INSTALL_DIR
    source venv/bin/activate

    print_info "Nu wordt de eerste admin user aangemaakt voor het web dashboard"
    print_info "Deze user heeft volledige toegang tot de dashboard"
    echo

    # Run setup_admin_user.py interactively (not in background)
    python3 setup_admin_user.py

    echo
    print_success "Admin user aangemaakt"
}

setup_systemd_services() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 9/11: Systemd Services Setup"

    cd $INSTALL_DIR

    # Use install_services.sh to generate service files from templates
    print_info "Genereren van service files via install_services.sh..."

    # Run install_services.sh non-interactively (auto-enable services)
    # Set environment variable to enable auto-confirmation
    export AUTO_CONFIRM=yes
    bash install_services.sh >> $LOG_FILE 2>&1

    if [ $? -eq 0 ]; then
        print_success "Service files gegenereerd via templates"
    else
        print_error "Service generatie mislukt - check $LOG_FILE"
        return 1
    fi

    # Start main service
    systemctl start netmonitor >> $LOG_FILE 2>&1
    print_success "NetMonitor service gestart"

    # Start feed update timer
    systemctl start netmonitor-feed-update.timer >> $LOG_FILE 2>&1
    print_success "Feed update timer gestart"

    # Start MCP API if enabled
    if [[ $MCP_API_ENABLED == "true" ]]; then
        systemctl start netmonitor-mcp-http >> $LOG_FILE 2>&1
        print_success "MCP API service gestart"
    fi

    # Check status
    sleep 2
    if systemctl is-active --quiet netmonitor; then
        print_success "NetMonitor draait!"
    else
        print_error "NetMonitor failed to start - check logs:"
        echo "  sudo journalctl -u netmonitor -n 50"
    fi
}

setup_mcp_api() {
    if [[ ! $INSTALL_MCP =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 10/11: MCP HTTP API Server Setup"

    cd $INSTALL_DIR
    source venv/bin/activate

    # Install additional dependencies
    pip install fastapi uvicorn[standard] >> $LOG_FILE 2>&1

    # Setup MCP server
    cd mcp_server
    ./setup_http_api.sh >> $LOG_FILE 2>&1

    print_success "MCP API server geïnstalleerd"

    # Start service
    systemctl start netmonitor-mcp
    systemctl enable netmonitor-mcp

    if systemctl is-active --quiet netmonitor-mcp; then
        print_success "MCP API draait op http://localhost:8000"
    else
        print_warning "MCP API failed to start - check logs:"
        echo "  sudo journalctl -u netmonitor-mcp -n 50"
    fi
}

setup_nginx() {
    if [[ ! $INSTALL_NGINX =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 11/11: Nginx Reverse Proxy Setup"

    cd $INSTALL_DIR

    # Copy config
    cp nginx-netmonitor.conf /etc/nginx/sites-available/netmonitor

    # Update domain in config
    if [ ! -z "$DOMAIN_NAME" ]; then
        sed -i "s/soc\.example\.com/$DOMAIN_NAME/g" /etc/nginx/sites-available/netmonitor
    fi

    # Enable site
    ln -sf /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/

    # Test config
    if nginx -t >> $LOG_FILE 2>&1; then
        print_success "Nginx config valid"
        systemctl reload nginx
        print_success "Nginx reloaded"
    else
        print_error "Nginx config invalid - check manually"
        return
    fi

    # SSL certificate (if domain provided)
    if [ ! -z "$DOMAIN_NAME" ]; then
        print_info "SSL Certificate Setup"
        echo
        print_warning "Run this manually after installation:"
        echo "  sudo certbot --nginx -d $DOMAIN_NAME"
        echo
    fi
}

print_summary() {
    print_header "INSTALLATIE COMPLEET!"

    echo
    echo -e "${GREEN}✓ Installatie succesvol!${NC}"
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    if [[ $INSTALL_CORE =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}NetMonitor SOC Dashboard:${NC}"
        echo "  Local:  http://localhost:8080"
        echo "  Note:   Login required (use admin credentials created during setup)"
        if [ ! -z "$DOMAIN_NAME" ]; then
            echo "  Public: https://$DOMAIN_NAME (after SSL setup)"
        fi
        echo
    fi

    if [[ $INSTALL_MCP =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}MCP HTTP API:${NC}"
        echo "  URL:  http://localhost:8000"
        echo "  Docs: http://localhost:8000/docs"
        echo
    fi

    echo -e "${BLUE}Configuratie:${NC}"
    echo "  Interface:      $INTERFACE"
    echo "  Internal Net:   $INTERNAL_NET"
    echo "  Database:       $DB_NAME (user: $DB_USER)"
    echo "  Config File:    $INSTALL_DIR/config.yaml"
    echo
    echo -e "${BLUE}Services Status:${NC}"

    if [[ $INSTALL_CORE =~ ^[Yy]$ ]]; then
        if systemctl is-active --quiet netmonitor; then
            echo -e "  NetMonitor:     ${GREEN}running${NC}"
        else
            echo -e "  NetMonitor:     ${RED}stopped${NC}"
        fi
    fi

    if [[ $INSTALL_MCP =~ ^[Yy]$ ]]; then
        if systemctl is-active --quiet netmonitor-mcp; then
            echo -e "  MCP API:        ${GREEN}running${NC}"
        else
            echo -e "  MCP API:        ${RED}stopped${NC}"
        fi
    fi

    if [[ $INSTALL_DB =~ ^[Yy]$ ]]; then
        if systemctl is-active --quiet postgresql; then
            echo -e "  PostgreSQL:     ${GREEN}running${NC}"
        else
            echo -e "  PostgreSQL:     ${RED}stopped${NC}"
        fi
    fi

    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    echo -e "${YELLOW}Volgende Stappen:${NC}"
    echo
    echo "1. Login naar Dashboard:"
    echo "   URL: http://localhost:8080"
    echo "   User de admin credentials die je zojuist hebt aangemaakt"
    echo
    echo "2. Enable 2FA (aanbevolen):"
    echo "   - Login naar dashboard"
    echo "   - User menu (rechtsboven) → Two-Factor Auth"
    echo "   - Scan QR code met authenticator app"
    echo
    echo "3. Genereer Sensor Token (voor remote sensors):"
    echo "   cd $INSTALL_DIR"
    echo "   source venv/bin/activate"
    echo "   python3 setup_sensor_auth.py"
    echo
    echo "4. Configureer Sensors via Dashboard:"
    echo "   - Navigate naar Sensors tab"
    echo "   - Click 'Edit sensor settings' voor elke sensor"
    echo "   - Stel location en internal networks in"
    echo
    echo "5. Check Logs:"
    echo "   sudo journalctl -u netmonitor -f"
    echo
    echo "6. View Documentation:"
    echo "   - Admin Manual:  $INSTALL_DIR/ADMIN_MANUAL.md"
    echo "   - User Manual:   $INSTALL_DIR/USER_MANUAL.md"
    echo
    if [ ! -z "$DOMAIN_NAME" ]; then
        echo "7. Setup SSL Certificate:"
        echo "   sudo certbot --nginx -d $DOMAIN_NAME"
        echo
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_success "Installatie voltooid! Veel succes met je SOC! 🛡️"
    echo
}

# Main execution
main() {
    # Initialize log file immediately
    echo "=== NetMonitor Installation Log ===" > $LOG_FILE
    echo "Started: $(date)" >> $LOG_FILE
    echo >> $LOG_FILE

    clear

    print_header "NetMonitor SOC - Complete Installation"
    echo "Versie: 2.3.0"
    echo "Dit script installeert ALLES automatisch inclusief web authenticatie"
    echo "Ondersteunde OS: Ubuntu 24.04 & Debian 12"
    echo

    check_root
    check_os

    echo
    print_warning "BELANGRIJK:"
    echo "  - Dit script moet als root worden uitgevoerd"
    echo "  - Installatie duurt ~20-30 minuten"
    echo "  - Systeem packages worden automatisch geïnstalleerd/geüpdatet"
    echo "  - PostgreSQL database wordt aangemaakt (indien gekozen)"
    echo "  - Bestaande .env waarden worden gebruikt als defaults"
    echo "  - Log file: $LOG_FILE"
    echo
    read -p "Doorgaan met installatie? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installatie geannuleerd"
        exit 0
    fi

    # Run installation steps with error handling
    prompt_config || { print_error "Configuratie mislukt"; exit 1; }

    install_system_packages || { print_error "System packages installatie mislukt"; exit 1; }

    install_timescaledb || { print_error "TimescaleDB installatie mislukt"; exit 1; }

    setup_database || { print_error "Database setup mislukt"; exit 1; }

    install_netmonitor || { print_error "NetMonitor installatie mislukt"; exit 1; }

    configure_netmonitor || { print_error "NetMonitor configuratie mislukt"; exit 1; }

    download_bootstrap_assets || { print_error "Bootstrap assets download mislukt"; exit 1; }

    init_database_schema || { print_error "Database schema initialisatie mislukt"; exit 1; }

    init_database_defaults || { print_error "Database defaults laden mislukt"; exit 1; }

    download_threat_feeds || { print_error "Threat feeds download mislukt"; exit 1; }

    setup_admin_user || { print_error "Admin user setup mislukt"; exit 1; }

    setup_systemd_services || { print_error "Systemd services setup mislukt"; exit 1; }

    setup_mcp_api || { print_error "MCP API setup mislukt"; exit 1; }

    setup_nginx || { print_error "Nginx setup mislukt"; exit 1; }

    # Finish
    echo >> $LOG_FILE
    echo "Completed: $(date)" >> $LOG_FILE

    print_summary

    print_info "Installatie log: $LOG_FILE"

    # Run post-installation setup
    echo
    print_header "POST-INSTALLATIE SETUP"
    echo
    print_info "Running post-installation configuration..."

    if [ -f "$INSTALL_DIR/post_install.sh" ]; then
        cd $INSTALL_DIR
        if bash ./post_install.sh; then
            print_success "Post-installatie setup compleet"
        else
            print_warning "Post-installatie setup had warnings - check output above"
        fi
    else
        print_warning "post_install.sh niet gevonden in $INSTALL_DIR"
        echo "  Run handmatig: cd $INSTALL_DIR && ./post_install.sh"
    fi
}

# Run main
main "$@"
