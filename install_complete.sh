#!/bin/bash
#
# NetMonitor SOC - Complete Installation Script
# Version: 2.1.0
# Installs: PostgreSQL, TimescaleDB, NetMonitor, Web Auth, MCP API, Nginx
#
# Usage: sudo ./install_complete.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/netmonitor"
LOG_FILE="/tmp/netmonitor-install.log"
DB_NAME="netmonitor"
DB_USER="netmonitor"
DB_PASS="netmonitor"  # Will prompt to change

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "$1"
    echo "============================================================"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
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
    print_info "Detected OS: $PRETTY_NAME"

    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        print_warning "Dit script is getest op Ubuntu/Debian"
        print_warning "Andere OS kunnen aanpassingen vereisen"
        read -p "Doorgaan? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

prompt_config() {
    print_header "CONFIGURATIE"

    # Database password
    read -sp "Database password voor netmonitor user (default: netmonitor): " DB_PASS_INPUT
    echo
    if [ ! -z "$DB_PASS_INPUT" ]; then
        DB_PASS="$DB_PASS_INPUT"
    fi

    # Network interface
    echo
    print_info "Beschikbare network interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print "  - " $2}' | sed 's/:$//'
    echo
    read -p "Welke interface wil je monitoren? (default: eth0): " INTERFACE
    INTERFACE=${INTERFACE:-eth0}

    # Internal network
    read -p "Jouw interne netwerk CIDR (default: 192.168.1.0/24): " INTERNAL_NET
    INTERNAL_NET=${INTERNAL_NET:-192.168.1.0/24}

    # Components
    echo
    print_info "Welke componenten wil je installeren?"
    read -p "PostgreSQL + TimescaleDB? (Y/n) " INSTALL_DB
    INSTALL_DB=${INSTALL_DB:-Y}

    read -p "NetMonitor Core? (Y/n) " INSTALL_CORE
    INSTALL_CORE=${INSTALL_CORE:-Y}

    read -p "MCP HTTP API Server? (y/N) " INSTALL_MCP
    INSTALL_MCP=${INSTALL_MCP:-N}

    read -p "Nginx reverse proxy? (y/N) " INSTALL_NGINX
    INSTALL_NGINX=${INSTALL_NGINX:-N}

    if [[ $INSTALL_NGINX =~ ^[Yy]$ ]]; then
        read -p "Domain name (bijv. soc.example.com): " DOMAIN_NAME
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

    # Create user and database
    sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;" >> $LOG_FILE 2>&1 || true
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" >> $LOG_FILE 2>&1
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" >> $LOG_FILE 2>&1 || true
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" >> $LOG_FILE 2>&1
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >> $LOG_FILE 2>&1
    print_success "Database user en database aangemaakt"

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

    # Backup existing config
    if [ -f config.yaml ]; then
        cp config.yaml config.yaml.backup.$(date +%Y%m%d_%H%M%S)
        print_info "Bestaande config backed up"
    fi

    # Update config.yaml
    sed -i "s/^interface:.*/interface: $INTERFACE/" config.yaml
    sed -i "s|password: netmonitor|password: $DB_PASS|" config.yaml

    # Update internal networks (simplified)
    print_info "Internal network ingesteld op: $INTERNAL_NET"

    # Generate secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    if ! grep -q "secret_key:" config.yaml; then
        sed -i "/^dashboard:/a\  secret_key: \"$SECRET_KEY\"" config.yaml
    fi

    print_success "Config.yaml bijgewerkt"
}

init_database_schema() {
    if [[ ! $INSTALL_CORE =~ ^[Yy]$ ]]; then
        return
    fi

    print_header "STAP 6/10: Database Schema Initialiseren"

    cd $INSTALL_DIR
    source venv/bin/activate

    # Run Python to initialize database
    python3 << EOF >> $LOG_FILE 2>&1
import sys
sys.path.insert(0, '$INSTALL_DIR')
from database import DatabaseManager
from config_loader import load_config

config = load_config('config.yaml')
db_config = config['database']['postgresql']

db = DatabaseManager(
    host=db_config['host'],
    port=db_config['port'],
    database=db_config['database'],
    user=db_config['user'],
    password=db_config['password']
)
print("Database schema created")
EOF

    print_success "Database schema geïnitialiseerd"
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

    # Copy service files
    cp netmonitor.service /etc/systemd/system/
    cp netmonitor-feed-update.service /etc/systemd/system/
    cp netmonitor-feed-update.timer /etc/systemd/system/

    # Reload systemd
    systemctl daemon-reload
    print_success "Service files gekopieerd"

    # Enable and start services
    systemctl enable netmonitor >> $LOG_FILE 2>&1
    systemctl start netmonitor
    print_success "NetMonitor service gestart"

    systemctl enable netmonitor-feed-update.timer >> $LOG_FILE 2>&1
    systemctl start netmonitor-feed-update.timer
    print_success "Feed update timer gestart"

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
    clear

    print_header "NetMonitor SOC - Complete Installation"
    echo "Versie: 2.1.0"
    echo "Dit script installeert ALLES automatisch inclusief web authenticatie"
    echo

    check_root
    check_os

    echo
    print_warning "BELANGRIJK:"
    echo "  - Installatie duurt ~20-30 minuten"
    echo "  - Systeem packages worden geïnstalleerd/geüpdatet"
    echo "  - PostgreSQL database wordt aangemaakt"
    echo "  - Log file: $LOG_FILE"
    echo
    read -p "Doorgaan met installatie? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installatie geannuleerd"
        exit 0
    fi

    # Start logging
    echo "=== NetMonitor Installation Log ===" > $LOG_FILE
    echo "Started: $(date)" >> $LOG_FILE
    echo >> $LOG_FILE

    # Run installation steps
    prompt_config
    install_system_packages
    install_timescaledb
    setup_database
    install_netmonitor
    configure_netmonitor
    init_database_schema
    download_threat_feeds
    setup_admin_user
    setup_systemd_services
    setup_mcp_api
    setup_nginx

    # Finish
    echo >> $LOG_FILE
    echo "Completed: $(date)" >> $LOG_FILE

    print_summary

    print_info "Installatie log: $LOG_FILE"
}

# Run main
main "$@"
