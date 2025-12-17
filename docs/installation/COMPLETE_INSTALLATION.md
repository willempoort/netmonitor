# NetMonitor SOC - Complete Installation Guide

**Versie:** 2.0.0
**Datum:** 2025-11-28
**Installatie tijd:** ~30-45 minuten

Deze guide installeert **ALLES** in de juiste volgorde:
- PostgreSQL + TimescaleDB
- Python virtual environment + dependencies
- NetMonitor SOC (main + sensors)
- Sensor authenticatie
- MCP HTTP API server
- Nginx reverse proxy + SSL
- MFA (optioneel)

---

## 📋 **Vereisten**

### Hardware (Minimaal):
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disk**: 20 GB vrij
- **Network**: 1 Gbps interface

### Ondersteunde OS:
- Ubuntu 20.04/22.04 LTS ✅ (aanbevolen)
- Debian 11/12 ✅
- Andere Linux met systemd ⚠️ (mogelijk aanpassingen nodig)

### Root/Sudo toegang vereist!

---

## 🚀 **Quick Install (Automatisch)**

**Voor wie het snel wil:**

```bash
# 1. Clone repository
git clone https://github.com/yourusername/netmonitor.git
cd netmonitor

# 2. Run master installer (installeert ALLES)
sudo ./install_complete.sh

# 3. Follow prompts en wacht ~20-30 minuten
# Script doet:
#   - PostgreSQL + TimescaleDB installatie
#   - Python venv setup
#   - Database schema
#   - Systemd services
#   - Sensor token setup
#   - MCP API setup
#   - Nginx configuratie (optioneel)

# 4. Done! Open dashboard
# http://localhost:8080
```

**Spring naar:** [Post-Installation](#-post-installation) na automatische installatie.

---

## 📖 **Handmatige Installatie (Stap-voor-Stap)**

Voor wie controle wil of troubleshooting nodig heeft.

---

### **STAP 1: Systeem Voorbereiding**

#### 1.1 Systeem Updates
```bash
sudo apt update
sudo apt upgrade -y
```

#### 1.2 Benodigde Packages
```bash
sudo apt install -y \
  git \
  python3 \
  python3-pip \
  python3-venv \
  postgresql \
  postgresql-contrib \
  postgresql-server-dev-all \
  build-essential \
  libpcap-dev \
  tcpdump \
  nginx \
  certbot \
  python3-certbot-nginx
```

#### 1.3 Check Versies
```bash
python3 --version    # Should be 3.8+
psql --version       # Should be 12+
nginx -v             # Should be 1.18+
```

---

### **STAP 2: PostgreSQL + TimescaleDB Setup**

#### 2.1 PostgreSQL Configuratie
```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database user
sudo -u postgres psql << EOF
CREATE USER netmonitor WITH PASSWORD 'netmonitor';
CREATE DATABASE netmonitor OWNER netmonitor;
GRANT ALL PRIVILEGES ON DATABASE netmonitor TO netmonitor;
\q
EOF
```

#### 2.2 TimescaleDB Installatie
```bash
# Add TimescaleDB repository
sudo sh -c "echo 'deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescaledb.list"
wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | sudo apt-key add -

# Install TimescaleDB
sudo apt update
sudo apt install -y timescaledb-2-postgresql-14

# Configure PostgreSQL for TimescaleDB
sudo timescaledb-tune --quiet --yes

# Restart PostgreSQL
sudo systemctl restart postgresql
```

#### 2.3 Enable TimescaleDB Extension
```bash
sudo -u postgres psql -d netmonitor << EOF
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
\q
EOF
```

#### 2.4 Verify Installation
```bash
# Should show TimescaleDB version
sudo -u postgres psql -d netmonitor -c "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb';"
```

---

### **STAP 3: NetMonitor Installatie**

#### 3.1 Clone Repository
```bash
cd /opt
sudo git clone https://github.com/yourusername/netmonitor.git
cd netmonitor
sudo chown -R $USER:$USER /opt/netmonitor
```

#### 3.2 Python Virtual Environment
```bash
# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import scapy, psycopg2, flask; print('✓ All packages installed')"
```

#### 3.3 Directory Setup
```bash
# Create required directories
sudo mkdir -p /var/log/netmonitor
sudo mkdir -p /var/cache/netmonitor/feeds
sudo mkdir -p /var/lib/netmonitor

# Set permissions
sudo chown -R $USER:$USER /var/log/netmonitor
sudo chown -R $USER:$USER /var/cache/netmonitor
sudo chown -R $USER:$USER /var/lib/netmonitor
```

---

### **STAP 4: Database Schema Initialisatie**

```bash
# Run Python script to create all tables
python3 << EOF
import sys
sys.path.insert(0, '/opt/netmonitor')
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

print("✓ Database schema created")
print("✓ TimescaleDB hypertables created")
EOF
```

#### 4.1 Verify Database Schema
```bash
psql -U netmonitor -d netmonitor -c "\dt"

# Should show tables:
# - alerts
# - traffic_metrics
# - top_talkers
# - system_stats
# - sensors
# - sensor_metrics
# - sensor_commands
# - sensor_configs
# - ip_whitelists
# - sensor_tokens (NEW!)
```

---

### **STAP 5: Configuratie**

#### 5.1 Edit config.yaml
```bash
nano config.yaml
```

**Belangrijke settings:**
```yaml
# Network interface (WIJZIG DIT!)
interface: eth0  # Of 'any' voor alle interfaces

# Internal networks (WIJZIG DIT!)
internal_networks:
  - 192.168.1.0/24  # Jouw interne netwerk
  - 10.0.0.0/8

# Database (standaard is OK)
database:
  type: postgresql
  postgresql:
    host: localhost
    port: 5432
    database: netmonitor
    user: netmonitor
    password: netmonitor  # WIJZIG in productie!

# Dashboard
dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8080
  # Generate secret: python3 -c "import secrets; print(secrets.token_hex(32))"
  secret_key: "CHANGE-ME-IN-PRODUCTION"

# Threat feeds
threat_feeds:
  enabled: true
  feeds:
    - feodotracker
    - urlhaus
    - threatfox

# Detection thresholds (standaard is OK, tune later)
thresholds:
  port_scan:
    enabled: true
    unique_ports: 20
    time_window: 60

  dns_tunnel:
    enabled: true
    query_length_threshold: 50
    queries_per_minute: 150

  icmp_tunnel:
    enabled: true
    size_threshold: 500
    rate_threshold: 10

  # ... andere thresholds
```

#### 5.2 Download Threat Feeds
```bash
source venv/bin/activate
python3 update_feeds.py

# Should download:
# - FeodoTracker
# - URLhaus
# - ThreatFox
# - SSL Blacklist
```

---

### **STAP 6: Systemd Services**

#### 6.1 Main NetMonitor Service
```bash
# Copy service file
sudo cp netmonitor.service /etc/systemd/system/

# Edit if needed (check paths)
sudo nano /etc/systemd/system/netmonitor.service

# Should contain:
[Unit]
Description=NetMonitor SOC - Main Monitor
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netmonitor
ExecStart=/opt/netmonitor/venv/bin/python3 /opt/netmonitor/netmonitor.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 6.2 Threat Feed Update Service
```bash
# Copy service and timer
sudo cp netmonitor-feed-update.service /etc/systemd/system/
sudo cp netmonitor-feed-update.timer /etc/systemd/system/

# Enable timer (auto-update feeds every hour)
sudo systemctl daemon-reload
sudo systemctl enable netmonitor-feed-update.timer
sudo systemctl start netmonitor-feed-update.timer
```

#### 6.3 Enable and Start
```bash
# Enable main service
sudo systemctl daemon-reload
sudo systemctl enable netmonitor
sudo systemctl start netmonitor

# Check status
sudo systemctl status netmonitor
sudo systemctl status netmonitor-feed-update.timer

# View logs
sudo journalctl -u netmonitor -f
```

#### 6.4 Verify Dashboard
```bash
# Open browser:
http://localhost:8080

# Should show NetMonitor dashboard
# If not, check logs:
sudo journalctl -u netmonitor -n 50
```

---

### **STAP 7: Sensor Authentication Setup**

#### 7.1 Generate Master Token (for central SOC)
```bash
cd /opt/netmonitor
source venv/bin/activate

# Run token generator
python3 setup_sensor_auth.py

# Follow prompts:
Sensor ID: central-soc
Token name: Central SOC Token
Expires in days: (leave empty = never)
Allow remote commands? N

# SAVE THE TOKEN!
```

#### 7.2 Update Sensor Endpoints (Web Dashboard)
```bash
# Edit web_dashboard.py to require token auth
# Already implemented in version 2.0!

# Restart service
sudo systemctl restart netmonitor
```

---

### **STAP 8: Remote Sensors (Optioneel)**

**Skip dit als je alleen centrale monitoring wilt.**

#### 8.1 Install Sensor on Remote Machine

**Op remote machine (bijv. Nano Pi):**

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git tcpdump

# 2. Clone repo
cd /opt
sudo git clone https://github.com/yourusername/netmonitor.git
cd netmonitor

# 3. Setup venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-sensor.txt  # Lighter requirements for sensors

# 4. Configure
cp config.yaml sensor-config.yaml
nano sensor-config.yaml
# Edit: interface, internal_networks

# 5. Generate sensor token on CENTRAL server:
# (On central server)
python3 setup_sensor_auth.py
Sensor ID: nano-vlan10-01
Token name: VLAN 10 Sensor
Expires: 365
Commands: N
# COPY THE TOKEN

# 6. Setup environment (on sensor)
sudo nano /etc/systemd/system/netmonitor-sensor.service

[Unit]
Description=NetMonitor Remote Sensor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netmonitor
ExecStart=/opt/netmonitor/venv/bin/python3 /opt/netmonitor/sensor_client.py -c /opt/netmonitor/sensor-config.yaml
Environment="SOC_SERVER_URL=http://192.168.1.100:8080"
Environment="SENSOR_ID=nano-vlan10-01"
Environment="SENSOR_TOKEN=YOUR-TOKEN-HERE"
Environment="SENSOR_LOCATION=Building A - VLAN 10"
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target

# 7. Start sensor
sudo systemctl daemon-reload
sudo systemctl enable netmonitor-sensor
sudo systemctl start netmonitor-sensor

# 8. Check status
sudo systemctl status netmonitor-sensor
sudo journalctl -u netmonitor-sensor -f
```

#### 8.2 Verify on Dashboard
Open dashboard → Scroll to "Remote Sensors" → Should see sensor online

---

### **STAP 9: MCP HTTP API Server (Optioneel)**

**Voor AI integration (Claude Desktop, Open WebUI, etc.)**

#### 9.1 Install MCP Server
```bash
cd /opt/netmonitor

# Install additional dependencies
source venv/bin/activate
pip install fastapi uvicorn[standard]

# Setup MCP server
cd mcp_server
./setup_http_api.sh

# This creates:
# - /etc/systemd/system/netmonitor-mcp.service
# - Environment file with config
```

#### 9.2 Generate MCP Token
```bash
# Use database to create MCP access token
psql -U netmonitor -d netmonitor << EOF
-- This will be automated in token management UI
-- For now, use sensor token system
EOF

# Or use existing sensor auth system
python3 /opt/netmonitor/setup_sensor_auth.py
Sensor ID: mcp-api
Token name: MCP API Token
Expires: (empty)
Commands: Y  # MCP needs full access
```

#### 9.3 Start MCP Server
```bash
sudo systemctl start netmonitor-mcp
sudo systemctl enable netmonitor-mcp

# Check status
sudo systemctl status netmonitor-mcp

# Test API
curl http://localhost:8000/health

# Should return:
{
  "status": "healthy",
  "timestamp": "...",
  "database": "connected"
}
```

#### 9.4 API Documentation
```bash
# Open browser:
http://localhost:8000/docs

# Shows all available MCP tools and endpoints
```

---

### **STAP 10: Nginx Reverse Proxy + SSL (Productie)**

**Voor productie deployment met SSL en MFA**

#### 10.1 Basic Nginx Setup
```bash
# Copy nginx config
sudo cp nginx-netmonitor.conf /etc/nginx/sites-available/netmonitor

# Edit domain
sudo nano /etc/nginx/sites-available/netmonitor
# Change: soc.example.com → your-domain.com

# Enable site
sudo ln -s /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# If OK, reload
sudo systemctl reload nginx
```

#### 10.2 SSL Certificate (Let's Encrypt)
```bash
# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Follow prompts:
# - Email: your@email.com
# - Agree to ToS: Yes
# - Redirect HTTP to HTTPS: Yes

# Auto-renewal is enabled by default
# Test renewal:
sudo certbot renew --dry-run
```

#### 10.3 Verify HTTPS
```bash
# Open browser:
https://your-domain.com

# Should show NetMonitor dashboard with valid SSL
```

---

### **STAP 11: MFA Setup (Optioneel)**

**Voor extra beveiliging van web dashboard**

#### 11.1 Install Authelia (Recommended MFA solution)

**Via Docker:**
```bash
# Install Docker if not present
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Create Authelia config directory
sudo mkdir -p /opt/authelia
cd /opt/authelia

# Create configuration
sudo nano configuration.yml
```

**Authelia Config (minimal):**
```yaml
server:
  host: 0.0.0.0
  port: 9091

log:
  level: info

totp:
  issuer: NetMonitor SOC

authentication_backend:
  file:
    path: /config/users_database.yml

access_control:
  default_policy: deny
  rules:
    - domain: soc.example.com
      policy: two_factor

session:
  name: authelia_session
  secret: CHANGE_ME_TO_RANDOM_STRING
  expiration: 3600
  inactivity: 300
  domain: soc.example.com

storage:
  local:
    path: /config/db.sqlite3

notifier:
  filesystem:
    filename: /config/notification.txt
```

**Create users file:**
```bash
sudo nano users_database.yml
```

```yaml
users:
  admin:
    displayname: "Admin User"
    password: "$argon2id$v=19$m=65536,t=3,p=4$HASH"  # Generate with: authelia hash-password 'yourpassword'
    email: admin@example.com
    groups:
      - admins
      - dev
```

**Run Authelia:**
```bash
sudo docker run -d \
  --name authelia \
  -v /opt/authelia:/config \
  -p 9091:9091 \
  authelia/authelia:latest
```

#### 11.2 Test MFA
```bash
# Open browser:
https://your-domain.com

# Should redirect to Authelia login
# After login: Setup TOTP with phone app (Google Authenticator, etc.)
# Then: Access dashboard
```

---

### **STAP 12: Firewall Configuration**

```bash
# Allow SSH (important!)
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS (for Nginx)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow dashboard (if not behind Nginx)
sudo ufw allow 8080/tcp

# Allow MCP API (if needed externally)
sudo ufw allow 8000/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

---

## ✅ **Post-Installation**

### Verification Checklist

```bash
# 1. PostgreSQL running
sudo systemctl status postgresql
psql -U netmonitor -d netmonitor -c "SELECT COUNT(*) FROM alerts;"

# 2. NetMonitor service running
sudo systemctl status netmonitor
curl http://localhost:8080/api/status

# 3. Threat feeds downloaded
ls -lh /var/cache/netmonitor/feeds/

# 4. Dashboard accessible
# Browser: http://localhost:8080 (or https://your-domain.com)

# 5. Sensors connected (if applicable)
# Dashboard → Remote Sensors section

# 6. MCP API running (if installed)
curl http://localhost:8000/health

# 7. Logs clean (no errors)
sudo journalctl -u netmonitor -n 50
```

### First Steps After Installation

#### 1. Generate Dashboard Secret Key
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"

# Copy output and add to config.yaml:
dashboard:
  secret_key: "your-generated-key-here"

# Restart
sudo systemctl restart netmonitor
```

#### 2. Configure Whitelist
```bash
# Edit config.yaml
nano config.yaml

# Add trusted IPs/networks
whitelist:
  - 192.168.1.0/24
  - 10.0.0.0/8
  - 224.0.0.0/4  # Multicast

# Restart
sudo systemctl restart netmonitor
```

#### 3. Test Detection
```bash
# Generate test traffic to trigger alerts

# 1. Port scan (should trigger PORT_SCAN)
nmap -p 1-100 localhost

# 2. DNS tunnel test (should trigger DNS alerts)
dig $(python3 -c "print('a'*60)").example.com

# 3. Large ICMP (should trigger ICMP_LARGE_PAYLOAD)
ping -s 1000 8.8.8.8 -c 5

# Check dashboard for alerts
```

#### 4. Setup Monitoring
```bash
# Monitor logs
sudo journalctl -u netmonitor -f

# Monitor resources
top -p $(pgrep -f netmonitor.py)

# Database size
du -sh /var/lib/postgresql/14/main/
```

---

## 🔧 **Troubleshooting**

### Common Issues

#### Issue: "Permission denied" on packet capture
```bash
# Solution: Service must run as root
sudo systemctl status netmonitor

# Check User= in service file
sudo nano /etc/systemd/system/netmonitor.service
# Should be: User=root
```

#### Issue: "Database connection failed"
```bash
# Check PostgreSQL running
sudo systemctl status postgresql

# Check credentials
psql -U netmonitor -d netmonitor

# If fails, reset password:
sudo -u postgres psql -c "ALTER USER netmonitor PASSWORD 'netmonitor';"
```

#### Issue: "No alerts appearing"
```bash
# Check interface
ip link show

# Check config
grep interface config.yaml

# Check if packets captured
sudo tcpdump -i eth0 -c 10

# Check detector running
sudo journalctl -u netmonitor -n 100 | grep -i detector
```

#### Issue: "Sensor not connecting"
```bash
# On sensor, check connectivity
curl http://192.168.1.100:8080/api/status

# Check token
echo $SENSOR_TOKEN

# Check logs
sudo journalctl -u netmonitor-sensor -n 50
```

#### Issue: "MFA not working"
```bash
# Check Authelia running
docker ps | grep authelia
docker logs authelia

# Check Nginx config
sudo nginx -t
sudo nginx -s reload

# Check browser console (F12)
```

---

## 📊 **Performance Tuning**

### For High Traffic Networks (>1 Gbps)

```yaml
# In config.yaml:

# Increase thresholds to reduce false positives
thresholds:
  port_scan:
    unique_ports: 50  # Instead of 20
    time_window: 120  # Instead of 60

  dns_tunnel:
    queries_per_minute: 500  # Instead of 150

# Reduce logging verbosity
logging:
  level: WARNING  # Instead of INFO

# Increase database connection pool
database:
  postgresql:
    min_connections: 5
    max_connections: 20
```

### For Low Resources (Nano Pi)

```yaml
# Disable heavy features
threat_feeds:
  enabled: false  # Disable if not needed

# Increase batch intervals
alerts:
  batch_upload_interval: 120  # Instead of 60

# Reduce metrics frequency
performance:
  metrics_interval: 120  # Instead of 60
```

---

## 🔄 **Updates & Maintenance**

### Update NetMonitor
```bash
cd /opt/netmonitor

# Stop service
sudo systemctl stop netmonitor

# Backup config
cp config.yaml config.yaml.backup

# Pull updates
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Restart
sudo systemctl start netmonitor
```

### Database Maintenance
```bash
# Cleanup old alerts (older than 90 days)
psql -U netmonitor -d netmonitor << EOF
DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '90 days';
VACUUM ANALYZE alerts;
EOF

# Database size
psql -U netmonitor -d netmonitor -c "SELECT pg_size_pretty(pg_database_size('netmonitor'));"
```

### Log Rotation
```bash
# Create logrotate config
sudo nano /etc/logrotate.d/netmonitor

/var/log/netmonitor/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload netmonitor > /dev/null 2>&1 || true
    endscript
}
```

---

## 📚 **Additional Documentation**

- **Detection Features**: [DETECTION_FEATURES.md](DETECTION_FEATURES.md)
- **Remote Sensors**: [REMOTE_SENSORS.md](REMOTE_SENSORS.md)
- **Dashboard Guide**: [DASHBOARD.md](DASHBOARD.md)
- **MCP API**: [MCP_HTTP_API.md](MCP_HTTP_API.md)
- **Production**: [PRODUCTION.md](PRODUCTION.md)

---

## 🆘 **Support**

### Get Help
- Check logs: `sudo journalctl -u netmonitor -n 100`
- Check documentation: All `.md` files in repo
- GitHub Issues: `https://github.com/yourusername/netmonitor/issues`

### Reporting Bugs
Include:
1. OS version: `lsb_release -a`
2. NetMonitor version: `git log -1`
3. Error logs: `sudo journalctl -u netmonitor -n 200`
4. Config (redact passwords!)

---

**Installation Complete! 🎉**

**Next Steps:**
1. Access dashboard: `http://localhost:8080` (or `https://your-domain.com`)
2. Configure whitelist voor jouw netwerk
3. Setup remote sensors (optioneel)
4. Configure MFA (aanbevolen voor productie)
5. Monitor en tune thresholds

**Veel succes met je SOC! 🛡️**
