# NetMonitor Sensor Deployment Guide

Complete handleiding voor het opzetten van gedistribueerde netwerk monitoring met remote sensors.

## 📋 Overzicht

Remote sensors stellen je in staat om meerdere netwerk segmenten te monitoren zonder dat al het verkeer naar één centraal punt hoeft te worden gestuurd via switch mirror ports.

### Architectuur

```
┌─────────────────────────────────────────────────────────┐
│                  Central SOC Server                      │
│  ┌────────────────────────────────────────────────┐     │
│  │  - PostgreSQL + TimescaleDB                    │     │
│  │  - Web Dashboard (port 8080)                   │     │
│  │  - API Endpoints voor sensors                  │     │
│  │  - Centralized configuration management        │     │
│  └────────────────────────────────────────────────┘     │
└──────────────────────────▲──────────────────────────────┘
                           │ HTTPS + Token Auth
           ┌───────────────┼───────────────┐
           │               │               │
     ┌─────┴────┐    ┌─────┴────┐    ┌────┴─────┐
     │ Sensor 1 │    │ Sensor 2 │    │ Sensor 3 │
     │ Nano Pi  │    │ Nano Pi  │    │ Nano Pi  │
     │ VLAN 10  │    │ VLAN 20  │    │   DMZ    │
     └──────────┘    └──────────┘    └──────────┘
```

**Key Principles:**
- **Remote Sensors**: Run `sensor_client.py`, use `sensor.conf` (bash KEY=value format)
- **SOC Server**: Runs `netmonitor.py`, uses `config.yaml` (YAML format)
- **Configuration**: Detection settings managed centrally, sensors only need connection info
- **Authentication**: Token-based authentication voor veilige communicatie

### SOC Server vs Remote Sensors

| Component | SOC Server | Remote Sensors |
|-----------|------------|----------------|
| **Program** | `netmonitor.py` | `sensor_client.py` |
| **Config File** | `config.yaml` (YAML) | `sensor.conf` (bash) |
| **Self-Monitor** | Optional via `self_monitor.enabled` | Always monitors |
| **Heartbeat** | Implicit (via metrics, 60s) | Explicit (API call, 30s) |
| **Dashboard** | ✅ Runs web UI | ❌ No UI |
| **Database** | ✅ Direct access | ❌ API only |
| **Service** | `netmonitor.service` | `netmonitor-sensor.service` |

**IMPORTANT:** SOC server does NOT need `sensor_client.py`. The `netmonitor.py` program has built-in self-monitoring capability. Simply enable `self_monitor.enabled: true` in `config.yaml`.

### Voordelen

✅ **Schaalbaarheid** - Monitor meerdere network segmenten tegelijk
✅ **Geen mirror port bottleneck** - Elke sensor monitort lokaal
✅ **Cost-effective** - Nano Pi ~€35 vs dure managed switches
✅ **Flexible deployment** - Plaats sensors waar nodig
✅ **Lokale processing** - Detectie gebeurt op sensor
✅ **Centrale configuratie** - Alle settings via SOC dashboard
✅ **Token authenticatie** - Veilige sensor-server communicatie

---

## 🛠️ Hardware Requirements

### Aanbevolen: Nano Pi

**Nano Pi R2S** (~€35-45) ⭐ **Recommended**
- CPU: RK3328 Quad-core ARM Cortex-A53
- RAM: 1GB DDR4
- Network: 2x Gigabit Ethernet
- OS: Ubuntu/Armbian
- **Perfect voor 90% van use cases**

**Nano Pi R4S** (~€60-70) - Voor drukke netwerken
- CPU: RK3399 Hexa-core
- RAM: 4GB LPDDR4
- Network: 2x Gigabit Ethernet
- **Voor high-traffic environments (>500 Mbps)**

### Alternatieven

- **Raspberry Pi 4** (2GB+) - Goed, maar iets duurder
- **Rock Pi** - Vergelijkbaar met Nano Pi
- **Oude PC/laptop** - Werkt ook, meer power verbruik

### Netwerk Setup

Twee opties:

**1. Inline deployment** (Aanbevolen voor Nano Pi R2S/R4S)
```
Internet ──→ [eth0] Nano Pi [eth1] ──→ Internal Network
              └─ Mirror/analyze traffic
```

**2. Mirror/SPAN port** (Voor switch-based monitoring)
```
Switch (SPAN/Mirror Port) ──→ [eth0] Nano Pi [eth1] ──→ SOC Server
                               └─ Monitor only    └─ Management traffic
```

#### ⚠️ **BELANGRIJK: Mirror Port Configuratie**

**Meerdere NICs vereist:**
Sommige switches (zoals Allied Telesis) configureren mirror ports als **destination-only** (TX disabled). Dit betekent:

✅ **eth0** (mirror port) - Ontvangt gemirrord verkeer (RX only)
✅ **eth1** (management port) - Voor communicatie met SOC server (TX/RX)

**Gevolgen:**
- De sensor **moet minstens 2 network interfaces hebben**
- Mirror port kan geen uitgaand verkeer versturen
- Management verkeer (heartbeats, alerts) gaat via aparte interface

**Voordeel:**
- Sensor traffic naar SOC kan via apart netwerksegment (meer security)
- Mirror port blijft dedicated voor monitoring

**Configuratie:**
```bash
# sensor.conf
INTERFACE=eth0              # Monitor traffic op mirror port
# eth1 wordt automatisch gebruikt voor SOC communicatie
```

**Switch configuratie voorbeeld (Allied Telesis - GETEST):**
```
# Configureer port1.0.24 als mirror destination
# Mirror al het verkeer van port1.0.1 t/m port1.0.23 naar port1.0.24 (beide richtingen)

enable
configure terminal
interface port1.0.24
mirror interface none                                    # Clear previous config
mirror interface port1.0.1-port1.0.23 direction both    # Mirror ports 1-23 → 24
do write
exit
exit

# Verificatie:
show mirror interface
```

**Belangrijke notities:**
- Je configureert de **destination port** (waar de sensor aan hangt)
- `mirror interface none` wist eerdere mirror configuratie
- `direction both` mirrort zowel inbound als outbound verkeer
- Notatie: `port1.0.1-port1.0.23` (met volledige port nummer na streepje)
- **NIET** gebruiken: `mirror session` syntax (oudere/andere modellen)

---

## 📦 Software Installatie

### Stap 1: Prepare Nano Pi

```bash
# 1. Flash Armbian/Ubuntu op SD card
#    Download: https://www.armbian.com/nanopi-r2s/

# 2. Boot en login (default: root/1234)

# 3. Update system
apt update && apt upgrade -y

# 4. Install dependencies
apt install -y python3 python3-pip python3-venv git tcpdump libpcap-dev
```

### Stap 2: Clone Repository

```bash
# Clone netmonitor repository
cd /opt
git clone https://github.com/yourusername/netmonitor.git
cd netmonitor
```

### Stap 3: Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### Stap 4: Generate Sensor Token

**Op de SOC Server:**

```bash
cd /opt/netmonitor
source venv/bin/activate
python3 setup_sensor_auth.py
```

Volg de prompts:
```
Sensor ID (e.g., nano-vlan10-01): nano-office-dmz-01
Token name (optional): DMZ Sensor Main Token
Expires in days (leave empty for no expiration): <Enter>
Allow remote commands? (y/N): N
```

Output:
```
TOKEN: abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx
```

**⚠️ SAVE THIS TOKEN - IT WILL NOT BE SHOWN AGAIN!**

### Stap 5: Configure Sensor

**Optie A: Interactive setup (Recommended)**

```bash
./setup_sensor.sh
```

**Optie B: Manual configuration**

```bash
cp sensor.conf.template sensor.conf
nano sensor.conf
```

Edit `sensor.conf`:

```bash
# Network interface to monitor
INTERFACE=eth0

# SOC Server URL (REQUIRED)
SOC_SERVER_URL=https://soc.example.com:8080

# Unique Sensor ID (REQUIRED)
SENSOR_ID=nano-office-dmz-01

# Sensor Location Description (REQUIRED)
SENSOR_LOCATION=Main Office - DMZ - Edge Network

# Authentication Token (REQUIRED for production)
SENSOR_TOKEN=abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx

# Internal networks (comma-separated CIDR ranges)
INTERNAL_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Heartbeat interval (seconds)
HEARTBEAT_INTERVAL=30

# Config sync interval (seconds)
CONFIG_SYNC_INTERVAL=300

# Enable SSL verification (true/false)
SSL_VERIFY=true
```

### Stap 6: Whitelist SOC Server (BELANGRIJK voor mirror port setups!)

**Waarom nodig:**
Bij mirror port configuraties ziet de sensor zijn **eigen uitgaande verkeer** naar de SOC server via de mirror. Dit veroorzaakt false positive brute force alerts omdat meerdere HTTPS requests naar dezelfde server worden gedetecteerd.

**Symptoom:**
```
⚠️ [HIGH] BRUTE_FORCE_ATTEMPT: Mogelijke brute force aanval op HTTPS: 5 pogingen
```

**Oplossing - Whitelist via sensor.conf:**

```bash
nano sensor.conf

# Voeg toe (onderaan):
SENSOR_WHITELIST=soc.poort.net

# Of met IP adres:
SENSOR_WHITELIST=10.100.0.100/32

# Meerdere entries (comma-separated):
SENSOR_WHITELIST=soc.poort.net,10.100.0.100/32
```

**Alternatief - Whitelist via Dashboard:**
1. Login op SOC Dashboard
2. Navigeer naar **Whitelist Management**
3. Klik **Add Entry**
4. Vul in:
   - IP/Domain: `soc.poort.net`
   - Scope: `Sensor-specific`
   - Sensor: `sensor-8282b4`
   - Comment: `SOC server - prevent false positives`
5. Klik **Save**

### Stap 7: Test Configuration

```bash
# Test sensor in foreground (Ctrl+C to stop)
sudo python3 sensor_client.py -c sensor.conf

# Check for errors in output
# Should see: "Registered sensor..." and "Config synced from server..."
# Should NOT see brute force alerts for SOC server communication
```

### Stap 8: Install Systemd Service

```bash
# Copy service file
sudo cp netmonitor-sensor.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable netmonitor-sensor
sudo systemctl start netmonitor-sensor

# Check status
sudo systemctl status netmonitor-sensor
```

### Stap 9: Verify in Dashboard

1. Open SOC dashboard: `https://soc.example.com:8080`
2. Login
3. Navigate to **Sensors** → **Remote Sensors**
4. Verify sensor appears in list with status "Online"

---

## 🔐 Authentication & Security

### Token Management

**Generate new token:**
```bash
cd /opt/netmonitor
python3 setup_sensor_auth.py
```

**List existing tokens:**
```bash
python3 -c "from sensor_auth import SensorAuthManager; from database import DatabaseManager; from config_loader import load_config; config=load_config('config.yaml'); db=DatabaseManager(**config['database']['postgresql']); auth=SensorAuthManager(db); tokens=auth.list_tokens(); print('\n'.join([f'{t[\"sensor_id\"]}: {t[\"token_name\"]}' for t in tokens]))"
```

**Revoke token:**
```bash
# Via database
psql -U netmonitor -d netmonitor
DELETE FROM sensor_tokens WHERE sensor_id = 'nano-office-dmz-01';
```

### Security Best Practices

1. **Always use HTTPS** for production deployments
2. **Use unique tokens** per sensor
3. **Set token expiration** for high-security environments
4. **Rotate tokens** periodically (every 90 days)
5. **Monitor failed auth** attempts in SOC logs
6. **Firewall sensor** to only communicate with SOC server

---

## 📊 Configuration Management

### How Detection Settings Work

1. **Sensor startup**: Loads minimal `sensor.conf` (connection info only)
2. **Initial sync**: Fetches detection thresholds from SOC server database
3. **Periodic sync**: Updates configuration every 5 minutes (configurable)
4. **Dashboard changes**: SOC admin updates thresholds via web UI
5. **Auto-propagation**: All sensors receive new settings within 5 minutes

**Example flow:**
```
SOC Admin (Web UI)
    ↓
Updates port_scan.unique_ports = 15
    ↓
Saved to PostgreSQL database
    ↓ (within 5 minutes)
All sensors fetch new config
    ↓
Detection updated across all sensors
```

### Override Configuration Sync Interval

To sync more frequently:
```bash
# In sensor.conf
CONFIG_SYNC_INTERVAL=60  # Sync every minute
```

---

## 🚀 Deployment Scenarios

### Scenario 1: Multi-VLAN Office Network

**DMZ Sensor** (`sensor.conf`):
```bash
INTERFACE=eth1
SOC_SERVER_URL=https://soc.internal.example.com:8443
SENSOR_ID=nano-dmz-edge-01
SENSOR_LOCATION=DMZ - Edge Network - Public Servers
SENSOR_TOKEN=abc123_dmz_token
SSL_VERIFY=true
```

**Internal Office Sensor** (`sensor.conf`):
```bash
INTERFACE=eth0
SOC_SERVER_URL=https://soc.internal.example.com:8443
SENSOR_ID=nano-office-vlan10-01
SENSOR_LOCATION=Main Office - VLAN 10 - Workstations
SENSOR_TOKEN=def456_office_token
SSL_VERIFY=true
```

**Production Server Sensor** (`sensor.conf`):
```bash
INTERFACE=eth0
SOC_SERVER_URL=https://soc.internal.example.com:8443
SENSOR_ID=nano-datacenter-prod-01
SENSOR_LOCATION=Datacenter - Production VLAN
SENSOR_TOKEN=ghi789_prod_token
SSL_VERIFY=true
```

### Scenario 2: Remote Branch Offices

**Remote Site Sensor**:
```bash
INTERFACE=eth0
SOC_SERVER_URL=https://soc.company.com:8443
SENSOR_ID=nano-branch-amsterdam-01
SENSOR_LOCATION=Amsterdam Branch Office - Main Network
SENSOR_TOKEN=jkl012_amsterdam_token
SSL_VERIFY=true
HEARTBEAT_INTERVAL=60  # More frequent for remote sites
```

### Scenario 3: Guest WiFi Monitoring

**Guest Network Sensor**:
```bash
INTERFACE=wlan0
SOC_SERVER_URL=https://soc.internal.example.com:8443
SENSOR_ID=nano-wifi-guest-01
SENSOR_LOCATION=Building A - Guest WiFi Network
SENSOR_TOKEN=mno345_guest_token
SSL_VERIFY=true
INTERNAL_NETWORKS=10.50.0.0/24  # Guest network only
```

---

## 🔧 Monitoring & Troubleshooting

### Check Sensor Status

```bash
# Service status
sudo systemctl status netmonitor-sensor

# Live logs
sudo journalctl -u netmonitor-sensor -f

# Recent errors
sudo journalctl -u netmonitor-sensor --since "10 minutes ago" -p err

# Config sync status
sudo journalctl -u netmonitor-sensor | grep -i "config sync"
```

### Common Issues

#### 1. Sensor not appearing in SOC dashboard

**Symptoms:**
- Service running but not visible in sensor list

**Diagnosis:**
```bash
# Check connectivity
curl -v https://soc.example.com:8443/api/sensors

# Check logs for registration errors
sudo journalctl -u netmonitor-sensor | grep -i "register\|connection\|token"
```

**Solutions:**
- ✓ Verify `SOC_SERVER_URL` is correct (check HTTPS vs HTTP)
- ✓ Check firewall allows outbound HTTPS (port 8443)
- ✓ Verify `SENSOR_TOKEN` is correct and not expired
- ✓ Check SOC server is running: `sudo systemctl status netmonitor`

#### 2. Authentication failures

**Symptoms:**
```
ERROR - Authentication failed: Invalid token
```

**Solutions:**
```bash
# 1. Generate new token on SOC server
cd /opt/netmonitor
python3 setup_sensor_auth.py

# 2. Update sensor.conf with new token
nano /opt/netmonitor/sensor.conf
# Update SENSOR_TOKEN=...

# 3. Restart sensor
sudo systemctl restart netmonitor-sensor
```

#### 3. Configuration not syncing from SOC

**Symptoms:**
- Sensor uses outdated detection thresholds
- No "Config synced" messages in logs

**Diagnosis:**
```bash
# Check config sync logs
sudo journalctl -u netmonitor-sensor | grep -i "config"

# Check API accessibility
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://soc.example.com:8443/api/config
```

**Solutions:**
- ✓ Verify `CONFIG_SYNC_INTERVAL` is set (default: 300s)
- ✓ Check token has correct permissions
- ✓ Verify database has default config loaded (run `init_database_defaults.py` on SOC server)
- ✓ Restart sensor: `sudo systemctl restart netmonitor-sensor`

#### 4. Permission errors (packet capture)

**Symptoms:**
```
PermissionError: Operation not permitted
```

**Solutions:**
```bash
# Ensure service runs as root
sudo systemctl edit netmonitor-sensor

# Add:
[Service]
User=root

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart netmonitor-sensor
```

#### 5. High CPU/Memory usage

**Symptoms:**
- Nano Pi becomes slow or unresponsive
- CPU at 100%

**Diagnosis:**
```bash
# Check resource usage
top
htop

# Check packet rate
sudo tcpdump -i eth0 -nn -q | pv -l > /dev/null
```

**Solutions:**
- ✓ Reduce detection frequency in SOC dashboard
- ✓ Disable unused detection modules
- ✓ Upgrade to Nano Pi R4S for high-traffic networks
- ✓ Use packet sampling (monitor every Nth packet)

---

## 📐 Sensor Naming Convention

Use descriptive, hierarchical sensor IDs:

```
{device}-{location}-{network}-{number}

Examples:
- nano-hq-dmz-edge-01
- nano-branch-nyc-office-01
- nano-dc-prod-db-01
- nano-wifi-guest-01
- rpi-home-lab-monitor-01
```

**Benefits:**
- Easy to identify in dashboard
- Logical grouping by location
- Scalable naming scheme

---

## 🎯 Network Placement Best Practices

**Optimal sensor placement:**

1. **Edge/DMZ** (Priority: HIGH)
   - Monitor external threats
   - Place: Between firewall and public-facing servers

2. **VLAN boundaries** (Priority: HIGH)
   - Monitor inter-VLAN traffic
   - Place: At VLAN routing points

3. **Critical servers** (Priority: MEDIUM)
   - Database servers
   - File servers
   - Application servers

4. **User networks** (Priority: MEDIUM)
   - Office workstations
   - Developer networks

5. **Guest networks** (Priority: LOW)
   - Visitor WiFi
   - IoT devices

---

## 🔄 Migration from config.yaml to sensor.conf

If you have an existing sensor using `config.yaml`:

### Step 1: Backup

```bash
cp config.yaml config.yaml.backup
```

### Step 2: Generate Token on SOC Server

```bash
cd /opt/netmonitor
python3 setup_sensor_auth.py
# Save the generated token
```

### Step 3: Create sensor.conf

```bash
./setup_sensor.sh
# OR manually create from template
cp sensor.conf.template sensor.conf
```

Extract these values from old `config.yaml`:
- `interface` → `INTERFACE`
- `self_monitor.sensor_id` → `SENSOR_ID`
- `self_monitor.location` → `SENSOR_LOCATION`
- SOC server URL (new field)
- Token from Step 2 (new field)

### Step 4: Update Service

```bash
# Edit service file to use sensor_client.py
sudo nano /etc/systemd/system/netmonitor-sensor.service

# Change ExecStart to:
ExecStart=/opt/netmonitor/venv/bin/python3 /opt/netmonitor/sensor_client.py -c /opt/netmonitor/sensor.conf

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart netmonitor-sensor
```

### Step 5: Verify

```bash
# Check logs
sudo journalctl -u netmonitor-sensor -f

# Verify in SOC dashboard
# Should see sensor in "Remote Sensors" list
```

---

## 📋 Configuration Reference

### sensor.conf vs config.yaml

| Feature | sensor.conf (Sensor) | config.yaml (SOC Server) |
|---------|---------------------|--------------------------|
| **Size** | ~15 lines | ~300+ lines |
| **Purpose** | Connection settings only | Full configuration |
| **Detection thresholds** | ❌ (from SOC server) | ✅ (managed locally) |
| **Database** | ❌ | ✅ PostgreSQL + TimescaleDB |
| **Dashboard** | ❌ | ✅ Web UI on port 8080 |
| **Threat feeds** | ❌ | ✅ Multiple sources |
| **GeoIP** | ❌ | ✅ MaxMind GeoLite2 |
| **Authentication** | ✅ Token-based | ✅ Manages tokens |
| **Use case** | Remote sensors | Central SOC server |

### sensor.conf Fields Reference

#### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `INTERFACE` | Network interface to monitor | `eth0`, `ens33`, `wlan0` |
| `SOC_SERVER_URL` | URL of SOC server dashboard | `https://soc.example.com:8443` |
| `SENSOR_ID` | Unique identifier for this sensor | `nano-office-01` |
| `SENSOR_LOCATION` | Human-readable location | `Building A - VLAN 10` |
| `SENSOR_TOKEN` | Authentication token from SOC server | `abc123...` |

#### Optional Fields

| Field | Default | Description |
|-------|---------|-------------|
| `INTERNAL_NETWORKS` | RFC1918 ranges | Internal network CIDRs (comma-separated) |
| `HEARTBEAT_INTERVAL` | `30` | Status update frequency (seconds) |
| `CONFIG_SYNC_INTERVAL` | `300` | Configuration fetch frequency (seconds) |
| `SSL_VERIFY` | `true` | Verify SSL certificates |

---

## 🆘 Support & Resources

**Logs:**
```bash
sudo journalctl -u netmonitor-sensor -f
```

**SOC Dashboard:**
- Sensors status: `/sensors`
- Configuration: `/config`
- Alerts: `/alerts`

**Common Commands:**
```bash
# Restart sensor
sudo systemctl restart netmonitor-sensor

# View sensor config
cat /opt/netmonitor/sensor.conf

# Test connectivity
curl -v https://soc.example.com:8443/api/sensors

# Check sensor status in database (on SOC server)
psql -U netmonitor -d netmonitor -c "SELECT sensor_id, status, last_seen FROM sensors;"
```

**Documentation:**
- `README.md` - Project overview
- `AUTHENTICATION.md` - Detailed authentication setup
- `CONFIG.md` - Configuration options

---

## 🔖 Quick Reference Card

**Sensor Setup (5 minutes):**

```bash
# 1. On SOC Server: Generate token
python3 setup_sensor_auth.py

# 2. On Sensor: Setup
cd /opt/netmonitor
./setup_sensor.sh

# 3. Install service
sudo cp netmonitor-sensor.service /etc/systemd/system/
sudo systemctl enable --now netmonitor-sensor

# 4. Verify
sudo systemctl status netmonitor-sensor
```

**Troubleshooting Checklist:**
- [ ] Service running? `systemctl status netmonitor-sensor`
- [ ] Network connectivity? `ping soc.example.com`
- [ ] Token valid? Check SOC dashboard → Sensors
- [ ] Config syncing? `journalctl -u netmonitor-sensor | grep "Config sync"`
- [ ] Firewall open? `curl -v https://soc.example.com:8443`

---

*Last updated: December 2025*
