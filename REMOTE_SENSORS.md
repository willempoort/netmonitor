# Remote Sensor Deployment Guide

Uitgebreide handleiding voor het opzetten van gedistribueerde netwerk monitoring met Nano Pi (of andere lightweight Linux devices).

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
│  └────────────────────────────────────────────────┘     │
└──────────────────────────▲──────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
     ┌─────┴────┐    ┌─────┴────┐    ┌────┴─────┐
     │ Sensor 1 │    │ Sensor 2 │    │ Sensor 3 │
     │ Nano Pi  │    │ Nano Pi  │    │ Nano Pi  │
     │ VLAN 10  │    │ VLAN 20  │    │   DMZ    │
     └──────────┘    └──────────┘    └──────────┘
```

### Voordelen

✅ **Schaalbaarheid** - Monitor meerdere network segmenten tegelijk
✅ **Geen mirror port bottleneck** - Elke sensor monitort lokaal
✅ **Cost-effective** - Nano Pi ~€35 vs dure managed switches
✅ **Flexible deployment** - Plaats sensors waar nodig
✅ **Lokale processing** - Detectie gebeurt op sensor
✅ **Batch upload** - Efficiënte netwerk gebruik

## 🛠️ Hardware Requirements

### Aanbevolen: Nano Pi

**Nano Pi R2S** (~€35-45)
- CPU: RK3328 Quad-core ARM Cortex-A53
- RAM: 1GB DDR4
- Network: 2x Gigabit Ethernet
- OS: Ubuntu/Armbian

**Nano Pi R4S** (~€60-70) - Voor drukke netwerken
- CPU: RK3399 Hexa-core
- RAM: 4GB LPDDR4
- Network: 2x Gigabit Ethernet

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

**2. Mirror port** (Voor single ethernet devices)
```
Switch (SPAN/Mirror Port) ──→ Nano Pi
```

## 📦 Software Installatie

### Stap 1: Prepare Nano Pi

```bash
# 1. Flash Armbian/Ubuntu op SD card
#    Download: https://www.armbian.com/nanopi-r2s/

# 2. Boot en login (default: root/1234)

# 3. Update system
apt update && apt upgrade -y

# 4. Install dependencies
apt install -y python3 python3-pip python3-venv git tcpdump
```

### Stap 2: Clone Repository

```bash
# Clone netmonitor repository
cd /opt
git clone https://github.com/yourusername/netmonitor.git
cd netmonitor
```

### Stap 3: Setup Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Install dependencies (lightweight for sensors!)
venv/bin/pip install -r requirements-sensor.txt

# Note: Use requirements.txt only on central SOC server
```

### Stap 4: Configure Sensor

```bash
# Copy example config
cp config.yaml sensor-config.yaml

# Edit configuration
nano sensor-config.yaml
```

**sensor-config.yaml aanpassingen:**

```yaml
# Interface to monitor
interface: eth0  # Of eth1 voor inline deployment

# Internal networks (BELANGRIJK!)
internal_networks:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 192.168.10.0/24  # Pas aan naar jouw VLAN

# Detection thresholds (optioneel: verlaag voor kleinere netwerken)
thresholds:
  port_scan:
    enabled: true
    unique_ports: 15  # Lager voor kleine netwerken
    time_window: 60

# Threat feeds
threat_feeds:
  enabled: true  # Recommended
  feeds:
    - feodotracker
    - urlhaus

# AbuseIPDB (optioneel)
abuseipdb:
  enabled: false  # Stel in op central server
```

### Stap 5: Configure Environment Variables

```bash
# Create sensor environment file
cat > /opt/netmonitor/sensor.env << 'EOF'
# Central SOC Server URL
SOC_SERVER_URL=http://192.168.1.100:8080

# Unique sensor ID (wijzig per sensor!)
SENSOR_ID=nano-vlan10-01

# Sensor location beschrijving
SENSOR_LOCATION=Building A - VLAN 10 - Production
EOF
```

**Let op:**
- `SOC_SERVER_URL`: IP adres van je centrale SOC server
- `SENSOR_ID`: Moet uniek zijn per sensor!
- `SENSOR_LOCATION`: Duidelijke beschrijving voor dashboard

### Stap 6: Test Sensor

```bash
# Load environment
source sensor.env

# Test sensor (manual)
sudo /opt/netmonitor/venv/bin/python3 /opt/netmonitor/sensor_client.py \
  -c /opt/netmonitor/sensor-config.yaml \
  --server-url $SOC_SERVER_URL \
  --sensor-id $SENSOR_ID \
  --location "$SENSOR_LOCATION"
```

Je zou moeten zien:
```
Sensor ID: nano-vlan10-01
Location: Building A - VLAN 10 - Production
SOC Server: http://192.168.1.100:8080
✓ Sensor registered successfully
Starting packet capture...
```

Druk Ctrl+C om te stoppen.

### Stap 7: Install Systemd Service

```bash
# Copy service file
sudo cp netmonitor-sensor.service /etc/systemd/system/

# Edit service file
sudo nano /etc/systemd/system/netmonitor-sensor.service
```

**Pas aan:**
```ini
[Service]
WorkingDirectory=/opt/netmonitor
ExecStart=/opt/netmonitor/venv/bin/python3 /opt/netmonitor/sensor_client.py -c /opt/netmonitor/sensor-config.yaml

# Environment (WIJZIG DEZE!)
Environment="SOC_SERVER_URL=http://192.168.1.100:8080"
Environment="SENSOR_ID=nano-vlan10-01"
Environment="SENSOR_LOCATION=Building A - VLAN 10 - Production"
```

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start at boot)
sudo systemctl enable netmonitor-sensor

# Start service
sudo systemctl start netmonitor-sensor

# Check status
sudo systemctl status netmonitor-sensor
```

### Stap 8: Verify on Dashboard

1. Open SOC Dashboard: `http://192.168.1.100:8080`
2. Scroll naar "Remote Sensors" sectie
3. Je sensor zou moeten verschijnen met status "Online"

## 🔧 Configuratie Opties

### Batch Upload Interval

Standaard uploadt de sensor elke 30 seconden alerts. Aanpassen:

```bash
# In systemd service:
Environment="BATCH_INTERVAL=60"  # Upload elke minuut

# Of via command line:
sudo /opt/netmonitor/venv/bin/python3 sensor_client.py --interval 60
```

### Metrics Reporting

Sensor stuurt elke 60 seconden metrics (CPU, RAM, disk):
- CPU usage
- Memory usage
- Disk usage
- Packets captured
- Alerts sent

### Network Configuration

**Voor inline deployment (2x ethernet):**

```bash
# Configure eth0 as WAN, eth1 as LAN
# Example: /etc/network/interfaces

auto eth0
iface eth0 inet dhcp

auto eth1
iface eth1 inet static
  address 192.168.10.1
  netmask 255.255.255.0

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
```

## 📊 Dashboard Features

De centrale SOC server dashboard toont voor elke sensor:

- **Status**: Online/Warning/Offline
- **Hostname**: Sensor naam
- **Location**: Configureerde locatie
- **CPU**: Realtime CPU gebruik (color-coded)
- **RAM**: Realtime memory gebruik (color-coded)
- **Packets**: Aantal gevangen packets
- **Alerts (24h)**: Aantal alerts laatste 24 uur
- **Last Seen**: Laatste heartbeat

**Status kleuren:**
- 🟢 **Online**: Last seen < 2 minuten
- 🟡 **Warning**: Last seen 2-10 minuten
- 🔴 **Offline**: Last seen > 10 minuten

## 🔍 Monitoring & Troubleshooting

### Check Sensor Logs

```bash
# Systemd journal
sudo journalctl -u netmonitor-sensor -f

# Log file
tail -f /var/log/netmonitor/sensor.log
```

### Common Issues

**Sensor not appearing on dashboard:**
```bash
# Check if sensor can reach SOC server
curl -I http://192.168.1.100:8080/api/status

# Check firewall
sudo ufw status
sudo ufw allow from 192.168.1.100  # Allow SOC server
```

**Permission denied:**
```bash
# Sensor needs root for packet capture
# Make sure service runs as root
sudo systemctl status netmonitor-sensor
```

**High CPU usage:**
```bash
# Check if interface is correct
ip link show

# Reduce detection sensitivity in sensor-config.yaml
# Increase thresholds
```

**Alerts not uploading:**
```bash
# Check sensor logs for upload errors
grep "upload" /var/log/netmonitor/sensor.log

# Check network connectivity
ping 192.168.1.100

# Check SOC server logs
```

## 🚀 Production Deployment

### Multiple Sensors Setup

Voor elk network segment:

| Sensor ID | Location | IP Address | VLAN | Interface |
|-----------|----------|------------|------|-----------|
| nano-prod-01 | Building A - Production | 192.168.10.10 | 10 | eth0 |
| nano-dmz-01 | DMZ Segment | 192.168.20.10 | 20 | eth0 |
| nano-guest-01 | Guest WiFi | 192.168.30.10 | 30 | eth0 |
| nano-iot-01 | IoT Devices | 192.168.40.10 | 40 | eth0 |

### Best Practices

1. **Unique IDs**: Gebruik altijd unieke sensor IDs
2. **Descriptive locations**: Maak locaties duidelijk
3. **Network segmentation**: Plaats sensors strategisch
4. **Time sync**: Zorg dat alle sensors NTP gebruiken
5. **Monitoring**: Monitor de sensors zelf (CPU/RAM alerts)
6. **Updates**: Update sensors regelmatig
7. **Backups**: Backup sensor configuraties

### Security Considerations

```bash
# Firewall: Allow only necessary traffic
sudo ufw default deny incoming
sudo ufw allow 22/tcp  # SSH (restrictive source IPs!)
sudo ufw allow out to 192.168.1.100 port 8080  # SOC server only
sudo ufw enable

# SSH security
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no  # Use keys only
sudo systemctl restart sshd

# Automatic updates (security only)
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

## 📈 Performance Guidelines

### Network Segments < 100 Mbps
- Nano Pi R2S (1GB RAM): Perfect ✅
- Batch interval: 30s
- Expected CPU: 10-20%
- Expected RAM: 200-400 MB

### Network Segments 100 Mbps - 500 Mbps
- Nano Pi R4S (4GB RAM): Recommended
- Batch interval: 15-30s
- Expected CPU: 20-40%
- Expected RAM: 400-800 MB

### Network Segments > 500 Mbps
- Consider dedicated hardware (oude PC)
- Of gebruik BPF filters om verkeer te filteren
- Batch interval: 15s

## 🔄 Maintenance

### Update Sensor Software

```bash
cd /opt/netmonitor
git pull

# Restart service
sudo systemctl restart netmonitor-sensor
```

### View Sensor Stats on Dashboard

Dashboard → Remote Sensors sectie toont:
- Real-time status
- CPU/RAM usage
- Packet counts
- Alert statistics

## 💡 Tips & Tricks

### BPF Filters voor high-traffic

```bash
# Monitor alleen bepaalde protocols
sudo /opt/netmonitor/venv/bin/python3 sensor_client.py \
  --bpf-filter "tcp or udp"  # Only TCP/UDP

# Skip bepaalde ports
--bpf-filter "not port 22"  # Skip SSH
```

### Centralized Configuration Management

Voor meerdere sensors, gebruik Ansible/Salt:

```yaml
# ansible playbook example
- hosts: sensors
  tasks:
    - name: Update sensor config
      template:
        src: sensor-config.yaml.j2
        dest: /opt/netmonitor/sensor-config.yaml
    - name: Restart sensor
      systemd:
        name: netmonitor-sensor
        state: restarted
```

## 📞 Support

Bij problemen:
1. Check sensor logs
2. Check SOC server logs
3. Verify network connectivity
4. Check firewall rules
5. Test API endpoints manually

---

**Happy Monitoring!** 🛡️
