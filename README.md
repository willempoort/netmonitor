# Network Monitor - Security Operations Center (SOC)

Een krachtig netwerk monitoring platform voor Linux met **real-time web dashboard** dat verdacht netwerkverkeer kan detecteren. **Speciaal ontworpen voor monitoring van intern verkeer** om gecompromitteerde machines te detecteren. Geschikt voor gebruik op een monitoring/span port van een switch.

![SOC Dashboard Preview](docs/dashboard-preview.png)
*Real-time Security Operations Center dashboard voor netwerkmonitoring*

## 🎯 Key Features

### 🖥️ Real-Time Web Dashboard (Nieuw!)

**Professional SOC Dashboard op http://localhost:8080**

- **Live Alert Feed**: Real-time security alerts met kleuren en geluid
- **Traffic Visualisaties**: Grafieken en gauges voor verkeer monitoring
- **System Metrics**: CPU, Memory, Packets/sec, Alerts/min gauges
- **Top Talkers**: IPs met meeste verkeer (inclusief hostnames)
- **WebSocket Updates**: Sub-seconde real-time updates
- **Dark Theme**: Professional security monitoring interface
- **Responsive Design**: Werkt op desktop, tablet en mobile

[Zie DASHBOARD.md voor complete dashboard documentatie →](DASHBOARD.md)

## Detection Features

### 🎯 Threat Intelligence (Nieuw!)

- **C&C Server Detectie**: Automatische detectie van communicatie met bekende Command & Control servers (Emotet, TrickBot, etc.)
- **Malware Download Detectie**: Detecteert downloads van bekende malware distributie sites
- **Auto-updating Threat Feeds**: Automatisch uurlijkse updates van abuse.ch feeds (FeodoTracker, URLhaus, ThreatFox)
- **AbuseIPDB Integratie**: Optionele real-time IP reputation lookups (1000/dag gratis)

### 🔍 Behavior-Based Detectie (Nieuw!)

- **Beaconing Detection**: Detecteert regelmatige callbacks naar externe servers (botnet behavior)
- **Outbound Traffic Volume**: Monitort data exfiltration (abnormaal hoge upload volumes)
- **Lateral Movement**: Detecteert interne machines die andere internal IPs scannen (SMB, RDP, SSH)
- **Internal Network Awareness**: Onderscheidt internal vs external verkeer

### 📊 Signature-Based Detectie

- **Port Scanning Detectie**: Detecteert wanneer een host systematisch meerdere poorten scant
- **Connection Flooding**: Detecteert abnormaal hoge aantallen connecties in korte tijd
- **DNS Tunneling**: Detecteert verdachte DNS queries (lange queries, hoge query rates)
- **Ongewone Packet Sizes**: Detecteert abnormaal grote packets (mogelijk data exfiltration)
- **IP Blacklist/Whitelist**: Configureerbare IP lijsten

### Algemene Features

- Real-time packet capture en analyse
- Configureerbare detection thresholds
- Gekleurde console output
- Gestructureerde logging naar file
- Rate limiting om alert flooding te voorkomen
- Graceful shutdown bij SIGINT/SIGTERM

## Vereisten

- Linux systeem met root/sudo privileges
- Python 3.7 of hoger
- libpcap (meestal standaard geïnstalleerd)

## Installatie

### 1. Clone de repository

```bash
git clone <repository-url>
cd netmonitor
```

### 2. Installeer Python dependencies

```bash
pip install -r requirements.txt
```

Of met sudo voor system-wide installatie:

```bash
sudo pip install -r requirements.txt
```

### 3. Maak directories aan

```bash
sudo mkdir -p /var/log/netmonitor
sudo mkdir -p /var/cache/netmonitor/feeds
sudo mkdir -p /var/lib/netmonitor
sudo chmod 755 /var/log/netmonitor
sudo chmod 755 /var/cache/netmonitor
sudo chmod 755 /var/lib/netmonitor
```

### 4. Download threat feeds (eerste keer)

```bash
sudo python3 update_feeds.py
```

### 5. Setup auto-updates (optioneel maar aanbevolen)

```bash
# Installeer systemd timer voor automatische feed updates
sudo cp netmonitor-feed-update.service /etc/systemd/system/
sudo cp netmonitor-feed-update.timer /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable netmonitor-feed-update.timer
sudo systemctl start netmonitor-feed-update.timer

# Verificeer
sudo systemctl status netmonitor-feed-update.timer
```

## Configuratie

Pas `config.yaml` aan naar je wensen:

### Network Interface

```yaml
interface: eth0  # Vervang met je monitoring interface (eth0, ens33, etc.)
```

Om alle interfaces te monitoren, gebruik:
```yaml
interface: any
```

### Internal Networks (BELANGRIJK!)

Definieer je interne netwerk ranges voor behavior detection:

```yaml
internal_networks:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16  # Pas aan naar je netwerk
```

### Threat Intelligence Feeds

De tool gebruikt gratis threat feeds van abuse.ch. Geen API key nodig!

```yaml
threat_feeds:
  enabled: true
  feeds:
    - feodotracker    # Botnet C&C servers (AANBEVOLEN)
    - urlhaus         # Malware distribution
    - threatfox       # Recent IOCs
    - sslblacklist    # SSL threats
  update_interval: 3600  # 1 uur
```

### AbuseIPDB API (Optioneel)

Voor real-time IP reputation lookups:

1. Maak gratis account: https://www.abuseipdb.com/register
2. Haal API key op: https://www.abuseipdb.com/account/api
3. Configureer:

```yaml
abuseipdb:
  enabled: true
  api_key: "YOUR_API_KEY_HERE"
  rate_limit: 1000  # Gratis tier
  threshold: 50     # Alert bij score >= 50
```

Zie [THREAT_FEEDS.md](THREAT_FEEDS.md) voor gedetailleerde documentatie.

### Detection Thresholds Aanpassen

Je kunt de gevoeligheid van elke detector aanpassen:

```yaml
thresholds:
  # Signature-based
  port_scan:
    enabled: true
    unique_ports: 20
    time_window: 60

  # Behavior-based (NIEUW!)
  beaconing:
    enabled: true
    min_connections: 5
    max_jitter_percent: 20

  lateral_movement:
    enabled: true
    unique_targets: 5
    time_window: 300

  outbound_volume:
    enabled: true
    threshold_mb: 100
    time_window: 300
```

### Whitelist/Blacklist

Voeg vertrouwde netwerken toe aan whitelist:

```yaml
whitelist:
  - 192.168.1.0/24      # Je eigen netwerk
  - 10.0.0.0/8          # Intern netwerk
```

Voeg bekende malicious IPs toe aan blacklist:

```yaml
blacklist:
  - 203.0.113.0/24      # Bekend malicious netwerk
  - 198.51.100.50       # Specifiek IP
```

## 🚀 Gebruik

### Start Network Monitor + Web Dashboard

Run als root (vereist voor packet capture):

```bash
sudo python3 netmonitor.py
```

**Output:**
```
Network Monitor geïnitialiseerd
Database Manager enabled
Metrics Collector enabled
Threat Feed Manager enabled
Behavior Detector enabled
Web Dashboard enabled
Dashboard beschikbaar op: http://0.0.0.0:8080
Starting network monitor op interface: eth0
```

### Open Web Dashboard

**Lokale toegang:**
```
http://localhost:8080
```

**Remote toegang (vanaf andere machine):**
```
http://192.168.1.X:8080  # Vervang X met server IP
```

### Dashboard Features

✅ **Live Alert Feed** - Real-time security alerts
✅ **Traffic Graphs** - 24-uur inbound/outbound charts
✅ **System Gauges** - Packets/sec, Alerts/min, CPU, Memory
✅ **Top Talkers** - IPs met meeste verkeer
✅ **Threat Types** - Meest voorkomende threats
✅ **Audio Alerts** - Beep bij CRITICAL/HIGH alerts

[→ Complete Dashboard Documentatie (DASHBOARD.md)](DASHBOARD.md)

### Command Line Opties

```bash
# Met specifieke interface
sudo python3 netmonitor.py -i eth0

# Met custom config file
sudo python3 netmonitor.py -c /path/to/config.yaml

# Verbose mode (debug)
sudo python3 netmonitor.py -v
```

### Standalone Dashboard (Zonder Monitoring)

Voor testing of development:

```bash
sudo python3 web_dashboard.py
```

### Stoppen

Druk op `Ctrl+C` voor graceful shutdown.

## Command Line Opties

```
usage: netmonitor.py [-h] [-c CONFIG] [-i INTERFACE] [-v]

options:
  -h, --help            Toon help bericht
  -c CONFIG, --config CONFIG
                        Pad naar configuratie file (default: config.yaml)
  -i INTERFACE, --interface INTERFACE
                        Network interface om te monitoren (overschrijft config file)
  -v, --verbose         Verbose output (DEBUG level)
```

## Output en Logging

### Console Output

Alerts worden real-time getoond in de console met kleuren:
- **ROOD**: HIGH/CRITICAL severity
- **GEEL**: MEDIUM severity
- **CYAAN**: LOW severity

### Voorbeeld Alerts

**C&C Communicatie (KRITISCH!):**
```
[2025-11-06 15:30:45] [CRITICAL] [C2_COMMUNICATION] Internal machine verbindt met C&C server: Emotet | Source: 192.168.1.100 | Destination: 203.0.113.50 | Malware: Emotet
```

**Beaconing Gedetecteerd:**
```
[2025-11-06 15:31:20] [HIGH] [BEACONING_DETECTED] Beaconing gedetecteerd: 8 connecties met avg interval 60.2s | Source: 192.168.1.50 | Destination: 198.51.100.100:443
```

**Lateral Movement:**
```
[2025-11-06 15:32:10] [HIGH] [LATERAL_MOVEMENT] Mogelijk lateral movement: 7 interne IPs gescand binnen 300s | Source: 192.168.1.75 | Protocols: SMB: 5, RDP: 2
```

**Data Exfiltration:**
```
[2025-11-06 15:33:00] [MEDIUM] [HIGH_OUTBOUND_VOLUME] Hoog outbound volume: 150.25 MB in 300s | Source: 192.168.1.100
```

**Port Scan:**
```
[2025-11-06 15:34:00] [HIGH] [PORT_SCAN] Mogelijk port scan gedetecteerd: 25 unieke poorten binnen 60s | Source: 192.168.1.100 | Destination: 10.0.0.50
```

### Log Files

Drie log files worden aangemaakt:

1. **Algemene logs**: `/var/log/netmonitor/alerts.log`
   - Alle system events en errors

2. **Security alerts**: `/var/log/netmonitor/security_alerts.log`
   - Alleen security threats

3. **Feed updates**: `/var/log/netmonitor/feed_updates.log`
   - Threat feed download status

### Database

Alerts en metrics worden opgeslagen in SQLite database:

**Location**: `/var/lib/netmonitor/netmonitor.db`

**Tables**:
- `alerts` - Alle security alerts met metadata
- `traffic_metrics` - Traffic statistieken per minuut
- `top_talkers` - Top IPs per 5 minuten
- `system_stats` - System resource metrics

Toegang via web dashboard of direct via API.

## Monitoring Port Setup

### Switch Configuratie

Voor gebruik op een monitoring/span port, configureer je switch om verkeer te mirroren:

#### Cisco IOS Voorbeeld

```
configure terminal
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24
end
```

#### Linux Bridge Voorbeeld

```bash
# Stel port mirroring in met tc
tc qdisc add dev eth0 ingress
tc filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev eth1
```

### Interface in Promiscuous Mode

De tool zet de interface automatisch in promiscuous mode, maar je kunt dit ook manueel doen:

```bash
sudo ip link set eth0 promisc on
```

## 🔧 Troubleshooting

### Network Monitor Issues

#### "Permission Denied" Error

De tool vereist root privileges voor packet capture:

```bash
sudo python3 netmonitor.py
```

#### Interface Niet Gevonden

Controleer beschikbare interfaces:

```bash
ip link show
# of
ifconfig
```

Pas `interface` in `config.yaml` aan naar een bestaande interface.

#### Geen Packets Ontvangen

1. Check of interface UP is:
   ```bash
   sudo ip link set eth0 up
   ```

2. Check of er daadwerkelijk verkeer is:
   ```bash
   sudo tcpdump -i eth0 -c 10
   ```

3. Bij monitoring port: check switch configuratie

#### Te Veel False Positives

Pas detection thresholds aan in `config.yaml`:
- Verhoog `unique_ports` voor port scan detectie
- Verhoog `connections_per_second` voor flood detectie
- Voeg interne netwerken toe aan whitelist

### Web Dashboard Issues

#### Dashboard Niet Toegankelijk

```bash
# Check of Flask server draait
ps aux | grep web_dashboard

# Check of port open is
netstat -tulpn | grep 8080

# Check firewall
sudo ufw status
```

**Oplossing:** Open port in firewall:
```bash
sudo ufw allow 8080/tcp
```

#### WebSocket Verbinding Mislukt

Check browser console (F12):
```
WebSocket connection failed
```

**Oplossing:**
- Check firewall toestaat WebSocket traffic
- Check `host` setting in config.yaml (gebruik 0.0.0.0 voor remote access)

#### Geen Alerts op Dashboard

```bash
# Check database
sqlite3 /var/lib/netmonitor/netmonitor.db "SELECT COUNT(*) FROM alerts;"

# Check logs
tail -f /var/log/netmonitor/alerts.log

# Restart monitor
sudo pkill -f netmonitor.py
sudo python3 netmonitor.py
```

#### Charts Laden Niet

1. Open browser console (F12) en check voor JavaScript errors
2. Check of Chart.js CDN beschikbaar is
3. Check internet connectie (voor CDN resources)
4. Try hard refresh: Ctrl+Shift+R

#### Database Errors

```bash
# Check permissions
ls -la /var/lib/netmonitor/

# Fix permissions
sudo chmod 755 /var/lib/netmonitor
sudo chmod 644 /var/lib/netmonitor/netmonitor.db

# Rebuild database (DANGER: verwijdert alle data)
sudo rm /var/lib/netmonitor/netmonitor.db
sudo python3 netmonitor.py
```

### Threat Feed Issues

Zie [THREAT_FEEDS.md](THREAT_FEEDS.md) voor gedetailleerde troubleshooting.

## ⚡ Performance Consideraties

### Resource Gebruik

**Network Monitor:**
- CPU: 5-15% tijdens actieve monitoring (afhankelijk van verkeer)
- Memory: 200-500 MB (inclusief dashboard en database)
- Disk: ~10-50 MB/dag voor database (afhankelijk van alert volume)

**Web Dashboard:**
- CPU: 2-5% extra (Flask + WebSocket)
- Memory: ~100-200 MB extra
- Network: ~1-5 KB/sec (WebSocket overhead)

### Optimalisaties

- De tool gebruikt `store=0` bij packet capture om memory laag te houden
- Database gebruikt bounded deques voor memory-efficient tracking
- Metrics worden geaggregeerd voor minder database writes
- Charts updaten zonder volledige re-render
- Thread-safe database connections

### High Traffic Netwerken (>1Gbps)

Voor zeer drukke netwerken:

1. **BPF Filters**: Filter verkeer in scapy
```python
sniff(filter="tcp and not port 22")  # Skip SSH verkeer
```

2. **Sampling**: Monitor slechts percentage van verkeer
3. **Dedicated Hardware**: Gebruik dedicated monitoring machine
4. **Database**: Overweeg PostgreSQL voor grotere volumes

### Monitoring

Monitor de monitor zelf:
```bash
# Check resource usage
top -p $(pgrep -f netmonitor.py)

# Check database size
du -h /var/lib/netmonitor/netmonitor.db

# Check logs
tail -f /var/log/netmonitor/alerts.log
```

## Systemd Service (Optioneel)

Om de monitor automatisch te starten bij boot:

1. Maak service file `/etc/systemd/system/netmonitor.service`:

```ini
[Unit]
Description=Network Monitor - Threat Detection
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/netmonitor
ExecStart=/usr/bin/python3 /path/to/netmonitor/netmonitor.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. Enable en start service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable netmonitor
sudo systemctl start netmonitor
```

3. Check status:

```bash
sudo systemctl status netmonitor
sudo journalctl -u netmonitor -f  # Live logs
```

## Security Overwegingen

- **Run als root**: Vereist voor raw packet access, maar wees voorzichtig
- **Log file permissions**: Zorg dat alleen root toegang heeft tot logs (kunnen gevoelige info bevatten)
- **Whitelist configuratie**: Voeg vertrouwde systemen toe om false positives te reduceren
- **Monitor de monitor**: Check periodiek of de tool nog draait en correct functioneert

## 🏗️ Architectuur

```
netmonitor.py              - Main entry point, packet capture loop
├── config_loader.py       - YAML configuratie laden
├── detector.py            - Signature-based threat detection
├── behavior_detector.py   - Behavior-based threat detection
├── threat_feeds.py        - Threat intelligence feed manager
├── abuseipdb_client.py    - AbuseIPDB API client
├── alerts.py              - Alert management en logging
├── database.py            - SQLite database manager
├── metrics_collector.py   - Traffic & system metrics
├── web_dashboard.py       - Flask web server + WebSocket
└── web/                   - Dashboard frontend
    ├── templates/
    │   └── dashboard.html - Bootstrap 5 UI
    └── static/
        ├── css/dashboard.css
        └── js/dashboard.js    - Chart.js + WebSocket client
```

### Data Flow

```
1. Packet Captured (scapy)
   ↓
2. Metrics Collector (track traffic)
   ↓
3. Threat Detector (analyze)
   ├─→ Signature detection
   ├─→ Behavior detection
   └─→ Threat feed check
   ↓
4. Alert Found?
   ├─→ Console/File (AlertManager)
   ├─→ Database (SQLite)
   └─→ WebSocket Broadcast (Dashboard)
   ↓
5. Dashboard Updates (real-time)
```

## 🌐 Web Dashboard

### Quick Access

Start monitor en open:
```
http://localhost:8080
```

### Dashboard Sections

**System Metrics** (Top Row)
- 🟢 **Packets/sec**: Real-time packet rate
- 🟡 **Alerts/min**: Security alert frequency
- 🔵 **CPU Usage**: Processor utilization
- 🟠 **Memory**: RAM usage

**Traffic Analysis** (Middle Row)
- 📈 **Traffic Volume**: 24-hour line chart (inbound vs outbound)
- 🥧 **Alert Distribution**: Pie chart by severity

**Live Feeds** (Bottom Row)
- 🔔 **Recent Alerts**: Last 50 alerts with severity colors
- 👥 **Top Talkers**: Top 10 IPs by traffic (with hostnames)
- 🐛 **Threat Types**: Most common threat types

### API Endpoints

```bash
# Get all dashboard data
curl http://localhost:8080/api/dashboard

# Get recent alerts
curl http://localhost:8080/api/alerts?limit=50&hours=24

# Get alert statistics
curl http://localhost:8080/api/alerts/stats

# Get traffic history
curl http://localhost:8080/api/traffic/history?hours=24

# Get top talkers
curl http://localhost:8080/api/top-talkers?limit=10
```

### Dashboard Configuration

In `config.yaml`:

```yaml
dashboard:
  enabled: true
  host: 0.0.0.0  # Toegankelijk vanaf alle interfaces
  port: 8080     # Dashboard port
  database_path: /var/lib/netmonitor/netmonitor.db
```

**Disable dashboard:**
```yaml
dashboard:
  enabled: false
```

**Custom port:**
```yaml
dashboard:
  port: 3000  # Of andere beschikbare port
```

### Remote Access

Om dashboard toegankelijk te maken vanaf andere machines:

1. **Firewall regel toevoegen:**
```bash
sudo ufw allow 8080/tcp
```

2. **Access URL:**
```
http://<server-ip>:8080
```

### Security (Production)

Voor productie gebruik, zie [DASHBOARD.md](DASHBOARD.md) voor:
- HTTPS/SSL setup met nginx
- Authentication (Basic Auth, OAuth)
- IP whitelisting
- Rate limiting

## 📊 Visualisaties

Het dashboard biedt verschillende visualisatie types:

### Gauge Charts (4x)
- **Type**: Doughnut gauges (180° arc)
- **Update**: Real-time, elk 5 seconden
- **Kleuren**: Color-coded per metric type

### Line Charts
- **Traffic Volume**: Dubbele lijn (inbound/outbound)
- **Historie**: 24 uur met uurlijkse data points
- **Smooth**: Tension curves voor vloeiende lijnen

### Pie Charts
- **Alert Distribution**: Severity breakdown
- **Dynamic**: Updates bij nieuwe alerts

### Tables
- **Top Talkers**: Sorteerbaar, met hostname resolution
- **Threat Types**: Top 10 met badge counts

## Licentie

[Specificeer licentie]

## Contributing

[Specificeer contribution guidelines]

## Contact

[Contact informatie]
