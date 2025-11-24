# Web Dashboard - Security Operations Center

Een real-time web dashboard voor het monitoren van netwerkverkeer en security events.

## 🎨 Features

### Real-Time Monitoring
- **Live Alert Feed**: Real-time alerts met severity kleuren en geluid
- **WebSocket Updates**: Sub-seconde updates zonder page refresh
- **Traffic Gauges**: Visuele meters voor packets/sec, alerts/min, CPU en Memory
- **System Stats**: Live systeembronnen monitoring

### Visualisaties
- **Traffic Volume Chart**: 24-uur historische data met inbound/outbound traffic
- **Alert Distribution**: Pie chart van alert types en severity
- **Top Talkers**: Lijst van IPs met meeste verkeer (hostname resolution)
- **Threat Types**: Top 10 meest voorkomende threats

### Alert Management
- **Severity Levels**: Visuele kleurcodering (Critical/High/Medium/Low)
- **Alert Geluiden**: Optionele audio alerts voor kritieke events
- **Smooth Animations**: Nieuwe alerts slide in met animatie
- **Detailed Info**: Source/destination IPs, timestamps, beschrijvingen

## 🚀 Quick Start

### Standalone Dashboard Server

Run het dashboard als standalone server:

```bash
sudo python3 web_dashboard.py
```

Toegankelijk op: **http://localhost:8080**

### Geïntegreerd met Network Monitor

Het dashboard start automatisch wanneer je de network monitor draait:

```bash
sudo python3 netmonitor.py
```

Output:
```
Network Monitor geïnitialiseerd
Dashboard beschikbaar op: http://0.0.0.0:8080
Starting network monitor op interface: eth0
```

## ⚙️ Configuratie

Edit `config.yaml`:

```yaml
dashboard:
  enabled: true
  host: 0.0.0.0  # Alle interfaces (toegankelijk van andere machines)
  port: 8080     # Port nummer
  database_path: /var/lib/netmonitor/netmonitor.db
```

### Host Configuratie

- **`0.0.0.0`**: Toegankelijk vanaf alle netwerkinterfaces (andere machines kunnen verbinden)
- **`127.0.0.1`**: Alleen lokale toegang
- **Specifiek IP**: Bind naar specifieke interface

### Port Configuratie

Default port is **8080**. Verander naar een andere port als 8080 bezet is:

```yaml
port: 3000  # Of andere beschikbare port
```

## 🖥️ Dashboard Toegang

### Lokale Toegang

Open browser op de machine die de monitor draait:
```
http://localhost:8080
```

### Remote Toegang

Vanaf een andere machine in het netwerk:
```
http://<IP-VAN-MONITOR-MACHINE>:8080
```

Bijvoorbeeld:
```
http://192.168.1.100:8080
```

### Firewall

Als je niet kunt verbinden, open de port in de firewall:

```bash
# Ubuntu/Debian
sudo ufw allow 8080/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

## 📊 Dashboard Layout

### Top Row - System Gauges
- **Packets/sec**: Huidige packet rate (groen)
- **Alerts/min**: Alerts per minuut (geel)
- **CPU Usage**: CPU percentage (blauw)
- **Memory Usage**: Memory percentage (oranje)

### Middle Row - Charts
- **Traffic Volume**: Line chart met 24-uur inbound/outbound traffic
- **Alert Distribution**: Doughnut chart van alert severities

### Bottom Row - Details
- **Recent Alerts**: Scrollable feed van laatste 50 alerts
- **Top Talkers**: Top 10 IPs met meeste verkeer
- **Threat Types**: Top 10 threat types met counts

## 🎯 Alert Severities

Alerts worden getoond met kleurcodering:

| Severity | Kleur | Border | Gebruik |
|----------|-------|--------|---------|
| CRITICAL | Rood | Dikke rode border | C&C communicatie, actieve breaches |
| HIGH | Oranje | Dikke oranje border | Port scans, beaconing, lateral movement |
| MEDIUM | Geel | Dikke gele border | Data exfiltration, DNS tunneling |
| LOW | Cyaan | Dikke cyaan border | Ongewone packets, verdachte patronen |
| INFO | Grijs | Dikke grijze border | Informatie, statistieken |

## 🔔 Geluid Alerts

Bij **CRITICAL** en **HIGH** severity alerts wordt een korte beep afgespeeld:
- **CRITICAL**: 800Hz beep (hoger)
- **HIGH**: 600Hz beep (lager)

Disable geluid alerts door je browser te muten of edit `dashboard.js`.

## 📡 WebSocket Events

Het dashboard gebruikt WebSocket voor real-time updates:

### Events ontvangen:
- `connected`: Verbinding bevestiging
- `new_alert`: Nieuwe alert van monitoring
- `metrics_update`: Metrics update (elk 5 sec)
- `dashboard_update`: Volledige dashboard data refresh

### Events versturen:
- `request_update`: Request data refresh

## 🔧 REST API Endpoints

Het dashboard biedt ook een REST API:

### Status
```
GET /api/status
```
Returns: API status en timestamp

### Dashboard Data
```
GET /api/dashboard
```
Returns: Alle dashboard data (alerts, stats, traffic, top talkers)

### Recent Alerts
```
GET /api/alerts?limit=100&hours=24
```
Parameters:
- `limit`: Max aantal alerts (default: 100)
- `hours`: Lookback periode (default: 24)

### Alert Statistics
```
GET /api/alerts/stats?hours=24
```
Returns: Alert counts by severity en type

### Acknowledge Alert
```
POST /api/alerts/<alert_id>/acknowledge
```
Mark alert als acknowledged

### Traffic History
```
GET /api/traffic/history?hours=24
```
Returns: Traffic metrics history

### Top Talkers
```
GET /api/top-talkers?limit=10
```
Returns: Top IPs by traffic volume

## 🗄️ Database

Alle data wordt opgeslagen in PostgreSQL database met TimescaleDB extensie:

**Default Location**: `localhost:5432/netmonitor`

### Main Tables:
- **alerts**: Alle security alerts met metadata (TimescaleDB hypertable)
- **traffic_metrics**: Traffic statistieken per minuut
- **top_talkers**: Top IPs per 5 minuten
- **system_stats**: System resource metrics
- **sensors**: Remote sensor registratie en status
- **sensor_metrics**: Sensor performance metrics (CPU, RAM, bandwidth)
- **whitelist**: Centralized IP whitelist management

### Database Cleanup

Oude data (>30 dagen) wordt automatisch verwijderd om diskspace te besparen.

Manuele cleanup:
```python
from database import DatabaseManager
db = DatabaseManager()
db.cleanup_old_data(days=30)
```

## 🎨 Customization

### Kleuren Aanpassen

Edit `/home/user/netmonitor/web/static/css/dashboard.css`:

```css
/* Verander severity kleuren */
.alert-severity.CRITICAL {
    background-color: #dc3545;  /* Rood */
}

.alert-severity.HIGH {
    background-color: #fd7e14;  /* Oranje */
}
```

### Chart Update Interval

Edit `/home/user/netmonitor/web/static/js/dashboard.js`:

```javascript
// Auto-refresh data every 30 seconds
setInterval(loadDashboardData, 30000);  // Verander naar gewenste interval
```

### Metrics Broadcast Interval

Edit `netmonitor.py`:

```python
threading.Event().wait(5)  # Verander naar gewenste seconden
```

## 🔒 Security Overwegingen

### Productie Deployment

Voor productie gebruik:

1. **Gebruik HTTPS**: Setup reverse proxy (nginx) met SSL
2. **Authenticatie**: Voeg basic auth toe of gebruik OAuth
3. **Firewall**: Limiteer toegang tot specifieke IPs
4. **Secret Key**: Verander Flask secret key in `web_dashboard.py`

### Nginx Reverse Proxy Voorbeeld

```nginx
server {
    listen 443 ssl;
    server_name monitor.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Basic Auth

Voeg authenticatie toe aan Flask app:

```python
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Implement your auth logic
    return username == 'admin' and password == 'secret'

@app.route('/')
@auth.login_required
def index():
    return render_template('dashboard.html')
```

## 📈 Performance

### Resource Gebruik

- **CPU**: ~2-5% tijdens normale operatie
- **Memory**: ~100-200 MB (afhankelijk van database size)
- **Network**: WebSocket overhead ~1-5 KB/sec
- **Database**: ~10-50 MB per dag (afhankelijk van alert volume)

### Optimalisatie Tips

1. **Limiteer History**: Houd traffic history beperkt tot 24-48 uur
2. **Database Cleanup**: Run cleanup periodiek
3. **Alert Rate Limiting**: Configureer max alerts per minuut
4. **Metrics Interval**: Verhoog interval als CPU hoog is

## 🐛 Troubleshooting

### Dashboard Niet Toegankelijk

```bash
# Check of server draait
ps aux | grep web_dashboard

# Check of port open is
netstat -tulpn | grep 8080

# Check firewall
sudo ufw status
```

### WebSocket Verbinding Mislukt

Check browser console (F12):
```
WebSocket connection failed
```

**Oplossing**: Check of firewall WebSocket traffic toestaat.

### Geen Alerts Worden Getoond

```bash
# Check database
psql -U netmonitor -d netmonitor -c "SELECT COUNT(*) FROM alerts;"

# Check logs
tail -f /var/log/netmonitor/alerts.log
```

### Charts Laden Niet

Check browser console voor JavaScript errors. Zorg dat Chart.js correct geladen wordt.

## 📚 Technische Details

### Tech Stack

- **Backend**: Flask + Flask-SocketIO
- **Frontend**: HTML5 + Bootstrap 5 + Chart.js
- **Real-time**: Socket.IO WebSocket
- **Database**: PostgreSQL + TimescaleDB
- **Charts**: Chart.js 4.4
- **Icons**: Bootstrap Icons

### Browser Support

Getest op:
- Chrome/Chromium 90+
- Firefox 88+
- Safari 14+
- Edge 90+

### Dependencies

```
flask>=3.0.0
flask-socketio>=5.3.0
flask-cors>=4.0.0
python-socketio>=5.10.0
psutil>=5.9.0
```

## 🎓 Advanced Usage

### API in Scripts

```python
import requests

# Get recent alerts
response = requests.get('http://localhost:8080/api/alerts?limit=10')
alerts = response.json()['data']

# Get alert stats
response = requests.get('http://localhost:8080/api/alerts/stats')
stats = response.json()['data']
```

### Custom Alerts

```python
from database import DatabaseManager

db = DatabaseManager()
db.add_alert({
    'severity': 'HIGH',
    'type': 'CUSTOM_ALERT',
    'source_ip': '192.168.1.100',
    'description': 'Custom security event detected'
})
```

## 📞 Support

Voor issues en vragen, zie de main README.md.

Geniet van je real-time Security Operations Center! 🚀
