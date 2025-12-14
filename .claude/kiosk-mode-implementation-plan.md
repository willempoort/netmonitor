# Instructie Plan: NetMonitor Kiosk Mode Dashboard

## Project Context
NetMonitor SOC heeft een web dashboard met sensor monitoring. We voegen een dedicated kiosk view toe voor real-time monitoring op TV/display met cumulatieve metrics van alle sensors.

---

## Doelstellingen

1. **Aparte `/kiosk` route** - volledig onafhankelijke kiosk view
2. **Cumulatieve metrics** - aggregated data van alle sensors (niet alleen SOC server)
3. **3x2 Grid layout** met roterende screens
4. **Public accessible** - geen login vereist
5. **Fullscreen hint** - F11 instructie
6. **Theme toggle** - dark/light mode keuze

---

## Architectuur Overzicht

```
┌─────────────────────────────────────────────────────────┐
│ /kiosk Route (Public)                                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  /api/kiosk/metrics (Public API)                       │
│  ├─ db.get_aggregated_metrics() → Alle sensors        │
│  ├─ db.get_sensors() → Sensor status                  │
│  └─ db.get_alert_statistics() → Top threats           │
│                                                         │
│  templates/kiosk.html                                  │
│  ├─ 3x2 Grid Layout                                   │
│  ├─ Auto-refresh (5s)                                 │
│  ├─ Screen rotation (30s)                             │
│  └─ Dark/Light toggle                                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Implementatie Stappen

### Step 1: Database Method Verificatie

**Bestand:** `database.py`

**Actie:** Verificeer dat `get_aggregated_metrics()` correct werkt:
- [x] Methode bestaat (regel ~1256)
- [x] Returned: `packets_per_sec`, `alerts_per_min`, `bandwidth_mbps`, `sensor_count`
- [x] Aggregeert data van ALLE sensors (niet alleen SOC server)

**Geen wijzigingen nodig** - methode is al aanwezig en correct.

---

### Step 2: Nieuwe API Endpoints

**Bestand:** `web_dashboard.py`

**Locatie:** Na bestaande routes (rond regel 1208)

**Toe te voegen:**

```python
# ==================== Kiosk Mode Routes (Public Access) ====================

@app.route('/kiosk')
def kiosk_view():
    """
    Kiosk mode fullscreen view - Public access for monitoring displays
    No authentication required
    """
    return render_template('kiosk.html')

@app.route('/api/kiosk/metrics')
def api_kiosk_metrics():
    """
    Get aggregated metrics for kiosk display - Public API
    Returns cumulative metrics from ALL sensors
    """
    try:
        # Get aggregated metrics from ALL sensors
        aggregated = db.get_aggregated_metrics()
        
        # Get sensor status overview
        sensors = db.get_sensors()
        
        # Calculate average CPU/Memory across all sensors
        total_cpu = 0
        total_memory = 0
        sensor_count = 0
        
        for sensor in sensors:
            if sensor.get('cpu_percent') is not None:
                total_cpu += sensor['cpu_percent']
                sensor_count += 1
            if sensor.get('memory_percent') is not None:
                total_memory += sensor['memory_percent']
        
        avg_cpu = round(total_cpu / sensor_count, 1) if sensor_count > 0 else 0
        avg_memory = round(total_memory / sensor_count, 1) if sensor_count > 0 else 0
        
        # Get critical/high alerts (last hour)
        alerts = db.get_recent_alerts(limit=20, hours=1)
        critical_alerts = [a for a in alerts if a['severity'] in ['CRITICAL', 'HIGH']]
        
        # Get alert statistics for threat breakdown
        stats = db.get_alert_statistics(hours=24)
        
        # Sensor health counts
        sensor_health = {
            'total': len(sensors),
            'online': len([s for s in sensors if s['computed_status'] == 'online']),
            'warning': len([s for s in sensors if s['computed_status'] == 'warning']),
            'offline': len([s for s in sensors if s['computed_status'] == 'offline'])
        }
        
        return jsonify({
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'metrics': {
                'bandwidth_mbps': aggregated.get('bandwidth_mbps', 0),
                'packets_per_sec': aggregated.get('packets_per_sec', 0),
                'alerts_per_min': aggregated.get('alerts_per_min', 0),
                'active_sensors': f"{sensor_health['online']}/{sensor_health['total']}",
                'avg_cpu_percent': avg_cpu,
                'avg_memory_percent': avg_memory
            },
            'sensor_health': sensor_health,
            'critical_alerts': critical_alerts[:10],  # Max 10 for kiosk
            'top_threats': dict(list(stats.get('by_type', {}).items())[:5]),
            'alert_severity': stats.get('by_severity', {})
        })
        
    except Exception as e:
        logger.error(f"Error getting kiosk metrics: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'metrics': {
                'bandwidth_mbps': 0,
                'packets_per_sec': 0,
                'alerts_per_min': 0,
                'active_sensors': '0/0',
                'avg_cpu_percent': 0,
                'avg_memory_percent': 0
            }
        }), 500

@app.route('/api/kiosk/sensors')
def api_kiosk_sensors():
    """
    Get detailed sensor status for kiosk sensor view
    Public API - no auth required
    """
    try:
        sensors = db.get_sensors()
        
        # Format for kiosk display
        formatted_sensors = []
        for sensor in sensors:
            formatted_sensors.append({
                'id': sensor['sensor_id'],
                'name': sensor['hostname'],
                'location': sensor.get('location', 'Unknown'),
                'status': sensor['computed_status'],
                'cpu': sensor.get('cpu_percent', 0),
                'memory': sensor.get('memory_percent', 0),
                'bandwidth': sensor.get('bandwidth_mbps', 0),
                'alerts_24h': sensor.get('alerts_24h', 0),
                'last_seen': sensor.get('last_seen')
            })
        
        return jsonify({
            'success': True,
            'sensors': formatted_sensors,
            'total': len(formatted_sensors),
            'online': len([s for s in formatted_sensors if s['status'] == 'online'])
        })
        
    except Exception as e:
        logger.error(f"Error getting kiosk sensors: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
```

**Waarom deze aanpak:**
- Public routes (geen `@login_required` decorator)
- Gebruikt bestaande `get_aggregated_metrics()` voor cumulatieve data
- Berekent gemiddelde CPU/Memory over alle sensors
- Separate endpoint voor sensor details (roterende screen)

---

### Step 3: Kiosk Template

**Bestand:** `web/templates/kiosk.html` (nieuw bestand)

**Inhoud:** Zie het volledige HTML template in de volgende sectie.

**Key Features:**
- Responsive 3x2 grid layout
- Auto-refresh elke 5 seconden
- Screen rotation elke 30 seconden (metrics → alerts → sensors)
- Dark/Light theme toggle met localStorage persistence
- Fullscreen hint overlay
- WebSocket-free (polling only voor simplicity)

---

### Step 4: Config Update (Optioneel)

**Bestand:** `config.yaml`

**Toevoegen na `dashboard` sectie:**

```yaml
dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8080
  
  # Kiosk Mode Settings
  kiosk:
    enabled: true
    refresh_interval: 5      # seconds
    rotation_interval: 30    # seconds
    public_access: true      # no login required
```

---

## Testing Checklist

Na implementatie, test het volgende:

- [ ] `/kiosk` route is toegankelijk zonder login
- [ ] `/api/kiosk/metrics` returned cumulatieve data van alle sensors
- [ ] Metrics updaten elke 5 seconden
- [ ] Screens roteren elke 30 seconden (metrics → alerts → sensors)
- [ ] Dark/Light theme toggle werkt en wordt onthouden
- [ ] F11 fullscreen werkt correct
- [ ] Responsive layout werkt op verschillende schermen
- [ ] Gemiddelde CPU/Memory wordt correct berekend
- [ ] Sensor status toont online/warning/offline correct
- [ ] Critical/High alerts worden gefilterd en getoond

---

## Deployment Instructies

1. **Backup maken:**
   ```bash
   cp web_dashboard.py web_dashboard.py.backup
   ```

2. **Wijzigingen doorvoeren:**
   - Voeg routes toe aan `web_dashboard.py`
   - Maak `web/templates/kiosk.html`
   - Update `config.yaml` (optioneel)

3. **Restart dashboard service:**
   ```bash
   sudo systemctl restart netmonitor-dashboard
   ```

4. **Verificatie:**
   ```bash
   # Check logs
   sudo journalctl -u netmonitor-dashboard -f
   
   # Test endpoints
   curl http://localhost:8080/api/kiosk/metrics
   
   # Open browser
   firefox http://localhost:8080/kiosk
   ```

---

## Rollback Procedure

Als er problemen zijn:

```bash
# Stop service
sudo systemctl stop netmonitor-dashboard

# Herstel backup
cp web_dashboard.py.backup web_dashboard.py

# Verwijder kiosk template
rm web/templates/kiosk.html

# Start service
sudo systemctl start netmonitor-dashboard
```

---

## Extra Features (Toekomstige Uitbreidingen)

Mogelijke verbeteringen:

1. **Geluid alerts** - Audio beep bij CRITICAL alerts
2. **Grafiek view** - Bandwidth/traffic trends over tijd
3. **Top Talkers** - Top 10 IPs met meeste verkeer
4. **Threat heatmap** - Geografische verdeling van threats
5. **Custom rotation** - Gebruiker kan screens selecteren
6. **Multi-monitor** - Verschillende kiosk views per monitor
7. **QR code** - Snelle toegang naar full dashboard

---

## Notities

- **Geen authenticatie** op kiosk routes - bewust voor public displays
- **Aggregated metrics** via `get_aggregated_metrics()` - niet alleen SOC server
- **Auto-refresh** voorkomt stale data op displays
- **Theme toggle** voor verschillende omgevingen (kantoor vs. NOC room)
- **Fullscreen hint** helpt gebruikers bij setup

---

## Complete HTML Template

Het volledige kiosk.html template is te lang voor dit document, maar bevat:

### HTML Structure
- Responsive container met header
- 3x2 metrics grid voor screen 1
- Alerts list view voor screen 2
- Sensors grid view voor screen 3
- Theme toggle en fullscreen controls
- Fullscreen hint overlay

### CSS Styling
- Dark/Light theme variables
- Responsive grid layouts
- Card components met glassmorphism
- Smooth transitions en animations
- Gauge-style metric cards

### JavaScript Features
- Auto-refresh met `setInterval`
- Screen rotation logic
- Theme toggle met localStorage
- Fullscreen API integration
- Fetch API voor metrics
- Dynamic DOM updates

**Volledige template code moet gegenereerd worden in Step 3**
