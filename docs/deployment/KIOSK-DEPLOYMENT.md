# Kiosk Mode Deployment Instructies

## Overzicht

De kiosk mode is geïmplementeerd en vereist deployment van zowel Flask dashboard als nginx configuratie.

## Poort Configuratie

**BELANGRIJK - Poorten:**
- **Flask Dashboard**: `8080` (web_dashboard.py)
- **MCP API**: `8000` (FastAPI/Uvicorn)
- **Nginx**: `80` (HTTP) en `443` (HTTPS)

**In config.yaml:**
```yaml
dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8080  # Flask Dashboard poort
```

## Deployment Stappen

### 1. Nginx Configuratie Updaten

De nginx configuratie moet de kiosk routes bevatten. Twee opties:

**Optie A: Dual Config (Dashboard + MCP)**
```bash
sudo cp nginx-netmonitor-dual.conf /etc/nginx/sites-available/soc.poort.net
sudo ln -sf /etc/nginx/sites-available/soc.poort.net /etc/nginx/sites-enabled/
```

**Optie B: Dashboard-only Config**
```bash
sudo cp nginx-netmonitor.conf /etc/nginx/sites-available/soc.poort.net
sudo ln -sf /etc/nginx/sites-available/soc.poort.net /etc/nginx/sites-enabled/
```

### 2. Test Nginx Configuratie
```bash
sudo nginx -t
```

Als succesvol, reload nginx:
```bash
sudo systemctl reload nginx
```

### 3. Restart Flask Dashboard

```bash
# Als systemd service
sudo systemctl restart netmonitor-dashboard
sudo systemctl status netmonitor-dashboard

# Of handmatig
cd /opt/netmonitor
python3 web_dashboard.py -c config.yaml
```

### 4. Verificatie

**Test lokaal op server:**
```bash
# Test Flask dashboard direct (poort 8080)
curl http://localhost:8080/kiosk

# Test kiosk metrics API
curl http://localhost:8080/api/kiosk/metrics | jq .

# Test sensors API
curl http://localhost:8080/api/kiosk/sensors | jq .
```

**Test via nginx (als proxy):**
```bash
# Via localhost (let op: GEEN poort, nginx luistert op 80/443)
curl http://localhost/kiosk

# Via domein
curl https://soc.poort.net/kiosk
```

**Test in browser:**
```
https://soc.poort.net/kiosk
```

## Nginx Location Blocks

De volgende location blocks zijn toegevoegd voor kiosk mode:

```nginx
# Kiosk Mode - Public access (GEEN authenticatie vereist)
location ~ ^/(kiosk|api/kiosk/) {
    proxy_pass http://netmonitor_dashboard;  # upstream: 127.0.0.1:8080
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # NO cookie passthrough - kiosk is public
    # NO authentication required

    proxy_buffering off;
    proxy_redirect off;
}
```

Dit matched:
- `/kiosk` - HTML pagina
- `/api/kiosk/metrics` - Metrics API
- `/api/kiosk/sensors` - Sensors API

## Troubleshooting

### 404 Error bij /kiosk

**Probleem:** `wget http://localhost:8000/kiosk` geeft 404

**Oorzaak:** Verkeerde poort! Flask dashboard draait op **8080**, niet 8000.

**Oplossing:**
```bash
# Correct - Test op poort 8080 (Flask dashboard)
curl http://localhost:8080/kiosk

# Of via nginx (geen poort nodig)
curl http://localhost/kiosk
```

### Connection Refused

**Probleem:** `curl http://localhost:8080/kiosk` → Connection refused

**Oorzaak:** Flask dashboard service draait niet.

**Oplossing:**
```bash
# Check of service draait
sudo systemctl status netmonitor-dashboard

# Start service
sudo systemctl start netmonitor-dashboard

# Check logs
sudo journalctl -u netmonitor-dashboard -f
```

### Nginx 502 Bad Gateway

**Probleem:** Nginx geeft 502 error

**Oorzaak:** Nginx kan Flask dashboard niet bereiken op poort 8080.

**Oplossing:**
```bash
# Check of Flask draait op 8080
netstat -tlnp | grep 8080
# Of
ss -tlnp | grep 8080

# Check nginx error log
sudo tail -f /var/log/nginx/netmonitor_error.log

# Restart dashboard
sudo systemctl restart netmonitor-dashboard
```

### API geeft lege data

**Probleem:** `/api/kiosk/metrics` returned zero values

**Oorzaak:** Database heeft geen sensor data.

**Oplossing:**
```bash
# Check of sensors data versturen
cd /opt/netmonitor
python3 -c "from database import DatabaseManager; db = DatabaseManager('netmonitor.db'); print(db.get_sensors())"

# Check database directly
sqlite3 netmonitor.db "SELECT sensor_id, hostname, last_seen FROM sensors;"
```

## Firewall Configuratie

Als je externe toegang wilt:

```bash
# Allow HTTP/HTTPS via nginx
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Dashboard poort 8080 NIET direct exposen (alleen via nginx)
# MCP poort 8000 NIET direct exposen (alleen via nginx)
```

## Kiosk Features Checklist

- [x] `/kiosk` route - Public accessible HTML pagina
- [x] `/api/kiosk/metrics` - Aggregated metrics van alle sensors
- [x] `/api/kiosk/sensors` - Sensor status overzicht
- [x] Auto-refresh (5 seconden)
- [x] Screen rotation (30 seconden)
- [x] Dark/Light theme toggle
- [x] Fullscreen support (F11)
- [x] Responsive design
- [x] Geen authenticatie vereist
- [x] Nginx proxy configuratie

## URLs Overzicht

| URL | Service | Poort | Doel |
|-----|---------|-------|------|
| `http://localhost:8080/kiosk` | Flask Direct | 8080 | Test zonder nginx |
| `http://localhost/kiosk` | Via Nginx | 80 | Test met nginx (HTTP) |
| `https://soc.poort.net/kiosk` | Via Nginx | 443 | Productie (HTTPS) |
| `http://localhost:8080/api/kiosk/metrics` | Flask Direct | 8080 | Metrics API direct |
| `https://soc.poort.net/api/kiosk/metrics` | Via Nginx | 443 | Metrics API productie |

## Monitoring

Monitor kiosk mode in productie:

```bash
# Nginx access log - kiosk requests
sudo tail -f /var/log/nginx/netmonitor_access.log | grep kiosk

# Flask dashboard logs
sudo journalctl -u netmonitor-dashboard -f | grep kiosk

# Check actieve connecties
sudo netstat -an | grep :8080 | grep ESTABLISHED
```

## Security Overwegingen

**Kiosk mode is PUBLIEK toegankelijk:**
- Geen login vereist
- Geen cookies/sessies nodig
- Read-only data (geen mutations)
- Alleen aggregated metrics (geen gevoelige details)

**Beperkingen aanbrengen (optioneel):**
```nginx
# In nginx config, voeg IP whitelist toe:
location ~ ^/(kiosk|api/kiosk/) {
    # Allow only internal network
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;

    proxy_pass http://netmonitor_dashboard;
    # ... rest van config
}
```

## Volgende Stappen

1. Deploy nginx configuratie
2. Restart netmonitor-dashboard service
3. Test lokaal op server
4. Test via domein
5. Open kiosk in browser op TV/display
6. Druk F11 voor fullscreen
7. Geniet van real-time SOC monitoring!

---

**Vragen of problemen?**
Check logs en test stap voor stap volgens deze guide.
