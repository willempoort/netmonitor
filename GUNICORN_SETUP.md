# Gunicorn Production Setup voor NetMonitor

Complete productie setup met Gunicorn WSGI server op poort 8000.

## Waarom Gunicorn?

**Voordelen vs Eventlet direct:**
- ✅ Production-ready en battle-tested
- ✅ Better process management (worker pools)
- ✅ Automatic worker recycling
- ✅ Better performance under load
- ✅ Extensive logging en monitoring
- ✅ Graceful restarts zonder downtime

## 📦 Installatie

### 1. Installeer Dependencies

```bash
cd /opt/netmonitor
sudo pip install gunicorn eventlet
sudo pip install -r requirements.txt
```

### 2. Kopieer Configuratie Bestanden

```bash
# WSGI entry point
sudo cp wsgi.py /opt/netmonitor/

# Gunicorn configuratie
sudo cp gunicorn_config.py /opt/netmonitor/

# Systemd service
sudo cp netmonitor-gunicorn.service /etc/systemd/system/

# Nginx configuratie
sudo cp nginx-netmonitor-gunicorn.conf /etc/nginx/sites-available/netmonitor
sudo ln -sf /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/netmonitor
```

### 3. Maak Benodigde Directories

```bash
# Log directory
sudo mkdir -p /var/log/netmonitor
sudo chown root:root /var/log/netmonitor
sudo chmod 755 /var/log/netmonitor

# Runtime directory (voor PID files)
sudo mkdir -p /var/run/netmonitor
sudo chown root:root /var/run/netmonitor

# Database directory
sudo mkdir -p /var/lib/netmonitor
sudo chmod 755 /var/lib/netmonitor

# Cache directory (voor threat feeds)
sudo mkdir -p /var/cache/netmonitor/feeds
sudo chmod 755 /var/cache/netmonitor
```

### 4. Configureer Nginx

Pas je domeinnaam aan in de nginx config:

```bash
sudo nano /etc/nginx/sites-available/netmonitor
```

Wijzig:
```nginx
server_name soc.example.com;  # WIJZIG NAAR JE DOMEIN
```

Naar bijvoorbeeld:
```nginx
server_name soc.rapidsteelservice.com;
```

Test nginx configuratie:

```bash
sudo nginx -t
```

### 5. SSL Certificaat (Let's Encrypt)

```bash
# Installeer certbot
sudo apt-get install certbot python3-certbot-nginx

# Genereer certificaat
sudo certbot --nginx -d soc.jouwdomein.com

# Certbot update nginx config automatisch
```

Of gebruik bestaande certificaten door de paden aan te passen in nginx config.

### 6. Reload Systemd en Start Services

```bash
# Reload systemd
sudo systemctl daemon-reload

# Stop oude eventlet service (indien actief)
sudo systemctl stop netmonitor.service

# Enable en start Gunicorn service
sudo systemctl enable netmonitor-gunicorn.service
sudo systemctl start netmonitor-gunicorn.service

# Reload nginx
sudo systemctl reload nginx
```

## 🔍 Verificatie

### Check Service Status

```bash
# Check of Gunicorn draait
sudo systemctl status netmonitor-gunicorn.service

# Check logs
sudo journalctl -u netmonitor-gunicorn.service -f

# Check of poort 8000 luistert
sudo netstat -tulpn | grep 8000
sudo lsof -i :8000
```

### Test Dashboard

```bash
# Test direct op Gunicorn (local)
curl http://localhost:8000/api/status

# Test via nginx (local)
curl http://localhost/api/status

# Test via nginx met HTTPS (external)
curl https://soc.jouwdomein.com/api/status
```

Expected response:
```json
{
  "status": "online",
  "version": "1.0",
  "timestamp": "2025-12-10T12:34:56"
}
```

## 🔧 Configuratie Aanpassingen

### Worker Count Aanpassen

Edit `/opt/netmonitor/gunicorn_config.py`:

```python
# Standaard: CPU cores * 2 + 1
workers = multiprocessing.cpu_count() * 2 + 1

# Voor high traffic: meer workers
workers = 8

# Voor low memory: minder workers
workers = 2
```

Herstart service:
```bash
sudo systemctl restart netmonitor-gunicorn.service
```

### Timeout Aanpassen

Voor slow endpoints/long-running requests:

```python
# In gunicorn_config.py
timeout = 60  # Van 30 naar 60 seconden
graceful_timeout = 60
```

### Poort Aanpassen

**Als je een andere poort dan 8000 wilt gebruiken:**

1. Edit `gunicorn_config.py`:
   ```python
   bind = "127.0.0.1:8001"  # Wijzig poort
   ```

2. Edit `nginx-netmonitor-gunicorn.conf`:
   ```nginx
   upstream netmonitor_gunicorn {
       server 127.0.0.1:8001;  # Wijzig poort
   }
   ```

3. Herstart beide services:
   ```bash
   sudo systemctl restart netmonitor-gunicorn.service
   sudo systemctl reload nginx
   ```

## 📊 Monitoring en Logging

### Bekijk Logs

```bash
# Gunicorn logs
sudo tail -f /var/log/netmonitor/gunicorn_access.log
sudo tail -f /var/log/netmonitor/gunicorn_error.log

# Systemd journal
sudo journalctl -u netmonitor-gunicorn.service -f

# Nginx logs
sudo tail -f /var/log/nginx/netmonitor_access.log
sudo tail -f /var/log/nginx/netmonitor_error.log
```

### Worker Status

```bash
# Check hoeveel workers draaien
ps aux | grep gunicorn

# Detailed info
sudo systemctl status netmonitor-gunicorn.service
```

### Performance Metrics

```bash
# Request rate (in access log)
sudo tail -1000 /var/log/netmonitor/gunicorn_access.log | grep -oP '\d{2}/\w+/\d{4}:\d{2}:\d{2}' | sort | uniq -c

# Error rate
sudo grep -c "ERROR" /var/log/netmonitor/gunicorn_error.log

# Response times (in microseconds in access log)
sudo tail -1000 /var/log/netmonitor/gunicorn_access.log | awk '{print $(NF)}' | sort -n | tail -10
```

## 🔄 Updates en Restarts

### Code Update (Zero Downtime)

```bash
# Pull nieuwe code
cd /opt/netmonitor
git pull

# Graceful reload (workers worden 1-voor-1 vervangen)
sudo systemctl reload netmonitor-gunicorn.service

# Of gebruik HUP signal
sudo kill -HUP $(cat /var/run/netmonitor/gunicorn.pid)
```

### Full Restart

```bash
sudo systemctl restart netmonitor-gunicorn.service
```

### Config Update

```bash
# Na wijziging van gunicorn_config.py
sudo systemctl restart netmonitor-gunicorn.service

# Na wijziging van nginx config
sudo nginx -t && sudo systemctl reload nginx
```

## 🚨 Troubleshooting

### Service Start Faalt

```bash
# Check detailed error
sudo journalctl -u netmonitor-gunicorn.service -n 50 --no-pager

# Test Gunicorn handmatig
cd /opt/netmonitor
sudo gunicorn -c gunicorn_config.py wsgi:application
```

### Import Errors

```
ModuleNotFoundError: No module named 'eventlet'
```

**Oplossing:**
```bash
sudo pip install eventlet gunicorn
```

### Port Already in Use

```
[ERROR] Connection in use: ('127.0.0.1', 8000)
```

**Check wat de poort gebruikt:**
```bash
sudo lsof -i :8000
sudo netstat -tulpn | grep 8000
```

**Kill oude process:**
```bash
sudo kill $(sudo lsof -t -i:8000)
# Of
sudo systemctl stop netmonitor-gunicorn.service
```

### Worker Timeouts

```
[CRITICAL] WORKER TIMEOUT (pid:12345)
```

**Oplossing:** Verhoog timeout in `gunicorn_config.py`:
```python
timeout = 60  # Was 30
```

### SocketIO Connection Errors

```
WebSocket connection failed
```

**Check:**
1. Worker class is `eventlet`:
   ```python
   worker_class = "eventlet"
   ```

2. Nginx WebSocket headers zijn correct:
   ```nginx
   proxy_http_version 1.1;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection "upgrade";
   ```

3. Firewall allow WebSocket:
   ```bash
   sudo ufw allow 443/tcp
   ```

### High Memory Usage

**Reduce worker count** in `gunicorn_config.py`:
```python
workers = 2  # Minder workers
```

**Add memory limits** in systemd service:
```ini
[Service]
MemoryLimit=2G
```

## 📈 Performance Tuning

### High Traffic Networks

```python
# In gunicorn_config.py

# Meer workers
workers = 8

# Meer connections per worker
worker_connections = 2000

# Hogere backlog
backlog = 4096

# Worker recycling
max_requests = 2000
max_requests_jitter = 100
```

### Low Latency

```python
# Minder workers maar meer responsive
workers = 4
worker_connections = 500
timeout = 15
```

### Memory Constrained

```python
# Minimaal aantal workers
workers = 2
worker_connections = 500

# Aggressieve worker recycling
max_requests = 500
```

## 🔐 Security Hardening

### Systemd Hardening

Al inbegrepen in `netmonitor-gunicorn.service`:
```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/netmonitor /var/log/netmonitor
```

### Nginx Rate Limiting

Add to nginx config:
```nginx
# Limit requests per IP
limit_req_zone $binary_remote_addr zone=dashboard:10m rate=10r/s;

server {
    ...
    location /api/ {
        limit_req zone=dashboard burst=20 nodelay;
        ...
    }
}
```

### Firewall

```bash
# Only allow nginx to access Gunicorn
sudo ufw deny 8000/tcp

# Allow HTTPS
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
```

## ✅ Production Checklist

- [ ] Gunicorn installed (`pip show gunicorn`)
- [ ] Eventlet installed (`pip show eventlet`)
- [ ] WSGI file in `/opt/netmonitor/wsgi.py`
- [ ] Gunicorn config in `/opt/netmonitor/gunicorn_config.py`
- [ ] Service file copied and daemon-reload
- [ ] Log directories created (`/var/log/netmonitor`)
- [ ] Runtime directory created (`/var/run/netmonitor`)
- [ ] Nginx config updated with correct domain
- [ ] SSL certificate installed (Let's Encrypt)
- [ ] Nginx config tested (`nginx -t`)
- [ ] Service enabled and started
- [ ] Port 8000 listening (`lsof -i :8000`)
- [ ] Dashboard accessible via nginx
- [ ] SocketIO connections working
- [ ] Logs being written
- [ ] Worker processes running (check with `ps aux | grep gunicorn`)

## 🔄 Vergelijking: Eventlet vs Gunicorn+Eventlet

| Feature | Direct Eventlet | Gunicorn+Eventlet |
|---------|----------------|-------------------|
| Worker Management | Manual | Automatic |
| Zero-downtime Reload | ❌ | ✅ |
| Worker Recycling | ❌ | ✅ |
| Load Balancing | ❌ | ✅ (tussen workers) |
| Monitoring | Basic | Extensive |
| Production Ready | ⚠️ | ✅ |

**Conclusie:** Gunicorn+Eventlet is de betere keuze voor productie!

## 📞 Support

Als je problemen hebt:

1. Check logs: `sudo journalctl -u netmonitor-gunicorn.service -f`
2. Test handmatig: `cd /opt/netmonitor && gunicorn -c gunicorn_config.py wsgi:application`
3. Verify dependencies: `pip list | grep -E "flask|socketio|eventlet|gunicorn"`
4. Test WSGI app: `python3 wsgi.py`

**Alles werkt?** 🎉 Je NetMonitor draait nu op een production-ready Gunicorn setup!
