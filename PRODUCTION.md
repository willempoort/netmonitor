# Production Deployment Guide

Gids voor het deployen van Network Monitor als systemd service in productie.

## Probleem: Werkzeug Development Server

Als je deze fout krijgt:
```
RuntimeError: The Werkzeug web server is not designed to run in production...
```

Dit komt omdat Flask's development server niet geschikt is voor productie, vooral niet met threading.

**Oplossing**: We gebruiken nu **eventlet** als production-ready WSGI server.

## ✅ Fix is al Geïmplementeerd

De code is al aangepast om eventlet te gebruiken:
- `web_dashboard.py` gebruikt `async_mode='eventlet'`
- `eventlet.monkey_patch()` wordt toegepast bij import
- `requirements.txt` bevat `eventlet>=0.33.0`

## 🚀 Installatie als Systemd Service

### 1. Installeer Dependencies

```bash
cd /opt/netmonitor
sudo pip install -r requirements.txt
```

**BELANGRIJK**: Zorg dat eventlet geïnstalleerd is:
```bash
sudo pip install eventlet>=0.33.0
```

### 2. Kopieer Service Files

```bash
# Network monitor service
sudo cp netmonitor.service /etc/systemd/system/

# Threat feed update service en timer
sudo cp netmonitor-feed-update.service /etc/systemd/system/
sudo cp netmonitor-feed-update.timer /etc/systemd/system/
```

### 3. Pas Service File Aan (indien nodig)

Edit `/etc/systemd/system/netmonitor.service`:

```ini
[Unit]
Description=Network Monitor - Security Operations Center
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netmonitor
ExecStart=/usr/bin/python3 /opt/netmonitor/netmonitor.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Check Python pad**:
```bash
which python3  # Use dit pad in ExecStart
```

### 4. Reload Systemd

```bash
sudo systemctl daemon-reload
```

### 5. Enable en Start Service

```bash
# Enable voor autostart bij boot
sudo systemctl enable netmonitor.service
sudo systemctl enable netmonitor-feed-update.timer

# Start service
sudo systemctl start netmonitor.service
sudo systemctl start netmonitor-feed-update.timer
```

### 6. Check Status

```bash
# Check of service draait
sudo systemctl status netmonitor.service

# Check logs
sudo journalctl -u netmonitor.service -f

# Check of dashboard accessible is
curl http://localhost:8080/api/status
```

## 🔧 Troubleshooting

### Service Start Mislukt

```bash
# Bekijk detailed logs
sudo journalctl -u netmonitor.service -n 50 --no-pager

# Check voor Python errors
sudo journalctl -u netmonitor.service | grep -i error

# Test manueel
cd /opt/netmonitor
sudo python3 netmonitor.py
```

### Eventlet Import Error

```
ImportError: No module named 'eventlet'
```

**Oplossing:**
```bash
sudo pip install eventlet
# Of
sudo pip install -r requirements.txt
```

### Permission Errors

```
PermissionError: [Errno 13] Permission denied
```

**Oplossing:**
```bash
# Service moet als root draaien voor packet capture
sudo systemctl edit netmonitor.service

# Voeg toe:
[Service]
User=root
```

### Database Permission Issues

```bash
# Fix database permissions
sudo mkdir -p /var/lib/netmonitor
sudo chmod 755 /var/lib/netmonitor
sudo chown root:root /var/lib/netmonitor
```

### Port 8080 Already in Use

```
OSError: [Errno 98] Address already in use
```

**Check wat port gebruikt:**
```bash
sudo netstat -tulpn | grep 8080
sudo lsof -i :8080
```

**Oplossing 1 - Kill andere process:**
```bash
sudo kill $(sudo lsof -t -i:8080)
```

**Oplossing 2 - Gebruik andere port:**

Edit `config.yaml`:
```yaml
dashboard:
  port: 8081  # Of andere vrije port
```

### Service Stopt Direct

```bash
# Check logs voor crash reason
sudo journalctl -u netmonitor.service -n 100

# Meest voorkomende oorzaken:
# 1. Config file niet gevonden
# 2. Interface bestaat niet
# 3. Geen root privileges
# 4. Dependency missing
```

## 📊 Monitoring van Service

### Logs Bekijken

```bash
# Real-time logs
sudo journalctl -u netmonitor.service -f

# Laatste 100 regels
sudo journalctl -u netmonitor.service -n 100

# Logs van vandaag
sudo journalctl -u netmonitor.service --since today

# Filter op errors
sudo journalctl -u netmonitor.service -p err
```

### Resource Usage

```bash
# CPU en Memory
sudo systemctl status netmonitor.service

# Detailed stats
top -p $(pgrep -f netmonitor.py)

# Memory details
ps aux | grep netmonitor.py
```

### Service Health Check

```bash
# Check of service actief is
sudo systemctl is-active netmonitor.service

# Check of dashboard responding is
curl http://localhost:8080/api/status

# Check database
sqlite3 /var/lib/netmonitor/netmonitor.db "SELECT COUNT(*) FROM alerts;"
```

## 🔄 Updates en Restart

### Code Update

```bash
# Stop service
sudo systemctl stop netmonitor.service

# Pull nieuwe code (of update files)
cd /opt/netmonitor
git pull  # Of kopieer nieuwe files

# Update dependencies
sudo pip install -r requirements.txt --upgrade

# Restart service
sudo systemctl start netmonitor.service

# Check status
sudo systemctl status netmonitor.service
```

### Config Update

```bash
# Edit config
sudo nano /opt/netmonitor/config.yaml

# Restart service om nieuwe config te laden
sudo systemctl restart netmonitor.service
```

### Database Reset

```bash
# WAARSCHUWING: Dit verwijdert alle data!

# Stop service
sudo systemctl stop netmonitor.service

# Backup oude database
sudo cp /var/lib/netmonitor/netmonitor.db /var/lib/netmonitor/netmonitor.db.backup

# Verwijder database
sudo rm /var/lib/netmonitor/netmonitor.db

# Start service (maakt nieuwe database)
sudo systemctl start netmonitor.service
```

## 🔒 Security Hardening

### Firewall Configuration

```bash
# Allow dashboard port
sudo ufw allow 8080/tcp

# Allow from specific IP only
sudo ufw allow from 192.168.1.0/24 to any port 8080

# Check firewall status
sudo ufw status
```

### Run as Non-Root (Advanced)

**Probleem**: Packet capture vereist root privileges.

**Oplossing**: Geef CAP_NET_RAW capability aan Python:

```bash
# Install libcap2-bin
sudo apt-get install libcap2-bin

# Set capability
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.11

# Create netmonitor user
sudo useradd -r -s /bin/false netmonitor

# Update service file
sudo systemctl edit netmonitor.service

# Set:
[Service]
User=netmonitor
Group=netmonitor
```

**WAARSCHUWING**: Dit heeft security implicaties. Test grondig!

### Limit Service Resources

Edit service file:

```ini
[Service]
# Limit memory to 1GB
MemoryLimit=1G

# Limit CPU to 50%
CPUQuota=50%

# Prevent fork bombs
TasksMax=100
```

## 📈 Production Best Practices

### 1. Log Rotation

Edit `/etc/logrotate.d/netmonitor`:

```
/var/log/netmonitor/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload netmonitor.service > /dev/null 2>&1 || true
    endscript
}
```

### 2. Database Maintenance

Cron job voor cleanup:

```bash
# Edit crontab
sudo crontab -e

# Voeg toe: cleanup elke nacht om 2:00
0 2 * * * /usr/bin/python3 -c "from database import DatabaseManager; db = DatabaseManager(); db.cleanup_old_data(days=30)" >> /var/log/netmonitor/cleanup.log 2>&1
```

### 3. Monitoring met Systemd Watchdog

Edit service file:

```ini
[Service]
WatchdogSec=30
Restart=always
RestartSec=10
```

### 4. Alerting op Service Failure

Install OnFailure handler:

```bash
# Create alert script
sudo nano /usr/local/bin/netmonitor-alert.sh

#!/bin/bash
echo "Network Monitor service failed!" | mail -s "ALERT: NetMonitor Down" admin@example.com

# Make executable
sudo chmod +x /usr/local/bin/netmonitor-alert.sh

# Update service
[Unit]
OnFailure=netmonitor-alert.service
```

## 🚀 Performance Tuning

### High Traffic Networks

Edit `config.yaml`:

```yaml
# Reduce log verbosity
logging:
  level: WARNING  # Instead of INFO

# Increase alert rate limit
alerts:
  max_per_minute: 200  # Instead of 100

# Optimize database writes
dashboard:
  metrics_save_interval: 120  # Save every 2 min instead of 1
```

### Optimize Eventlet

In `web_dashboard.py`:

```python
# Increase eventlet pool size
import eventlet
eventlet.monkey_patch()
```

## 📞 Support

Als je nog steeds problemen hebt:

1. **Check logs**: `sudo journalctl -u netmonitor.service -f`
2. **Test manually**: `sudo python3 netmonitor.py`
3. **Verify eventlet**: `python3 -c "import eventlet; print(eventlet.__version__)"`
4. **Check all dependencies**: `pip list | grep -E "flask|socketio|eventlet"`

## ✅ Checklist voor Production

- [ ] Eventlet geïnstalleerd (`pip show eventlet`)
- [ ] Config file correct (`/opt/netmonitor/config.yaml`)
- [ ] Directories exist (`/var/lib/netmonitor`, `/var/log/netmonitor`)
- [ ] Service file gekopieerd en daemon-reload
- [ ] Firewall regel toegevoegd
- [ ] Service enabled en started
- [ ] Dashboard toegankelijk (curl http://localhost:8080)
- [ ] Logs worden geschreven
- [ ] Database wordt aangemaakt
- [ ] Threat feeds gedownload
- [ ] Auto-update timer actief

**Alle checks OK? Dan ben je klaar voor productie!** 🎉
