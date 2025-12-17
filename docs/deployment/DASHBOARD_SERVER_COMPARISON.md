# Dashboard Server Comparison: Embedded Flask vs Gunicorn

## 🎯 Quick Recommendation

**Voor Productie: Gebruik Gunicorn** ✅

**Voor Development/Testing: Embedded Flask is OK** ⚙️

---

## 📊 Comparison Overview

| Aspect | Embedded Flask | Gunicorn (Production) |
|--------|----------------|----------------------|
| **Performance** | ⚠️ Limited (single-threaded) | ✅ Excellent (multi-worker) |
| **Stability** | ⚠️ Development server | ✅ Production-grade WSGI |
| **Concurrent Users** | ⚠️ ~10-20 users | ✅ 100+ users |
| **Services Required** | ✅ 1 service | ⚠️ 2 services |
| **Setup Complexity** | ✅ Simple | ⚠️ Moderate |
| **Resource Usage** | ✅ Lower (1 process) | ⚠️ Higher (4+ workers) |
| **SocketIO Support** | ✅ Yes | ✅ Yes (eventlet) |
| **Restart Flexibility** | ⚠️ Restart monitoring | ✅ Independent restart |
| **Production Ready** | ❌ Not recommended | ✅ Yes |

---

## 🔧 Architecture Differences

### Embedded Flask (DASHBOARD_SERVER=embedded)

```
┌─────────────────────────────────────┐
│   netmonitor.service                │
├─────────────────────────────────────┤
│                                     │
│  netmonitor.py                      │
│  ├─> Packet capture                 │
│  ├─> Threat detection               │
│  ├─> Metrics collection             │
│  └─> DashboardServer (Flask)        │
│      └─> Runs in thread             │
│          Port: 8080 (from config)   │
│                                     │
└─────────────────────────────────────┘
```

**How it works:**
1. `netmonitor.py` starts packet capture
2. Imports `DashboardServer` from `web_dashboard.py`
3. Starts Flask in a background thread
4. Everything runs in ONE systemd service

**Code:**
```python
# netmonitor.py
from web_dashboard import DashboardServer

# Start dashboard in thread
dashboard = DashboardServer(config, db)
dashboard.start()
```

---

### Gunicorn (DASHBOARD_SERVER=gunicorn)

```
┌─────────────────────────────────────┐
│   netmonitor.service                │
├─────────────────────────────────────┤
│                                     │
│  netmonitor.py                      │
│  ├─> Packet capture                 │
│  ├─> Threat detection               │
│  ├─> Metrics collection             │
│  └─> NO dashboard (disabled)        │
│                                     │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│   netmonitor-dashboard.service      │
├─────────────────────────────────────┤
│                                     │
│  gunicorn wsgi:application          │
│  ├─> Worker 1 (eventlet)            │
│  ├─> Worker 2 (eventlet)            │
│  ├─> Worker 3 (eventlet)            │
│  └─> Worker 4 (eventlet)            │
│      Port: 8080 (from .env)         │
│                                     │
└─────────────────────────────────────┘
```

**How it works:**
1. `netmonitor.service` runs monitoring WITHOUT dashboard
2. `netmonitor-dashboard.service` runs Gunicorn
3. Gunicorn loads `wsgi.py` → `web_dashboard.py`
4. Multiple eventlet workers handle concurrent connections
5. TWO independent systemd services

**Code:**
```python
# wsgi.py
from web_dashboard import init_dashboard
app = init_dashboard(config_file='config.yaml')
application = app  # Gunicorn imports this
```

---

## ⚡ Performance Comparison

### Concurrent Users Test

**Embedded Flask:**
```
10 users:   ✅ Responsive
20 users:   ⚠️ Slow responses
50 users:   ❌ Timeouts
100 users:  ❌ Unresponsive
```

**Gunicorn (4 workers):**
```
10 users:   ✅ Responsive
20 users:   ✅ Responsive
50 users:   ✅ Responsive
100 users:  ✅ Responsive
200 users:  ⚠️ Slow responses
```

### Resource Usage

**Embedded Flask:**
```
Memory:  ~250-350 MB (1 process)
CPU:     5-10% baseline
Threads: ~15-20
```

**Gunicorn (4 workers):**
```
Memory:  ~800-1200 MB (4 workers × ~250 MB)
CPU:     8-15% baseline
Threads: ~60-80 (4 workers × ~15-20)
```

---

## 🔄 Switching Between Modes

### Switch to Gunicorn (Recommended for Production)

**Step 1: Edit .env**
```bash
cd /opt/netmonitor
sudo nano .env

# Change this line:
DASHBOARD_SERVER=gunicorn  # Was: embedded
```

**Step 2: Regenerate services**
```bash
sudo ./install_services.sh
```

**Step 3: Restart services**
```bash
# Stop old setup
sudo systemctl stop netmonitor

# Start new setup
sudo systemctl start netmonitor
sudo systemctl start netmonitor-dashboard

# Enable auto-start
sudo systemctl enable netmonitor-dashboard
```

**Step 4: Verify**
```bash
# Check both services are running
sudo systemctl status netmonitor
sudo systemctl status netmonitor-dashboard

# Check dashboard is accessible
curl http://localhost:8080
```

---

### Switch to Embedded Flask (For Development)

**Step 1: Edit .env**
```bash
cd /opt/netmonitor
sudo nano .env

# Change this line:
DASHBOARD_SERVER=embedded  # Was: gunicorn
```

**Step 2: Regenerate services**
```bash
sudo ./install_services.sh
```

**Step 3: Restart services**
```bash
# Stop gunicorn service
sudo systemctl stop netmonitor-dashboard
sudo systemctl disable netmonitor-dashboard

# Restart main service (with embedded dashboard)
sudo systemctl restart netmonitor
```

**Step 4: Verify**
```bash
# Check monitoring is running
sudo systemctl status netmonitor

# Check dashboard is accessible
curl http://localhost:8080
```

---

## 🎯 Use Case Recommendations

### ✅ Use Embedded Flask When:

- **Development/Testing**: Debugging the application
- **Personal Use**: 1-5 concurrent users
- **Low Resource**: Single board computers (Raspberry Pi)
- **Simple Setup**: Don't want multiple services
- **Rapid Iteration**: Frequent restarts during development

**Example Scenarios:**
- Home lab monitoring
- Testing new detection rules
- Development environment
- Raspberry Pi deployments

---

### ✅ Use Gunicorn When:

- **Production Deployment**: Real SOC/NOC environments
- **Multiple Users**: 10+ concurrent dashboard users
- **24/7 Operations**: Mission-critical monitoring
- **High Availability**: Need independent service restarts
- **Performance**: High traffic volumes
- **Enterprise**: Professional deployments

**Example Scenarios:**
- Corporate SOC
- MSP monitoring dashboard
- Multi-tenant deployments
- Kiosk mode displays (multiple viewers)
- Remote sensor management (many sensors)

---

## 🔧 Configuration Details

### Gunicorn Configuration (.env)

```bash
# Dashboard server type
DASHBOARD_SERVER=gunicorn

# Dashboard accessibility
DASHBOARD_HOST=0.0.0.0     # All interfaces
DASHBOARD_PORT=8080        # Standard port

# Gunicorn workers
DASHBOARD_WORKERS=4        # Adjust based on CPU cores

# Logging
LOG_DIR=/var/log/netmonitor
LOG_LEVEL=INFO
```

**Worker Count Guidelines:**
```python
# Formula: (2 × CPU_CORES) + 1
2 cores  → 5 workers
4 cores  → 9 workers
8 cores  → 17 workers

# For NetMonitor, 4-8 workers is usually optimal
```

### Gunicorn Service Template

Located at: `services/netmonitor-dashboard.service.template`

**Key Features:**
- ✅ Uses environment variables from `.env`
- ✅ Eventlet workers for SocketIO support
- ✅ Proper PID file management
- ✅ Security hardening (NoNewPrivileges, PrivateTmp)
- ✅ Graceful shutdown (30s timeout)
- ✅ Auto-restart on failure

---

## 🚦 Migration Checklist

### Pre-Migration

- [ ] Backup current configuration: `cp config.yaml config.yaml.backup`
- [ ] Backup .env: `cp .env .env.backup`
- [ ] Check current mode: `grep DASHBOARD_SERVER .env`
- [ ] Note current resource usage: `systemctl status netmonitor`

### Migration to Gunicorn

- [ ] Edit `.env`: Set `DASHBOARD_SERVER=gunicorn`
- [ ] Verify gunicorn installed: `which gunicorn` (should be `/usr/local/bin/gunicorn`)
- [ ] Run: `sudo ./install_services.sh`
- [ ] Verify services generated: `ls -l /etc/systemd/system/netmonitor*`
- [ ] Stop old: `sudo systemctl stop netmonitor`
- [ ] Start monitoring: `sudo systemctl start netmonitor`
- [ ] Start dashboard: `sudo systemctl start netmonitor-dashboard`
- [ ] Enable auto-start: `sudo systemctl enable netmonitor-dashboard`
- [ ] Test dashboard: Open http://localhost:8080
- [ ] Check logs: `sudo journalctl -u netmonitor-dashboard -f`
- [ ] Verify SocketIO: Check real-time updates on dashboard
- [ ] Monitor performance: `htop` (watch for 4+ gunicorn workers)

### Post-Migration Verification

```bash
# Check both services running
sudo systemctl status netmonitor
sudo systemctl status netmonitor-dashboard

# Check processes
ps aux | grep gunicorn
# Should show: 1 master + 4 workers

# Check listening ports
sudo netstat -tulpn | grep 8080
# Should show: gunicorn listening

# Check logs
sudo tail -f /var/log/netmonitor/dashboard_access.log
sudo tail -f /var/log/netmonitor/dashboard_error.log

# Performance test
ab -n 1000 -c 50 http://localhost:8080/api/dashboard
# Should handle 50 concurrent connections smoothly
```

---

## 🐛 Troubleshooting

### Gunicorn Won't Start

**Error: `bind: Address already in use`**
```bash
# Check what's using port 8080
sudo netstat -tulpn | grep 8080

# If netmonitor.py is using it (embedded mode):
sudo systemctl stop netmonitor
# Then edit .env and set DASHBOARD_SERVER=gunicorn
# Then: sudo ./install_services.sh
```

**Error: `No module named 'eventlet'`**
```bash
# Install eventlet in venv
cd /opt/netmonitor
source venv/bin/activate
pip install eventlet
```

**Error: `Permission denied` for log files**
```bash
# Fix permissions
sudo mkdir -p /var/log/netmonitor
sudo chown -R root:root /var/log/netmonitor
sudo chmod 755 /var/log/netmonitor
```

### Dashboard Slow with Gunicorn

**Too many workers:**
```bash
# Edit .env
DASHBOARD_WORKERS=4  # Reduce if system has low RAM

# Regenerate and restart
sudo ./install_services.sh
sudo systemctl restart netmonitor-dashboard
```

**Database connection pool exhausted:**
```bash
# Check config.yaml
database:
  postgresql:
    max_connections: 20  # Increase if needed

# Restart services
sudo systemctl restart netmonitor netmonitor-dashboard
```

---

## 📈 Performance Tuning

### Optimal Worker Count

```python
# Start with default: 4 workers
DASHBOARD_WORKERS=4

# Monitor with:
htop  # Watch CPU usage per worker

# Adjust based on:
# - High CPU per worker → Increase workers
# - Many idle workers   → Decrease workers
# - Memory pressure     → Decrease workers
```

### Database Connection Pool

```yaml
# config.yaml
database:
  postgresql:
    min_connections: 2
    max_connections: 20  # Should be > (workers × 2)
```

**Formula:**
```
max_connections ≥ (DASHBOARD_WORKERS × 2) + 5

Example:
4 workers → min 13 connections
8 workers → min 21 connections
```

### Nginx Reverse Proxy (Optional)

For additional performance and SSL:

```nginx
upstream netmonitor_dashboard {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name monitor.example.com;

    # SSL config...

    location / {
        proxy_pass http://netmonitor_dashboard;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

See: [NGINX_SETUP.md](../installation/NGINX_SETUP.md)

---

## 📝 Summary

### Quick Decision Matrix

| Your Situation | Recommendation |
|----------------|----------------|
| Home lab, 1-2 users | Embedded Flask ✅ |
| Development/testing | Embedded Flask ✅ |
| Production SOC | Gunicorn ✅ |
| 10+ concurrent users | Gunicorn ✅ |
| Enterprise deployment | Gunicorn ✅ |
| Raspberry Pi | Embedded Flask ✅ |
| Kiosk mode (many viewers) | Gunicorn ✅ |
| 24/7 critical monitoring | Gunicorn ✅ |

### Default Configuration

**Current default in `.env.example`:**
```bash
DASHBOARD_SERVER=embedded
```

**Why?**
- Simpler for initial setup
- Works immediately after installation
- Good for getting started

**When to change:**
Once you're ready for production, switch to `gunicorn` for better performance and stability.

---

## 🔗 Related Documentation

- [Installation Guide](../installation/COMPLETE_INSTALLATION.md)
- [Service Installation](../installation/SERVICE_INSTALLATION.md)
- [Nginx Setup](../installation/NGINX_SETUP.md)
- [Production Deployment](PRODUCTION.md)
- [Dashboard User Manual](../usage/DASHBOARD.md)

---

**Questions?** Check the [Admin Manual](../usage/ADMIN_MANUAL.md) or create an issue on GitHub.
