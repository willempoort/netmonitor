# NetMonitor Startup Guide

## Current Status
- ✗ NetMonitor is NOT running
- ✗ Database tables NOT initialized (because NetMonitor hasn't run yet)
- ✗ PostgreSQL might not be running

## How to Fix - Step by Step

### Step 1: Start PostgreSQL (if needed)

Check if running:
```bash
ps aux | grep postgres | grep -v grep
```

If not running, start it:
```bash
# Option A: With systemd (production)
sudo systemctl start postgresql
sudo systemctl enable postgresql  # Auto-start on boot

# Option B: Manual start (development)
sudo -u postgres /usr/lib/postgresql/*/bin/postgres -D /var/lib/postgresql/*/main &
```

### Step 2: Create database (if doesn't exist)

```bash
sudo -u postgres psql -c "CREATE DATABASE netmonitor;"
sudo -u postgres psql -c "CREATE USER netmonitor WITH PASSWORD 'netmonitor';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE netmonitor TO netmonitor;"
```

### Step 3: Start NetMonitor

```bash
cd /opt/netmonitor

# Option A: Foreground (see logs directly)
python3 netmonitor.py

# Option B: Background (with systemd)
sudo systemctl start netmonitor
sudo systemctl status netmonitor

# Option C: Background (with nohup)
nohup python3 netmonitor.py > netmonitor.log 2>&1 &
```

### Step 4: Verify database initialization

Wait 5 seconds for NetMonitor to initialize, then check:

```bash
./check_database_status.py
```

You should see:
- ✓ Schema version: 13
- ✓ sensor_configs table exists
- ✓ Multiple tables created

### Step 5: Access Web Dashboard

Open browser:
```
http://localhost:8080
```

Login with default credentials:
- Username: admin
- Password: admin

### Step 6: Check threat detection config

1. Go to Configuration Management
2. Click "Advanced Threats" tab
3. You should see 6 threat types with toggle switches
4. The "All Parameters" tab should show `threat.*` parameters

### Step 7: Hard refresh browser

After starting NetMonitor:
- Windows/Linux: **Ctrl + F5**
- Mac: **Cmd + Shift + R**

This loads the new JavaScript with cache buster v=4

## What NetMonitor Does on Startup

When you start NetMonitor, it automatically:
1. ✓ Connects to PostgreSQL
2. ✓ Creates `netmonitor_meta` table
3. ✓ Sets SCHEMA_VERSION to 13
4. ✓ Creates all 20+ tables (sensors, alerts, sensor_configs, etc.)
5. ✓ Initializes 24 threat detection parameters in sensor_configs
6. ✓ Starts web dashboard on port 8080
7. ✓ Starts monitoring configured interface

## Troubleshooting

**If PostgreSQL connection fails:**
- Check config.yaml database settings
- Verify PostgreSQL is running
- Check user/password are correct

**If web dashboard doesn't load:**
- Check if port 8080 is already in use: `netstat -tlnp | grep 8080`
- Check NetMonitor logs for errors

**If threat parameters don't show:**
- Hard refresh browser (Ctrl+F5)
- Check browser console for JavaScript errors (F12)
- Verify cache buster is v=4: view page source, search for "config-management.js"

## Quick Start (All-in-One)

```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Start NetMonitor
cd /opt/netmonitor
python3 netmonitor.py &

# Wait 10 seconds
sleep 10

# Check status
./check_database_status.py

# Open browser
xdg-open http://localhost:8080  # Linux
# or just navigate to http://localhost:8080
```

Done! 🎉
