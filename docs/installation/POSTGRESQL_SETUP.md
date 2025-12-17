# PostgreSQL + TimescaleDB Setup voor NetMonitor

## 📋 Overzicht

NetMonitor gebruikt **PostgreSQL + TimescaleDB** voor het opslaan van security alerts en metrics:

- **PostgreSQL**: Robuuste relationele database
- **TimescaleDB**: Time-series extensie voor efficiënte opslag van tijdgebonden data
- **Hypertables**: Automatische time-based partitioning
- **Continuous Aggregates**: Pre-computed statistics voor snelle queries

---

## 🏗️ Database Architectuur

### Database: `netmonitor`

### Tabellen:

1. **alerts** (Hypertable)
   - Security alerts (port scans, beaconing, etc.)
   - Partitioned op timestamp voor snelle time-range queries
   - JSONB metadata field voor flexible data opslag

2. **traffic_metrics** (Hypertable)
   - Inbound/outbound traffic statistieken
   - Per-minuut aggregatie

3. **top_talkers** (Hypertable)
   - Meest actieve IPs per tijdsperiode
   - Hostname lookups cached

4. **threat_feeds**
   - Bekende malicious IPs/domains van threat intelligence feeds
   - Updated elk uur via `update_feeds.py`

### Database Users:

1. **netmonitor** (Owner - Read/Write)
   - Main application user
   - Schrijft alerts, metrics, top talkers
   - Volledige toegang tot alle tabellen

2. **mcp_readonly** (Read-Only)
   - Voor MCP AI server
   - Alleen SELECT rechten
   - Security: kan geen data wijzigen/verwijderen

---

## 🚀 Quick Start (Automated)

### Methode 1: Gebruik het Setup Script (Aanbevolen)

```bash
cd /path/to/netmonitor
sudo ./setup_database.sh
```

Dit script:
- ✅ Installeert PostgreSQL + TimescaleDB
- ✅ Maakt database `netmonitor` aan
- ✅ Maakt user `netmonitor` met password
- ✅ Enabled TimescaleDB extensie
- ✅ Configured connection pooling

**Duurt:** ~5-10 minuten (afhankelijk van internet snelheid)

---

## 🔧 Handmatige Setup (Stap voor Stap)

Als je de automated setup niet wilt gebruiken of meer controle wilt:

### Stap 1: Installeer PostgreSQL

```bash
# Update package list
sudo apt-get update

# Install PostgreSQL
sudo apt-get install -y postgresql postgresql-contrib

# Check status
sudo systemctl status postgresql
```

**Versie check:**
```bash
psql --version
# Zou moeten zijn: PostgreSQL 12+ (liefst 14+)
```

### Stap 2: Installeer TimescaleDB

```bash
# Add TimescaleDB repository
sudo sh -c "echo 'deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescale_timescaledb.list"

# Add GPG key
wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | sudo apt-key add -

# Update and install
sudo apt-get update
sudo apt-get install -y timescaledb-2-postgresql-14

# Tune TimescaleDB for your system
sudo timescaledb-tune --quiet --yes

# Restart PostgreSQL
sudo systemctl restart postgresql
```

**Verificatie:**
```bash
sudo -u postgres psql -c "SELECT default_version FROM pg_available_extensions WHERE name='timescaledb';"
```

### Stap 3: Maak Database en Main User

```bash
# Switch to postgres user
sudo -u postgres psql
```

**In de PostgreSQL prompt:**
```sql
-- Create user
CREATE USER netmonitor WITH PASSWORD 'netmonitor';

-- Create database
CREATE DATABASE netmonitor OWNER netmonitor;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE netmonitor TO netmonitor;

-- Exit
\q
```

### Stap 4: Enable TimescaleDB Extensie

```bash
# Connect to netmonitor database
sudo -u postgres psql -d netmonitor
```

**In PostgreSQL:**
```sql
-- Enable TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO netmonitor;

-- Grant table permissions (for future tables)
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT ALL PRIVILEGES ON TABLES TO netmonitor;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT ALL PRIVILEGES ON SEQUENCES TO netmonitor;

-- Verify extension
\dx

-- Exit
\q
```

Je zou moeten zien:
```
Name         | Version | Schema | Description
-------------+---------+--------+-------------
timescaledb  | 2.x.x   | public | ...
```

### Stap 5: Maak MCP Read-Only User

Voor de MCP AI server (optioneel, alleen als je MCP gebruikt):

```bash
cd /path/to/netmonitor
sudo ./setup_mcp_user.sh
```

Of handmatig:
```bash
sudo -u postgres psql -d netmonitor
```

```sql
-- Create read-only user
CREATE USER mcp_readonly WITH PASSWORD 'mcp_netmonitor_readonly_2024';

-- Grant connect
GRANT CONNECT ON DATABASE netmonitor TO mcp_readonly;

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO mcp_readonly;

-- Grant SELECT on existing tables
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;

-- Grant SELECT on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT ON TABLES TO mcp_readonly;

-- Verify
\du mcp_readonly

-- Exit
\q
```

### Stap 6: Test Database Connection

**Als netmonitor user:**
```bash
psql -U netmonitor -d netmonitor -h localhost
# Password: netmonitor
```

**In psql:**
```sql
-- Check TimescaleDB
SELECT extversion FROM pg_extension WHERE extname = 'timescaledb';

-- List tables (should be empty initially)
\dt

-- Exit
\q
```

### Stap 7: Eerste Start van NetMonitor

NetMonitor maakt automatisch de schema's aan bij de eerste start:

```bash
cd /path/to/netmonitor
source venv/bin/activate
sudo python3 netmonitor.py
```

**Let op de logs:**
```
INFO - Database geïnitialiseerd: PostgreSQL + TimescaleDB
INFO - Hypertable created: alerts
INFO - Hypertable created: traffic_metrics
INFO - Hypertable created: top_talkers
```

Stop NetMonitor (Ctrl+C) en check de tabellen:

```bash
psql -U netmonitor -d netmonitor -h localhost -c "\dt"
```

Je zou moeten zien:
```
            List of relations
 Schema |      Name       | Type  |   Owner
--------+-----------------+-------+------------
 public | alerts          | table | netmonitor
 public | threat_feeds    | table | netmonitor
 public | top_talkers     | table | netmonitor
 public | traffic_metrics | table | netmonitor
```

---

## 🔐 Security Best Practices

### 1. Wijzig Default Passwords (BELANGRIJK!)

**In PostgreSQL:**
```sql
-- Change netmonitor password
ALTER USER netmonitor WITH PASSWORD 'your_strong_password_here';

-- Change mcp_readonly password
ALTER USER mcp_readonly WITH PASSWORD 'your_strong_readonly_password';
```

**Update config.yaml:**
```yaml
database:
  postgresql:
    password: your_strong_password_here
```

**Update MCP service:**
```bash
sudo nano /etc/systemd/system/netmonitor-mcp.service
# Wijzig NETMONITOR_DB_PASSWORD environment variable
sudo systemctl daemon-reload
sudo systemctl restart netmonitor-mcp
```

### 2. Restrict Network Access

**Edit pg_hba.conf:**
```bash
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

**Restrictieve configuratie:**
```
# TYPE  DATABASE    USER            ADDRESS         METHOD

# Local connections (Unix socket)
local   netmonitor  netmonitor                      peer
local   netmonitor  mcp_readonly                    md5

# Localhost only (TCP)
host    netmonitor  netmonitor      127.0.0.1/32    md5
host    netmonitor  mcp_readonly    127.0.0.1/32    md5

# Block everything else
host    all         all             0.0.0.0/0       reject
```

**Reload PostgreSQL:**
```bash
sudo systemctl reload postgresql
```

### 3. Enable SSL (Optioneel maar aanbevolen)

```bash
# Generate self-signed certificate
sudo openssl req -new -x509 -days 365 -nodes -text \
  -out /etc/postgresql/14/main/server.crt \
  -keyout /etc/postgresql/14/main/server.key \
  -subj "/CN=localhost"

# Set permissions
sudo chmod 600 /etc/postgresql/14/main/server.key
sudo chown postgres:postgres /etc/postgresql/14/main/server.{crt,key}

# Enable SSL in postgresql.conf
sudo nano /etc/postgresql/14/main/postgresql.conf
# Uncomment and set: ssl = on

# Restart
sudo systemctl restart postgresql
```

### 4. Backup User (Optioneel)

Voor backups zonder write permissions:

```sql
CREATE USER netmonitor_backup WITH PASSWORD 'backup_password';
GRANT CONNECT ON DATABASE netmonitor TO netmonitor_backup;
GRANT USAGE ON SCHEMA public TO netmonitor_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO netmonitor_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT ON TABLES TO netmonitor_backup;
```

---

## 💾 Backup & Restore

### Backup Maken

**Full database backup:**
```bash
# Met pg_dump
pg_dump -U netmonitor -h localhost netmonitor > netmonitor_backup_$(date +%Y%m%d).sql

# Compressed backup
pg_dump -U netmonitor -h localhost netmonitor | gzip > netmonitor_backup_$(date +%Y%m%d).sql.gz
```

**Backup script (automated):**
```bash
#!/bin/bash
# backup_netmonitor.sh

BACKUP_DIR="/var/backups/netmonitor"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/netmonitor_${DATE}.sql.gz"

mkdir -p "$BACKUP_DIR"

PGPASSWORD='netmonitor' pg_dump -U netmonitor -h localhost netmonitor | gzip > "$BACKUP_FILE"

# Keep only last 7 days
find "$BACKUP_DIR" -name "netmonitor_*.sql.gz" -mtime +7 -delete

echo "Backup saved: $BACKUP_FILE"
```

**Cron job (daily at 2 AM):**
```bash
sudo crontab -e
# Add:
0 2 * * * /path/to/backup_netmonitor.sh
```

### Restore van Backup

```bash
# Decompress if needed
gunzip netmonitor_backup_20250111.sql.gz

# Drop existing database (DESTRUCTIVE!)
sudo -u postgres psql -c "DROP DATABASE IF EXISTS netmonitor;"
sudo -u postgres psql -c "CREATE DATABASE netmonitor OWNER netmonitor;"

# Restore
psql -U netmonitor -h localhost netmonitor < netmonitor_backup_20250111.sql

# Verify
psql -U netmonitor -d netmonitor -h localhost -c "SELECT COUNT(*) FROM alerts;"
```

---

## 📊 Database Maintenance

### Vacuum en Analyze

**Manual:**
```sql
-- Connect
psql -U netmonitor -d netmonitor -h localhost

-- Vacuum all tables
VACUUM ANALYZE;

-- Specific table
VACUUM ANALYZE alerts;
```

**Automated (PostgreSQL autovacuum):**

PostgreSQL doet dit automatisch, maar je kunt settings tunen:

```bash
sudo nano /etc/postgresql/14/main/postgresql.conf
```

```
autovacuum = on
autovacuum_naptime = 1min
autovacuum_vacuum_threshold = 50
autovacuum_analyze_threshold = 50
```

### Data Retention (Oude Data Opruimen)

**Delete old alerts (older than 90 days):**
```sql
DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '90 days';
```

**Automated cleanup script:**
```sql
-- Create function
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS void AS $$
BEGIN
  -- Delete alerts older than 90 days
  DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '90 days';

  -- Delete metrics older than 30 days
  DELETE FROM traffic_metrics WHERE timestamp < NOW() - INTERVAL '30 days';
  DELETE FROM top_talkers WHERE timestamp < NOW() - INTERVAL '30 days';

  RAISE NOTICE 'Old data cleaned up';
END;
$$ LANGUAGE plpgsql;

-- Schedule with pg_cron (if installed)
SELECT cron.schedule('cleanup-old-data', '0 3 * * *', 'SELECT cleanup_old_data();');
```

### Database Size Monitoring

```sql
-- Database size
SELECT pg_size_pretty(pg_database_size('netmonitor'));

-- Table sizes
SELECT
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Row counts
SELECT
  tablename,
  n_live_tup AS rows
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY n_live_tup DESC;
```

---

## 🔍 Troubleshooting

### Probleem: "Connection refused"

**Oorzaak:** PostgreSQL draait niet of luistert niet op TCP

**Oplossing:**
```bash
# Check status
sudo systemctl status postgresql

# Start als gestopt
sudo systemctl start postgresql

# Check of het luistert op port 5432
sudo netstat -tlnp | grep 5432
# of
sudo ss -tlnp | grep 5432

# Check postgresql.conf
sudo nano /etc/postgresql/14/main/postgresql.conf
# Ensure: listen_addresses = 'localhost'  (or '*' for all)

# Restart
sudo systemctl restart postgresql
```

### Probleem: "FATAL: password authentication failed"

**Oorzaak:** Verkeerd password of pg_hba.conf configuratie

**Oplossing:**
```bash
# Reset password
sudo -u postgres psql -c "ALTER USER netmonitor WITH PASSWORD 'newpassword';"

# Check pg_hba.conf
sudo nano /etc/postgresql/14/main/pg_hba.conf
# Ensure:
# host netmonitor netmonitor 127.0.0.1/32 md5

# Reload
sudo systemctl reload postgresql

# Test
psql -U netmonitor -d netmonitor -h localhost
```

### Probleem: "TimescaleDB extension not found"

**Oorzaak:** TimescaleDB niet correct geïnstalleerd

**Oplossing:**
```bash
# Reinstall TimescaleDB
sudo apt-get install --reinstall timescaledb-2-postgresql-14

# Tune
sudo timescaledb-tune --quiet --yes

# Restart
sudo systemctl restart postgresql

# Verify
sudo -u postgres psql -c "SELECT default_version FROM pg_available_extensions WHERE name='timescaledb';"
```

### Probleem: Hypertable creation failed

**Error:** `ERROR: table "alerts" is not empty`

**Oorzaak:** Kan geen hypertable maken van bestaande tabel met data

**Oplossing:**
```sql
-- Backup data first!
CREATE TABLE alerts_backup AS SELECT * FROM alerts;

-- Drop and recreate
DROP TABLE alerts;
-- NetMonitor will recreate it as hypertable on next start

-- Or manually migrate (advanced)
-- See: https://docs.timescale.com/migrate/latest/
```

### Probleem: Database disk full

**Check disk space:**
```bash
df -h /var/lib/postgresql
```

**Solutions:**
```bash
# 1. Clean old data (see Data Retention section above)

# 2. Vacuum to reclaim space
sudo -u postgres psql -d netmonitor -c "VACUUM FULL;"

# 3. Archive old data
pg_dump -U netmonitor -h localhost netmonitor \
  --table=alerts \
  --where="timestamp < NOW() - INTERVAL '180 days'" \
  | gzip > old_alerts_archive.sql.gz

# Then delete archived data
psql -U netmonitor -d netmonitor -h localhost \
  -c "DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '180 days';"

# 4. Move PostgreSQL data directory (advanced)
# See: https://www.postgresql.org/docs/current/runtime-config-file-locations.html
```

---

## 📈 Performance Tuning

### PostgreSQL Configuration

```bash
sudo nano /etc/postgresql/14/main/postgresql.conf
```

**Voor server met 4GB RAM:**
```
# Memory
shared_buffers = 1GB
effective_cache_size = 3GB
work_mem = 16MB
maintenance_work_mem = 256MB

# Checkpoints
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100

# Logging (voor debugging)
log_min_duration_statement = 1000  # Log queries > 1s
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
```

**Restart na wijzigingen:**
```bash
sudo systemctl restart postgresql
```

### TimescaleDB Compression (Advanced)

Voor oude data kun je compression enablen:

```sql
-- Enable compression on alerts (older than 7 days)
ALTER TABLE alerts SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'severity,threat_type'
);

SELECT add_compression_policy('alerts', INTERVAL '7 days');

-- Check compression stats
SELECT
  hypertable_name,
  total_chunks,
  number_compressed_chunks,
  before_compression_total_bytes,
  after_compression_total_bytes,
  pg_size_pretty(before_compression_total_bytes) AS before,
  pg_size_pretty(after_compression_total_bytes) AS after
FROM timescaledb_information.compressed_hypertable_stats;
```

---

## ✅ Quick Reference

### Useful PostgreSQL Commands

```bash
# Connect as netmonitor
psql -U netmonitor -d netmonitor -h localhost

# Connect as postgres (admin)
sudo -u postgres psql -d netmonitor

# List databases
psql -U postgres -l

# List users
psql -U postgres -c "\du"

# Backup
pg_dump -U netmonitor -h localhost netmonitor > backup.sql

# Restore
psql -U netmonitor -h localhost netmonitor < backup.sql

# Check logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

### Useful SQL Queries

```sql
-- Check extension
SELECT * FROM pg_extension WHERE extname = 'timescaledb';

-- List hypertables
SELECT * FROM timescaledb_information.hypertables;

-- Row counts
SELECT
  'alerts' AS table, COUNT(*) AS rows FROM alerts
UNION ALL
SELECT 'traffic_metrics', COUNT(*) FROM traffic_metrics
UNION ALL
SELECT 'top_talkers', COUNT(*) FROM top_talkers
UNION ALL
SELECT 'threat_feeds', COUNT(*) FROM threat_feeds;

-- Recent alerts
SELECT timestamp, severity, threat_type, source_ip, description
FROM alerts
ORDER BY timestamp DESC
LIMIT 10;

-- Alert counts by type (last 24h)
SELECT
  threat_type,
  severity,
  COUNT(*) as count
FROM alerts
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY threat_type, severity
ORDER BY count DESC;

-- Top talkers (last hour)
SELECT
  ip_address,
  hostname,
  SUM(packet_count) as total_packets,
  SUM(byte_count) as total_bytes
FROM top_talkers
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY ip_address, hostname
ORDER BY total_bytes DESC
LIMIT 10;
```

---

## 📚 Additional Resources

**PostgreSQL:**
- Official Docs: https://www.postgresql.org/docs/
- Performance Tuning: https://wiki.postgresql.org/wiki/Performance_Optimization

**TimescaleDB:**
- Official Docs: https://docs.timescale.com/
- Best Practices: https://docs.timescale.com/timescaledb/latest/how-to-guides/
- Compression: https://docs.timescale.com/timescaledb/latest/how-to-guides/compression/

**NetMonitor Specific:**
- [TIMESCALEDB_SETUP.md](TIMESCALEDB_SETUP.md) - TimescaleDB features en optimalisaties
- [SERVICE_INSTALLATION.md](SERVICE_INSTALLATION.md) - Service management
- [VENV_SETUP.md](VENV_SETUP.md) - Virtual environment setup

---

## 🆘 Getting Help

**Check NetMonitor logs:**
```bash
# Service logs
sudo journalctl -u netmonitor -f

# Application log
tail -f /var/log/netmonitor/alerts.log
```

**Check PostgreSQL logs:**
```bash
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

**Database connection test:**
```bash
# From Python
python3 -c "
import psycopg2
try:
    conn = psycopg2.connect(
        host='localhost',
        port=5432,
        database='netmonitor',
        user='netmonitor',
        password='netmonitor'
    )
    print('✓ Connection successful!')
    conn.close()
except Exception as e:
    print(f'✗ Connection failed: {e}')
"
```

---

**Database setup compleet? Start NetMonitor services! 🚀**

```bash
cd /path/to/netmonitor
sudo ./install_services.sh
```
