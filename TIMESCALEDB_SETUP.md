# TimescaleDB Setup Guide

## 🚀 Waarom TimescaleDB?

**TimescaleDB is speciaal gemaakt voor time-series data zoals security logs!**

### Performance Vergelijking
```
SQLite:          5 queries × 200ms = 1000ms  ❌
TimescaleDB:     1 query (aggregates) = 50ms ✅

→ 20x sneller!
```

### Features
- ✅ **Hypertables** - Automatisch gepartitioneerde time-series tables
- ✅ **Continuous Aggregates** - Pre-computed statistics
- ✅ **time_bucket()** - 5-minuten aggregaties voor snelle charts
- ✅ **Automatic Compression** - Data ouder dan 7 dagen wordt gecomprimeerd
- ✅ **Retention Policies** - Automatisch oude data verwijderen (90 dagen)
- ✅ **Connection Pooling** - Thread-safe met 2-10 connections

## 📦 Installatie

### Optie 1: Automatisch (Aanbevolen)

```bash
cd /opt/netmonitor
sudo ./setup_database.sh
```

Dit script installeert:
1. PostgreSQL 14
2. TimescaleDB extension
3. Tuned configuratie
4. Database + user aangemaakt

### Optie 2: Handmatig

```bash
# 1. Install PostgreSQL
sudo apt update
sudo apt install -y postgresql postgresql-contrib

# 2. Add TimescaleDB repository
sudo sh -c "echo 'deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescale_timescaledb.list"
wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | sudo apt-key add -

# 3. Install TimescaleDB
sudo apt update
sudo apt install -y timescaledb-2-postgresql-14

# 4. Tune TimescaleDB
sudo timescaledb-tune --yes

# 5. Restart PostgreSQL
sudo systemctl restart postgresql

# 6. Create database and user
sudo -u postgres psql <<EOF
CREATE USER netmonitor WITH PASSWORD 'netmonitor';
CREATE DATABASE netmonitor OWNER netmonitor;
GRANT ALL PRIVILEGES ON DATABASE netmonitor TO netmonitor;

\c netmonitor
CREATE EXTENSION timescaledb CASCADE;
GRANT ALL ON SCHEMA public TO netmonitor;
EOF
```

## 🔧 Configuration

De code is al aangepast! Check `config.yaml`:

```yaml
database:
  type: postgresql

  postgresql:
    host: localhost
    port: 5432
    database: netmonitor
    user: netmonitor
    password: netmonitor  # ⚠️ Change in production!
    min_connections: 2
    max_connections: 10
```

## 🧪 Test de Connectie

```bash
# Test PostgreSQL connectie
psql -U netmonitor -d netmonitor -h localhost
# Password: netmonitor

# In psql:
\dt              # Toon tables
\dx              # Toon extensions (moet timescaledb tonen)
\q               # Quit
```

## 🚀 Start NetMonitor

```bash
# Install Python dependencies (includes psycopg2)
pip3 install -r requirements.txt

# Test run
sudo python3 netmonitor.py

# Check logs
# Moet zien:
# - "Connection pool created: localhost:5432/netmonitor"
# - "Created hypertable: alerts"
# - "Created hypertable: traffic_metrics"
# - "TimescaleDB features configured"
```

## 📊 Database Schema

### Hypertables (Automatisch gepartitioneerd)

1. **alerts** - Chunked per dag
   - Alert history met compression na 7 dagen
   - Retention: 90 dagen

2. **traffic_metrics** - Chunked per dag
   - Verkeer statistieken
   - time_bucket aggregaties voor snelle queries

3. **top_talkers** - Chunked per uur
   - IP adres statistieken

4. **system_stats** - Chunked per dag
   - CPU, memory, packets/sec metrics

### Continuous Aggregates

**alert_stats_hourly** - Pre-computed per uur
```sql
SELECT time_bucket('1 hour', timestamp) AS bucket,
       severity, threat_type, COUNT(*)
FROM alerts
GROUP BY bucket, severity, threat_type
```

Auto-refresh: Elk uur

## 🎯 Performance Features

### 1. time_bucket Aggregatie
```sql
-- Oude manier (traag):
SELECT * FROM traffic_metrics WHERE timestamp > NOW() - INTERVAL '24 hours';
-- 1440 records voor 1 dag @ 1/min

-- Nieuwe manier (snel):
SELECT time_bucket('5 minutes', timestamp), AVG(total_bytes)
FROM traffic_metrics
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY time_bucket('5 minutes', timestamp);
-- Slechts 288 records (24h ÷ 5min)
```

### 2. Connection Pooling
```python
# Thread-safe connection pool
ThreadedConnectionPool(min=2, max=10)

# Automatisch connection reuse
# Geen overhead van nieuwe connections
```

### 3. Batch Inserts
```python
# Oude manier:
for talker in talkers:
    cursor.execute("INSERT ...")  # N queries

# Nieuwe manier:
cursor.executemany("INSERT ...", values)  # 1 query
```

### 4. Compression
```sql
-- Data ouder dan 7 dagen wordt automatisch gecomprimeerd
-- 90% ruimte besparing!
ALTER TABLE alerts SET (timescaledb.compress);
SELECT add_compression_policy('alerts', INTERVAL '7 days');
```

## 🔍 Nuttige Queries

```sql
-- Check hypertables
SELECT hypertable_name, chunk_sizing_func_name
FROM timescaledb_information.hypertables;

-- Check compression status
SELECT hypertable_name, compression_enabled
FROM timescaledb_information.hypertables;

-- Chunk sizes
SELECT hypertable_name, chunk_name,
       range_start, range_end,
       compressed_chunk_name IS NOT NULL as is_compressed
FROM timescaledb_information.chunks;

-- Alert statistieken (gebruik continuous aggregate!)
SELECT bucket, severity, threat_type, count
FROM alert_stats_hourly
WHERE bucket > NOW() - INTERVAL '24 hours'
ORDER BY bucket DESC;
```

## 🐛 Troubleshooting

### Error: "extension timescaledb does not exist"
```bash
sudo apt install timescaledb-2-postgresql-14
sudo systemctl restart postgresql
```

### Error: "FATAL: Peer authentication failed"
Edit `/etc/postgresql/14/main/pg_hba.conf`:
```
# Change:
local   all   all   peer

# To:
local   all   all   md5
```

Restart: `sudo systemctl restart postgresql`

### Error: "role netmonitor does not exist"
```bash
sudo -u postgres createuser netmonitor
sudo -u postgres createdb -O netmonitor netmonitor
```

### Slow Queries?
```sql
-- Check query performance
EXPLAIN ANALYZE SELECT ...;

-- Check missing indices
SELECT schemaname, tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public';
```

## 📈 Monitoring

```sql
-- Database size
SELECT pg_size_pretty(pg_database_size('netmonitor'));

-- Table sizes
SELECT hypertable_name,
       pg_size_pretty(hypertable_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass))
FROM timescaledb_information.hypertables;

-- Compression ratio
SELECT chunk_name,
       before_compression_total_bytes,
       after_compression_total_bytes,
       (before_compression_total_bytes::numeric - after_compression_total_bytes::numeric) /
       before_compression_total_bytes::numeric * 100 as compression_percent
FROM timescaledb_information.compressed_chunk_stats;

-- Active connections
SELECT count(*) FROM pg_stat_activity
WHERE datname = 'netmonitor';
```

## 🔐 Security (Production)

```bash
# 1. Change default password
sudo -u postgres psql -d netmonitor
ALTER USER netmonitor WITH PASSWORD 'your_strong_password_here';

# 2. Update config.yaml
database:
  postgresql:
    password: your_strong_password_here

# 3. Restrict PostgreSQL access
# Edit /etc/postgresql/14/main/pg_hba.conf
# Allow only from localhost:
host    netmonitor    netmonitor    127.0.0.1/32    md5

# 4. Restart PostgreSQL
sudo systemctl restart postgresql
```

## 🎉 Success Indicators

✅ Dashboard laadt in < 2 seconden (was minuten)
✅ Gauges tonen direct data
✅ Smooth scrolling in charts
✅ Database groeit met 90% compression
✅ Automatic old data cleanup

## 📚 More Info

- TimescaleDB Docs: https://docs.timescale.com/
- Best Practices: https://docs.timescale.com/timescaledb/latest/how-to-guides/
- SQL API: https://docs.timescale.com/api/latest/

---

**Need help?** Check logs:
```bash
sudo journalctl -u postgresql -f
sudo journalctl -u netmonitor.service -f
```
