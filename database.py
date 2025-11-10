"""
Database Module - PostgreSQL + TimescaleDB
Optimized for time-series security data with hypertables and continuous aggregates
"""

import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import threading


class DatabaseManager:
    """Manages PostgreSQL + TimescaleDB for alerts and metrics"""

    def __init__(self, host='localhost', port=5432, database='netmonitor',
                 user='netmonitor', password='netmonitor',
                 min_connections=2, max_connections=10):
        """Initialize database manager with connection pooling"""
        self.logger = logging.getLogger('NetMonitor.Database')

        # Connection pool for thread-safe database access
        try:
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                min_connections,
                max_connections,
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )
            self.logger.info(f"Connection pool created: {host}:{port}/{database}")
        except Exception as e:
            self.logger.error(f"Failed to create connection pool: {e}")
            raise

        # Initialize database schema
        self._init_database()

        # Create hypertables and continuous aggregates
        self._setup_timescaledb()

        self.logger.info(f"Database geïnitialiseerd: PostgreSQL + TimescaleDB")

    def _get_connection(self):
        """Get connection from pool"""
        return self.connection_pool.getconn()

    def _return_connection(self, conn):
        """Return connection to pool"""
        self.connection_pool.putconn(conn)

    def _init_database(self):
        """Initialize database schema"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Enable TimescaleDB extension
            cursor.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")

            # Alerts table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    severity TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    source_ip INET,
                    destination_ip INET,
                    description TEXT,
                    metadata JSONB,
                    acknowledged BOOLEAN DEFAULT FALSE
                );
            ''')

            # Traffic metrics table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_metrics (
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    total_packets BIGINT DEFAULT 0,
                    total_bytes BIGINT DEFAULT 0,
                    inbound_packets BIGINT DEFAULT 0,
                    inbound_bytes BIGINT DEFAULT 0,
                    outbound_packets BIGINT DEFAULT 0,
                    outbound_bytes BIGINT DEFAULT 0
                );
            ''')

            # Top talkers table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS top_talkers (
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    ip_address INET NOT NULL,
                    hostname TEXT,
                    packet_count BIGINT DEFAULT 0,
                    byte_count BIGINT DEFAULT 0,
                    direction TEXT
                );
            ''')

            # System stats table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_stats (
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    cpu_percent REAL,
                    memory_percent REAL,
                    packets_per_second REAL,
                    alerts_per_minute INTEGER,
                    threat_feed_iocs INTEGER
                );
            ''')

            conn.commit()
            self.logger.info("Database schema created")

            # Migration: Add hostname column if it doesn't exist (for existing databases)
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'top_talkers' AND column_name = 'hostname'
                    ) THEN
                        ALTER TABLE top_talkers ADD COLUMN hostname TEXT;
                    END IF;
                END $$;
            """)
            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating schema: {e}")
            raise
        finally:
            self._return_connection(conn)

    def _setup_timescaledb(self):
        """Setup TimescaleDB hypertables and continuous aggregates"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Create hypertables (partitioned by time)
            # Skip if already exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'alerts'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('alerts', 'timestamp',
                        chunk_time_interval => INTERVAL '1 day',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: alerts")

            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'traffic_metrics'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('traffic_metrics', 'timestamp',
                        chunk_time_interval => INTERVAL '1 day',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: traffic_metrics")

            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'top_talkers'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('top_talkers', 'timestamp',
                        chunk_time_interval => INTERVAL '1 hour',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: top_talkers")

            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'system_stats'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('system_stats', 'timestamp',
                        chunk_time_interval => INTERVAL '1 day',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: system_stats")

            # Create indices for fast queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts (threat_type);")

            # Create continuous aggregate for alert statistics (pre-computed every hour)
            cursor.execute("""
                CREATE MATERIALIZED VIEW IF NOT EXISTS alert_stats_hourly
                WITH (timescaledb.continuous) AS
                SELECT
                    time_bucket('1 hour', timestamp) AS bucket,
                    severity,
                    threat_type,
                    COUNT(*) as count
                FROM alerts
                GROUP BY bucket, severity, threat_type
                WITH NO DATA;
            """)

            # Add refresh policy (auto-refresh every hour)
            cursor.execute("""
                SELECT add_continuous_aggregate_policy('alert_stats_hourly',
                    start_offset => INTERVAL '3 hours',
                    end_offset => INTERVAL '1 hour',
                    schedule_interval => INTERVAL '1 hour',
                    if_not_exists => TRUE
                );
            """)

            # Create retention policy (delete data older than 90 days)
            cursor.execute("""
                SELECT add_retention_policy('alerts', INTERVAL '90 days', if_not_exists => TRUE);
            """)
            cursor.execute("""
                SELECT add_retention_policy('traffic_metrics', INTERVAL '90 days', if_not_exists => TRUE);
            """)

            # Enable compression for old data (compress data older than 7 days)
            cursor.execute("""
                ALTER TABLE alerts SET (
                    timescaledb.compress,
                    timescaledb.compress_segmentby = 'severity,threat_type'
                );
            """)
            cursor.execute("""
                SELECT add_compression_policy('alerts', INTERVAL '7 days', if_not_exists => TRUE);
            """)

            conn.commit()
            self.logger.info("TimescaleDB features configured (hypertables, aggregates, compression)")

        except Exception as e:
            conn.rollback()
            self.logger.warning(f"TimescaleDB setup warning (may already exist): {e}")
        finally:
            self._return_connection(conn)

    def add_alert(self, alert: Dict) -> int:
        """Add alert to database"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Convert metadata dict to JSON
            metadata_json = json.dumps(alert.get('metadata', {})) if alert.get('metadata') else None

            cursor.execute('''
                INSERT INTO alerts (severity, threat_type, source_ip, destination_ip, description, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                alert.get('severity', 'INFO'),
                alert.get('type', 'UNKNOWN'),
                alert.get('source_ip'),
                alert.get('destination_ip'),
                alert.get('description', ''),
                metadata_json
            ))

            alert_id = cursor.fetchone()[0]
            conn.commit()
            return alert_id

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding alert: {e}")
            return -1
        finally:
            self._return_connection(conn)

    def get_recent_alerts(self, limit: int = 100, hours: int = 24) -> List[Dict]:
        """Get recent alerts"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            cursor.execute('''
                SELECT
                    id,
                    timestamp,
                    severity,
                    threat_type,
                    source_ip::text as source_ip,
                    destination_ip::text as destination_ip,
                    description,
                    metadata,
                    acknowledged
                FROM alerts
                WHERE timestamp > %s
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (cutoff_time, limit))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_alert_statistics(self, hours: int = 24) -> Dict:
        """Get alert statistics using continuous aggregates for speed"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Total alerts
            cursor.execute('SELECT COUNT(*) as total FROM alerts WHERE timestamp > %s', (cutoff_time,))
            total = cursor.fetchone()['total']

            # By severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE timestamp > %s
                GROUP BY severity
            ''', (cutoff_time,))
            by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

            # By type
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM alerts
                WHERE timestamp > %s
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 10
            ''', (cutoff_time,))
            by_type = {row['threat_type']: row['count'] for row in cursor.fetchall()}

            # Top source IPs
            cursor.execute('''
                SELECT source_ip::text as source_ip, COUNT(*) as count
                FROM alerts
                WHERE timestamp > %s AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (cutoff_time,))
            top_sources = [{'ip': row['source_ip'], 'count': row['count']} for row in cursor.fetchall()]

            return {
                'total': total,
                'by_severity': by_severity,
                'by_type': by_type,
                'top_sources': top_sources
            }

        except Exception as e:
            self.logger.error(f"Error getting alert statistics: {e}")
            return {'total': 0, 'by_severity': {}, 'by_type': {}, 'top_sources': []}
        finally:
            self._return_connection(conn)

    def add_traffic_metrics(self, metrics: Dict):
        """Add traffic metrics"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO traffic_metrics
                (total_packets, total_bytes, inbound_packets, inbound_bytes, outbound_packets, outbound_bytes)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                metrics.get('total_packets', 0),
                metrics.get('total_bytes', 0),
                metrics.get('inbound_packets', 0),
                metrics.get('inbound_bytes', 0),
                metrics.get('outbound_packets', 0),
                metrics.get('outbound_bytes', 0)
            ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding traffic metrics: {e}")
        finally:
            self._return_connection(conn)

    def get_traffic_history(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get traffic history - optimized with time_bucket for aggregation"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Use time_bucket for efficient aggregation
            cursor.execute('''
                SELECT
                    time_bucket('5 minutes', timestamp) AS timestamp,
                    AVG(total_packets) as total_packets,
                    AVG(total_bytes) as total_bytes,
                    AVG(inbound_packets) as inbound_packets,
                    AVG(inbound_bytes) as inbound_bytes,
                    AVG(outbound_packets) as outbound_packets,
                    AVG(outbound_bytes) as outbound_bytes
                FROM traffic_metrics
                WHERE timestamp > %s
                GROUP BY time_bucket('5 minutes', timestamp)
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (cutoff_time, limit))

            results = [dict(row) for row in cursor.fetchall()]
            results.reverse()  # Chronological order
            return results

        except Exception as e:
            self.logger.error(f"Error getting traffic history: {e}")
            return []
        finally:
            self._return_connection(conn)

    def update_top_talkers(self, talkers: List[Dict]):
        """Batch insert top talkers"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Use executemany for batch insert
            values = [
                (
                    talker['ip'],
                    talker.get('hostname'),  # Include hostname
                    talker.get('packets', 0),
                    talker.get('bytes', 0),
                    talker.get('direction', 'unknown')
                )
                for talker in talkers
            ]

            cursor.executemany('''
                INSERT INTO top_talkers (ip_address, hostname, packet_count, byte_count, direction)
                VALUES (%s, %s, %s, %s, %s)
            ''', values)

            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating top talkers: {e}")
        finally:
            self._return_connection(conn)

    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get current top talkers (last 5 minutes)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(minutes=5)

            cursor.execute('''
                SELECT
                    ip_address::text as ip,
                    MAX(hostname) as hostname,
                    SUM(packet_count) as packets,
                    SUM(byte_count) as bytes,
                    direction
                FROM top_talkers
                WHERE timestamp > %s
                GROUP BY ip_address, direction
                ORDER BY bytes DESC
                LIMIT %s
            ''', (cutoff_time, limit))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting top talkers: {e}")
            return []
        finally:
            self._return_connection(conn)

    def add_system_stats(self, stats: Dict):
        """Add system statistics"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO system_stats (cpu_percent, memory_percent, packets_per_second, alerts_per_minute, threat_feed_iocs)
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                stats.get('cpu_percent', 0),
                stats.get('memory_percent', 0),
                stats.get('packets_per_second', 0),
                stats.get('alerts_per_minute', 0),
                stats.get('threat_feed_iocs', 0)
            ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding system stats: {e}")
        finally:
            self._return_connection(conn)

    def get_latest_system_stats(self) -> Dict:
        """Get latest system statistics for gauges"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cursor.execute('''
                SELECT * FROM system_stats
                ORDER BY timestamp DESC
                LIMIT 1
            ''')

            row = cursor.fetchone()
            if row:
                return {
                    'traffic': {
                        'packets_per_second': row.get('packets_per_second', 0),
                        'alerts_per_minute': row.get('alerts_per_minute', 0)
                    },
                    'system': {
                        'cpu_percent': row.get('cpu_percent', 0),
                        'memory_percent': row.get('memory_percent', 0)
                    }
                }
            else:
                return {
                    'traffic': {'packets_per_second': 0, 'alerts_per_minute': 0},
                    'system': {'cpu_percent': 0, 'memory_percent': 0}
                }

        except Exception as e:
            self.logger.error(f"Error getting latest system stats: {e}")
            return {
                'traffic': {'packets_per_second': 0, 'alerts_per_minute': 0},
                'system': {'cpu_percent': 0, 'memory_percent': 0}
            }
        finally:
            self._return_connection(conn)

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark alert as acknowledged"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute('UPDATE alerts SET acknowledged = TRUE WHERE id = %s', (alert_id,))

            conn.commit()
            return cursor.rowcount > 0

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error acknowledging alert: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_threat_type_details(self, threat_type: str, hours: int = 24, limit: int = 100) -> Dict:
        """Get detailed information for a specific threat type"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Get all alerts for this threat type
            cursor.execute('''
                SELECT
                    id,
                    timestamp,
                    severity,
                    threat_type,
                    source_ip::text as source_ip,
                    destination_ip::text as destination_ip,
                    description,
                    metadata,
                    acknowledged
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (threat_type, cutoff_time, limit))

            alerts = [dict(row) for row in cursor.fetchall()]

            # Collect unique IPs for hostname resolution
            unique_ips = set()
            for alert in alerts:
                if alert['source_ip']:
                    unique_ips.add(alert['source_ip'])
                if alert['destination_ip']:
                    unique_ips.add(alert['destination_ip'])

            # Try to get hostnames from top_talkers table
            ip_hostnames = {}
            if unique_ips:
                placeholders = ','.join(['%s'] * len(unique_ips))
                cursor.execute(f'''
                    SELECT DISTINCT ON (ip_address)
                        ip_address::text as ip,
                        hostname
                    FROM top_talkers
                    WHERE ip_address IN ({placeholders})
                    AND hostname IS NOT NULL
                    ORDER BY ip_address, timestamp DESC
                ''', tuple(unique_ips))

                for row in cursor.fetchall():
                    if row['hostname'] and row['hostname'] != row['ip']:
                        ip_hostnames[row['ip']] = row['hostname']

            # Parse metadata for additional details
            for alert in alerts:
                if alert['source_ip']:
                    alert['source_hostname'] = ip_hostnames.get(alert['source_ip'])
                if alert['destination_ip']:
                    alert['destination_hostname'] = ip_hostnames.get(alert['destination_ip'])

                # Parse metadata JSON if present
                if alert['metadata']:
                    import json
                    try:
                        alert['metadata_parsed'] = json.loads(alert['metadata'])
                    except:
                        alert['metadata_parsed'] = {}

            # Get statistics for this threat type
            cursor.execute('''
                SELECT
                    COUNT(*) as total_count,
                    COUNT(DISTINCT source_ip) as unique_sources,
                    COUNT(DISTINCT destination_ip) as unique_targets,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s
            ''', (threat_type, cutoff_time))

            stats = dict(cursor.fetchone())

            # Get top source IPs for this threat type
            cursor.execute('''
                SELECT
                    source_ip::text as ip,
                    COUNT(*) as count
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (threat_type, cutoff_time))

            top_sources = [dict(row) for row in cursor.fetchall()]

            # Add hostnames to top sources
            for source in top_sources:
                source['hostname'] = ip_hostnames.get(source['ip'])

            # Get top destination IPs for this threat type
            cursor.execute('''
                SELECT
                    destination_ip::text as ip,
                    COUNT(*) as count
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s AND destination_ip IS NOT NULL
                GROUP BY destination_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (threat_type, cutoff_time))

            top_targets = [dict(row) for row in cursor.fetchall()]

            # Add hostnames to top targets
            for target in top_targets:
                target['hostname'] = ip_hostnames.get(target['ip'])

            return {
                'threat_type': threat_type,
                'alerts': alerts,
                'statistics': stats,
                'top_sources': top_sources,
                'top_targets': top_targets
            }

        except Exception as e:
            self.logger.error(f"Error getting threat type details: {e}")
            return {
                'threat_type': threat_type,
                'alerts': [],
                'statistics': {},
                'top_sources': [],
                'top_targets': []
            }
        finally:
            self._return_connection(conn)

    def get_dashboard_data(self) -> Dict:
        """Get all data for dashboard in one call - optimized for performance"""
        return {
            'recent_alerts': self.get_recent_alerts(limit=20, hours=24),
            'alert_stats': self.get_alert_statistics(hours=24),
            'traffic_history': self.get_traffic_history(hours=24, limit=100),
            'top_talkers': self.get_top_talkers(limit=10),
            'current_metrics': self.get_latest_system_stats()
        }

    def close(self):
        """Close all connections in the pool"""
        if hasattr(self, 'connection_pool'):
            self.connection_pool.closeall()
            self.logger.info("Database connection pool closed")
