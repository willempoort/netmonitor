# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Database Module
Stores alerts, metrics and statistics for the web dashboard
"""

import sqlite3
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
import threading


class DatabaseManager:
    """Manages SQLite database for alerts and metrics"""

    def __init__(self, db_path='/var/lib/netmonitor/netmonitor.db'):
        """Initialize database manager"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger('NetMonitor.Database')
        self._local = threading.local()

        # Initialize database
        self._init_database()

        self.logger.info(f"Database geïnitialiseerd: {self.db_path}")

    def _get_connection(self):
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_database(self):
        """Initialize database schema"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                severity TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                description TEXT,
                metadata TEXT,
                acknowledged BOOLEAN DEFAULT 0
            )
        ''')

        # Create indices on timestamp for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp DESC)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts(severity)
        ''')

        # Traffic metrics table (aggregated per minute)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                inbound_packets INTEGER DEFAULT 0,
                inbound_bytes INTEGER DEFAULT 0,
                outbound_packets INTEGER DEFAULT 0,
                outbound_bytes INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp
            ON traffic_metrics(timestamp DESC)
        ''')

        # Top talkers (IPs with most traffic)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS top_talkers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT NOT NULL,
                packet_count INTEGER DEFAULT 0,
                byte_count INTEGER DEFAULT 0,
                direction TEXT
            )
        ''')

        # System stats
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                packets_per_second REAL,
                alerts_per_minute INTEGER,
                threat_feed_iocs INTEGER
            )
        ''')

        conn.commit()
        self.logger.info("Database schema geïnitialiseerd")

    def add_alert(self, alert: Dict) -> int:
        """
        Add alert to database

        Returns:
            Alert ID
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Extract metadata
        metadata = {k: v for k, v in alert.items()
                   if k not in ['severity', 'type', 'source_ip', 'destination_ip', 'description']}

        cursor.execute('''
            INSERT INTO alerts (severity, threat_type, source_ip, destination_ip, description, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert.get('severity', 'UNKNOWN'),
            alert.get('type', 'UNKNOWN'),
            alert.get('source_ip'),
            alert.get('destination_ip'),
            alert.get('description', ''),
            json.dumps(metadata)
        ))

        conn.commit()
        alert_id = cursor.lastrowid

        self.logger.debug(f"Alert toegevoegd: ID {alert_id}, Type: {alert.get('type')}")
        return alert_id

    def get_recent_alerts(self, limit: int = 100, hours: int = 24) -> List[Dict]:
        """Get recent alerts"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff_time = datetime.now() - timedelta(hours=hours)

        cursor.execute('''
            SELECT * FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (cutoff_time, limit))

        alerts = []
        for row in cursor.fetchall():
            alert = dict(row)
            if alert['metadata']:
                alert['metadata'] = json.loads(alert['metadata'])
            alerts.append(alert)

        return alerts

    def get_alert_statistics(self, hours: int = 24) -> Dict:
        """Get alert statistics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff_time = datetime.now() - timedelta(hours=hours)

        # Total alerts
        cursor.execute('''
            SELECT COUNT(*) as total FROM alerts
            WHERE timestamp > ?
        ''', (cutoff_time,))
        total = cursor.fetchone()['total']

        # By severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count FROM alerts
            WHERE timestamp > ?
            GROUP BY severity
        ''', (cutoff_time,))
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        # By type
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count FROM alerts
            WHERE timestamp > ?
            GROUP BY threat_type
            ORDER BY count DESC
            LIMIT 10
        ''', (cutoff_time,))
        by_type = {row['threat_type']: row['count'] for row in cursor.fetchall()}

        # Top source IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count FROM alerts
            WHERE timestamp > ? AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''', (cutoff_time,))
        top_sources = [{'ip': row['source_ip'], 'count': row['count']}
                      for row in cursor.fetchall()]

        return {
            'total': total,
            'by_severity': by_severity,
            'by_type': by_type,
            'top_sources': top_sources
        }

    def add_traffic_metrics(self, metrics: Dict):
        """Add traffic metrics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO traffic_metrics
            (total_packets, total_bytes, inbound_packets, inbound_bytes, outbound_packets, outbound_bytes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            metrics.get('total_packets', 0),
            metrics.get('total_bytes', 0),
            metrics.get('inbound_packets', 0),
            metrics.get('inbound_bytes', 0),
            metrics.get('outbound_packets', 0),
            metrics.get('outbound_bytes', 0)
        ))

        conn.commit()

    def get_traffic_history(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """
        Get traffic history with limit for performance
        Returns most recent records up to limit
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff_time = datetime.now() - timedelta(hours=hours)

        # Simple LIMIT query - much faster
        cursor.execute('''
            SELECT * FROM traffic_metrics
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (cutoff_time, limit))

        # Reverse to get chronological order (oldest first)
        results = [dict(row) for row in cursor.fetchall()]
        results.reverse()

        return results

    def update_top_talkers(self, talkers: List[Dict]):
        """Update top talkers"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Clear old entries (keep last hour)
        cutoff_time = datetime.now() - timedelta(hours=1)
        cursor.execute('DELETE FROM top_talkers WHERE timestamp < ?', (cutoff_time,))

        # Insert new data
        for talker in talkers:
            cursor.execute('''
                INSERT INTO top_talkers (ip_address, packet_count, byte_count, direction)
                VALUES (?, ?, ?, ?)
            ''', (
                talker['ip'],
                talker.get('packets', 0),
                talker.get('bytes', 0),
                talker.get('direction', 'unknown')
            ))

        conn.commit()

    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get current top talkers"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff_time = datetime.now() - timedelta(minutes=5)

        cursor.execute('''
            SELECT ip_address, SUM(packet_count) as packets, SUM(byte_count) as bytes, direction
            FROM top_talkers
            WHERE timestamp > ?
            GROUP BY ip_address, direction
            ORDER BY bytes DESC
            LIMIT ?
        ''', (cutoff_time, limit))

        return [dict(row) for row in cursor.fetchall()]

    def add_system_stats(self, stats: Dict):
        """Add system statistics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO system_stats
            (cpu_percent, memory_percent, packets_per_second, alerts_per_minute, threat_feed_iocs)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            stats.get('cpu_percent', 0),
            stats.get('memory_percent', 0),
            stats.get('packets_per_second', 0),
            stats.get('alerts_per_minute', 0),
            stats.get('threat_feed_iocs', 0)
        ))

        conn.commit()

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark alert as acknowledged"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE alerts SET acknowledged = 1
            WHERE id = ?
        ''', (alert_id,))

        conn.commit()
        return cursor.rowcount > 0

    def cleanup_old_data(self, days: int = 30):
        """Cleanup old database entries"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff_time = datetime.now() - timedelta(days=days)

        # Delete old alerts
        cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_time,))
        deleted_alerts = cursor.rowcount

        # Delete old metrics
        cursor.execute('DELETE FROM traffic_metrics WHERE timestamp < ?', (cutoff_time,))
        deleted_metrics = cursor.rowcount

        # Delete old system stats
        cursor.execute('DELETE FROM system_stats WHERE timestamp < ?', (cutoff_time,))
        deleted_stats = cursor.rowcount

        conn.commit()

        self.logger.info(f"Database cleanup: {deleted_alerts} alerts, {deleted_metrics} metrics, {deleted_stats} stats verwijderd")

    def get_latest_system_stats(self) -> Dict:
        """Get latest system statistics for gauges"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get most recent system stats
        cursor.execute('''
            SELECT * FROM system_stats
            ORDER BY timestamp DESC
            LIMIT 1
        ''')

        row = cursor.fetchone()
        if row:
            stats = dict(row)
            return {
                'traffic': {
                    'packets_per_second': stats.get('packets_per_second', 0),
                    'alerts_per_minute': stats.get('alerts_per_minute', 0)
                },
                'system': {
                    'cpu_percent': stats.get('cpu_percent', 0),
                    'memory_percent': stats.get('memory_percent', 0)
                }
            }
        else:
            # Return zeros if no data yet
            return {
                'traffic': {
                    'packets_per_second': 0,
                    'alerts_per_minute': 0
                },
                'system': {
                    'cpu_percent': 0,
                    'memory_percent': 0
                }
            }

    def get_dashboard_data(self) -> Dict:
        """Get all data for dashboard in one call - optimized for performance"""
        return {
            'recent_alerts': self.get_recent_alerts(limit=20, hours=24),  # Reduced to 20 for faster load
            'alert_stats': self.get_alert_statistics(hours=24),
            'traffic_history': self.get_traffic_history(hours=24, limit=100),  # Limit to 100 data points
            'top_talkers': self.get_top_talkers(limit=10),
            'current_metrics': self.get_latest_system_stats()
        }

    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            delattr(self._local, 'conn')
