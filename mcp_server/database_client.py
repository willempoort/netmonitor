"""
Read-only database client voor MCP server
"""

import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import logging
from typing import List, Dict, Optional


class MCPDatabaseClient:
    """Read-only database client voor MCP server"""

    def __init__(self, host: str, database: str, user: str, password: str, port: int = 5432):
        """
        Initialize read-only database connection

        Args:
            host: Database host
            database: Database name
            user: Database user (should be read-only)
            password: Database password
            port: Database port (default 5432)
        """
        self.logger = logging.getLogger('MCP.Database')

        try:
            self.conn = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )

            # Force read-only mode for extra safety
            self.conn.set_session(readonly=True, autocommit=True)

            self.logger.info(f"Connected to database as {user} (read-only)")

        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            raise

    def get_alerts_by_ip(self, ip_address: str, hours: int = 24) -> List[Dict]:
        """
        Get all alerts for a specific IP address

        Args:
            ip_address: IP address to search for
            hours: Lookback period in hours

        Returns:
            List of alert dictionaries
        """
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)

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
                WHERE (source_ip::text = %s OR destination_ip::text = %s)
                  AND timestamp > %s
                ORDER BY timestamp DESC
            ''', (ip_address, ip_address, cutoff_time))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting alerts by IP: {e}")
            return []

    def get_recent_alerts(self, limit: int = 50, hours: int = 24,
                         severity: Optional[str] = None,
                         threat_type: Optional[str] = None) -> List[Dict]:
        """
        Get recent alerts with optional filters

        Args:
            limit: Maximum number of alerts to return
            hours: Lookback period in hours
            severity: Filter by severity (optional)
            threat_type: Filter by threat type (optional)

        Returns:
            List of alert dictionaries
        """
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Build query with optional filters
            query = '''
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
            '''

            params = [cutoff_time]

            if severity:
                query += ' AND severity = %s'
                params.append(severity)

            if threat_type:
                query += ' AND threat_type = %s'
                params.append(threat_type)

            query += ' ORDER BY timestamp DESC LIMIT %s'
            params.append(limit)

            cursor.execute(query, params)

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []

    def get_threat_timeline(self, source_ip: Optional[str] = None,
                           hours: int = 24) -> List[Dict]:
        """
        Get chronological timeline of threats

        Args:
            source_ip: Filter by source IP (optional)
            hours: Lookback period in hours

        Returns:
            Chronological list of alerts
        """
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            query = '''
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
            '''

            params = [cutoff_time]

            if source_ip:
                query += ' AND source_ip::text = %s'
                params.append(source_ip)

            query += ' ORDER BY timestamp ASC'  # Chronological order

            cursor.execute(query, params)

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting threat timeline: {e}")
            return []

    def get_dashboard_stats(self) -> Dict:
        """
        Get dashboard statistics

        Returns:
            Dictionary with dashboard stats
        """
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=24)

            # Total alerts
            cursor.execute(
                'SELECT COUNT(*) as total FROM alerts WHERE timestamp > %s',
                (cutoff_time,)
            )
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
                SELECT source_ip::text as ip, COUNT(*) as count
                FROM alerts
                WHERE timestamp > %s AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (cutoff_time,))
            top_sources = [dict(row) for row in cursor.fetchall()]

            return {
                'total': total,
                'by_severity': by_severity,
                'by_type': by_type,
                'top_sources': top_sources,
                'period_hours': 24
            }

        except Exception as e:
            self.logger.error(f"Error getting dashboard stats: {e}")
            return {
                'total': 0,
                'by_severity': {},
                'by_type': {},
                'top_sources': [],
                'period_hours': 24
            }

    def close(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()
            self.logger.info("Database connection closed")
