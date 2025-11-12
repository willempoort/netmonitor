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

    def get_traffic_trends(self, hours: int = 24, interval: str = 'hourly') -> List[Dict]:
        """
        Get traffic trends over time

        Args:
            hours: Lookback period in hours
            interval: 'hourly' or 'daily' aggregation

        Returns:
            List of traffic metrics grouped by time interval
        """
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Determine time bucket based on interval
            if interval == 'daily':
                time_bucket = "1 day"
            else:  # hourly
                time_bucket = "1 hour"

            cursor.execute(f'''
                SELECT
                    time_bucket(%s, timestamp) AS time_period,
                    SUM(total_packets) as total_packets,
                    SUM(total_bytes) as total_bytes,
                    SUM(inbound_packets) as inbound_packets,
                    SUM(inbound_bytes) as inbound_bytes,
                    SUM(outbound_packets) as outbound_packets,
                    SUM(outbound_bytes) as outbound_bytes,
                    AVG(total_packets) as avg_packets,
                    AVG(total_bytes) as avg_bytes
                FROM traffic_metrics
                WHERE timestamp > %s
                GROUP BY time_period
                ORDER BY time_period DESC
            ''', (time_bucket, cutoff_time))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting traffic trends: {e}")
            return []

    def get_top_talkers_stats(self, hours: int = 24, limit: int = 20,
                              direction: Optional[str] = None) -> List[Dict]:
        """
        Get top communicating hosts with statistics

        Args:
            hours: Lookback period in hours
            limit: Maximum number of results
            direction: Filter by 'inbound' or 'outbound' (optional)

        Returns:
            List of top talkers with packet/byte counts
        """
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Build query with optional direction filter
            direction_filter = ""
            params = [cutoff_time, limit]

            if direction:
                direction_filter = "AND direction = %s"
                params.insert(1, direction)

            cursor.execute(f'''
                SELECT
                    ip_address::text as ip_address,
                    hostname,
                    direction,
                    SUM(packet_count) as total_packets,
                    SUM(byte_count) as total_bytes,
                    COUNT(*) as observation_count,
                    MAX(timestamp) as last_seen,
                    MIN(timestamp) as first_seen
                FROM top_talkers
                WHERE timestamp > %s
                {direction_filter}
                GROUP BY ip_address, hostname, direction
                ORDER BY total_bytes DESC
                LIMIT %s
            ''', params)

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting top talkers: {e}")
            return []

    def get_alert_statistics(self, hours: int = 24, group_by: str = 'severity') -> Dict:
        """
        Get alert statistics grouped by specified field

        Args:
            hours: Lookback period in hours
            group_by: Group by 'severity', 'threat_type', or 'hour'

        Returns:
            Dictionary with statistics
        """
        try:
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Get total count
            cursor.execute('''
                SELECT COUNT(*) as total
                FROM alerts
                WHERE timestamp > %s
            ''', (cutoff_time,))

            total = cursor.fetchone()['total']

            # Get grouped statistics
            if group_by == 'hour':
                cursor.execute('''
                    SELECT
                        time_bucket('1 hour', timestamp) AS time_period,
                        COUNT(*) as count
                    FROM alerts
                    WHERE timestamp > %s
                    GROUP BY time_period
                    ORDER BY time_period DESC
                ''', (cutoff_time,))
            elif group_by == 'threat_type':
                cursor.execute('''
                    SELECT
                        threat_type as category,
                        COUNT(*) as count,
                        MAX(timestamp) as last_occurrence
                    FROM alerts
                    WHERE timestamp > %s
                    GROUP BY threat_type
                    ORDER BY count DESC
                ''', (cutoff_time,))
            else:  # severity
                cursor.execute('''
                    SELECT
                        severity as category,
                        COUNT(*) as count,
                        MAX(timestamp) as last_occurrence
                    FROM alerts
                    WHERE timestamp > %s
                    GROUP BY severity
                    ORDER BY
                        CASE severity
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH' THEN 2
                            WHEN 'MEDIUM' THEN 3
                            WHEN 'LOW' THEN 4
                            WHEN 'INFO' THEN 5
                        END
                ''', (cutoff_time,))

            grouped_data = [dict(row) for row in cursor.fetchall()]

            return {
                'total_alerts': total,
                'analysis_period_hours': hours,
                'grouped_by': group_by,
                'data': grouped_data
            }

        except Exception as e:
            self.logger.error(f"Error getting alert statistics: {e}")
            return {
                'total_alerts': 0,
                'analysis_period_hours': hours,
                'grouped_by': group_by,
                'data': []
            }

    def close(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()
            self.logger.info("Database connection closed")
