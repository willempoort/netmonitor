# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
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
        self._host = host
        self._port = port
        self._database = database
        self._user = user
        self._password = password
        self.conn = None
        self._connect()

    def _connect(self):
        """Establish database connection"""
        try:
            self.conn = psycopg2.connect(
                host=self._host,
                port=self._port,
                database=self._database,
                user=self._user,
                password=self._password
            )
            # Force read-only mode for extra safety
            self.conn.set_session(readonly=True, autocommit=True)
            self.logger.info(f"Connected to database as {self._user} (read-only)")
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            raise

    def _ensure_connection(self):
        """Ensure database connection is alive, reconnect if needed"""
        try:
            if self.conn is None or self.conn.closed:
                self.logger.info("Database connection closed, reconnecting...")
                self._connect()
            else:
                # Test connection with a simple query
                with self.conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            self.logger.warning(f"Database connection lost ({e}), reconnecting...")
            self._connect()

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
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
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
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
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
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
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
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
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
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
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
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
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
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
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

    # ==================== Device Classification Queries ====================

    def get_device_templates(self, category: str = None,
                            include_inactive: bool = False) -> List[Dict]:
        """
        Get all device templates

        Args:
            category: Filter by category (optional)
            include_inactive: Include inactive templates

        Returns:
            List of device template dictionaries
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                query = 'SELECT * FROM device_templates WHERE 1=1'
                params = []

                if not include_inactive:
                    query += ' AND is_active = TRUE'

                if category:
                    query += ' AND category = %s'
                    params.append(category)

                query += ' ORDER BY is_builtin DESC, name ASC'
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting device templates: {e}")
            return []

    def get_device_template_by_id(self, template_id: int) -> Optional[Dict]:
        """
        Get a specific device template with its behaviors

        Args:
            template_id: Template ID

        Returns:
            Device template dictionary with behaviors, or None
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Get template
                cursor.execute('SELECT * FROM device_templates WHERE id = %s', (template_id,))
                template = cursor.fetchone()
                if not template:
                    return None

                template = dict(template)

                # Get behaviors
                cursor.execute('''
                    SELECT * FROM template_behaviors
                    WHERE template_id = %s
                    ORDER BY behavior_type
                ''', (template_id,))
                template['behaviors'] = [dict(row) for row in cursor.fetchall()]

                return template
        except Exception as e:
            self.logger.error(f"Error getting device template: {e}")
            return None

    def get_device_template_by_name(self, name: str) -> Optional[Dict]:
        """
        Get a device template by its name (case-insensitive)

        Args:
            name: Template name

        Returns:
            Device template dictionary, or None
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('''
                    SELECT * FROM device_templates
                    WHERE LOWER(name) = LOWER(%s) AND is_active = TRUE
                    LIMIT 1
                ''', (name,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.logger.error(f"Error getting device template by name: {e}")
            return None

    def assign_template_to_device(self, device_id: int, template_id: int,
                                  method: str = 'ml_classifier',
                                  confidence: float = None) -> bool:
        """
        Assign a template to a device with classification metadata.

        Args:
            device_id: Device ID
            template_id: Template ID to assign
            method: Classification method (e.g., 'ml_classifier', 'manual')
            confidence: Classification confidence (0.0-1.0)

        Returns:
            True if successful
        """
        try:
            self._ensure_connection()
            with self.conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE devices
                    SET template_id = %s,
                        classification_method = %s,
                        classification_confidence = %s,
                        last_seen = NOW()
                    WHERE id = %s
                ''', (template_id, method, confidence, device_id))
                self.conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            self.conn.rollback()
            self.logger.error(f"Error assigning template to device: {e}")
            return False

    def get_devices(self, sensor_id: str = None, template_id: int = None,
                   include_inactive: bool = False) -> List[Dict]:
        """
        Get all registered devices

        Args:
            sensor_id: Filter by sensor ID (optional)
            template_id: Filter by template ID (optional)
            include_inactive: Include inactive devices

        Returns:
            List of device dictionaries
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                query = '''
                    SELECT d.*,
                           d.ip_address::text as ip_address,
                           d.mac_address::text as mac_address,
                           t.name as template_name,
                           t.icon as template_icon,
                           t.category as template_category
                    FROM devices d
                    LEFT JOIN device_templates t ON d.template_id = t.id
                    WHERE 1=1
                '''
                params = []

                if not include_inactive:
                    query += ' AND d.is_active = TRUE'

                if sensor_id:
                    query += ' AND d.sensor_id = %s'
                    params.append(sensor_id)

                if template_id:
                    query += ' AND d.template_id = %s'
                    params.append(template_id)

                query += ' ORDER BY d.last_seen DESC'
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting devices: {e}")
            return []

    def get_device_by_ip(self, ip_address: str, sensor_id: str = None) -> Optional[Dict]:
        """
        Get a specific device by IP address

        Args:
            ip_address: Device IP address
            sensor_id: Sensor ID (optional)

        Returns:
            Device dictionary or None
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                query = '''
                    SELECT d.*,
                           d.ip_address::text as ip_address,
                           d.mac_address::text as mac_address,
                           t.name as template_name,
                           t.icon as template_icon
                    FROM devices d
                    LEFT JOIN device_templates t ON d.template_id = t.id
                    WHERE d.ip_address = %s
                '''
                params = [ip_address]

                if sensor_id:
                    query += ' AND d.sensor_id = %s'
                    params.append(sensor_id)

                cursor.execute(query, params)
                result = cursor.fetchone()
                return dict(result) if result else None
        except Exception as e:
            self.logger.error(f"Error getting device by IP: {e}")
            return None

    def get_service_providers(self, category: str = None,
                             include_inactive: bool = False) -> List[Dict]:
        """
        Get all service providers

        Args:
            category: Filter by category (optional)
            include_inactive: Include inactive providers

        Returns:
            List of service provider dictionaries
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                query = 'SELECT * FROM service_providers WHERE 1=1'
                params = []

                if not include_inactive:
                    query += ' AND is_active = TRUE'

                if category:
                    query += ' AND category = %s'
                    params.append(category)

                query += ' ORDER BY category, name'
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting service providers: {e}")
            return []

    def get_service_provider_by_id(self, provider_id: int) -> Optional[Dict]:
        """
        Get a specific service provider

        Args:
            provider_id: Provider ID

        Returns:
            Service provider dictionary or None
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT * FROM service_providers WHERE id = %s', (provider_id,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except Exception as e:
            self.logger.error(f"Error getting service provider: {e}")
            return None

    def check_ip_in_service_providers(self, ip_address: str,
                                      category: str = None) -> Optional[Dict]:
        """
        Check if an IP belongs to any service provider

        Args:
            ip_address: IP address to check
            category: Category to check (optional)

        Returns:
            Matching provider info or None
        """
        import ipaddress
        import json

        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return None

        providers = self.get_service_providers(category=category)

        for provider in providers:
            ip_ranges = provider.get('ip_ranges', [])
            if isinstance(ip_ranges, str):
                ip_ranges = json.loads(ip_ranges)

            for ip_range in ip_ranges:
                try:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ip in network:
                        return {
                            'provider_id': provider['id'],
                            'provider_name': provider['name'],
                            'category': provider['category'],
                            'matched_range': ip_range
                        }
                except ValueError:
                    continue

        return None

    def get_device_classification_stats(self) -> Dict:
        """
        Get statistics about device classification

        Returns:
            Dictionary with classification statistics
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Total devices
                cursor.execute('SELECT COUNT(*) as total FROM devices WHERE is_active = TRUE')
                total_devices = cursor.fetchone()['total']

                # Classified vs unclassified
                cursor.execute('''
                    SELECT
                        COUNT(*) FILTER (WHERE template_id IS NOT NULL) as classified,
                        COUNT(*) FILTER (WHERE template_id IS NULL) as unclassified
                    FROM devices
                    WHERE is_active = TRUE
                ''')
                classification = dict(cursor.fetchone())

                # By template category
                cursor.execute('''
                    SELECT
                        COALESCE(t.category, 'unclassified') as category,
                        COUNT(*) as count
                    FROM devices d
                    LEFT JOIN device_templates t ON d.template_id = t.id
                    WHERE d.is_active = TRUE
                    GROUP BY t.category
                    ORDER BY count DESC
                ''')
                by_category = {row['category']: row['count'] for row in cursor.fetchall()}

                # By template
                cursor.execute('''
                    SELECT
                        COALESCE(t.name, 'Unclassified') as template_name,
                        COUNT(*) as count
                    FROM devices d
                    LEFT JOIN device_templates t ON d.template_id = t.id
                    WHERE d.is_active = TRUE
                    GROUP BY t.name
                    ORDER BY count DESC
                    LIMIT 10
                ''')
                by_template = [dict(row) for row in cursor.fetchall()]

                # Active templates count
                cursor.execute('SELECT COUNT(*) as total FROM device_templates WHERE is_active = TRUE')
                total_templates = cursor.fetchone()['total']

                # Service providers count
                cursor.execute('SELECT COUNT(*) as total FROM service_providers WHERE is_active = TRUE')
                total_providers = cursor.fetchone()['total']

                return {
                    'total_devices': total_devices,
                    'classified_devices': classification['classified'],
                    'unclassified_devices': classification['unclassified'],
                    'classification_rate': round(
                        (classification['classified'] / total_devices * 100) if total_devices > 0 else 0, 1
                    ),
                    'by_category': by_category,
                    'by_template': by_template,
                    'total_templates': total_templates,
                    'total_service_providers': total_providers
                }
        except Exception as e:
            self.logger.error(f"Error getting device classification stats: {e}")
            return {
                'total_devices': 0,
                'classified_devices': 0,
                'unclassified_devices': 0,
                'classification_rate': 0,
                'by_category': {},
                'by_template': [],
                'total_templates': 0,
                'total_service_providers': 0
            }

    def get_device_traffic_stats(self, ip_address: str, hours: int = 168) -> Optional[Dict]:
        """
        Get traffic statistics for a specific device from top_talkers table.

        Args:
            ip_address: IP address to get stats for
            hours: Lookback period in hours (default 168 = 1 week)

        Returns:
            Dictionary with inbound/outbound byte counts, or None if no data
        """
        try:
            self._ensure_connection()
            with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cutoff_time = datetime.now() - timedelta(hours=hours)

                cursor.execute('''
                    SELECT
                        direction,
                        SUM(byte_count) as total_bytes,
                        SUM(packet_count) as total_packets,
                        COUNT(*) as observation_count,
                        MAX(timestamp) as last_seen,
                        MIN(timestamp) as first_seen
                    FROM top_talkers
                    WHERE ip_address = %s::inet
                      AND timestamp > %s
                    GROUP BY direction
                ''', (ip_address, cutoff_time))

                rows = cursor.fetchall()

                if not rows:
                    return None

                result = {
                    'ip_address': ip_address,
                    'period_hours': hours,
                    'inbound': {'bytes': 0, 'packets': 0, 'observations': 0},
                    'outbound': {'bytes': 0, 'packets': 0, 'observations': 0},
                    'internal': {'bytes': 0, 'packets': 0, 'observations': 0}
                }

                for row in rows:
                    direction = row.get('direction', 'unknown')
                    if direction in ('inbound', 'outbound', 'internal'):
                        result[direction] = {
                            'bytes': row.get('total_bytes', 0) or 0,
                            'packets': row.get('total_packets', 0) or 0,
                            'observations': row.get('observation_count', 0) or 0,
                            'first_seen': str(row.get('first_seen')) if row.get('first_seen') else None,
                            'last_seen': str(row.get('last_seen')) if row.get('last_seen') else None
                        }

                return result

        except Exception as e:
            self.logger.error(f"Error getting device traffic stats: {e}")
            return None

    def close(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()
            self.logger.info("Database connection closed")
