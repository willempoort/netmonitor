#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Shared NetMonitor MCP Tool Implementations

Contains all 60 tools extracted from production http_server.py.
Centralized for use across all MCP transports (stdio, SSE, Streamable HTTP).

All tool logic is maintained here as the single source of truth.
"""

import os
import sys
import json
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from database_client import MCPDatabaseClient
from geoip_helper import get_country_for_ip, is_private_ip
from ollama_client import OllamaClient

logger = logging.getLogger('NetMonitor.MCP.SharedTools')


class NetMonitorTools:
    """
    Shared tool implementations for all MCP transports

    Contains all 60 production tools from http_server.py.
    Used by stdio, SSE, and Streamable HTTP transports.
    """

    def __init__(self, db: MCPDatabaseClient, ollama: OllamaClient = None, dashboard_url: str = "http://localhost:8080"):
        """
        Initialize shared tools

        Args:
            db: Database client instance
            ollama: Ollama AI client instance (optional)
            dashboard_url: Base URL for dashboard API calls (default: http://localhost:8080)
        """
        self.db = db
        self.ollama = ollama
        self.base_url = dashboard_url  # For memory management tools
        logger.info(f"NetMonitorTools initialized with {len(TOOL_DEFINITIONS)} tools")

    # ==================== Tool Implementations ====================

    # analyze_ip
    async def analyze_ip(self, params: Dict) -> Dict:
        """Implement analyze_ip tool"""
        import socket
        from geoip_helper import get_country_for_ip, is_private_ip

        ip_address = params.get('ip_address')
        hours = params.get('hours', 24)

        # Get all alerts for this IP
        alerts = self.db.get_alerts_by_ip(ip_address, hours)

        # Get geolocation
        country = get_country_for_ip(ip_address)

        # Determine if internal
        internal = not is_private_ip(ip_address)  # is_private_ip returns True for RFC1918 IPs NOT in configured internal_networks

        # Try hostname resolution
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except:
            pass

        # Analyze alerts
        threat_types = list(set(a['threat_type'] for a in alerts))
        severity_counts = {}
        for alert in alerts:
            sev = alert['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Calculate threat score (0-100)
        threat_score = min(100, len(alerts) * 5 + len(threat_types) * 10)

        # Determine risk level
        if threat_score >= 80:
            risk_level = "CRITICAL"
            recommendation = "URGENT: Block this IP immediately and investigate affected systems"
        elif threat_score >= 60:
            risk_level = "HIGH"
            recommendation = "High priority: Review and consider blocking this IP"
        elif threat_score >= 40:
            risk_level = "MEDIUM"
            recommendation = "Monitor this IP closely for suspicious activity"
        elif threat_score >= 20:
            risk_level = "LOW"
            recommendation = "Informational: Minor suspicious activity detected"
        else:
            risk_level = "INFO"
            recommendation = "No significant threats detected"

        return {
            'ip_address': ip_address,
            'hostname': hostname,
            'country': country,
            'is_internal': internal,
            'alert_count': len(alerts),
            'threat_types': threat_types,
            'severity_counts': severity_counts,
            'threat_score': threat_score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'recent_alerts': alerts[:10] if len(alerts) > 10 else alerts
        }


    # get_recent_threats
    async def get_recent_threats(self, params: Dict) -> Dict:
        """Implement get_recent_threats tool"""
        hours = params.get('hours', 24)
        severity = params.get('severity')
        threat_type = params.get('threat_type')
        limit = params.get('limit', 50)

        alerts = self.db.get_recent_alerts(
            limit=limit,
            hours=hours,
            severity=severity,
            threat_type=threat_type
        )

        # Calculate statistics
        total = len(alerts)
        by_severity = {}
        by_type = {}
        unique_sources = set()

        for alert in alerts:
            by_severity[alert['severity']] = by_severity.get(alert['severity'], 0) + 1
            by_type[alert['threat_type']] = by_type.get(alert['threat_type'], 0) + 1
            unique_sources.add(alert.get('source_ip', 'unknown'))

        return {
            'total_alerts': total,
            'statistics': {
                'by_severity': by_severity,
                'by_type': by_type
            },
            'unique_source_ips': len(unique_sources),
            'alerts': alerts
        }


    # get_sensor_status
    async def get_sensor_status(self, params: Dict) -> Dict:
        """Implement get_sensor_status tool"""
        import sys
        from pathlib import Path

        # Import main database module for sensor access
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from database import DatabaseManager

            # Create DB connection with main credentials
            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'netmonitor'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db_main = DatabaseManager(
                host=host,
                database=database,
                user=user,
                password=password
            )

            sensors = db_main.get_sensors()
            db_main.close()

            return {
                'sensors': sensors,
                'total': len(sensors),
                'online': len([s for s in sensors if s.get('status') == 'online']),
                'offline': len([s for s in sensors if s.get('status') == 'offline'])
            }

        except Exception as e:
            logger.error(f"Error getting sensor status: {e}")
            return {
                'error': str(e),
                'sensors': [],
                'total': 0
            }


    # set_config_parameter
    async def set_config_parameter(self, params: Dict) -> Dict:
        """Implement set_config_parameter tool"""
        import requests

        parameter_name = params.get('parameter_name')
        value = params.get('value')
        scope = params.get('scope', 'global')
        sensor_name = params.get('sensor_name')

        # Configuration changes go through the dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/config/set",
                json={
                    'parameter': parameter_name,
                    'value': value,
                    'scope': scope,
                    'sensor_name': sensor_name
                },
                timeout=10
            )

            response.raise_for_status()

            return {
                'success': True,
                'message': f"Configuration parameter '{parameter_name}' updated successfully"
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error setting config parameter: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to update configuration. Ensure the dashboard API is running.'
            }


    # get_config_parameters
    async def get_config_parameters(self, params: Dict) -> Dict:
        """Implement get_config_parameters tool"""
        import requests

        sensor_id = params.get('sensor_id')

        # Get config from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            query_params = {}
            if sensor_id:
                query_params['sensor_id'] = sensor_id

            response = requests.get(
                f"{dashboard_url}/api/config/parameters",
                params=query_params,
                timeout=10
            )

            response.raise_for_status()
            data = response.json()

            if data.get('success'):
                parameters = data.get('parameters', [])
                return {
                    'success': True,
                    'parameters': parameters,
                    'count': len(parameters)
                }
            else:
                return {
                    'success': False,
                    'error': data.get('error', 'Unknown error')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting config parameters: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve configuration. Ensure the dashboard API is running.'
            }

    # ==================== Device Classification Tool Implementations ====================


    # get_device_templates
    async def get_device_templates(self, params: Dict) -> Dict:
        """Implement get_device_templates tool"""
        category = params.get('category')

        templates = self.db.get_device_templates(category=category)

        return {
            'success': True,
            'templates': templates,
            'count': len(templates)
        }


    # get_device_template_details
    async def get_device_template_details(self, params: Dict) -> Dict:
        """Implement get_device_template_details tool"""
        template_id = params.get('template_id')

        if not template_id:
            return {'success': False, 'error': 'template_id is required'}

        template = self.db.get_device_template_by_id(template_id)

        if not template:
            return {'success': False, 'error': f'Template with ID {template_id} not found'}

        return {
            'success': True,
            'template': template
        }


    # get_devices
    async def get_devices(self, params: Dict) -> Dict:
        """Implement get_devices tool"""
        sensor_id = params.get('sensor_id')
        template_id = params.get('template_id')
        include_inactive = params.get('include_inactive', False)

        devices = self.db.get_devices(
            sensor_id=sensor_id,
            template_id=template_id,
            include_inactive=include_inactive
        )

        # Calculate summary
        classified = len([d for d in devices if d.get('template_id')])
        unclassified = len(devices) - classified

        return {
            'success': True,
            'devices': devices,
            'count': len(devices),
            'summary': {
                'total': len(devices),
                'classified': classified,
                'unclassified': unclassified
            }
        }


    # get_device_by_ip
    async def get_device_by_ip(self, params: Dict) -> Dict:
        """Implement get_device_by_ip tool"""
        ip_address = params.get('ip_address')
        sensor_id = params.get('sensor_id')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        device = self.db.get_device_by_ip(ip_address, sensor_id=sensor_id)

        if not device:
            # Check if IP belongs to a service provider
            provider_match = self.db.check_ip_in_service_providers(ip_address)
            if provider_match:
                return {
                    'success': True,
                    'device': None,
                    'service_provider': provider_match,
                    'message': f"IP belongs to service provider: {provider_match['provider_name']}"
                }

            return {
                'success': True,
                'device': None,
                'message': f'No device found with IP {ip_address}'
            }

        return {
            'success': True,
            'device': device
        }


    # touch_device
    async def touch_device(self, params: Dict) -> Dict:
        """Implement touch_device tool - update device's last_seen to NOW"""
        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        result = self.db.touch_device(ip_address=ip_address)

        if result:
            return {
                'success': True,
                'message': f'Successfully updated last_seen for device {ip_address}',
                'ip_address': ip_address
            }
        else:
            return {
                'success': False,
                'error': f'Device not found with IP {ip_address}'
            }


    # touch_devices_bulk
    async def touch_devices_bulk(self, params: Dict) -> Dict:
        """Implement touch_devices_bulk tool - update last_seen for multiple devices"""
        ip_addresses = params.get('ip_addresses', [])

        if not ip_addresses:
            return {'success': False, 'error': 'ip_addresses is required and must not be empty'}

        if not isinstance(ip_addresses, list):
            return {'success': False, 'error': 'ip_addresses must be a list'}

        updated_count = self.db.touch_devices_bulk(ip_addresses)

        return {
            'success': True,
            'message': f'Successfully updated last_seen for {updated_count} devices',
            'updated_count': updated_count,
            'requested_count': len(ip_addresses)
        }


    # get_service_providers
    async def get_service_providers(self, params: Dict) -> Dict:
        """Implement get_service_providers tool"""
        category = params.get('category')

        providers = self.db.get_service_providers(category=category)

        # Group by category for summary
        by_category = {}
        for p in providers:
            cat = p.get('category', 'other')
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            'success': True,
            'providers': providers,
            'count': len(providers),
            'by_category': by_category
        }


    # check_ip_service_provider
    async def check_ip_service_provider(self, params: Dict) -> Dict:
        """Implement check_ip_service_provider tool"""
        ip_address = params.get('ip_address')
        category = params.get('category')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        match = self.db.check_ip_in_service_providers(ip_address, category=category)

        if match:
            return {
                'success': True,
                'is_service_provider': True,
                'provider': match,
                'message': f"IP {ip_address} belongs to {match['provider_name']} ({match['category']})"
            }
        else:
            return {
                'success': True,
                'is_service_provider': False,
                'provider': None,
                'message': f"IP {ip_address} does not match any known service provider"
            }


    # get_device_classification_stats
    async def get_device_classification_stats(self, params: Dict) -> Dict:
        """Implement get_device_classification_stats tool"""
        stats = self.db.get_device_classification_stats()

        return {
            'success': True,
            'statistics': stats
        }


    # assign_device_template
    async def assign_device_template(self, params: Dict) -> Dict:
        """Implement assign_device_template tool (requires write access)"""
        # Accept either device_id (legacy) or ip_address
        device_id = params.get('device_id')
        ip_address = params.get('ip_address')
        template_id = params.get('template_id')

        if not template_id:
            return {'success': False, 'error': 'template_id is required'}

        if not device_id and not ip_address:
            return {'success': False, 'error': 'device_id or ip_address is required'}

        # If device_id provided, look up the IP address
        if device_id and not ip_address:
            # Try to find device by ID in our read-only DB
            devices = self.db.get_devices()
            device = next((d for d in devices if d.get('id') == device_id), None)
            if device:
                ip_address = device.get('ip_address')
            else:
                return {'success': False, 'error': f'Device with ID {device_id} not found'}

        # Route through internal dashboard API (localhost access without auth)
        import requests
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.put(
                f"{dashboard_url}/api/internal/devices/{ip_address}/template",
                json={'template_id': template_id},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'message': data.get('message', f'Template {template_id} assigned to device {ip_address}')
                }
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                return {
                    'success': False,
                    'error': data.get('error', f'API returned status {response.status_code}')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error assigning device template: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to assign template. Ensure the dashboard API is running.'
            }


    # create_service_provider
    async def create_service_provider(self, params: Dict) -> Dict:
        """Implement create_service_provider tool (requires write access)"""
        name = params.get('name')
        category = params.get('category')
        ip_ranges = params.get('ip_ranges', [])
        domains = params.get('domains', [])
        description = params.get('description', '')

        if not name or not category:
            return {'success': False, 'error': 'name and category are required'}

        if not ip_ranges and not domains:
            return {'success': False, 'error': 'At least ip_ranges or domains is required'}

        # Route through internal dashboard API (localhost access without auth)
        import requests
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/internal/service-providers",
                json={
                    'name': name,
                    'category': category,
                    'ip_ranges': ip_ranges,
                    'domains': domains,
                    'description': description
                },
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'provider_id': data.get('provider_id'),
                    'message': data.get('message', f'Service provider "{name}" created')
                }
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                return {
                    'success': False,
                    'error': data.get('error', f'API returned status {response.status_code}')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating service provider: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to create service provider. Ensure the dashboard API is running.'
            }

    # ==================== Device Discovery Tool Implementations ====================

    # get_top_talkers
    async def get_top_talkers(self, params: Dict) -> Dict:
        """Get top communicating hosts by traffic volume"""
        hours = params.get('hours', 24)
        limit = params.get('limit', 10)
        direction = params.get('direction')  # Optional: 'inbound' or 'outbound'

        try:
            # Use the database client's get_top_talkers_stats method
            # Run in thread pool to avoid blocking the event loop
            top_talkers = await asyncio.to_thread(
                self.db.get_top_talkers_stats,
                hours=hours,
                limit=limit,
                direction=direction
            )

            # Format bytes for readability
            def format_bytes(bytes_val):
                if bytes_val is None:
                    return "0 B"
                for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if bytes_val < 1024:
                        return f"{bytes_val:.1f} {unit}"
                    bytes_val /= 1024
                return f"{bytes_val:.1f} PB"

            # Enhance results with formatted values
            for talker in top_talkers:
                talker['total_bytes_formatted'] = format_bytes(talker.get('total_bytes', 0))
                # Convert datetime objects to strings for JSON serialization
                if 'last_seen' in talker and talker['last_seen']:
                    talker['last_seen'] = str(talker['last_seen'])
                if 'first_seen' in talker and talker['first_seen']:
                    talker['first_seen'] = str(talker['first_seen'])

            return {
                'success': True,
                'period_hours': hours,
                'direction_filter': direction or 'all',
                'count': len(top_talkers),
                'top_talkers': top_talkers
            }

        except Exception as e:
            logger.error(f"Error getting top talkers: {e}")
            return {'success': False, 'error': str(e)}

    # get_device_traffic_stats
    async def get_device_traffic_stats(self, params: Dict) -> Dict:
        """Get traffic statistics for a specific device"""
        ip_address = params.get('ip_address')
        hours = params.get('hours', 168)  # Default 1 week

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        try:
            # Query database directly using thread pool to avoid blocking
            stats = await asyncio.to_thread(
                self.db.get_device_traffic_stats,
                ip_address=ip_address,
                hours=hours
            )

            if not stats:
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'message': f'No traffic data found for {ip_address} in the last {hours} hours'
                }

            # Format bytes for readability
            def format_bytes(bytes_val):
                if bytes_val is None or bytes_val == 0:
                    return "0 B"
                for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if bytes_val < 1024:
                        return f"{bytes_val:.2f} {unit}"
                    bytes_val /= 1024
                return f"{bytes_val:.2f} PB"

            inbound = stats.get('inbound', {})
            outbound = stats.get('outbound', {})
            internal = stats.get('internal', {})

            total_bytes = inbound.get('bytes', 0) + outbound.get('bytes', 0) + internal.get('bytes', 0)
            total_packets = inbound.get('packets', 0) + outbound.get('packets', 0) + internal.get('packets', 0)

            return {
                'success': True,
                'ip_address': ip_address,
                'period_hours': hours,
                'inbound': {
                    'bytes': inbound.get('bytes', 0),
                    'bytes_formatted': format_bytes(inbound.get('bytes', 0)),
                    'packets': inbound.get('packets', 0),
                    'first_seen': inbound.get('first_seen'),
                    'last_seen': inbound.get('last_seen')
                },
                'outbound': {
                    'bytes': outbound.get('bytes', 0),
                    'bytes_formatted': format_bytes(outbound.get('bytes', 0)),
                    'packets': outbound.get('packets', 0),
                    'first_seen': outbound.get('first_seen'),
                    'last_seen': outbound.get('last_seen')
                },
                'internal': {
                    'bytes': internal.get('bytes', 0),
                    'bytes_formatted': format_bytes(internal.get('bytes', 0)),
                    'packets': internal.get('packets', 0),
                    'first_seen': internal.get('first_seen'),
                    'last_seen': internal.get('last_seen')
                },
                'total': {
                    'bytes': total_bytes,
                    'bytes_formatted': format_bytes(total_bytes),
                    'packets': total_packets
                }
            }

        except Exception as e:
            logger.error(f"Error getting device traffic stats: {e}")
            return {'success': False, 'error': str(e)}


    # get_device_classification_hints
    async def get_device_classification_hints(self, params: Dict) -> Dict:
        """Implement get_device_classification_hints tool"""
        import requests

        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Get classification hints from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/devices/{ip_address}/classification-hints",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                hints = data.get('hints', {})

                return {
                    'success': True,
                    'ip_address': ip_address,
                    'hints': hints,
                    'suggested_templates': hints.get('suggested_templates', []),
                    'confidence': hints.get('confidence', 0.0),
                    'reasoning': hints.get('reasoning', [])
                }
            elif response.status_code == 404:
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'hints': None,
                    'message': f'No classification hints available for {ip_address}. Device may not have enough observed traffic.'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting device classification hints: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve classification hints. Ensure the dashboard API is running.'
            }


    # create_template_from_device
    async def create_template_from_device(self, params: Dict) -> Dict:
        """Implement create_template_from_device tool (requires write access)"""
        import requests

        ip_address = params.get('ip_address')
        template_name = params.get('template_name')
        category = params.get('category', 'other')
        description = params.get('description')
        assign_to_device = params.get('assign_to_device', True)

        if not ip_address or not template_name:
            return {'success': False, 'error': 'ip_address and template_name are required'}

        # Create template via internal dashboard API (localhost access without auth)
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/internal/device-templates/from-device",
                json={
                    'ip_address': ip_address,
                    'template_name': template_name,
                    'category': category,
                    'description': description,
                    'assign_to_device': assign_to_device
                },
                timeout=15
            )

            if response.status_code == 200 or response.status_code == 201:
                data = response.json()
                return {
                    'success': True,
                    'template_id': data.get('template_id'),
                    'template_name': template_name,
                    'message': data.get('message', f'Template "{template_name}" created from device {ip_address}'),
                    'behaviors_added': data.get('behaviors_added', 0)
                }
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                return {
                    'success': False,
                    'error': data.get('error', f'API returned status {response.status_code}')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating template from device: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to create template. Ensure the dashboard API is running.'
            }


    # clone_device_template
    async def clone_device_template(self, params: Dict) -> Dict:
        """Implement clone_device_template tool (requires write access)"""
        import requests

        template_id = params.get('template_id')
        new_name = params.get('new_name')
        new_description = params.get('new_description')

        if not template_id or not new_name:
            return {'success': False, 'error': 'template_id and new_name are required'}

        # Clone template via dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            payload = {'name': new_name}
            if new_description:
                payload['description'] = new_description

            response = requests.post(
                f"{dashboard_url}/api/device-templates/{template_id}/clone",
                json=payload,
                timeout=15
            )

            if response.status_code == 200 or response.status_code == 201:
                data = response.json()
                return {
                    'success': True,
                    'template_id': data.get('template_id'),
                    'template_name': new_name,
                    'message': data.get('message', f'Template cloned as "{new_name}"')
                }
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                return {
                    'success': False,
                    'error': data.get('error', f'API returned status {response.status_code}')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error cloning template: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to clone template. Ensure the dashboard API is running.'
            }

    # ==================== Alert Suppression Tool Implementations ====================


    # get_alert_suppression_stats
    async def get_alert_suppression_stats(self, params: Dict) -> Dict:
        """Implement get_alert_suppression_stats tool"""
        import requests

        # Get suppression stats from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/suppression/stats",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'statistics': data.get('stats', {}),
                    'message': 'Alert suppression statistics retrieved successfully'
                }
            else:
                # If API not available, return basic info
                return {
                    'success': True,
                    'statistics': {
                        'alerts_checked': 0,
                        'alerts_suppressed': 0,
                        'suppression_rate': 0,
                        'note': 'Live statistics require dashboard API'
                    },
                    'message': 'Statistics unavailable from live system'
                }

        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not get suppression stats from dashboard: {e}")
            return {
                'success': True,
                'statistics': {
                    'alerts_checked': 0,
                    'alerts_suppressed': 0,
                    'suppression_rate': 0,
                    'note': 'Live statistics require dashboard API'
                },
                'message': 'Statistics unavailable - dashboard API not responding'
            }


    # test_alert_suppression
    async def test_alert_suppression(self, params: Dict) -> Dict:
        """Implement test_alert_suppression tool"""
        source_ip = params.get('source_ip')
        destination_ip = params.get('destination_ip', '')
        alert_type = params.get('alert_type')
        destination_port = params.get('destination_port')

        if not source_ip or not alert_type:
            return {'success': False, 'error': 'source_ip and alert_type are required'}

        # Get device template for source IP
        device = self.db.get_device_by_ip(source_ip)

        if not device:
            return {
                'success': True,
                'would_suppress': False,
                'reason': f'No registered device found for IP {source_ip}',
                'device': None,
                'template': None
            }

        if not device.get('template_id'):
            return {
                'success': True,
                'would_suppress': False,
                'reason': f'Device {source_ip} has no assigned template',
                'device': {
                    'ip_address': device.get('ip_address'),
                    'hostname': device.get('hostname'),
                    'mac_address': device.get('mac_address')
                },
                'template': None
            }

        template = self.db.get_device_template_by_id(device['template_id'])
        if not template:
            return {
                'success': True,
                'would_suppress': False,
                'reason': 'Template not found',
                'device': device,
                'template': None
            }

        # Check behaviors
        behaviors = template.get('behaviors', [])
        matching_behaviors = []

        for behavior in behaviors:
            if behavior.get('action') != 'allow':
                continue

            behavior_type = behavior.get('behavior_type')
            params_b = behavior.get('parameters', {})

            # Check for matching rules
            match_reason = None

            if behavior_type == 'allowed_ports' and destination_port:
                allowed_ports = params_b.get('ports', [])
                if destination_port in allowed_ports:
                    match_reason = f"Port {destination_port} is in allowed ports list"

            elif behavior_type == 'expected_destinations' and destination_ip:
                # Check if destination is a service provider
                provider = self.db.check_ip_in_service_providers(destination_ip)
                allowed_categories = params_b.get('categories', [])
                if provider and provider['category'] in allowed_categories:
                    match_reason = f"Destination is {provider['provider_name']} ({provider['category']})"

            elif behavior_type == 'traffic_pattern':
                if params_b.get('high_bandwidth') and alert_type in ('HIGH_OUTBOUND_VOLUME', 'UNUSUAL_PACKET_SIZE'):
                    match_reason = "High bandwidth traffic is expected"
                if params_b.get('continuous') and alert_type == 'BEACONING':
                    match_reason = "Continuous streaming is expected"

            elif behavior_type == 'connection_behavior':
                if params_b.get('high_connection_rate') and alert_type == 'CONNECTION_FLOOD':
                    match_reason = "High connection rate is expected for servers"

            if match_reason:
                matching_behaviors.append({
                    'behavior_type': behavior_type,
                    'reason': match_reason,
                    'direction': 'outbound',
                    'device': 'source'
                })

        # Check 2: Destination device template (inbound behaviors)
        dst_device = None
        dst_template = None
        if destination_ip:
            dst_device = self.db.get_device_by_ip(destination_ip)
            if dst_device and dst_device.get('template_id'):
                dst_template = self.db.get_device_template_by_id(dst_device['template_id'])
                if dst_template:
                    dst_behaviors = dst_template.get('behaviors', [])
                    for behavior in dst_behaviors:
                        if behavior.get('action') != 'allow':
                            continue

                        behavior_type = behavior.get('behavior_type')
                        params_b = behavior.get('parameters', {})
                        direction = params_b.get('direction')

                        # For destination device, check inbound or bidirectional behaviors
                        if direction == 'outbound':
                            continue

                        match_reason = None

                        if behavior_type == 'allowed_ports' and destination_port:
                            allowed_ports = params_b.get('ports', [])
                            if destination_port in allowed_ports:
                                match_reason = f"Inbound port {destination_port} is allowed on destination"

                        elif behavior_type == 'allowed_sources':
                            import ipaddress
                            try:
                                src = ipaddress.ip_address(source_ip)
                                if params_b.get('internal'):
                                    internal_nets = [
                                        ipaddress.ip_network('10.0.0.0/8'),
                                        ipaddress.ip_network('172.16.0.0/12'),
                                        ipaddress.ip_network('192.168.0.0/16')
                                    ]
                                    if any(src in net for net in internal_nets):
                                        match_reason = "Internal source is allowed on destination"
                            except ValueError:
                                pass

                        elif behavior_type == 'connection_behavior':
                            if params_b.get('accepts_connections') or params_b.get('api_server'):
                                if alert_type in ('CONNECTION_FLOOD', 'HIGH_RISK_ATTACK_CHAIN', 'PORT_SCAN'):
                                    match_reason = "Destination accepts many connections"

                        if match_reason:
                            matching_behaviors.append({
                                'behavior_type': behavior_type,
                                'reason': match_reason,
                                'direction': 'inbound',
                                'device': 'destination'
                            })

        would_suppress = len(matching_behaviors) > 0

        result = {
            'success': True,
            'would_suppress': would_suppress,
            'reason': matching_behaviors[0]['reason'] if matching_behaviors else f'No matching behavior rules for {alert_type}',
            'matching_behaviors': matching_behaviors,
            'source_device': {
                'ip_address': device.get('ip_address'),
                'hostname': device.get('hostname'),
                'mac_address': device.get('mac_address'),
                'template_name': template.get('name') if template else None
            },
            'source_template': {
                'id': template.get('id'),
                'name': template.get('name'),
                'category': template.get('category'),
                'behaviors_count': len(behaviors)
            } if template else None
        }

        # Add destination info if available
        if dst_device:
            result['destination_device'] = {
                'ip_address': dst_device.get('ip_address'),
                'hostname': dst_device.get('hostname'),
                'template_name': dst_template.get('name') if dst_template else None
            }
            if dst_template:
                result['destination_template'] = {
                    'id': dst_template.get('id'),
                    'name': dst_template.get('name'),
                    'category': dst_template.get('category'),
                    'behaviors_count': len(dst_template.get('behaviors', []))
                }

        return result

    # ==================== Behavior Learning Tool Implementations ====================


    # get_device_learning_status
    async def get_device_learning_status(self, params: Dict) -> Dict:
        """Implement get_device_learning_status tool"""
        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Get device from database
        device = self.db.get_device_by_ip(ip_address)

        if not device:
            return {
                'success': True,
                'ip_address': ip_address,
                'learning_status': 'not_found',
                'message': f'Device {ip_address} not found in database. It may not have been discovered yet.'
            }

        learned_behavior = device.get('learned_behavior', {})

        # Analyze learning status
        has_behavior = bool(learned_behavior)
        packet_count = learned_behavior.get('packet_count', 0) if has_behavior else 0
        unique_ports = len(learned_behavior.get('typical_ports', [])) if has_behavior else 0
        unique_destinations = len(learned_behavior.get('typical_destinations', [])) if has_behavior else 0
        protocols = learned_behavior.get('protocols', []) if has_behavior else []

        # Determine learning status
        if not has_behavior:
            status = 'not_started'
            message = 'No traffic has been analyzed yet. Device needs active monitoring.'
        elif packet_count < 100:
            status = 'insufficient_data'
            message = f'Only {packet_count} packets analyzed. Need more traffic for reliable behavior profile.'
        elif unique_ports < 2 and unique_destinations < 3:
            status = 'learning'
            message = 'Basic traffic pattern detected. More diverse traffic would improve accuracy.'
        else:
            status = 'ready'
            message = 'Sufficient data available for behavior-based template generation.'

        return {
            'success': True,
            'ip_address': ip_address,
            'device': {
                'hostname': device.get('hostname'),
                'mac_address': device.get('mac_address'),
                'vendor': device.get('vendor'),
                'template_name': device.get('template_name'),
                'first_seen': str(device.get('first_seen')) if device.get('first_seen') else None,
                'last_seen': str(device.get('last_seen')) if device.get('last_seen') else None
            },
            'learning_status': status,
            'message': message,
            'statistics': {
                'has_learned_behavior': has_behavior,
                'packet_count': packet_count,
                'unique_ports': unique_ports,
                'unique_destinations': unique_destinations,
                'protocols': protocols
            }
        }


    # save_device_learned_behavior
    async def save_device_learned_behavior(self, params: Dict) -> Dict:
        """Implement save_device_learned_behavior tool (requires write access)"""
        import requests

        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Call dashboard internal API to save learned behavior
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/internal/devices/{ip_address}/save-learned-behavior",
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'message': f'Learned behavior saved successfully for {ip_address}',
                    'saved_behavior': data.get('learned_behavior', {})
                }
            elif response.status_code == 404:
                return {
                    'success': False,
                    'error': f'Device {ip_address} not found'
                }
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                return {
                    'success': False,
                    'error': data.get('error', f'API returned status {response.status_code}')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error saving learned behavior: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to save learned behavior. Ensure the dashboard API is running.'
            }


    # get_device_learned_behavior
    async def get_device_learned_behavior(self, params: Dict) -> Dict:
        """Implement get_device_learned_behavior tool"""
        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Get device from database
        device = self.db.get_device_by_ip(ip_address)

        if not device:
            return {
                'success': True,
                'ip_address': ip_address,
                'learned_behavior': None,
                'message': f'Device {ip_address} not found in database'
            }

        learned_behavior = device.get('learned_behavior', {})

        if not learned_behavior:
            return {
                'success': True,
                'ip_address': ip_address,
                'learned_behavior': None,
                'message': 'No learned behavior available. Device needs active monitoring to collect traffic data.'
            }

        # Format learned behavior for display
        formatted_behavior = {
            'protocols': learned_behavior.get('protocols', []),
            'traffic_pattern': learned_behavior.get('traffic_pattern'),
            'typical_ports': [
                {'port': p['port'], 'protocol': p.get('protocol', 'TCP'), 'connections': p.get('count', 0)}
                for p in learned_behavior.get('typical_ports', [])[:15]
            ],
            'server_ports': [
                {'port': p['port'], 'protocol': p.get('protocol', 'TCP'), 'inbound_connections': p.get('count', 0)}
                for p in learned_behavior.get('server_ports', [])[:10]
            ],
            'typical_destinations': learned_behavior.get('typical_destinations', [])[:20],
            'bytes_in': learned_behavior.get('bytes_in', 0),
            'bytes_out': learned_behavior.get('bytes_out', 0),
            'packet_count': learned_behavior.get('packet_count', 0),
            'observation_period': learned_behavior.get('observation_period'),
            'generated_at': learned_behavior.get('generated_at')
        }

        return {
            'success': True,
            'ip_address': ip_address,
            'device': {
                'hostname': device.get('hostname'),
                'mac_address': device.get('mac_address'),
                'vendor': device.get('vendor'),
                'template_name': device.get('template_name')
            },
            'learned_behavior': formatted_behavior,
            'can_create_template': learned_behavior.get('packet_count', 0) >= 100
        }

    # ==================== TLS Analysis Tool Implementations ====================


    # get_tls_metadata
    async def get_tls_metadata(self, params: Dict) -> Dict:
        """Implement get_tls_metadata tool"""
        import requests

        limit = params.get('limit', 100)
        ip_filter = params.get('ip_filter')
        sni_filter = params.get('sni_filter')

        # Get TLS metadata from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/internal/tls-metadata",
                params={'limit': limit, 'ip_filter': ip_filter, 'sni_filter': sni_filter},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'metadata': data.get('metadata', []),
                    'count': len(data.get('metadata', [])),
                    'filters_applied': {
                        'ip_filter': ip_filter,
                        'sni_filter': sni_filter,
                        'limit': limit
                    }
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting TLS metadata: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve TLS metadata. Ensure the dashboard API is running and TLS analysis is enabled.'
            }


    # get_tls_stats
    async def get_tls_stats(self, params: Dict) -> Dict:
        """Implement get_tls_stats tool"""
        import requests

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/internal/tls-stats",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'stats': data.get('stats', {}),
                    'message': 'TLS analysis statistics retrieved successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting TLS stats: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve TLS stats. TLS analysis may not be enabled.'
            }


    # check_ja3_fingerprint
    async def check_ja3_fingerprint(self, params: Dict) -> Dict:
        """Implement check_ja3_fingerprint tool"""
        import requests

        ja3_hash = params.get('ja3_hash')

        if not ja3_hash:
            return {'success': False, 'error': 'ja3_hash is required'}

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/internal/ja3-check/{ja3_hash}",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'ja3_hash': ja3_hash,
                    'is_malicious': data.get('is_malicious', False),
                    'malware_family': data.get('malware_family'),
                    'message': 'Known malicious fingerprint' if data.get('is_malicious') else 'Not in blacklist'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking JA3: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to check JA3 fingerprint.'
            }


    # add_ja3_blacklist
    async def add_ja3_blacklist(self, params: Dict) -> Dict:
        """Implement add_ja3_blacklist tool (requires write access)"""
        import requests

        ja3_hash = params.get('ja3_hash')
        malware_family = params.get('malware_family')

        if not ja3_hash or not malware_family:
            return {'success': False, 'error': 'ja3_hash and malware_family are required'}

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/internal/ja3-blacklist",
                json={'ja3_hash': ja3_hash, 'malware_family': malware_family},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'ja3_hash': ja3_hash,
                    'malware_family': malware_family,
                    'message': f'JA3 fingerprint added to blacklist: {malware_family}'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error adding JA3 to blacklist: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to add JA3 to blacklist.'
            }

    # ==================== PCAP Export Tool Implementations ====================


    # get_pcap_captures
    async def get_pcap_captures(self, params: Dict) -> Dict:
        """Implement get_pcap_captures tool"""
        import requests

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/internal/pcap-captures",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                captures = data.get('captures', [])
                return {
                    'success': True,
                    'captures': captures,
                    'count': len(captures),
                    'message': f'Found {len(captures)} PCAP captures'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error listing PCAP captures: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to list PCAP captures. PCAP export may not be enabled.'
            }


    # get_pcap_stats
    async def get_pcap_stats(self, params: Dict) -> Dict:
        """Implement get_pcap_stats tool"""
        import requests

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/internal/pcap-stats",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'stats': data.get('stats', {}),
                    'message': 'PCAP exporter statistics retrieved successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting PCAP stats: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve PCAP stats. PCAP export may not be enabled.'
            }


    # export_flow_pcap
    async def export_flow_pcap(self, params: Dict) -> Dict:
        """Implement export_flow_pcap tool (requires write access)"""
        import requests

        src_ip = params.get('src_ip')
        dst_ip = params.get('dst_ip')
        dst_port = params.get('dst_port')

        if not src_ip or not dst_ip:
            return {'success': False, 'error': 'src_ip and dst_ip are required'}

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/internal/pcap-export-flow",
                json={'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': dst_port},
                timeout=30  # Longer timeout for PCAP export
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'filepath': data.get('filepath'),
                    'packet_count': data.get('packet_count'),
                    'message': f'Flow exported to {data.get("filepath")}'
                }
            elif response.status_code == 404:
                return {
                    'success': True,
                    'filepath': None,
                    'message': f'No packets found for flow {src_ip} -> {dst_ip}'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error exporting flow PCAP: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to export flow PCAP.'
            }


    # get_packet_buffer_summary
    async def get_packet_buffer_summary(self, params: Dict) -> Dict:
        """Implement get_packet_buffer_summary tool"""
        import requests

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/internal/packet-buffer-summary",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'summary': data.get('summary', {}),
                    'message': 'Packet buffer summary retrieved successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting packet buffer summary: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve packet buffer summary. PCAP export may not be enabled.'
            }


    # delete_pcap_capture
    async def delete_pcap_capture(self, params: Dict) -> Dict:
        """Implement delete_pcap_capture tool (requires write access)"""
        import requests

        filename = params.get('filename')

        if not filename:
            return {'success': False, 'error': 'filename is required'}

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.delete(
                f"{dashboard_url}/api/internal/pcap-captures/{filename}",
                timeout=10
            )

            if response.status_code == 200:
                return {
                    'success': True,
                    'filename': filename,
                    'message': f'PCAP capture {filename} deleted'
                }
            elif response.status_code == 404:
                return {
                    'success': False,
                    'error': f'PCAP capture {filename} not found'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error deleting PCAP capture: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to delete PCAP capture.'
            }

    # ==================== Export Tool Implementations ====================


    # export_alerts_csv
    async def export_alerts_csv(self, params: Dict) -> Dict:
        """Export security alerts to CSV format"""
        import csv
        import io

        hours = params.get('hours', 24)
        severity = params.get('severity')
        threat_type = params.get('threat_type')

        logger.info(f"Exporting alerts to CSV (hours={hours}, severity={severity}, threat_type={threat_type})")

        try:
            alerts = self.db.get_recent_alerts(
                limit=10000,  # High limit for exports
                hours=hours,
                severity=severity,
                threat_type=threat_type
            )

            # Generate CSV
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['Timestamp', 'Severity', 'Threat Type', 'Source IP', 'Destination IP',
                            'Description', 'Sensor ID', 'Acknowledged'])

            # Write data
            for alert in alerts:
                writer.writerow([
                    alert.get('timestamp', ''),
                    alert.get('severity', ''),
                    alert.get('threat_type', ''),
                    alert.get('source_ip', ''),
                    alert.get('destination_ip', ''),
                    alert.get('description', ''),
                    alert.get('sensor_id', ''),
                    'Yes' if alert.get('acknowledged') else 'No'
                ])

            csv_data = output.getvalue()
            output.close()

            return {
                'success': True,
                'format': 'csv',
                'rows': len(alerts),
                'filters': {
                    'hours': hours,
                    'severity': severity,
                    'threat_type': threat_type
                },
                'csv_data': csv_data,
                'message': f'Exported {len(alerts)} alerts to CSV'
            }

        except Exception as e:
            logger.error(f"Error exporting alerts to CSV: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== Memory Management Tool Implementations ====================


    # get_memory_status
    async def get_memory_status(self, params: Dict) -> Dict:
        """Get current memory usage of SOC server"""
        import requests

        try:
            # Call the internal API endpoint
            response = requests.get(
                f"{self.base_url}/api/internal/memory/status",
                timeout=5
            )
            response.raise_for_status()
            data = response.json()

            if data.get('success'):
                return {
                    'success': True,
                    'memory': data.get('memory', {}),
                    'message': 'Retrieved memory status successfully'
                }
            else:
                return {
                    'success': False,
                    'error': data.get('error', 'Unknown error')
                }

        except Exception as e:
            logger.error(f"Error getting memory status: {e}")
            return {'success': False, 'error': str(e)}


    # flush_memory
    async def flush_memory(self, params: Dict) -> Dict:
        """Trigger emergency memory flush on SOC server"""
        import requests

        try:
            # Call the internal API endpoint
            response = requests.post(
                f"{self.base_url}/api/internal/memory/flush",
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            if data.get('success'):
                return {
                    'success': True,
                    'before': data.get('before', {}),
                    'after': data.get('after', {}),
                    'reduction': data.get('reduction', {}),
                    'collected_objects': data.get('collected_objects', 0),
                    'message': f"Memory flushed successfully. System RAM reduced by {data.get('reduction', {}).get('system_percent', 0):.1f}%"
                }
            else:
                return {
                    'success': False,
                    'error': data.get('error', 'Unknown error')
                }

        except Exception as e:
            logger.error(f"Error flushing memory: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== Sensor Command Tool Implementations ====================


    # send_sensor_command
    async def send_sensor_command(self, params: Dict) -> Dict:
        """Send a command to a remote sensor"""
        sensor_id = params.get('sensor_id')
        command_type = params.get('command_type')
        parameters = params.get('parameters', {})

        if not sensor_id or not command_type:
            return {'success': False, 'error': 'sensor_id and command_type are required'}

        valid_commands = ['restart', 'update_config', 'update_whitelist', 'run_diagnostics']
        if command_type not in valid_commands:
            return {
                'success': False,
                'error': f"Invalid command_type. Must be one of: {', '.join(valid_commands)}"
            }

        logger.info(f"Sending command '{command_type}' to sensor {sensor_id}")

        try:
            # Verify sensor exists
            sensor = self.db.get_sensor_by_id(sensor_id)
            if not sensor:
                return {'success': False, 'error': f"Sensor '{sensor_id}' not found"}

            # Create command in database
            command_id = self.db.create_sensor_command(
                sensor_id=sensor_id,
                command_type=command_type,
                parameters=parameters
            )

            if command_id:
                return {
                    'success': True,
                    'command_id': command_id,
                    'sensor_id': sensor_id,
                    'command_type': command_type,
                    'parameters': parameters,
                    'message': f"Command '{command_type}' queued for sensor '{sensor_id}' (ID: {command_id})",
                    'note': 'Sensor will poll for this command within 30 seconds'
                }
            else:
                return {'success': False, 'error': 'Failed to create command'}

        except Exception as e:
            logger.error(f"Error sending sensor command: {e}")
            return {'success': False, 'error': str(e)}


    # get_sensor_command_history
    async def get_sensor_command_history(self, params: Dict) -> Dict:
        """Get command history for a sensor"""
        sensor_id = params.get('sensor_id')
        limit = params.get('limit', 20)

        if not sensor_id:
            return {'success': False, 'error': 'sensor_id is required'}

        logger.info(f"Getting command history for sensor {sensor_id} (limit={limit})")

        try:
            commands = self.db.get_sensor_command_history(sensor_id, limit=limit)

            return {
                'success': True,
                'sensor_id': sensor_id,
                'total_commands': len(commands),
                'commands': commands,
                'message': f'Found {len(commands)} commands for sensor {sensor_id}'
            }

        except Exception as e:
            logger.error(f"Error getting sensor command history: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== Whitelist Management Tool Implementations ====================


    # add_whitelist_entry
    async def add_whitelist_entry(self, params: Dict) -> Dict:
        """Add an IP, CIDR range, or domain to the whitelist with direction support"""
        import requests

        ip_cidr = params.get('ip_cidr')
        description = params.get('description')
        scope = params.get('scope', 'global')
        sensor_id = params.get('sensor_id')
        direction = params.get('direction', 'both')

        if not ip_cidr or not description:
            return {'success': False, 'error': 'ip_cidr and description are required'}

        if scope == 'sensor' and not sensor_id:
            return {'success': False, 'error': "sensor_id required when scope is 'sensor'"}

        # Validate direction (support both old and new terminology)
        valid_directions = ('source', 'destination', 'inbound', 'outbound', 'both')
        if direction not in valid_directions:
            return {'success': False, 'error': "direction must be 'source', 'destination', or 'both'"}

        logger.info(f"Adding whitelist entry: {ip_cidr} (scope: {scope}, direction: {direction})")

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/whitelist",
                json={
                    'ip_cidr': ip_cidr,
                    'description': description,
                    'scope': scope,
                    'sensor_id': sensor_id,
                    'direction': direction,
                    'created_by': 'mcp'
                },
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'success': True,
                        'message': f"Added {ip_cidr} to whitelist ({direction})",
                        'entry_id': result.get('entry_id'),
                        'ip_cidr': ip_cidr,
                        'description': description,
                        'scope': scope,
                        'sensor_id': sensor_id,
                        'direction': direction
                    }
                else:
                    return {'success': False, 'error': result.get('error', 'Unknown error')}
            else:
                return {'success': False, 'error': f'API returned status {response.status_code}'}

        except requests.exceptions.RequestException as e:
            logger.error(f"Error adding whitelist entry: {e}")
            return {'success': False, 'error': str(e)}


    # get_whitelist_entries
    async def get_whitelist_entries(self, params: Dict) -> Dict:
        """Get whitelist entries, optionally filtered by scope or sensor"""
        import requests

        scope = params.get('scope')
        sensor_id = params.get('sensor_id')

        logger.info(f"Getting whitelist entries (scope: {scope}, sensor: {sensor_id})")

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            req_params = {}
            if scope:
                req_params['scope'] = scope
            if sensor_id:
                req_params['sensor_id'] = sensor_id

            response = requests.get(
                f"{dashboard_url}/api/whitelist",
                params=req_params,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    entries = result.get('entries', [])
                    return {
                        'success': True,
                        'total_entries': len(entries),
                        'scope_filter': scope,
                        'sensor_filter': sensor_id,
                        'entries': entries
                    }
                else:
                    return {'success': False, 'error': result.get('error', 'Unknown error')}
            else:
                return {'success': False, 'error': f'API returned status {response.status_code}'}

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting whitelist entries: {e}")
            return {'success': False, 'error': str(e)}


    # remove_whitelist_entry
    async def remove_whitelist_entry(self, params: Dict) -> Dict:
        """Remove a whitelist entry by ID"""
        import requests

        entry_id = params.get('entry_id')

        if not entry_id:
            return {'success': False, 'error': 'entry_id is required'}

        logger.info(f"Removing whitelist entry: {entry_id}")

        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.delete(
                f"{dashboard_url}/api/whitelist/{entry_id}",
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'success': True,
                        'message': f'Removed whitelist entry {entry_id}'
                    }
                else:
                    return {'success': False, 'error': result.get('error', 'Unknown error')}
            elif response.status_code == 404:
                return {'success': False, 'error': f'Whitelist entry {entry_id} not found'}
            else:
                return {'success': False, 'error': f'API returned status {response.status_code}'}

        except requests.exceptions.RequestException as e:
            logger.error(f"Error removing whitelist entry: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== AD/Kerberos Attack Detection Tool Implementations ====================


    # get_kerberos_stats
    async def get_kerberos_stats(self, params: Dict) -> Dict:
        """Get Kerberos attack detection statistics"""
        hours = params.get('hours', 24)
        sensor_id = params.get('sensor_id')

        try:
            # Query alerts related to Kerberos attacks
            kerberos_types = ['kerberoasting', 'asrep_roasting', 'dcsync', 'pass_the_hash', 'golden_ticket', 'weak_encryption']

            stats = {
                'period_hours': hours,
                'total_kerberos_alerts': 0,
                'by_attack_type': {},
                'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'unique_sources': set(),
                'unique_targets': set()
            }

            alerts = self.db.get_recent_alerts(hours=hours, sensor_id=sensor_id)

            for alert in alerts:
                alert_type = alert.get('alert_type', '').lower()
                if any(kt in alert_type for kt in kerberos_types):
                    stats['total_kerberos_alerts'] += 1
                    stats['by_attack_type'][alert_type] = stats['by_attack_type'].get(alert_type, 0) + 1
                    severity = alert.get('severity', 'MEDIUM')
                    stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
                    if alert.get('src_ip'):
                        stats['unique_sources'].add(alert['src_ip'])
                    if alert.get('dst_ip'):
                        stats['unique_targets'].add(alert['dst_ip'])

            stats['unique_sources'] = list(stats['unique_sources'])
            stats['unique_targets'] = list(stats['unique_targets'])

            return {
                'success': True,
                'stats': stats
            }

        except Exception as e:
            logger.error(f"Error getting Kerberos stats: {e}")
            return {'success': False, 'error': str(e)}


    # get_kerberos_attacks
    async def get_kerberos_attacks(self, params: Dict) -> Dict:
        """Get detailed list of Kerberos attacks"""
        attack_type = params.get('attack_type')
        hours = params.get('hours', 24)
        limit = params.get('limit', 50)

        try:
            kerberos_types = ['kerberoasting', 'asrep_roasting', 'dcsync', 'pass_the_hash', 'golden_ticket']
            alerts = self.db.get_recent_alerts(hours=hours)

            attacks = []
            for alert in alerts:
                alert_type_lower = alert.get('alert_type', '').lower()

                # Filter by specific attack type if provided
                if attack_type:
                    if attack_type.lower() not in alert_type_lower:
                        continue
                else:
                    if not any(kt in alert_type_lower for kt in kerberos_types):
                        continue

                attacks.append({
                    'id': alert.get('id'),
                    'timestamp': str(alert.get('timestamp')),
                    'attack_type': alert.get('alert_type'),
                    'severity': alert.get('severity'),
                    'src_ip': alert.get('src_ip'),
                    'dst_ip': alert.get('dst_ip'),
                    'description': alert.get('description'),
                    'sensor_id': alert.get('sensor_id')
                })

                if len(attacks) >= limit:
                    break

            return {
                'success': True,
                'count': len(attacks),
                'attacks': attacks
            }

        except Exception as e:
            logger.error(f"Error getting Kerberos attacks: {e}")
            return {'success': False, 'error': str(e)}


    # check_weak_encryption
    async def check_weak_encryption(self, params: Dict) -> Dict:
        """Check for weak Kerberos encryption usage"""
        hours = params.get('hours', 24)

        try:
            alerts = self.db.get_recent_alerts(hours=hours)

            weak_encryption_events = []
            for alert in alerts:
                if 'weak_encryption' in alert.get('alert_type', '').lower() or \
                   'rc4' in alert.get('description', '').lower() or \
                   'des' in alert.get('description', '').lower():
                    weak_encryption_events.append({
                        'timestamp': str(alert.get('timestamp')),
                        'src_ip': alert.get('src_ip'),
                        'dst_ip': alert.get('dst_ip'),
                        'description': alert.get('description'),
                        'encryption_type': 'RC4' if 'rc4' in alert.get('description', '').lower() else 'DES'
                    })

            return {
                'success': True,
                'weak_encryption_detected': len(weak_encryption_events) > 0,
                'count': len(weak_encryption_events),
                'events': weak_encryption_events[:50],
                'recommendation': 'Disable RC4 and DES encryption in Active Directory Group Policy' if weak_encryption_events else 'No weak encryption detected'
            }

        except Exception as e:
            logger.error(f"Error checking weak encryption: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== Kill Chain Detection Tool Implementations ====================


    # get_attack_chains
    async def get_attack_chains(self, params: Dict) -> Dict:
        """Get detected multi-stage attack chains"""
        min_stages = params.get('min_stages', 2)
        hours = params.get('hours', 24)
        source_ip = params.get('source_ip')

        try:
            alerts = self.db.get_recent_alerts(hours=hours, limit=1000)

            # Group alerts by source IP to detect chains
            chains_by_source = {}
            for alert in alerts:
                src = alert.get('source_ip')  # Fixed: was 'src_ip'
                if not src:
                    continue
                if source_ip and src != source_ip:
                    continue

                if src not in chains_by_source:
                    chains_by_source[src] = {
                        'source_ip': src,
                        'stages': set(),
                        'alerts': [],
                        'first_seen': alert.get('timestamp'),
                        'last_seen': alert.get('timestamp')
                    }

                # Map alert type to kill chain stage
                threat_type = alert.get('threat_type', '')  # Fixed: was 'alert_type'
                stage = self._map_to_kill_chain_stage(threat_type)
                if stage:
                    chains_by_source[src]['stages'].add(stage)
                    chains_by_source[src]['alerts'].append({
                        'threat_type': threat_type,
                        'stage': stage,
                        'timestamp': str(alert.get('timestamp')),
                        'severity': alert.get('severity'),
                        'description': alert.get('description', '')[:100]
                    })
                    chains_by_source[src]['last_seen'] = alert.get('timestamp')

            # Filter by minimum stages and format output
            attack_chains = []
            for src, chain in chains_by_source.items():
                if len(chain['stages']) >= min_stages:
                    attack_chains.append({
                        'source_ip': src,
                        'stage_count': len(chain['stages']),
                        'stages': list(chain['stages']),
                        'alert_count': len(chain['alerts']),
                        'first_seen': str(chain['first_seen']),
                        'last_seen': str(chain['last_seen']),
                        'severity': 'CRITICAL' if len(chain['stages']) >= 4 else 'HIGH',
                        'alerts': chain['alerts'][:10]  # Limit alerts in response
                    })

            # Sort by stage count descending
            attack_chains.sort(key=lambda x: x['stage_count'], reverse=True)

            return {
                'success': True,
                'count': len(attack_chains),
                'attack_chains': attack_chains[:20]
            }

        except Exception as e:
            logger.error(f"Error getting attack chains: {e}")
            return {'success': False, 'error': str(e)}


    # get_mitre_mapping
    async def get_mitre_mapping(self, params: Dict) -> Dict:
        """Get MITRE ATT&CK technique mapping for alerts"""
        hours = params.get('hours', 24)
        tactic = params.get('tactic')

        try:
            # MITRE ATT&CK mapping for common alerts
            mitre_mapping = {
                'port_scan': {'technique': 'T1046', 'name': 'Network Service Scanning', 'tactic': 'discovery'},
                'brute_force': {'technique': 'T1110', 'name': 'Brute Force', 'tactic': 'credential_access'},
                'kerberoasting': {'technique': 'T1558.003', 'name': 'Kerberoasting', 'tactic': 'credential_access'},
                'dcsync': {'technique': 'T1003.006', 'name': 'DCSync', 'tactic': 'credential_access'},
                'pass_the_hash': {'technique': 'T1550.002', 'name': 'Pass the Hash', 'tactic': 'lateral_movement'},
                'smb_admin_share': {'technique': 'T1021.002', 'name': 'SMB/Windows Admin Shares', 'tactic': 'lateral_movement'},
                'lateral_movement': {'technique': 'T1021', 'name': 'Remote Services', 'tactic': 'lateral_movement'},
                'c2_communication': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'command_and_control'},
                'dns_tunneling': {'technique': 'T1071.004', 'name': 'DNS', 'tactic': 'command_and_control'},
                'data_exfiltration': {'technique': 'T1041', 'name': 'Exfiltration Over C2 Channel', 'tactic': 'exfiltration'},
                'beaconing': {'technique': 'T1573', 'name': 'Encrypted Channel', 'tactic': 'command_and_control'}
            }

            alerts = self.db.get_recent_alerts(hours=hours)

            mapped_alerts = []
            tactic_counts = {}

            for alert in alerts:
                alert_type = alert.get('alert_type', '').lower()

                for key, mapping in mitre_mapping.items():
                    if key in alert_type:
                        if tactic and mapping['tactic'] != tactic:
                            continue

                        mapped_alerts.append({
                            'alert_id': alert.get('id'),
                            'alert_type': alert.get('alert_type'),
                            'mitre_technique': mapping['technique'],
                            'technique_name': mapping['name'],
                            'tactic': mapping['tactic'],
                            'timestamp': str(alert.get('timestamp')),
                            'src_ip': alert.get('src_ip')
                        })

                        tactic_counts[mapping['tactic']] = tactic_counts.get(mapping['tactic'], 0) + 1
                        break

            return {
                'success': True,
                'total_mapped': len(mapped_alerts),
                'by_tactic': tactic_counts,
                'mapped_alerts': mapped_alerts[:100]
            }

        except Exception as e:
            logger.error(f"Error getting MITRE mapping: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== Risk Scoring Tool Implementations ====================


    # get_top_risk_assets
    async def get_top_risk_assets(self, params: Dict) -> Dict:
        """Get assets with highest risk scores"""
        limit = params.get('limit', 10)
        min_score = params.get('min_score', 0)

        try:
            # Calculate risk scores based on alert history
            alerts = self.db.get_recent_alerts(hours=168)  # 7 days

            risk_scores = {}
            severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}

            for alert in alerts:
                src_ip = alert.get('src_ip')
                if not src_ip:
                    continue

                if src_ip not in risk_scores:
                    risk_scores[src_ip] = {
                        'ip_address': src_ip,
                        'score': 0,
                        'alert_count': 0,
                        'critical_count': 0,
                        'high_count': 0,
                        'alert_types': set()
                    }

                severity = alert.get('severity', 'MEDIUM')
                weight = severity_weights.get(severity, 1)
                risk_scores[src_ip]['score'] += weight
                risk_scores[src_ip]['alert_count'] += 1
                risk_scores[src_ip]['alert_types'].add(alert.get('alert_type', 'unknown'))

                if severity == 'CRITICAL':
                    risk_scores[src_ip]['critical_count'] += 1
                elif severity == 'HIGH':
                    risk_scores[src_ip]['high_count'] += 1

            # Normalize scores to 0-100
            max_score = max((r['score'] for r in risk_scores.values()), default=1)
            for ip, data in risk_scores.items():
                data['score'] = min(100, int((data['score'] / max_score) * 100))
                data['alert_types'] = list(data['alert_types'])

            # Filter and sort
            top_assets = [
                data for data in risk_scores.values()
                if data['score'] >= min_score
            ]
            top_assets.sort(key=lambda x: x['score'], reverse=True)

            return {
                'success': True,
                'count': len(top_assets[:limit]),
                'assets': top_assets[:limit]
            }

        except Exception as e:
            logger.error(f"Error getting top risk assets: {e}")
            return {'success': False, 'error': str(e)}


    # get_asset_risk
    async def get_asset_risk(self, params: Dict) -> Dict:
        """Get detailed risk score for a specific IP"""
        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        try:
            alerts = self.db.get_recent_alerts(hours=168)  # 7 days

            severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
            risk_data = {
                'ip_address': ip_address,
                'score': 0,
                'alert_count': 0,
                'contributing_factors': [],
                'alert_timeline': [],
                'severity_breakdown': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            }

            for alert in alerts:
                if alert.get('src_ip') == ip_address or alert.get('dst_ip') == ip_address:
                    severity = alert.get('severity', 'MEDIUM')
                    weight = severity_weights.get(severity, 1)
                    risk_data['score'] += weight
                    risk_data['alert_count'] += 1
                    risk_data['severity_breakdown'][severity] = risk_data['severity_breakdown'].get(severity, 0) + 1

                    risk_data['alert_timeline'].append({
                        'timestamp': str(alert.get('timestamp')),
                        'type': alert.get('alert_type'),
                        'severity': severity
                    })

                    factor = f"{alert.get('alert_type')} ({severity})"
                    if factor not in risk_data['contributing_factors']:
                        risk_data['contributing_factors'].append(factor)

            # Normalize score
            risk_data['score'] = min(100, risk_data['score'])

            # Determine trend
            if risk_data['alert_count'] > 10:
                risk_data['trend'] = 'rising'
            elif risk_data['alert_count'] > 5:
                risk_data['trend'] = 'stable'
            else:
                risk_data['trend'] = 'low'

            # Limit timeline
            risk_data['alert_timeline'] = risk_data['alert_timeline'][:20]

            return {
                'success': True,
                'risk_data': risk_data
            }

        except Exception as e:
            logger.error(f"Error getting asset risk: {e}")
            return {'success': False, 'error': str(e)}


    # get_risk_trends
    async def get_risk_trends(self, params: Dict) -> Dict:
        """Get risk score trends over time"""
        hours = params.get('hours', 24)
        limit = params.get('limit', 10)

        try:
            # Get top assets first
            top_result = await self.get_top_risk_assets({'limit': limit})
            if not top_result.get('success'):
                return top_result

            trends = []
            for asset in top_result.get('assets', []):
                ip = asset['ip_address']

                # Simple trend calculation
                trends.append({
                    'ip_address': ip,
                    'current_score': asset['score'],
                    'alert_count': asset['alert_count'],
                    'trend': 'rising' if asset['critical_count'] > 0 else 'stable'
                })

            return {
                'success': True,
                'period_hours': hours,
                'trends': trends
            }

        except Exception as e:
            logger.error(f"Error getting risk trends: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== SOAR Tool Implementations ====================


    # get_soar_playbooks
    async def get_soar_playbooks(self, params: Dict) -> Dict:
        """Get configured SOAR playbooks"""
        enabled_only = params.get('enabled_only', False)

        try:
            # Default playbooks configuration
            playbooks = {
                'critical_threat': {
                    'name': 'Critical Threat Response',
                    'enabled': True,
                    'trigger': 'CRITICAL severity alert',
                    'actions': ['block_ip', 'isolate_host', 'notify_soc'],
                    'auto_approve': False,
                    'description': 'Responds to critical threats with immediate containment'
                },
                'lateral_movement': {
                    'name': 'Lateral Movement Response',
                    'enabled': True,
                    'trigger': 'Lateral movement detection',
                    'actions': ['quarantine_segment', 'disable_account', 'collect_forensics'],
                    'auto_approve': False,
                    'description': 'Contains lateral movement attempts'
                },
                'credential_theft': {
                    'name': 'Credential Theft Response',
                    'enabled': True,
                    'trigger': 'Kerberoasting, Pass-the-Hash detected',
                    'actions': ['force_password_reset', 'revoke_sessions', 'notify_admin'],
                    'auto_approve': False,
                    'description': 'Responds to credential theft attempts'
                },
                'reconnaissance': {
                    'name': 'Reconnaissance Response',
                    'enabled': True,
                    'trigger': 'Port scan, enumeration detected',
                    'actions': ['monitor_enhanced', 'capture_pcap'],
                    'auto_approve': True,
                    'description': 'Enhanced monitoring for reconnaissance activity'
                },
                'brute_force': {
                    'name': 'Brute Force Response',
                    'enabled': True,
                    'trigger': 'Failed authentication threshold',
                    'actions': ['temporary_block', 'rate_limit'],
                    'auto_approve': True,
                    'description': 'Blocks brute force attempts'
                }
            }

            if enabled_only:
                playbooks = {k: v for k, v in playbooks.items() if v['enabled']}

            return {
                'success': True,
                'playbook_count': len(playbooks),
                'playbooks': playbooks,
                'dry_run_mode': True,  # Default to dry run
                'require_approval': True
            }

        except Exception as e:
            logger.error(f"Error getting SOAR playbooks: {e}")
            return {'success': False, 'error': str(e)}


    # get_pending_approvals
    async def get_pending_approvals(self, params: Dict) -> Dict:
        """Get SOAR actions pending approval"""
        playbook = params.get('playbook')

        try:
            # In a real implementation, this would query a database
            # For now, return empty list as no actions are pending
            pending = []

            return {
                'success': True,
                'count': len(pending),
                'pending_approvals': pending,
                'message': 'No actions pending approval' if not pending else f'{len(pending)} actions pending'
            }

        except Exception as e:
            logger.error(f"Error getting pending approvals: {e}")
            return {'success': False, 'error': str(e)}


    # approve_soar_action
    async def approve_soar_action(self, params: Dict) -> Dict:
        """Approve or reject a SOAR action"""
        action_id = params.get('action_id')
        approved = params.get('approved')
        reason = params.get('reason', '')

        if action_id is None or approved is None:
            return {'success': False, 'error': 'action_id and approved are required'}

        try:
            # In a real implementation, this would update the database
            # and potentially execute the action if approved
            action = 'approved' if approved else 'rejected'

            return {
                'success': True,
                'action_id': action_id,
                'status': action,
                'reason': reason,
                'message': f'Action {action_id} has been {action}',
                'note': 'SOAR is in dry-run mode - no actual action was executed'
            }

        except Exception as e:
            logger.error(f"Error approving SOAR action: {e}")
            return {'success': False, 'error': str(e)}


    # get_soar_history
    async def get_soar_history(self, params: Dict) -> Dict:
        """Get history of SOAR actions"""
        hours = params.get('hours', 24)
        playbook = params.get('playbook')
        status = params.get('status')

        try:
            # In a real implementation, this would query action history
            # For now, return sample structure
            history = []

            return {
                'success': True,
                'period_hours': hours,
                'count': len(history),
                'history': history,
                'message': 'No SOAR actions in history' if not history else f'{len(history)} actions found'
            }

        except Exception as e:
            logger.error(f"Error getting SOAR history: {e}")
            return {'success': False, 'error': str(e)}


    # get_threat_feed_stats
    async def get_threat_feed_stats(self, params: Dict) -> Dict:
        """Implement get_threat_feed_stats tool"""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from database import DatabaseManager

            # Create DB connection
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'netmonitor'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db = DatabaseManager(
                host=host, database=database, user=user, password=password,
                min_connections=1, max_connections=2
            )

            stats = {}
            total_indicators = 0

            # Get counts per feed type
            for feed_type in ['phishing', 'tor_exit', 'cryptomining', 'vpn_exit',
                             'malware_c2', 'botnet_c2', 'known_attacker', 'malicious_domain']:
                indicators = db.get_threat_feed_indicators(
                    feed_type=feed_type,
                    is_active=True,
                    limit=100000
                )
                count = len(indicators)
                total_indicators += count

                if count > 0:
                    last_updated = max([i.get('last_updated') for i in indicators if i.get('last_updated')],
                                      default=None)
                    stats[feed_type] = {
                        'count': count,
                        'last_updated': last_updated.isoformat() if last_updated else None
                    }

            db.close()

            return {
                'success': True,
                'total_indicators': total_indicators,
                'feed_stats': stats,
                'active_feeds': len([f for f in stats.values() if f['count'] > 0])
            }

        except Exception as e:
            logger.error(f"Error getting threat feed stats: {e}")
            return {'success': False, 'error': str(e)}


    # get_threat_detections
    async def get_threat_detections(self, params: Dict) -> Dict:
        """Implement get_threat_detections tool"""
        hours = params.get('hours', 24)
        threat_type = params.get('threat_type')
        limit = params.get('limit', 50)

        # Get recent alerts filtered by advanced threat types
        advanced_threat_types = [
            'CRYPTOMINING_DETECTED',
            'PHISHING_DOMAIN_QUERY',
            'TOR_EXIT_NODE_CONNECTION',
            'CLOUD_METADATA_ACCESS',
            'DNS_ANOMALY'
        ]

        alerts = self.db.get_recent_alerts(
            limit=limit,
            hours=hours,
            threat_type=threat_type
        )

        # Filter only advanced threat detections
        threat_alerts = [a for a in alerts if a.get('threat_type') in advanced_threat_types]

        # Calculate statistics
        by_type = {}
        unique_sources = set()

        for alert in threat_alerts:
            t_type = alert['threat_type']
            by_type[t_type] = by_type.get(t_type, 0) + 1
            unique_sources.add(alert.get('source_ip', 'unknown'))

        return {
            'success': True,
            'total_detections': len(threat_alerts),
            'by_type': by_type,
            'unique_sources': len(unique_sources),
            'detections': threat_alerts
        }


    # get_threat_config
    async def get_threat_config(self, params: Dict) -> Dict:
        """Implement get_threat_config tool"""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from database import DatabaseManager

            # Create DB connection
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'netmonitor'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db = DatabaseManager(
                host=host, database=database, user=user, password=password,
                min_connections=1, max_connections=2
            )

            sensor_id = params.get('sensor_id')
            config = db.get_sensor_config(sensor_id=sensor_id)

            # Extract threat-related config
            threat_config = {}
            for key, value in config.items():
                if key.startswith('threat.'):
                    threat_config[key] = value.get('parameter_value')

            db.close()

            return {
                'success': True,
                'sensor_id': sensor_id or 'global',
                'config': threat_config
            }

        except Exception as e:
            logger.error(f"Error getting threat config: {e}")
            return {'success': False, 'error': str(e)}


    # enable_threat_detection
    async def enable_threat_detection(self, params: Dict) -> Dict:
        """Implement enable_threat_detection tool"""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from database import DatabaseManager

            # Create DB connection
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'netmonitor'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db = DatabaseManager(
                host=host, database=database, user=user, password=password,
                min_connections=1, max_connections=2
            )

            threat_type = params.get('threat_type')
            enabled = params.get('enabled')
            sensor_id = params.get('sensor_id')

            # Set config parameter
            param_path = f'threat.{threat_type}.enabled'
            scope = 'sensor' if sensor_id else 'global'

            success = db.set_config_parameter(
                parameter_path=param_path,
                value=enabled,
                sensor_id=sensor_id,
                scope=scope,
                description=f'Enable/disable {threat_type} detection',
                updated_by='mcp_api'
            )

            db.close()

            if success:
                return {
                    'success': True,
                    'message': f'{threat_type} detection {"enabled" if enabled else "disabled"} for {sensor_id or "all sensors"}',
                    'threat_type': threat_type,
                    'enabled': enabled,
                    'scope': scope
                }
            else:
                return {'success': False, 'error': 'Failed to update configuration'}

        except Exception as e:
            logger.error(f"Error enabling threat detection: {e}")
            return {'success': False, 'error': str(e)}


    # update_threat_feeds
    async def update_threat_feeds(self, params: Dict) -> Dict:
        """Implement update_threat_feeds tool"""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from database import DatabaseManager
            from threat_feed_updater import run_feed_updater

            # Create DB connection
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'netmonitor'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db = DatabaseManager(
                host=host, database=database, user=user, password=password,
                min_connections=1, max_connections=2
            )

            # Run feed updater
            results = run_feed_updater(db)

            db.close()

            if results:
                return {
                    'success': True,
                    'message': 'Threat feeds updated successfully',
                    'results': results
                }
            else:
                return {'success': False, 'error': 'Failed to update threat feeds'}

        except Exception as e:
            logger.error(f"Error updating threat feeds: {e}")
            return {'success': False, 'error': str(e)}


    # check_indicator
    async def check_indicator(self, params: Dict) -> Dict:
        """Implement check_indicator tool"""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from database import DatabaseManager

            # Create DB connection
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'netmonitor'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db = DatabaseManager(
                host=host, database=database, user=user, password=password,
                min_connections=1, max_connections=2
            )

            indicator = params.get('indicator')
            indicator_type = params.get('indicator_type')
            feed_types = params.get('feed_types')

            # Check based on indicator type
            if indicator_type == 'ip':
                match = db.check_ip_in_threat_feeds(indicator, feed_types=feed_types)
            else:
                match = db.check_threat_indicator(indicator, feed_types=feed_types)

            db.close()

            if match:
                return {
                    'success': True,
                    'indicator': indicator,
                    'indicator_type': indicator_type,
                    'match_found': True,
                    'feed_type': match.get('feed_type'),
                    'source': match.get('source'),
                    'confidence_score': match.get('confidence_score'),
                    'metadata': match.get('metadata')
                }
            else:
                return {
                    'success': True,
                    'indicator': indicator,
                    'indicator_type': indicator_type,
                    'match_found': False,
                    'message': 'Indicator not found in any threat feeds'
                }

        except Exception as e:
            logger.error(f"Error checking indicator: {e}")
            return {'success': False, 'error': str(e)}



# ==================== Tool Definitions Registry ====================

TOOL_DEFINITIONS = [

            {
                "name": "analyze_ip",
                "description": "Analyze a specific IP address to get detailed threat intelligence",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address to analyze"},
                        "hours": {"type": "number", "description": "Lookback period in hours", "default": 24}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_recent_threats",
                "description": "Get recent security threats from the monitoring system",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "number", "default": 24},
                        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                        "threat_type": {"type": "string"},
                        "limit": {"type": "number", "default": 50}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_sensor_status",
                "description": "Get status of all remote sensors",
                "input_schema": {"type": "object", "properties": {}},
                "scope_required": "read_only"
            },
            {
                "name": "set_config_parameter",
                "description": "Set a configuration parameter (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "parameter_name": {"type": "string"},
                        "value": {"type": "string"},
                        "scope": {"type": "string", "enum": ["global", "sensor"], "default": "global"},
                        "sensor_name": {"type": "string"}
                    },
                    "required": ["parameter_name", "value"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "get_config_parameters",
                "description": "Get all configuration parameters with their values and metadata",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Optional sensor ID to get sensor-specific config"}
                    }
                },
                "scope_required": "read_only"
            },
            # Device Classification Tools
            {
                "name": "get_device_templates",
                "description": "Get all device templates (predefined device types like Camera, Smart TV, Server, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "enum": ["iot", "server", "endpoint", "other"], "description": "Filter by category"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_template_details",
                "description": "Get detailed information about a specific device template including its expected behaviors",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "template_id": {"type": "number", "description": "Template ID to retrieve"}
                    },
                    "required": ["template_id"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_devices",
                "description": "Get all discovered/registered network devices with their classification status",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Filter by sensor ID"},
                        "template_id": {"type": "number", "description": "Filter by template ID"},
                        "include_inactive": {"type": "boolean", "default": False}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_by_ip",
                "description": "Get detailed information about a specific device by its IP address",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"},
                        "sensor_id": {"type": "string", "description": "Sensor ID (optional)"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "touch_device",
                "description": "Update a device's last_seen timestamp to NOW. Useful for manually refreshing devices that receive traffic but don't send much (like Access Points, servers, IoT devices)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device to touch"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "execute"
            },
            {
                "name": "touch_devices_bulk",
                "description": "Update last_seen timestamp for multiple devices at once. Returns count of updated devices",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_addresses": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of IP addresses to touch"
                        }
                    },
                    "required": ["ip_addresses"]
                },
                "scope_required": "execute"
            },
            {
                "name": "get_service_providers",
                "description": "Get all service providers (streaming services, CDN providers, etc.) used for filtering false positives",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "enum": ["streaming", "cdn", "cloud", "social", "gaming", "other"], "description": "Filter by category"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "check_ip_service_provider",
                "description": "Check if an IP address belongs to a known service provider (streaming, CDN, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address to check"},
                        "category": {"type": "string", "description": "Category to check (optional)"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_classification_stats",
                "description": "Get statistics about device classification (total devices, classified vs unclassified, by category)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "assign_device_template",
                "description": "Assign a device template to a device (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "device_id": {"type": "number", "description": "Device ID"},
                        "template_id": {"type": "number", "description": "Template ID to assign"}
                    },
                    "required": ["device_id", "template_id"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "create_service_provider",
                "description": "Create a new service provider entry (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Provider name"},
                        "category": {"type": "string", "enum": ["streaming", "cdn", "cloud", "social", "gaming", "other"]},
                        "ip_ranges": {"type": "array", "items": {"type": "string"}, "description": "List of IP ranges (CIDR notation)"},
                        "description": {"type": "string", "description": "Description of the provider"}
                    },
                    "required": ["name", "category", "ip_ranges"]
                },
                "scope_required": "read_write"
            },
            # Device Discovery Tools
            {
                "name": "get_top_talkers",
                "description": "Get top communicating hosts by traffic volume (bytes/packets). Perfect for finding bandwidth hogs or most active devices.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "number", "description": "Lookback period in hours (default: 24)"},
                        "limit": {"type": "number", "description": "Maximum number of results (default: 10)"},
                        "direction": {"type": "string", "enum": ["inbound", "outbound"], "description": "Filter by traffic direction (optional)"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_traffic_stats",
                "description": "Get traffic statistics for a specific device by IP (ports, protocols, bytes, communication partners)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_classification_hints",
                "description": "Get automatic classification suggestions for a device based on observed traffic patterns",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "create_template_from_device",
                "description": "Create a new device template based on observed behavior of a specific device (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device to learn from"},
                        "template_name": {"type": "string", "description": "Name for the new template"},
                        "category": {"type": "string", "enum": ["iot", "server", "endpoint", "other"]}
                    },
                    "required": ["ip_address", "template_name"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "clone_device_template",
                "description": "Clone an existing device template (including built-in templates) to create an editable copy with customizations",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "template_id": {"type": "number", "description": "ID of the template to clone"},
                        "new_name": {"type": "string", "description": "Name for the cloned template"},
                        "new_description": {"type": "string", "description": "Optional description for the cloned template"}
                    },
                    "required": ["template_id", "new_name"]
                },
                "scope_required": "read_write"
            },
            # Alert Suppression Tools
            {
                "name": "get_alert_suppression_stats",
                "description": "Get statistics about template-based alert suppression (alerts checked, suppressed, rates)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "test_alert_suppression",
                "description": "Test if an alert would be suppressed for a specific device based on its template",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "source_ip": {"type": "string", "description": "Source IP address of the device"},
                        "destination_ip": {"type": "string", "description": "Destination IP address"},
                        "alert_type": {"type": "string", "description": "Alert type (e.g., PORT_SCAN, BEACONING, CONNECTION_FLOOD)"},
                        "destination_port": {"type": "number", "description": "Destination port (optional)"}
                    },
                    "required": ["source_ip", "alert_type"]
                },
                "scope_required": "read_only"
            },
            # Behavior Learning Tools
            {
                "name": "get_device_learning_status",
                "description": "Get the learning status for a device, showing how much traffic has been analyzed and if enough data is available for template generation",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "save_device_learned_behavior",
                "description": "Save the learned behavior profile to the database for a device (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "get_device_learned_behavior",
                "description": "Get the learned behavior profile for a device including typical ports, protocols, destinations, and traffic patterns",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            # TLS Analysis Tools
            {
                "name": "get_tls_metadata",
                "description": "Get recent TLS handshake metadata including JA3 fingerprints, SNI hostnames, and certificate info",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Maximum number of records to return", "default": 100},
                        "ip_filter": {"type": "string", "description": "Filter by IP address (source or destination)"},
                        "sni_filter": {"type": "string", "description": "Filter by SNI hostname (partial match)"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_tls_stats",
                "description": "Get TLS analysis statistics (handshakes analyzed, malicious JA3 detected, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "check_ja3_fingerprint",
                "description": "Check if a JA3 fingerprint is known to be malicious",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ja3_hash": {"type": "string", "description": "JA3 MD5 hash to check"}
                    },
                    "required": ["ja3_hash"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "add_ja3_blacklist",
                "description": "Add a JA3 fingerprint to the malware blacklist (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ja3_hash": {"type": "string", "description": "JA3 MD5 hash to blacklist"},
                        "malware_family": {"type": "string", "description": "Name of malware family"}
                    },
                    "required": ["ja3_hash", "malware_family"]
                },
                "scope_required": "read_write"
            },
            # PCAP Export Tools
            {
                "name": "get_pcap_captures",
                "description": "List all saved PCAP capture files with metadata",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_pcap_stats",
                "description": "Get PCAP exporter statistics (buffer size, captures saved, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "export_flow_pcap",
                "description": "Export packets for a specific network flow to a PCAP file (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "src_ip": {"type": "string", "description": "Source IP address"},
                        "dst_ip": {"type": "string", "description": "Destination IP address"},
                        "dst_port": {"type": "number", "description": "Destination port (optional)"}
                    },
                    "required": ["src_ip", "dst_ip"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "get_packet_buffer_summary",
                "description": "Get summary of packets in the ring buffer (count, time span, protocol breakdown)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "delete_pcap_capture",
                "description": "Delete a PCAP capture file (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string", "description": "Name of the PCAP file to delete"}
                    },
                    "required": ["filename"]
                },
                "scope_required": "read_write"
            },
            # Export Tools
            {
                "name": "export_alerts_csv",
                "description": "Export security alerts to CSV format for reporting or SIEM integration",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Lookback period in hours (default: 24)"},
                        "severity": {"type": "string", "description": "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"},
                        "threat_type": {"type": "string", "description": "Filter by threat type"}
                    }
                },
                "scope_required": "read_only"
            },
            # Memory Management Tools
            {
                "name": "get_memory_status",
                "description": "Get current memory usage of SOC server (system and process RAM, GC stats)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "flush_memory",
                "description": "Trigger emergency memory flush on SOC server (garbage collection + malloc_trim)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "execute"
            },
            # Sensor Command Tools
            {
                "name": "send_sensor_command",
                "description": "Send a command to a remote sensor (restart, update_config, update_whitelist)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Target sensor ID"},
                        "command_type": {"type": "string", "description": "Command: restart, update_config, update_whitelist, run_diagnostics"},
                        "parameters": {"type": "object", "description": "Optional command parameters"}
                    },
                    "required": ["sensor_id", "command_type"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "get_sensor_command_history",
                "description": "Get command history for a sensor",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Sensor ID"},
                        "limit": {"type": "integer", "description": "Maximum number of commands to return (default: 20)"}
                    },
                    "required": ["sensor_id"]
                },
                "scope_required": "read_only"
            },
            # Whitelist Management Tools
            {
                "name": "add_whitelist_entry",
                "description": "Add an IP, CIDR range, or domain to the whitelist with optional direction filtering",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_cidr": {"type": "string", "description": "IP address, CIDR range (e.g., 192.168.1.0/24), or domain"},
                        "description": {"type": "string", "description": "Reason for whitelisting (e.g., 'Office network', 'Trusted partner')"},
                        "scope": {"type": "string", "description": "'global' for all sensors or 'sensor' for specific sensor (default: global)"},
                        "sensor_id": {"type": "string", "description": "Sensor ID (required if scope is 'sensor')"},
                        "direction": {"type": "string", "description": "'source' (when IP is traffic source), 'destination' (when IP is traffic destination), or 'both' (default)"}
                    },
                    "required": ["ip_cidr", "description"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "get_whitelist_entries",
                "description": "Get all whitelist entries or filter by scope/sensor",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "scope": {"type": "string", "description": "Filter by 'global' or 'sensor'"},
                        "sensor_id": {"type": "string", "description": "Filter by sensor ID"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "remove_whitelist_entry",
                "description": "Remove a whitelist entry by ID",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "integer", "description": "Whitelist entry ID to remove"}
                    },
                    "required": ["entry_id"]
                },
                "scope_required": "read_write"
            },
            # AD/Kerberos Attack Detection Tools
            {
                "name": "get_kerberos_stats",
                "description": "Get Kerberos attack detection statistics including Kerberoasting, AS-REP Roasting, and DCSync attempts",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Time window in hours (default: 24)"},
                        "sensor_id": {"type": "string", "description": "Filter by sensor ID"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_kerberos_attacks",
                "description": "Get detailed list of detected Kerberos attacks (Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "attack_type": {"type": "string", "description": "Filter by type: kerberoasting, asrep_roasting, dcsync, pass_the_hash, golden_ticket"},
                        "hours": {"type": "integer", "description": "Time window in hours (default: 24)"},
                        "limit": {"type": "integer", "description": "Maximum results (default: 50)"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "check_weak_encryption",
                "description": "Check for weak Kerberos encryption usage (RC4, DES) in the network",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Time window in hours (default: 24)"}
                    }
                },
                "scope_required": "read_only"
            },
            # Kill Chain Detection Tools
            {
                "name": "get_attack_chains",
                "description": "Get detected multi-stage attack chains with kill chain stage progression",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "min_stages": {"type": "integer", "description": "Minimum stages to include (default: 2)"},
                        "hours": {"type": "integer", "description": "Time window in hours (default: 24)"},
                        "source_ip": {"type": "string", "description": "Filter by source IP"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_mitre_mapping",
                "description": "Get MITRE ATT&CK technique mapping for detected alerts",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Time window in hours (default: 24)"},
                        "tactic": {"type": "string", "description": "Filter by tactic (e.g., 'credential_access', 'lateral_movement')"}
                    }
                },
                "scope_required": "read_only"
            },
            # Risk Scoring Tools
            {
                "name": "get_top_risk_assets",
                "description": "Get assets with highest risk scores based on alert history and asset criticality",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "description": "Number of assets to return (default: 10)"},
                        "min_score": {"type": "number", "description": "Minimum risk score threshold (0-100)"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_asset_risk",
                "description": "Get detailed risk score and contributing factors for a specific IP address",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address to check"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_risk_trends",
                "description": "Get risk score trends over time for top assets",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Time window in hours (default: 24)"},
                        "limit": {"type": "integer", "description": "Number of assets to include (default: 10)"}
                    }
                },
                "scope_required": "read_only"
            },
            # SOAR Tools
            {
                "name": "get_soar_playbooks",
                "description": "Get configured SOAR playbooks and their status",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "enabled_only": {"type": "boolean", "description": "Only show enabled playbooks (default: false)"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_pending_approvals",
                "description": "Get SOAR actions pending manual approval",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "playbook": {"type": "string", "description": "Filter by playbook name"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "approve_soar_action",
                "description": "Approve or reject a pending SOAR action",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action_id": {"type": "integer", "description": "Action ID to approve/reject"},
                        "approved": {"type": "boolean", "description": "True to approve, False to reject"},
                        "reason": {"type": "string", "description": "Reason for approval/rejection"}
                    },
                    "required": ["action_id", "approved"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "get_soar_history",
                "description": "Get history of executed SOAR actions",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Time window in hours (default: 24)"},
                        "playbook": {"type": "string", "description": "Filter by playbook name"},
                        "status": {"type": "string", "description": "Filter by status: executed, pending, rejected, failed"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "check_indicator",
                "description": "Check if an IP, domain, or hash matches any threat feeds",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "indicator": {"type": "string", "description": "IP address, domain, URL, or hash to check"},
                        "indicator_type": {"type": "string", "enum": ["ip", "domain", "url", "hash"]},
                        "feed_types": {"type": "array", "items": {"type": "string"}, "description": "Optional list of feed types to check"}
                    },
                    "required": ["indicator", "indicator_type"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "update_threat_feeds",
                "description": "Manually trigger threat feed updates (normally runs automatically every hour)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "admin"
            },
            # Threat Detection Tools
            {
                "name": "get_threat_feed_stats",
                "description": "Get statistics about threat intelligence feeds (phishing, Tor, cryptomining, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_threat_detections",
                "description": "Get recent threat detections (60+ threat types across 9 phases: Web App Security, DDoS, Ransomware, IoT, OT/ICS, Container, Evasion, Kill Chain)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "number", "default": 24},
                        "threat_type": {
                            "type": "string",
                            "enum": [
                                # Phase 1: Core Advanced Threats
                                "CRYPTOMINING_DETECTED", "PHISHING_DOMAIN_QUERY", "TOR_EXIT_NODE_CONNECTION",
                                "CLOUD_METADATA_ACCESS", "DNS_ANOMALY", "DNS_DGA_DETECTED",
                                # Phase 2: Web Application Security
                                "SQL_INJECTION_ATTEMPT", "XSS_ATTEMPT", "COMMAND_INJECTION_ATTEMPT",
                                "PATH_TRAVERSAL_ATTEMPT", "XXE_ATTEMPT", "SSRF_ATTEMPT",
                                "WEBSHELL_DETECTED", "API_ABUSE_RATE_LIMIT", "API_ABUSE_ENDPOINT",
                                # Phase 3: DDoS & Resource Exhaustion
                                "SYN_FLOOD_ATTACK", "UDP_FLOOD_ATTACK", "HTTP_FLOOD_ATTACK",
                                "SLOWLORIS_ATTACK", "DNS_AMPLIFICATION_ATTACK", "CONNECTION_EXHAUSTION",
                                "BANDWIDTH_SATURATION",
                                # Phase 4: Ransomware Indicators
                                "RANSOMWARE_MASS_ENCRYPTION", "RANSOMWARE_CRYPTO_EXTENSION",
                                "RANSOMWARE_RANSOM_NOTE", "RANSOMWARE_SHADOW_COPY_DELETION",
                                "RANSOMWARE_BACKUP_DELETION",
                                # Phase 5: IoT & Smart Device Security
                                "IOT_BOTNET_ACTIVITY", "UPNP_EXPLOIT_ATTEMPT", "MQTT_ABUSE",
                                # Phase 6: OT/ICS Protocol Security
                                "MODBUS_ATTACK", "DNP3_ATTACK", "IEC104_ATTACK",
                                # Phase 7: Container & Orchestration
                                "DOCKER_ESCAPE_ATTEMPT", "K8S_API_EXPLOIT",
                                # Phase 8: Advanced Evasion
                                "FRAGMENTATION_ATTACK", "PROTOCOL_TUNNELING", "POLYMORPHIC_MALWARE", "DGA_DETECTED",
                                # Phase 9: Completion Boost
                                "LATERAL_MOVEMENT", "DATA_EXFILTRATION", "PRIVILEGE_ESCALATION",
                                "PERSISTENCE_MECHANISM", "CREDENTIAL_DUMPING",
                                # Other common detections
                                "PORT_SCAN", "BRUTE_FORCE_ATTEMPT", "C2_COMMUNICATION",
                                "DNS_TUNNEL_SUSPICIOUS_LENGTH", "DNS_TUNNEL_HIGH_RATE",
                                "ICMP_TUNNEL_HIGH_RATE", "HTTP_EXCESSIVE_POSTS"
                            ]
                        },
                        "limit": {"type": "number", "default": 50}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_threat_config",
                "description": "Get current threat detection configuration (which threats are enabled, thresholds, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Optional sensor ID for sensor-specific config"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "enable_threat_detection",
                "description": "Enable or disable a specific threat detection type (60 total threat types across 9 phases)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "threat_type": {
                            "type": "string",
                            "enum": [
                                # Phase 1: Core Advanced Threats
                                "cryptomining", "phishing", "tor", "vpn", "cloud_metadata", "dns_anomaly",
                                # Phase 2: Web Application Security
                                "sql_injection", "xss", "command_injection", "path_traversal", "xxe", "ssrf", "webshell", "api_abuse",
                                # Phase 3: DDoS & Resource Exhaustion
                                "syn_flood", "udp_flood", "http_flood", "slowloris", "dns_amplification", "ntp_amplification", "connection_exhaustion", "bandwidth_saturation",
                                # Phase 4: Ransomware Indicators
                                "ransomware_smb", "ransomware_crypto_ext", "ransomware_ransom_note", "ransomware_shadow_copy", "ransomware_backup_deletion",
                                # Phase 5: IoT & Smart Device Security
                                "iot_botnet", "upnp_exploit", "mqtt_abuse", "smart_home_abuse", "insecure_rtsp", "coap_abuse", "zwave_attack", "zigbee_attack",
                                # Phase 6: OT/ICS Protocol Security
                                "modbus_attack", "dnp3_attack", "iec104_attack", "bacnet_attack", "profinet_attack", "ethernetip_attack",
                                # Phase 7: Container & Orchestration
                                "docker_escape", "k8s_exploit", "container_registry_poisoning", "privileged_container",
                                # Phase 8: Advanced Evasion
                                "fragmentation_attack", "tunneling", "polymorphic_malware", "dga",
                                # Phase 9: Completion Boost
                                "lateral_movement", "data_exfiltration", "privilege_escalation", "persistence", "credential_dumping",
                                "lolbins", "memory_injection", "process_hollowing", "registry_manipulation", "scheduled_task_abuse"
                            ]
                        },
                        "enabled": {"type": "boolean"},
                        "sensor_id": {"type": "string", "description": "Optional sensor ID for sensor-specific config"}
                    },
                    "required": ["threat_type", "enabled"]
                },
                "scope_required": "read_write"
            }
        ]

# Verify tool count
if __name__ == "__main__":
    print(f"Loaded {len(TOOL_DEFINITIONS)} tool definitions")
    print(f"Tool names: {[t['name'] for t in TOOL_DEFINITIONS]}")
