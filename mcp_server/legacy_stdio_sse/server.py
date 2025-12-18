#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
NetMonitor MCP Server

Provides AI assistants with read-only access to security monitoring data
through the Model Context Protocol (MCP).

Supports two transport modes:
  - stdio: Local process communication (for testing)
  - sse: HTTP Server-Sent Events (for network access)
"""

import os
import sys
import logging
import json
import csv
import io
import socket
import argparse
import asyncio
import yaml
from datetime import datetime
from typing import Any, Sequence
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server import Server, NotificationOptions
from mcp.server.stdio import stdio_server
from mcp.server.models import InitializationOptions
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)

# SSE imports (optional, only needed for network mode)
try:
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.responses import Response
    from sse_starlette.sse import EventSourceResponse
    import uvicorn
    SSE_AVAILABLE = True
except ImportError:
    SSE_AVAILABLE = False

import psycopg2
import psycopg2.extras

from database_client import MCPDatabaseClient
from geoip_helper import get_country_for_ip, is_private_ip
from ollama_client import OllamaClient

# Try to load .env file
try:
    from env_loader import get_db_config, load_env_into_environ
    # Load .env into os.environ for easy access
    load_env_into_environ()
    _env_available = True
except ImportError:
    _env_available = False


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/mcp_netmonitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NetMonitor.MCP')


class NetMonitorMCPServer:
    """MCP Server for NetMonitor SOC"""

    def __init__(self):
        """Initialize MCP server"""
        self.server = Server("netmonitor-soc")
        self.db = None
        self.ollama = None

        # Connect to database
        self._connect_database()

        # Initialize Ollama client (optional, may not be available)
        self._initialize_ollama()

        # Register handlers
        self._register_handlers()

        logger.info("NetMonitor MCP Server initialized")

    def _connect_database(self):
        """Connect to PostgreSQL database"""
        try:
            host = os.environ.get('NETMONITOR_DB_HOST', 'localhost')
            port = int(os.environ.get('NETMONITOR_DB_PORT', '5432'))
            database = os.environ.get('NETMONITOR_DB_NAME', 'netmonitor')
            user = os.environ.get('NETMONITOR_DB_USER', 'mcp_readonly')
            # Support both NETMONITOR_DB_PASSWORD and DB_PASSWORD (.env uses DB_PASSWORD)
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'mcp_netmonitor_readonly_2024'))

            self.db = MCPDatabaseClient(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )

            logger.info(f"Connected to database: {database}@{host}")

        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def _initialize_ollama(self):
        """Initialize Ollama client (optional)"""
        try:
            # Get Ollama configuration from environment
            ollama_url = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434')
            ollama_model = os.environ.get('OLLAMA_MODEL', 'llama3.2')

            self.ollama = OllamaClient(base_url=ollama_url, model=ollama_model)

            if self.ollama.available:
                logger.info(f"Ollama initialized: {ollama_model} at {ollama_url}")
            else:
                logger.warning("Ollama not available - AI analysis tools will be disabled")

        except Exception as e:
            logger.warning(f"Failed to initialize Ollama: {e}")
            self.ollama = None

    def _register_handlers(self):
        """Register MCP protocol handlers"""

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """List available resources"""
            return [
                Resource(
                    uri="dashboard://summary",
                    name="Dashboard Summary",
                    mimeType="text/plain",
                    description="Real-time security dashboard overview with statistics and top threats"
                )
            ]

        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read a resource"""
            if uri == "dashboard://summary":
                return await self._get_dashboard_summary()
            else:
                raise ValueError(f"Unknown resource: {uri}")

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available tools"""
            return [
                Tool(
                    name="analyze_ip",
                    description="Analyze a specific IP address to get detailed threat intelligence",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip_address": {
                                "type": "string",
                                "description": "IP address to analyze (e.g., '192.168.1.50' or '185.220.101.50')"
                            },
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            }
                        },
                        "required": ["ip_address"]
                    }
                ),
                Tool(
                    name="get_recent_threats",
                    description="Get recent security threats from the monitoring system",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            },
                            "severity": {
                                "type": "string",
                                "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO",
                                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                            },
                            "threat_type": {
                                "type": "string",
                                "description": "Filter by threat type: PORT_SCAN, BEACONING_DETECTED, CONNECTION_FLOOD, etc."
                            },
                            "limit": {
                                "type": "number",
                                "description": "Maximum number of results (default: 50)",
                                "default": 50
                            }
                        }
                    }
                ),
                Tool(
                    name="get_threat_timeline",
                    description="Get chronological timeline of threats for attack chain analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "source_ip": {
                                "type": "string",
                                "description": "Filter by source IP address (optional)"
                            },
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            }
                        }
                    }
                ),
                # ==================== Statistics Tools ====================
                Tool(
                    name="get_traffic_trends",
                    description="Get network traffic trends over time for capacity planning and trend analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            },
                            "interval": {
                                "type": "string",
                                "description": "Time aggregation interval: 'hourly' or 'daily' (default: hourly)",
                                "enum": ["hourly", "daily"],
                                "default": "hourly"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_top_talkers_stats",
                    description="Get top communicating hosts with bandwidth statistics for identifying bandwidth hogs",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            },
                            "limit": {
                                "type": "number",
                                "description": "Maximum number of results (default: 20)",
                                "default": 20
                            },
                            "direction": {
                                "type": "string",
                                "description": "Filter by direction: 'inbound' or 'outbound' (optional)",
                                "enum": ["inbound", "outbound"]
                            }
                        }
                    }
                ),
                Tool(
                    name="get_alert_statistics",
                    description="Get alert statistics and trends for security posture overview and reporting",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            },
                            "group_by": {
                                "type": "string",
                                "description": "Group statistics by: 'severity', 'threat_type', or 'hour' (default: severity)",
                                "enum": ["severity", "threat_type", "hour"],
                                "default": "severity"
                            }
                        }
                    }
                ),
                # ==================== Export Tools ====================
                Tool(
                    name="export_alerts_csv",
                    description="Export security alerts to CSV format for periodic reporting",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            },
                            "severity": {
                                "type": "string",
                                "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO",
                                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                            },
                            "threat_type": {
                                "type": "string",
                                "description": "Filter by threat type (optional)"
                            }
                        }
                    }
                ),
                Tool(
                    name="export_traffic_stats_csv",
                    description="Export traffic statistics to CSV for capacity planning and trend analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 168 = 1 week)",
                                "default": 168
                            },
                            "interval": {
                                "type": "string",
                                "description": "Time aggregation: 'hourly' or 'daily' (default: daily)",
                                "enum": ["hourly", "daily"],
                                "default": "daily"
                            }
                        }
                    }
                ),
                Tool(
                    name="export_top_talkers_csv",
                    description="Export top communicating hosts to CSV for bandwidth analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            },
                            "limit": {
                                "type": "number",
                                "description": "Maximum number of results (default: 50)",
                                "default": 50
                            },
                            "direction": {
                                "type": "string",
                                "description": "Filter by direction: 'inbound' or 'outbound'",
                                "enum": ["inbound", "outbound"]
                            }
                        }
                    }
                ),
                # ==================== Configuration Tools ====================
                Tool(
                    name="get_config",
                    description="Get current NetMonitor configuration settings",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "section": {
                                "type": "string",
                                "description": "Config section: 'thresholds', 'alerts', 'threat_feeds', or 'all' (default: all)",
                                "enum": ["thresholds", "alerts", "threat_feeds", "all"],
                                "default": "all"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_detection_rules",
                    description="List all active detection rules with their current settings",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                # ==================== Ollama AI Tools ====================
                Tool(
                    name="analyze_threat_with_ollama",
                    description="Use local Ollama AI to analyze a security threat and provide detailed assessment",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "alert_id": {
                                "type": "number",
                                "description": "Alert ID to analyze (get from other tools first)"
                            }
                        },
                        "required": ["alert_id"]
                    }
                ),
                Tool(
                    name="suggest_incident_response",
                    description="Use Ollama AI to generate incident response recommendations following NIST framework",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "alert_id": {
                                "type": "number",
                                "description": "Alert ID for incident response planning"
                            },
                            "context": {
                                "type": "string",
                                "description": "Additional context for response planning (optional)"
                            }
                        },
                        "required": ["alert_id"]
                    }
                ),
                Tool(
                    name="explain_ioc",
                    description="Use Ollama AI to explain an Indicator of Compromise (IOC) in simple, non-technical language",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ioc": {
                                "type": "string",
                                "description": "The IOC value (IP address, domain, hash, URL)"
                            },
                            "ioc_type": {
                                "type": "string",
                                "description": "Type of IOC",
                                "enum": ["ip", "domain", "hash", "url"],
                                "default": "ip"
                            }
                        },
                        "required": ["ioc"]
                    }
                ),
                Tool(
                    name="get_ollama_status",
                    description="Check Ollama availability and list available AI models",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                # ==================== Configuration Modification Tools ====================
                Tool(
                    name="update_threshold",
                    description="Update a detection threshold setting (WRITE operation - modifies config.yaml)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detection_type": {
                                "type": "string",
                                "description": "Detection type to modify",
                                "enum": ["port_scan", "connection_flood", "packet_size", "dns_tunnel",
                                        "beaconing", "outbound_volume", "lateral_movement"]
                            },
                            "setting": {
                                "type": "string",
                                "description": "Setting to modify (e.g., 'unique_ports', 'connections_per_second', 'threshold_mb')"
                            },
                            "value": {
                                "description": "New value (number or boolean)"
                            }
                        },
                        "required": ["detection_type", "setting", "value"]
                    }
                ),
                Tool(
                    name="toggle_detection_rule",
                    description="Enable or disable a detection rule (WRITE operation - modifies config.yaml)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detection_type": {
                                "type": "string",
                                "description": "Detection type to enable/disable",
                                "enum": ["port_scan", "connection_flood", "packet_size", "dns_tunnel",
                                        "beaconing", "outbound_volume", "lateral_movement"]
                            },
                            "enabled": {
                                "type": "boolean",
                                "description": "True to enable, False to disable"
                            }
                        },
                        "required": ["detection_type", "enabled"]
                    }
                ),
                # ==================== Sensor Management Tools ====================
                Tool(
                    name="get_sensor_status",
                    description="Get status of all remote sensors including health metrics and alert counts",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "status_filter": {
                                "type": "string",
                                "description": "Filter by status: 'online', 'warning', or 'offline' (optional)",
                                "enum": ["online", "warning", "offline"]
                            }
                        }
                    }
                ),
                Tool(
                    name="get_sensor_details",
                    description="Get detailed information about a specific sensor",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sensor_id": {
                                "type": "string",
                                "description": "Sensor ID to query"
                            }
                        },
                        "required": ["sensor_id"]
                    }
                ),
                Tool(
                    name="send_sensor_command",
                    description="Send a command to a remote sensor (WRITE operation)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sensor_id": {
                                "type": "string",
                                "description": "Target sensor ID"
                            },
                            "command_type": {
                                "type": "string",
                                "description": "Command to execute",
                                "enum": ["restart", "change_interval", "get_status", "flush_buffer", "update_config"]
                            },
                            "parameters": {
                                "type": "object",
                                "description": "Command parameters (e.g., {'interval': 60} for change_interval)"
                            }
                        },
                        "required": ["sensor_id", "command_type"]
                    }
                ),
                Tool(
                    name="get_sensor_alerts",
                    description="Get alerts from a specific sensor",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sensor_id": {
                                "type": "string",
                                "description": "Sensor ID to query"
                            },
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours (default: 24)",
                                "default": 24
                            },
                            "limit": {
                                "type": "number",
                                "description": "Maximum number of alerts (default: 50)",
                                "default": 50
                            }
                        },
                        "required": ["sensor_id"]
                    }
                ),
                Tool(
                    name="get_sensor_command_history",
                    description="Get command execution history for a sensor",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sensor_id": {
                                "type": "string",
                                "description": "Sensor ID to query"
                            },
                            "limit": {
                                "type": "number",
                                "description": "Maximum number of commands (default: 20)",
                                "default": 20
                            }
                        },
                        "required": ["sensor_id"]
                    }
                ),
                Tool(
                    name="get_bandwidth_summary",
                    description="Get bandwidth usage summary for all sensors with trend analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "number",
                                "description": "Lookback period in hours for trend analysis (default: 24)",
                                "default": 24
                            }
                        }
                    }
                ),
                # ==================== Configuration Management Tools (Database-backed) ====================
                Tool(
                    name="set_config_parameter",
                    description="Set configuration parameter in database (global or per-sensor)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "parameter_path": {
                                "type": "string",
                                "description": "Parameter path (e.g., 'detection.dns_tunnel.queries_per_minute')"
                            },
                            "value": {
                                "description": "Parameter value (auto-typed: bool/int/float/str)"
                            },
                            "sensor_id": {
                                "type": "string",
                                "description": "Sensor ID for sensor-specific config (omit for global)"
                            },
                            "scope": {
                                "type": "string",
                                "description": "Scope: 'global' or 'sensor'",
                                "enum": ["global", "sensor"],
                                "default": "global"
                            }
                        },
                        "required": ["parameter_path", "value"]
                    }
                ),
                Tool(
                    name="get_config_parameters",
                    description="Get all configuration parameters with metadata",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sensor_id": {
                                "type": "string",
                                "description": "Sensor ID to get sensor-specific config"
                            }
                        }
                    }
                ),
                Tool(
                    name="reset_config_to_defaults",
                    description="Reset configuration to best practice defaults (requires confirmation)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sensor_id": {
                                "type": "string",
                                "description": "Sensor ID to reset (omit for global reset)"
                            },
                            "confirm": {
                                "type": "boolean",
                                "description": "Must be true to confirm reset",
                                "default": False
                            }
                        },
                        "required": ["confirm"]
                    }
                ),

                # ==================== Whitelist Management Tools ====================
                Tool(
                    name="add_whitelist_entry",
                    description="Add an IP, CIDR range, or domain to the whitelist",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip_cidr": {
                                "type": "string",
                                "description": "IP address, CIDR range (e.g., 192.168.1.0/24), or domain"
                            },
                            "description": {
                                "type": "string",
                                "description": "Description/reason for whitelisting (e.g., 'Office network', 'Sonos speakers')"
                            },
                            "scope": {
                                "type": "string",
                                "enum": ["global", "sensor"],
                                "description": "Whitelist scope: 'global' for all sensors or 'sensor' for specific sensor",
                                "default": "global"
                            },
                            "sensor_id": {
                                "type": "string",
                                "description": "Sensor ID (required if scope is 'sensor')"
                            }
                        },
                        "required": ["ip_cidr", "description"]
                    }
                ),
                Tool(
                    name="get_whitelist_entries",
                    description="Get all whitelist entries or filter by scope/sensor",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scope": {
                                "type": "string",
                                "enum": ["global", "sensor"],
                                "description": "Filter by scope"
                            },
                            "sensor_id": {
                                "type": "string",
                                "description": "Filter by sensor ID"
                            }
                        }
                    }
                ),
                Tool(
                    name="remove_whitelist_entry",
                    description="Remove a whitelist entry by ID",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entry_id": {
                                "type": "integer",
                                "description": "Whitelist entry ID to remove"
                            }
                        },
                        "required": ["entry_id"]
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
            """Call a tool"""
            try:
                # Threat Analysis Tools
                if name == "analyze_ip":
                    result = await self._analyze_ip(**arguments)
                elif name == "get_recent_threats":
                    result = await self._get_recent_threats(**arguments)
                elif name == "get_threat_timeline":
                    result = await self._get_threat_timeline(**arguments)

                # Statistics Tools
                elif name == "get_traffic_trends":
                    result = await self._get_traffic_trends(**arguments)
                elif name == "get_top_talkers_stats":
                    result = await self._get_top_talkers_stats(**arguments)
                elif name == "get_alert_statistics":
                    result = await self._get_alert_statistics(**arguments)

                # Export Tools
                elif name == "export_alerts_csv":
                    result = await self._export_alerts_csv(**arguments)
                elif name == "export_traffic_stats_csv":
                    result = await self._export_traffic_stats_csv(**arguments)
                elif name == "export_top_talkers_csv":
                    result = await self._export_top_talkers_csv(**arguments)

                # Configuration Tools
                elif name == "get_config":
                    result = await self._get_config(**arguments)
                elif name == "get_detection_rules":
                    result = await self._get_detection_rules(**arguments)

                # Ollama AI Tools
                elif name == "analyze_threat_with_ollama":
                    result = await self._analyze_threat_with_ollama(**arguments)
                elif name == "suggest_incident_response":
                    result = await self._suggest_incident_response(**arguments)
                elif name == "explain_ioc":
                    result = await self._explain_ioc(**arguments)
                elif name == "get_ollama_status":
                    result = await self._get_ollama_status(**arguments)

                # Configuration Modification Tools
                elif name == "update_threshold":
                    result = await self._update_threshold(**arguments)
                elif name == "toggle_detection_rule":
                    result = await self._toggle_detection_rule(**arguments)

                # Sensor Management Tools
                elif name == "get_sensor_status":
                    result = await self._get_sensor_status(**arguments)
                elif name == "get_sensor_details":
                    result = await self._get_sensor_details(**arguments)
                elif name == "send_sensor_command":
                    result = await self._send_sensor_command(**arguments)
                elif name == "get_sensor_alerts":
                    result = await self._get_sensor_alerts(**arguments)
                elif name == "get_sensor_command_history":
                    result = await self._get_sensor_command_history(**arguments)
                elif name == "get_bandwidth_summary":
                    result = await self._get_bandwidth_summary(**arguments)

                # Configuration Management Tools
                elif name == "set_config_parameter":
                    result = await self._set_config_parameter(**arguments)
                elif name == "get_config_parameters":
                    result = await self._get_config_parameters(**arguments)
                elif name == "reset_config_to_defaults":
                    result = await self._reset_config_to_defaults(**arguments)

                # Whitelist Management Tools
                elif name == "add_whitelist_entry":
                    result = await self._add_whitelist_entry(**arguments)
                elif name == "get_whitelist_entries":
                    result = await self._get_whitelist_entries(**arguments)
                elif name == "remove_whitelist_entry":
                    result = await self._remove_whitelist_entry(**arguments)

                else:
                    raise ValueError(f"Unknown tool: {name}")

                return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

            except Exception as e:
                logger.error(f"Error calling tool {name}: {e}", exc_info=True)
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    # ==================== Tool Implementations ====================

    async def _analyze_ip(self, ip_address: str, hours: int = 24) -> dict:
        """
        Analyze a specific IP address

        Args:
            ip_address: IP address to analyze
            hours: Lookback period in hours

        Returns:
            Detailed analysis of the IP
        """
        logger.info(f"Analyzing IP: {ip_address} (lookback: {hours}h)")

        # Get all alerts for this IP
        alerts = self.db.get_alerts_by_ip(ip_address, hours)

        # Get geolocation
        country = get_country_for_ip(ip_address)

        # Determine if internal
        internal = is_private_ip(ip_address)

        # Try hostname resolution
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except:
            pass

        # Analyze alerts
        threat_types = list(set(a['threat_type'] for a in alerts))
        severity_breakdown = {}
        for alert in alerts:
            sev = alert['severity']
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        # Calculate threat score (0-100)
        threat_score = min(100, len(alerts) * 5)  # Simple scoring
        if any(a['severity'] == 'CRITICAL' for a in alerts):
            threat_score = min(100, threat_score + 30)

        # Generate recommendation
        if threat_score >= 80:
            recommendation = "URGENT: Block this IP immediately and investigate affected systems"
        elif threat_score >= 50:
            recommendation = "HIGH PRIORITY: Monitor closely and consider blocking"
        elif threat_score >= 20:
            recommendation = "MEDIUM: Keep monitoring, may be reconnaissance"
        else:
            recommendation = "LOW: Continue monitoring"

        return {
            "ip_address": ip_address,
            "hostname": hostname,
            "country": country,
            "is_internal": internal,
            "analysis_period_hours": hours,
            "alert_count": len(alerts),
            "threat_types": threat_types,
            "severity_breakdown": severity_breakdown,
            "first_seen": alerts[-1]['timestamp'] if alerts else None,
            "last_seen": alerts[0]['timestamp'] if alerts else None,
            "threat_score": threat_score,
            "risk_level": "CRITICAL" if threat_score >= 80 else "HIGH" if threat_score >= 50 else "MEDIUM" if threat_score >= 20 else "LOW",
            "recommendation": recommendation,
            "recent_alerts": alerts[:5]  # Include 5 most recent
        }

    async def _get_recent_threats(self, hours: int = 24, severity: str = None,
                                  threat_type: str = None, limit: int = 50) -> dict:
        """
        Get recent security threats

        Args:
            hours: Lookback period in hours
            severity: Filter by severity (optional)
            threat_type: Filter by threat type (optional)
            limit: Maximum number of results

        Returns:
            Recent threats with statistics
        """
        logger.info(f"Getting recent threats (hours={hours}, severity={severity}, type={threat_type}, limit={limit})")

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
            if alert['source_ip']:
                unique_sources.add(alert['source_ip'])

        return {
            "total_alerts": total,
            "analysis_period_hours": hours,
            "filters_applied": {
                "severity": severity,
                "threat_type": threat_type,
                "limit": limit
            },
            "statistics": {
                "by_severity": by_severity,
                "by_type": by_type,
                "unique_source_ips": len(unique_sources)
            },
            "alerts": alerts
        }

    async def _get_threat_timeline(self, source_ip: str = None, hours: int = 24) -> dict:
        """
        Get chronological timeline of threats

        Args:
            source_ip: Filter by source IP (optional)
            hours: Lookback period in hours

        Returns:
            Chronological threat timeline for attack chain analysis
        """
        logger.info(f"Getting threat timeline (source_ip={source_ip}, hours={hours})")

        alerts = self.db.get_threat_timeline(source_ip=source_ip, hours=hours)

        # Build timeline with phases
        timeline = []
        for i, alert in enumerate(alerts):
            timeline_entry = {
                "sequence": i + 1,
                "timestamp": alert['timestamp'],
                "threat_type": alert['threat_type'],
                "severity": alert['severity'],
                "source_ip": alert['source_ip'],
                "destination_ip": alert['destination_ip'],
                "description": alert['description']
            }

            # Try to parse metadata for additional details
            if alert['metadata']:
                try:
                    metadata = json.loads(alert['metadata'])
                    timeline_entry['details'] = metadata
                except:
                    pass

            timeline.append(timeline_entry)

        # Identify attack phases
        attack_phases = self._identify_attack_phases(timeline)

        return {
            "total_events": len(timeline),
            "analysis_period_hours": hours,
            "source_ip_filter": source_ip,
            "timeline": timeline,
            "attack_phases": attack_phases,
            "summary": self._generate_timeline_summary(timeline)
        }

    def _identify_attack_phases(self, timeline: list) -> dict:
        """Identify attack phases from timeline"""
        phases = {
            "reconnaissance": [],
            "exploitation": [],
            "persistence": [],
            "lateral_movement": [],
            "exfiltration": []
        }

        for event in timeline:
            threat_type = event['threat_type']

            if threat_type in ['PORT_SCAN', 'DNS_TUNNELING']:
                phases['reconnaissance'].append(event['sequence'])
            elif threat_type in ['CONNECTION_FLOOD', 'LARGE_PACKET']:
                phases['exploitation'].append(event['sequence'])
            elif threat_type in ['BEACONING_DETECTED']:
                phases['persistence'].append(event['sequence'])
            elif threat_type in ['LATERAL_MOVEMENT']:
                phases['lateral_movement'].append(event['sequence'])
            elif threat_type in ['HIGH_OUTBOUND_VOLUME']:
                phases['exfiltration'].append(event['sequence'])

        return {k: v for k, v in phases.items() if v}  # Only return non-empty phases

    def _generate_timeline_summary(self, timeline: list) -> str:
        """Generate human-readable summary of timeline"""
        if not timeline:
            return "No events in timeline"

        summary_parts = []
        summary_parts.append(f"Timeline contains {len(timeline)} events")

        if timeline:
            summary_parts.append(f"First event: {timeline[0]['threat_type']} at {timeline[0]['timestamp']}")
            summary_parts.append(f"Latest event: {timeline[-1]['threat_type']} at {timeline[-1]['timestamp']}")

        return ". ".join(summary_parts)

    # ==================== Statistics Tool Implementations ====================

    async def _get_traffic_trends(self, hours: int = 24, interval: str = 'hourly') -> dict:
        """
        Get network traffic trends over time

        Args:
            hours: Lookback period in hours
            interval: 'hourly' or 'daily' aggregation

        Returns:
            Traffic trends data
        """
        logger.info(f"Getting traffic trends (hours={hours}, interval={interval})")

        trends = self.db.get_traffic_trends(hours=hours, interval=interval)

        # Calculate summary statistics
        if trends:
            total_bytes = sum(t['total_bytes'] or 0 for t in trends)
            total_packets = sum(t['total_packets'] or 0 for t in trends)
            avg_bytes = sum(t['avg_bytes'] or 0 for t in trends) / len(trends)
            avg_packets = sum(t['avg_packets'] or 0 for t in trends) / len(trends)
        else:
            total_bytes = total_packets = avg_bytes = avg_packets = 0

        return {
            "analysis_period_hours": hours,
            "interval": interval,
            "data_points": len(trends),
            "summary": {
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "average_bytes_per_period": int(avg_bytes),
                "average_packets_per_period": int(avg_packets),
                "total_bytes_gb": round(total_bytes / (1024**3), 2),
                "total_bytes_mb": round(total_bytes / (1024**2), 2)
            },
            "trends": trends
        }

    async def _get_top_talkers_stats(self, hours: int = 24, limit: int = 20,
                                     direction: str = None) -> dict:
        """
        Get top communicating hosts with statistics

        Args:
            hours: Lookback period in hours
            limit: Maximum number of results
            direction: Filter by 'inbound' or 'outbound'

        Returns:
            Top talkers data
        """
        logger.info(f"Getting top talkers stats (hours={hours}, limit={limit}, direction={direction})")

        talkers = self.db.get_top_talkers_stats(hours=hours, limit=limit, direction=direction)

        # Calculate summary
        total_bytes = sum(t['total_bytes'] or 0 for t in talkers)
        total_packets = sum(t['total_packets'] or 0 for t in talkers)

        return {
            "analysis_period_hours": hours,
            "filters": {
                "limit": limit,
                "direction": direction
            },
            "total_hosts": len(talkers),
            "summary": {
                "combined_total_bytes": total_bytes,
                "combined_total_packets": total_packets,
                "combined_total_gb": round(total_bytes / (1024**3), 2),
                "combined_total_mb": round(total_bytes / (1024**2), 2)
            },
            "top_talkers": talkers
        }

    async def _get_alert_statistics(self, hours: int = 24, group_by: str = 'severity') -> dict:
        """
        Get alert statistics grouped by specified field

        Args:
            hours: Lookback period in hours
            group_by: Group by 'severity', 'threat_type', or 'hour'

        Returns:
            Alert statistics
        """
        logger.info(f"Getting alert statistics (hours={hours}, group_by={group_by})")

        stats = self.db.get_alert_statistics(hours=hours, group_by=group_by)

        # Add analysis
        if stats['data']:
            most_common = max(stats['data'], key=lambda x: x['count'])
            stats['insights'] = {
                'most_common_category': most_common.get('category') or most_common.get('time_period'),
                'most_common_count': most_common['count']
            }

        return stats

    # ==================== Export Tool Implementations ====================

    async def _export_alerts_csv(self, hours: int = 24, severity: str = None,
                                 threat_type: str = None) -> dict:
        """
        Export security alerts to CSV format

        Args:
            hours: Lookback period in hours
            severity: Filter by severity (optional)
            threat_type: Filter by threat type (optional)

        Returns:
            CSV data as string
        """
        logger.info(f"Exporting alerts to CSV (hours={hours}, severity={severity}, threat_type={threat_type})")

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
        writer.writerow(['Timestamp', 'Severity', 'Threat Type', 'Source IP', 'Destination IP', 'Description', 'Acknowledged'])

        # Write data
        for alert in alerts:
            writer.writerow([
                alert['timestamp'],
                alert['severity'],
                alert['threat_type'],
                alert.get('source_ip', ''),
                alert.get('destination_ip', ''),
                alert.get('description', ''),
                'Yes' if alert.get('acknowledged') else 'No'
            ])

        csv_data = output.getvalue()
        output.close()

        return {
            "format": "csv",
            "rows": len(alerts),
            "filters": {
                "hours": hours,
                "severity": severity,
                "threat_type": threat_type
            },
            "csv_data": csv_data
        }

    async def _export_traffic_stats_csv(self, hours: int = 168, interval: str = 'daily') -> dict:
        """
        Export traffic statistics to CSV

        Args:
            hours: Lookback period in hours
            interval: 'hourly' or 'daily' aggregation

        Returns:
            CSV data as string
        """
        logger.info(f"Exporting traffic stats to CSV (hours={hours}, interval={interval})")

        trends = self.db.get_traffic_trends(hours=hours, interval=interval)

        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['Time Period', 'Total Packets', 'Total Bytes', 'Inbound Packets', 'Inbound Bytes',
                        'Outbound Packets', 'Outbound Bytes', 'Avg Packets', 'Avg Bytes'])

        # Write data
        for trend in trends:
            writer.writerow([
                trend['time_period'],
                trend['total_packets'],
                trend['total_bytes'],
                trend['inbound_packets'],
                trend['inbound_bytes'],
                trend['outbound_packets'],
                trend['outbound_bytes'],
                int(trend['avg_packets']) if trend['avg_packets'] else 0,
                int(trend['avg_bytes']) if trend['avg_bytes'] else 0
            ])

        csv_data = output.getvalue()
        output.close()

        return {
            "format": "csv",
            "rows": len(trends),
            "interval": interval,
            "analysis_period_hours": hours,
            "csv_data": csv_data
        }

    async def _export_top_talkers_csv(self, hours: int = 24, limit: int = 50,
                                      direction: str = None) -> dict:
        """
        Export top communicating hosts to CSV

        Args:
            hours: Lookback period in hours
            limit: Maximum number of results
            direction: Filter by direction (optional)

        Returns:
            CSV data as string
        """
        logger.info(f"Exporting top talkers to CSV (hours={hours}, limit={limit}, direction={direction})")

        talkers = self.db.get_top_talkers_stats(hours=hours, limit=limit, direction=direction)

        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['IP Address', 'Hostname', 'Direction', 'Total Packets', 'Total Bytes',
                        'Total MB', 'Total GB', 'Observations', 'First Seen', 'Last Seen'])

        # Write data
        for talker in talkers:
            writer.writerow([
                talker['ip_address'],
                talker.get('hostname', ''),
                talker['direction'],
                talker['total_packets'],
                talker['total_bytes'],
                round(talker['total_bytes'] / (1024**2), 2),
                round(talker['total_bytes'] / (1024**3), 2),
                talker['observation_count'],
                talker['first_seen'],
                talker['last_seen']
            ])

        csv_data = output.getvalue()
        output.close()

        return {
            "format": "csv",
            "rows": len(talkers),
            "filters": {
                "hours": hours,
                "limit": limit,
                "direction": direction
            },
            "csv_data": csv_data
        }

    # ==================== Configuration Tool Implementations ====================

    async def _get_config(self, section: str = 'all') -> dict:
        """
        Get current NetMonitor configuration

        Args:
            section: Config section to retrieve

        Returns:
            Configuration data
        """
        logger.info(f"Getting config (section={section})")

        # Load config from file
        config_path = Path(__file__).parent.parent / 'config.yaml'

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            if section == 'all':
                return config
            elif section in config:
                return {section: config[section]}
            else:
                return {"error": f"Section '{section}' not found in configuration"}

        except Exception as e:
            logger.error(f"Error reading config: {e}")
            return {"error": str(e)}

    async def _get_detection_rules(self) -> dict:
        """
        List all active detection rules with current settings

        Returns:
            Detection rules overview
        """
        logger.info("Getting detection rules")

        # Load config to get thresholds
        config_path = Path(__file__).parent.parent / 'config.yaml'

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            thresholds = config.get('thresholds', {})

            # Format detection rules
            rules = []
            for detection_type, settings in thresholds.items():
                rule = {
                    "detection_type": detection_type,
                    "enabled": settings.get('enabled', False),
                    "settings": {k: v for k, v in settings.items() if k != 'enabled'}
                }
                rules.append(rule)

            return {
                "total_rules": len(rules),
                "active_rules": sum(1 for r in rules if r['enabled']),
                "rules": rules
            }

        except Exception as e:
            logger.error(f"Error getting detection rules: {e}")
            return {"error": str(e)}

    # ==================== Ollama AI Tool Implementations ====================

    async def _analyze_threat_with_ollama(self, alert_id: int) -> dict:
        """
        Analyze a security threat using Ollama AI

        Args:
            alert_id: Alert ID to analyze

        Returns:
            AI analysis of the threat
        """
        logger.info(f"Analyzing threat with Ollama (alert_id={alert_id})")

        # Check if Ollama is available
        if not self.ollama or not self.ollama.available:
            return {
                "error": "Ollama is not available",
                "message": "Please install and start Ollama: https://ollama.ai",
                "available": False
            }

        # Get alert from database
        try:
            cursor = self.db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('''
                SELECT
                    id,
                    timestamp,
                    severity,
                    threat_type,
                    source_ip::text as source_ip,
                    destination_ip::text as destination_ip,
                    description,
                    metadata
                FROM alerts
                WHERE id = %s
            ''', (alert_id,))

            alert = cursor.fetchone()

            if not alert:
                return {"error": f"Alert ID {alert_id} not found"}

            # Convert to dict for Ollama
            alert_dict = dict(alert)

            # Analyze with Ollama
            result = self.ollama.analyze_threat(alert_dict)

            return {
                "alert_id": alert_id,
                "alert": alert_dict,
                "ai_analysis": result,
                "ollama_model": result.get("model"),
                "success": result.get("success", False)
            }

        except Exception as e:
            logger.error(f"Error analyzing threat with Ollama: {e}")
            return {"error": str(e)}

    async def _suggest_incident_response(self, alert_id: int, context: str = None) -> dict:
        """
        Generate incident response recommendations using Ollama AI

        Args:
            alert_id: Alert ID for incident response planning
            context: Additional context (optional)

        Returns:
            Incident response recommendations
        """
        logger.info(f"Generating incident response with Ollama (alert_id={alert_id})")

        # Check if Ollama is available
        if not self.ollama or not self.ollama.available:
            return {
                "error": "Ollama is not available",
                "message": "Please install and start Ollama: https://ollama.ai",
                "available": False
            }

        # Get alert from database
        try:
            cursor = self.db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('''
                SELECT
                    id,
                    timestamp,
                    severity,
                    threat_type,
                    source_ip::text as source_ip,
                    destination_ip::text as destination_ip,
                    description,
                    metadata
                FROM alerts
                WHERE id = %s
            ''', (alert_id,))

            alert = cursor.fetchone()

            if not alert:
                return {"error": f"Alert ID {alert_id} not found"}

            # Convert to dict for Ollama
            alert_dict = dict(alert)

            # Generate response plan with Ollama
            result = self.ollama.suggest_incident_response(alert_dict, context=context)

            return {
                "alert_id": alert_id,
                "alert": alert_dict,
                "context": context,
                "incident_response": result,
                "ollama_model": result.get("model"),
                "success": result.get("success", False)
            }

        except Exception as e:
            logger.error(f"Error generating incident response with Ollama: {e}")
            return {"error": str(e)}

    async def _explain_ioc(self, ioc: str, ioc_type: str = "ip") -> dict:
        """
        Explain an Indicator of Compromise using Ollama AI

        Args:
            ioc: The IOC value
            ioc_type: Type of IOC (ip, domain, hash, url)

        Returns:
            Simple explanation of the IOC
        """
        logger.info(f"Explaining IOC with Ollama (ioc={ioc}, type={ioc_type})")

        # Check if Ollama is available
        if not self.ollama or not self.ollama.available:
            return {
                "error": "Ollama is not available",
                "message": "Please install and start Ollama: https://ollama.ai",
                "available": False
            }

        try:
            # Explain IOC with Ollama
            result = self.ollama.explain_ioc(ioc, ioc_type=ioc_type)

            return {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "explanation": result,
                "ollama_model": result.get("model"),
                "success": result.get("success", False)
            }

        except Exception as e:
            logger.error(f"Error explaining IOC with Ollama: {e}")
            return {"error": str(e)}

    async def _get_ollama_status(self) -> dict:
        """
        Get Ollama status and available models

        Returns:
            Ollama status information
        """
        logger.info("Getting Ollama status")

        if not self.ollama:
            return {
                "available": False,
                "message": "Ollama client not initialized",
                "installation_url": "https://ollama.ai"
            }

        try:
            status = self.ollama.get_status()

            return {
                "available": status.get("available", False),
                "base_url": status.get("base_url"),
                "current_model": status.get("current_model"),
                "models_available": status.get("models_available", 0),
                "models": status.get("models", []),
                "message": "Ollama is ready" if status.get("available") else "Ollama is not running. Start with: ollama serve"
            }

        except Exception as e:
            logger.error(f"Error getting Ollama status: {e}")
            return {
                "available": False,
                "error": str(e)
            }

    # ==================== Configuration Modification Tool Implementations ====================

    async def _update_threshold(self, detection_type: str, setting: str, value: Any) -> dict:
        """
        Update a detection threshold setting (WRITE operation)

        Args:
            detection_type: Detection type (e.g., 'port_scan')
            setting: Setting to modify (e.g., 'unique_ports')
            value: New value

        Returns:
            Result of the update operation
        """
        logger.info(f"Updating threshold: {detection_type}.{setting} = {value}")

        config_path = Path(__file__).parent.parent / 'config.yaml'

        try:
            # Load current config
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            # Validate detection type exists
            if detection_type not in config.get('thresholds', {}):
                return {
                    "success": False,
                    "error": f"Detection type '{detection_type}' not found",
                    "available_types": list(config.get('thresholds', {}).keys())
                }

            # Validate setting exists
            if setting not in config['thresholds'][detection_type]:
                return {
                    "success": False,
                    "error": f"Setting '{setting}' not found in {detection_type}",
                    "available_settings": list(config['thresholds'][detection_type].keys())
                }

            # Store old value
            old_value = config['thresholds'][detection_type][setting]

            # Auto-convert value to match old value type
            try:
                if isinstance(old_value, bool):
                    # Handle bool first (before int, since bool is subclass of int in Python)
                    if isinstance(value, str):
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    else:
                        value = bool(value)
                elif isinstance(old_value, int):
                    value = int(value)
                elif isinstance(old_value, float):
                    value = float(value)
                elif isinstance(old_value, str):
                    value = str(value)
            except (ValueError, TypeError) as e:
                return {
                    "success": False,
                    "error": f"Cannot convert value '{value}' to {type(old_value).__name__}: {e}",
                    "old_value": old_value,
                    "old_type": type(old_value).__name__
                }

            # Update the value
            config['thresholds'][detection_type][setting] = value

            # Create backup
            backup_path = config_path.parent / f"config.yaml.backup.{int(datetime.now().timestamp())}"
            with open(config_path, 'r') as f:
                with open(backup_path, 'w') as backup:
                    backup.write(f.read())

            # Write updated config
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Successfully updated {detection_type}.{setting}: {old_value} -> {value}")

            return {
                "success": True,
                "detection_type": detection_type,
                "setting": setting,
                "old_value": old_value,
                "new_value": value,
                "backup_file": str(backup_path),
                "message": f"Updated {detection_type}.{setting} from {old_value} to {value}",
                "note": "⚠️ Restart NetMonitor service to apply changes: sudo systemctl restart netmonitor"
            }

        except Exception as e:
            logger.error(f"Error updating threshold: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _toggle_detection_rule(self, detection_type: str, enabled: bool) -> dict:
        """
        Enable or disable a detection rule (WRITE operation)

        Args:
            detection_type: Detection type to toggle
            enabled: True to enable, False to disable

        Returns:
            Result of the operation
        """
        logger.info(f"Toggling detection rule: {detection_type} -> {'enabled' if enabled else 'disabled'}")

        config_path = Path(__file__).parent.parent / 'config.yaml'

        try:
            # Load current config
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            # Validate detection type exists
            if detection_type not in config.get('thresholds', {}):
                return {
                    "success": False,
                    "error": f"Detection type '{detection_type}' not found",
                    "available_types": list(config.get('thresholds', {}).keys())
                }

            # Store old value
            old_enabled = config['thresholds'][detection_type].get('enabled', False)

            # Check if already in desired state
            if old_enabled == enabled:
                return {
                    "success": True,
                    "detection_type": detection_type,
                    "enabled": enabled,
                    "message": f"Detection rule '{detection_type}' is already {'enabled' if enabled else 'disabled'}",
                    "changed": False
                }

            # Update the enabled status
            config['thresholds'][detection_type]['enabled'] = enabled

            # Create backup
            backup_path = config_path.parent / f"config.yaml.backup.{int(datetime.now().timestamp())}"
            with open(config_path, 'r') as f:
                with open(backup_path, 'w') as backup:
                    backup.write(f.read())

            # Write updated config
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Successfully {'enabled' if enabled else 'disabled'} {detection_type}")

            return {
                "success": True,
                "detection_type": detection_type,
                "old_enabled": old_enabled,
                "new_enabled": enabled,
                "backup_file": str(backup_path),
                "message": f"Detection rule '{detection_type}' {'enabled' if enabled else 'disabled'}",
                "changed": True,
                "note": "⚠️ Restart NetMonitor service to apply changes: sudo systemctl restart netmonitor"
            }

        except Exception as e:
            logger.error(f"Error toggling detection rule: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    # ==================== Sensor Management Tool Implementations ====================

    async def _get_sensor_status(self, status_filter: str = None) -> dict:
        """
        Get status of all remote sensors

        Args:
            status_filter: Filter by status (optional)

        Returns:
            Sensor status information
        """
        logger.info(f"Getting sensor status (filter={status_filter})")

        try:
            # Import database module to access sensor methods
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from database import DatabaseManager

            # Create DB connection with main credentials (not readonly)
            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db_main = DatabaseManager(
                host=host,
                database='netmonitor',
                user='netmonitor',
                password=password
            )

            sensors = db_main.get_sensors()
            db_main.close()

            # Apply status filter if provided
            if status_filter:
                sensors = [s for s in sensors if s.get('computed_status') == status_filter]

            # Calculate summary statistics
            total_sensors = len(sensors)
            online_count = sum(1 for s in sensors if s.get('computed_status') == 'online')
            warning_count = sum(1 for s in sensors if s.get('computed_status') == 'warning')
            offline_count = sum(1 for s in sensors if s.get('computed_status') == 'offline')
            total_alerts_24h = sum(s.get('alerts_24h', 0) for s in sensors)

            return {
                "total_sensors": total_sensors,
                "status_summary": {
                    "online": online_count,
                    "warning": warning_count,
                    "offline": offline_count
                },
                "total_alerts_24h": total_alerts_24h,
                "filters_applied": {
                    "status": status_filter
                },
                "sensors": sensors
            }

        except Exception as e:
            logger.error(f"Error getting sensor status: {e}")
            return {"error": str(e)}

    async def _get_sensor_details(self, sensor_id: str) -> dict:
        """
        Get detailed information about a specific sensor

        Args:
            sensor_id: Sensor ID to query

        Returns:
            Detailed sensor information
        """
        logger.info(f"Getting sensor details for {sensor_id}")

        try:
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from database import DatabaseManager

            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db_main = DatabaseManager(
                host=host,
                database='netmonitor',
                user='netmonitor',
                password=password
            )

            sensor = db_main.get_sensor_by_id(sensor_id)

            if not sensor:
                db_main.close()
                return {"error": f"Sensor '{sensor_id}' not found"}

            # Get metrics history
            metrics = db_main.get_sensor_metrics(sensor_id, hours=24)

            db_main.close()

            return {
                "sensor": sensor,
                "metrics_24h": metrics[:20],  # Last 20 metrics
                "metrics_count": len(metrics)
            }

        except Exception as e:
            logger.error(f"Error getting sensor details: {e}")
            return {"error": str(e)}

    async def _send_sensor_command(self, sensor_id: str, command_type: str,
                                  parameters: dict = None) -> dict:
        """
        Send a command to a remote sensor

        Args:
            sensor_id: Target sensor ID
            command_type: Command to execute
            parameters: Command parameters

        Returns:
            Command creation result
        """
        logger.info(f"Sending command '{command_type}' to sensor {sensor_id}")

        try:
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from database import DatabaseManager

            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db_main = DatabaseManager(
                host=host,
                database='netmonitor',
                user='netmonitor',
                password=password
            )

            # Verify sensor exists
            sensor = db_main.get_sensor_by_id(sensor_id)
            if not sensor:
                db_main.close()
                return {"error": f"Sensor '{sensor_id}' not found"}

            # Create command
            command_id = db_main.create_sensor_command(
                sensor_id=sensor_id,
                command_type=command_type,
                parameters=parameters
            )

            db_main.close()

            if command_id:
                return {
                    "success": True,
                    "command_id": command_id,
                    "sensor_id": sensor_id,
                    "command_type": command_type,
                    "parameters": parameters,
                    "message": f"Command '{command_type}' queued for sensor '{sensor_id}' (ID: {command_id})",
                    "note": "Sensor will poll for this command within 30 seconds"
                }
            else:
                return {"error": "Failed to create command"}

        except Exception as e:
            logger.error(f"Error sending sensor command: {e}")
            return {"error": str(e)}

    async def _get_sensor_alerts(self, sensor_id: str, hours: int = 24,
                                limit: int = 50) -> dict:
        """
        Get alerts from a specific sensor

        Args:
            sensor_id: Sensor ID to query
            hours: Lookback period in hours
            limit: Maximum number of alerts

        Returns:
            Sensor alerts
        """
        logger.info(f"Getting alerts for sensor {sensor_id} (hours={hours}, limit={limit})")

        try:
            # Get alerts with sensor_id filter
            cursor = self.db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            cursor.execute('''
                SELECT
                    id,
                    timestamp,
                    severity,
                    threat_type,
                    source_ip::text as source_ip,
                    destination_ip::text as destination_ip,
                    description,
                    acknowledged
                FROM alerts
                WHERE sensor_id = %s
                  AND timestamp > NOW() - INTERVAL '%s hours'
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (sensor_id, hours, limit))

            alerts = [dict(row) for row in cursor.fetchall()]

            # Calculate statistics
            by_severity = {}
            by_type = {}
            for alert in alerts:
                by_severity[alert['severity']] = by_severity.get(alert['severity'], 0) + 1
                by_type[alert['threat_type']] = by_type.get(alert['threat_type'], 0) + 1

            return {
                "sensor_id": sensor_id,
                "total_alerts": len(alerts),
                "analysis_period_hours": hours,
                "statistics": {
                    "by_severity": by_severity,
                    "by_type": by_type
                },
                "alerts": alerts
            }

        except Exception as e:
            logger.error(f"Error getting sensor alerts: {e}")
            return {"error": str(e)}

    async def _get_sensor_command_history(self, sensor_id: str, limit: int = 20) -> dict:
        """
        Get command execution history for a sensor

        Args:
            sensor_id: Sensor ID to query
            limit: Maximum number of commands

        Returns:
            Command history
        """
        logger.info(f"Getting command history for sensor {sensor_id} (limit={limit})")

        try:
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from database import DatabaseManager

            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db_main = DatabaseManager(
                host=host,
                database='netmonitor',
                user='netmonitor',
                password=password
            )

            commands = db_main.get_sensor_command_history(sensor_id, limit=limit)

            db_main.close()

            # Calculate statistics
            total_commands = len(commands)
            by_status = {}
            by_type = {}
            for cmd in commands:
                by_status[cmd['status']] = by_status.get(cmd['status'], 0) + 1
                by_type[cmd['command_type']] = by_type.get(cmd['command_type'], 0) + 1

            return {
                "sensor_id": sensor_id,
                "total_commands": total_commands,
                "statistics": {
                    "by_status": by_status,
                    "by_type": by_type
                },
                "commands": commands
            }

        except Exception as e:
            logger.error(f"Error getting command history: {e}")
            return {"error": str(e)}

    async def _get_bandwidth_summary(self, hours: int = 24) -> dict:
        """
        Get bandwidth usage summary for all sensors with trend analysis

        Args:
            hours: Lookback period in hours for trend analysis

        Returns:
            Bandwidth summary with current usage and trends
        """
        logger.info(f"Getting bandwidth summary for {hours} hours")

        try:
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from database import DatabaseManager
            from datetime import timedelta

            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db_main = DatabaseManager(
                host=host,
                database='netmonitor',
                user='netmonitor',
                password=password
            )

            # Get all sensors
            sensors = db_main.get_sensors()

            summary = {
                "total_sensors": len(sensors),
                "analysis_period_hours": hours,
                "sensors": [],
                "statistics": {
                    "total_bandwidth_mbps": 0.0,
                    "avg_bandwidth_mbps": 0.0,
                    "max_bandwidth_mbps": 0.0,
                    "sensors_over_80mbps": 0,
                    "sensors_over_200mbps": 0
                }
            }

            total_bandwidth = 0.0
            bandwidth_values = []

            for sensor in sensors:
                # Get recent metrics
                metrics = db_main.get_sensor_metrics(sensor['sensor_id'], hours=hours)

                if not metrics:
                    continue

                # Calculate bandwidth statistics
                bandwidth_readings = [m['bandwidth_mbps'] for m in metrics if m.get('bandwidth_mbps') is not None]

                if not bandwidth_readings:
                    continue

                current_bw = bandwidth_readings[0]  # Most recent
                avg_bw = sum(bandwidth_readings) / len(bandwidth_readings)
                max_bw = max(bandwidth_readings)
                min_bw = min(bandwidth_readings)

                # Trend analysis (compare first half vs second half)
                mid = len(bandwidth_readings) // 2
                if mid > 0:
                    recent_avg = sum(bandwidth_readings[:mid]) / mid
                    older_avg = sum(bandwidth_readings[mid:]) / (len(bandwidth_readings) - mid)
                    trend_pct = ((recent_avg - older_avg) / older_avg * 100) if older_avg > 0 else 0
                    trend = "increasing" if trend_pct > 10 else "decreasing" if trend_pct < -10 else "stable"
                else:
                    trend = "unknown"
                    trend_pct = 0

                sensor_summary = {
                    "sensor_id": sensor['sensor_id'],
                    "location": sensor.get('location', 'Unknown'),
                    "status": sensor.get('status', 'unknown'),
                    "bandwidth": {
                        "current_mbps": round(current_bw, 2),
                        "avg_mbps": round(avg_bw, 2),
                        "max_mbps": round(max_bw, 2),
                        "min_mbps": round(min_bw, 2),
                        "trend": trend,
                        "trend_percent": round(trend_pct, 1)
                    },
                    "health": "critical" if current_bw > 200 else "warning" if current_bw > 80 else "normal",
                    "samples": len(bandwidth_readings)
                }

                summary["sensors"].append(sensor_summary)
                total_bandwidth += current_bw
                bandwidth_values.append(current_bw)

                # Update statistics
                if current_bw > 80:
                    summary["statistics"]["sensors_over_80mbps"] += 1
                if current_bw > 200:
                    summary["statistics"]["sensors_over_200mbps"] += 1

            # Calculate overall statistics
            if bandwidth_values:
                summary["statistics"]["total_bandwidth_mbps"] = round(total_bandwidth, 2)
                summary["statistics"]["avg_bandwidth_mbps"] = round(sum(bandwidth_values) / len(bandwidth_values), 2)
                summary["statistics"]["max_bandwidth_mbps"] = round(max(bandwidth_values), 2)

            # Sort sensors by current bandwidth (highest first)
            summary["sensors"].sort(key=lambda s: s["bandwidth"]["current_mbps"], reverse=True)

            # Add recommendations
            recommendations = []
            if summary["statistics"]["sensors_over_200mbps"] > 0:
                recommendations.append(f"⚠️  {summary['statistics']['sensors_over_200mbps']} sensor(s) are using >200 Mbps - possible bottleneck")
            if summary["statistics"]["sensors_over_80mbps"] > 0:
                recommendations.append(f"⚡ {summary['statistics']['sensors_over_80mbps']} sensor(s) are using >80 Mbps - monitor closely")

            # Check for sensors with increasing trends
            increasing = [s for s in summary["sensors"] if s["bandwidth"]["trend"] == "increasing"]
            if increasing:
                recommendations.append(f"📈 {len(increasing)} sensor(s) show increasing bandwidth trends")

            summary["recommendations"] = recommendations if recommendations else ["✅ All sensors operating within normal bandwidth ranges"]

            db_main.close()

            return summary

        except Exception as e:
            logger.error(f"Error getting bandwidth summary: {e}")
            return {"error": str(e)}

    # ==================== Configuration Management Tool Implementations ====================

    async def _set_config_parameter(self, parameter_path: str, value: Any,
                                    sensor_id: str = None, scope: str = 'global') -> dict:
        """
        Set configuration parameter in database

        Args:
            parameter_path: Parameter path (e.g., 'detection.dns_tunnel.queries_per_minute')
            value: Parameter value (auto-typed)
            sensor_id: Optional sensor ID for sensor-specific config
            scope: 'global' or 'sensor'

        Returns:
            Result with success status
        """
        logger.info(f"Setting config parameter: {parameter_path} = {value} (scope={scope}, sensor={sensor_id})")

        try:
            import requests

            # Call dashboard API
            response = requests.put(
                f"http://localhost:8080/api/config/parameter",
                json={
                    'parameter_path': parameter_path,
                    'value': value,
                    'sensor_id': sensor_id,
                    'scope': scope,
                    'updated_by': 'mcp_server'
                },
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        "success": True,
                        "message": f"Parameter {parameter_path} updated successfully",
                        "parameter_path": parameter_path,
                        "value": value,
                        "scope": scope,
                        "sensor_id": sensor_id or "global"
                    }
                else:
                    return {"error": result.get('error', 'Unknown error')}
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            logger.error(f"Error setting config parameter: {e}")
            return {"error": str(e)}

    async def _get_config_parameters(self, sensor_id: str = None) -> dict:
        """
        Get all configuration parameters with metadata

        Args:
            sensor_id: Optional sensor ID to get sensor-specific config

        Returns:
            List of parameters with values and metadata
        """
        logger.info(f"Getting config parameters for sensor: {sensor_id or 'global'}")

        try:
            import requests

            # Call dashboard API
            params = {}
            if sensor_id:
                params['sensor_id'] = sensor_id

            response = requests.get(
                f"http://localhost:8080/api/config/parameters",
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    parameters = result.get('parameters', [])

                    return {
                        "success": True,
                        "total_parameters": len(parameters),
                        "sensor_id": sensor_id or "global",
                        "parameters": parameters
                    }
                else:
                    return {"error": result.get('error', 'Unknown error')}
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            logger.error(f"Error getting config parameters: {e}")
            return {"error": str(e)}

    async def _reset_config_to_defaults(self, confirm: bool = False, sensor_id: str = None) -> dict:
        """
        Reset configuration to best practice defaults

        Args:
            confirm: Must be True to confirm reset
            sensor_id: Optional sensor ID to reset specific sensor

        Returns:
            Result with number of parameters reset
        """
        if not confirm:
            return {
                "error": "Confirmation required",
                "message": "Set confirm=True to reset configuration to defaults"
            }

        logger.warning(f"Resetting config to defaults for sensor: {sensor_id or 'global'}")

        try:
            import requests

            # Call dashboard API
            response = requests.post(
                f"http://localhost:8080/api/config/reset",
                json={
                    'sensor_id': sensor_id,
                    'confirm': True
                },
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        "success": True,
                        "message": result.get('message'),
                        "parameters_reset": result.get('parameters_reset', 0),
                        "sensor_id": sensor_id or "global"
                    }
                else:
                    return {"error": result.get('error', 'Unknown error')}
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            logger.error(f"Error resetting config: {e}")
            return {"error": str(e)}

    # ==================== Whitelist Management Tool Implementations ====================

    async def _add_whitelist_entry(self, ip_cidr: str, description: str,
                                   scope: str = "global", sensor_id: str = None) -> dict:
        """
        Add an IP, CIDR range, or domain to the whitelist

        Args:
            ip_cidr: IP address, CIDR range, or domain to whitelist
            description: Reason for whitelisting
            scope: 'global' for all sensors or 'sensor' for specific sensor
            sensor_id: Sensor ID (required if scope is 'sensor')

        Returns:
            Result with entry details
        """
        logger.info(f"Adding whitelist entry: {ip_cidr} (scope: {scope})")

        if scope == "sensor" and not sensor_id:
            return {"error": "sensor_id required when scope is 'sensor'"}

        try:
            import requests

            # Call dashboard API
            response = requests.post(
                "http://localhost:8080/api/whitelist",
                json={
                    'ip_cidr': ip_cidr,
                    'description': description,
                    'scope': scope,
                    'sensor_id': sensor_id,
                    'created_by': 'mcp'
                },
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        "success": True,
                        "message": f"Added {ip_cidr} to whitelist",
                        "entry_id": result.get('entry_id'),
                        "ip_cidr": ip_cidr,
                        "description": description,
                        "scope": scope,
                        "sensor_id": sensor_id
                    }
                else:
                    return {"error": result.get('error', 'Unknown error')}
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            logger.error(f"Error adding whitelist entry: {e}")
            return {"error": str(e)}

    async def _get_whitelist_entries(self, scope: str = None, sensor_id: str = None) -> dict:
        """
        Get whitelist entries, optionally filtered by scope or sensor

        Args:
            scope: Filter by 'global' or 'sensor'
            sensor_id: Filter by sensor ID

        Returns:
            List of whitelist entries
        """
        logger.info(f"Getting whitelist entries (scope: {scope}, sensor: {sensor_id})")

        try:
            import requests

            params = {}
            if scope:
                params['scope'] = scope
            if sensor_id:
                params['sensor_id'] = sensor_id

            response = requests.get(
                "http://localhost:8080/api/whitelist",
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    entries = result.get('entries', [])
                    return {
                        "success": True,
                        "total_entries": len(entries),
                        "scope_filter": scope,
                        "sensor_filter": sensor_id,
                        "entries": entries
                    }
                else:
                    return {"error": result.get('error', 'Unknown error')}
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            logger.error(f"Error getting whitelist entries: {e}")
            return {"error": str(e)}

    async def _remove_whitelist_entry(self, entry_id: int) -> dict:
        """
        Remove a whitelist entry by ID

        Args:
            entry_id: Whitelist entry ID to remove

        Returns:
            Success status
        """
        logger.info(f"Removing whitelist entry: {entry_id}")

        try:
            import requests

            response = requests.delete(
                f"http://localhost:8080/api/whitelist/{entry_id}",
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        "success": True,
                        "message": f"Removed whitelist entry {entry_id}"
                    }
                else:
                    return {"error": result.get('error', 'Unknown error')}
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            logger.error(f"Error removing whitelist entry: {e}")
            return {"error": str(e)}

    # ==================== Resource Implementations ====================

    async def _get_dashboard_summary(self) -> str:
        """Get dashboard summary resource"""
        logger.info("Getting dashboard summary")

        stats = self.db.get_dashboard_stats()

        # Format as human-readable text for AI context
        summary = "=== NetMonitor Security Dashboard Summary ===\n\n"
        summary += f"Period: Last {stats['period_hours']} hours\n"
        summary += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        summary += f"TOTAL ALERTS: {stats['total']}\n\n"

        summary += "ALERTS BY SEVERITY:\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = stats['by_severity'].get(severity, 0)
            summary += f"  {severity}: {count}\n"

        summary += "\nTOP THREAT TYPES:\n"
        for threat_type, count in list(stats['by_type'].items())[:5]:
            summary += f"  {threat_type}: {count}\n"

        summary += "\nTOP SOURCE IPs:\n"
        for source in stats['top_sources'][:5]:
            summary += f"  {source['ip']}: {source['count']} alerts\n"

        summary += "\n" + "="*50 + "\n"

        return summary

    def run_stdio(self):
        """Run the MCP server in stdio mode (local)"""
        logger.info("Starting NetMonitor MCP Server in STDIO mode...")
        # stdio_server creates stdin/stdout streams, no parameters needed
        async def run():
            async with stdio_server() as (read_stream, write_stream):
                # Create initialization options for the server
                init_options = InitializationOptions(
                    server_name="netmonitor-soc",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={}
                    )
                )
                # Run the server with the stdio streams and init options
                await self.server.run(read_stream, write_stream, init_options)

        try:
            asyncio.run(run())
        except KeyboardInterrupt:
            logger.info("Server stopped by user (KeyboardInterrupt)")
        except Exception as e:
            logger.error(f"Server error in stdio mode: {e}", exc_info=True)
            raise

    def run_sse(self, host: str = "0.0.0.0", port: int = 3000):
        """Run the MCP server in SSE mode (network)"""
        if not SSE_AVAILABLE:
            logger.error("SSE dependencies not installed. Install with: pip install starlette uvicorn sse-starlette")
            sys.exit(1)

        logger.info(f"Starting NetMonitor MCP Server in SSE mode on {host}:{port}...")

        # Create MCP SSE endpoint handler
        async def handle_sse(request):
            """Handle SSE requests from MCP clients"""
            async def event_generator():
                # MCP SSE protocol implementation
                # This is a simplified version - full implementation would handle
                # the complete MCP SSE handshake and message protocol
                from mcp.server.sse import sse_server

                async for message in sse_server(self.server):
                    yield {
                        "data": message
                    }

            return EventSourceResponse(event_generator())

        async def handle_health(request):
            """Health check endpoint"""
            return Response("OK", status_code=200)

        # Create Starlette app
        app = Starlette(
            routes=[
                Route("/sse", handle_sse),
                Route("/health", handle_health),
            ]
        )

        # Run with uvicorn
        uvicorn.run(app, host=host, port=port, log_level="info")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="NetMonitor MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport mode: stdio (local) or sse (network)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (SSE mode only, default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3000,
        help="Port to bind to (SSE mode only, default: 3000)"
    )

    args = parser.parse_args()

    try:
        server = NetMonitorMCPServer()

        if args.transport == "stdio":
            server.run_stdio()
        elif args.transport == "sse":
            server.run_sse(host=args.host, port=args.port)

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
