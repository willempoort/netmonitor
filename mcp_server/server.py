#!/usr/bin/env python3
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
import socket
import argparse
import asyncio
from datetime import datetime
from typing import Any, Sequence
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
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

from database_client import MCPDatabaseClient
from geoip_helper import get_country_for_ip, is_private_ip


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

        # Connect to database
        self._connect_database()

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
            password = os.environ.get('NETMONITOR_DB_PASSWORD', 'mcp_netmonitor_readonly_2024')

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
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
            """Call a tool"""
            try:
                if name == "analyze_ip":
                    result = await self._analyze_ip(**arguments)
                elif name == "get_recent_threats":
                    result = await self._get_recent_threats(**arguments)
                elif name == "get_threat_timeline":
                    result = await self._get_threat_timeline(**arguments)
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
        # stdio_server is an async context manager, must use async with
        async def run():
            async with stdio_server(self.server) as (read_stream, write_stream):
                # Server is now running, wait until it finishes
                await read_stream.wait_closed()

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
