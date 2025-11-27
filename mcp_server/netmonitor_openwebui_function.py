"""
title: NetMonitor Security Tools
author: NetMonitor MCP Integration
author_url: https://github.com/willempoort/netmonitor
version: 1.0.0
description: Access NetMonitor SOC security tools via MCP HTTP API
required_open_webui_version: 0.3.0
"""

import requests
import json
from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field


class Tools:
    """NetMonitor MCP API Tools"""

    class Valves(BaseModel):
        """Configuration values"""
        MCP_API_URL: str = Field(
            default="https://soc.poort.net:8000",
            description="MCP HTTP API base URL"
        )
        MCP_API_TOKEN: str = Field(
            default="",
            description="MCP API Bearer token (krijg via: python3 manage_tokens.py create)"
        )
        VERIFY_SSL: bool = Field(
            default=True,
            description="Verify SSL certificates (False for self-signed)"
        )

    def __init__(self):
        self.valves = self.Valves()

    def _call_mcp_api(self, tool_name: str, parameters: dict) -> dict:
        """
        Internal helper to call MCP HTTP API

        Args:
            tool_name: Name of the MCP tool to call
            parameters: Tool parameters

        Returns:
            Tool execution result
        """
        if not self.valves.MCP_API_TOKEN:
            return {
                "success": False,
                "error": "MCP_API_TOKEN not configured. Set in Function Settings."
            }

        try:
            response = requests.post(
                f"{self.valves.MCP_API_URL}/mcp/tools/execute",
                headers={
                    'Authorization': f'Bearer {self.valves.MCP_API_TOKEN}',
                    'Content-Type': 'application/json'
                },
                json={
                    'tool_name': tool_name,
                    'parameters': parameters
                },
                verify=self.valves.VERIFY_SSL,
                timeout=30
            )

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"MCP API error: {str(e)}"
            }

    def get_recent_threats(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Get recent security threats from NetMonitor

        Use this to check for recent security incidents, attacks, or suspicious activity.

        Args:
            hours: Lookback period in hours (default: 24)
            severity: Filter by severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO
            limit: Maximum number of results (default: 50)

        Returns:
            Recent security threats with statistics

        Example:
            "Show me critical threats from the last 6 hours"
            get_recent_threats(hours=6, severity="CRITICAL")
        """
        result = self._call_mcp_api('get_recent_threats', {
            'hours': hours,
            'severity': severity,
            'limit': limit
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error', 'Unknown error')}"

        data = result.get('data', {})

        # Format response
        output = f"📊 **Security Threats Report**\n\n"
        output += f"**Period:** Last {hours} hours\n"
        output += f"**Total Alerts:** {data.get('total_alerts', 0)}\n\n"

        stats = data.get('statistics', {})

        if stats.get('by_severity'):
            output += "**By Severity:**\n"
            for sev, count in stats['by_severity'].items():
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡',
                        'LOW': '🟢', 'INFO': 'ℹ️'}.get(sev, '•')
                output += f"  {emoji} {sev}: {count}\n"
            output += "\n"

        if stats.get('by_type'):
            output += "**Top Threat Types:**\n"
            for threat_type, count in list(stats['by_type'].items())[:5]:
                output += f"  • {threat_type}: {count}\n"
            output += "\n"

        output += f"**Unique Source IPs:** {data.get('unique_source_ips', 0)}\n\n"

        # Show recent alerts
        alerts = data.get('alerts', [])[:5]
        if alerts:
            output += "**Recent Alerts:**\n"
            for alert in alerts:
                output += f"\n• **{alert.get('threat_type')}** ({alert.get('severity')})\n"
                output += f"  Source: {alert.get('source_ip')} → Dest: {alert.get('destination_ip')}\n"
                output += f"  Time: {alert.get('timestamp')}\n"

        return output

    def analyze_ip(
        self,
        ip_address: str,
        hours: int = 24
    ) -> str:
        """
        Analyze a specific IP address for security threats

        Use this to investigate suspicious IP addresses, check threat levels,
        and get recommendations for blocking or monitoring.

        Args:
            ip_address: IP address to analyze (e.g., "192.168.1.50" or "185.220.101.50")
            hours: Lookback period in hours (default: 24)

        Returns:
            Detailed threat analysis with risk assessment

        Example:
            "Analyze IP 185.220.101.50"
            analyze_ip("185.220.101.50")
        """
        result = self._call_mcp_api('analyze_ip', {
            'ip_address': ip_address,
            'hours': hours
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error', 'Unknown error')}"

        data = result.get('data', {})

        # Risk level emoji
        risk_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': 'ℹ️'
        }.get(data.get('risk_level', 'INFO'), '❓')

        output = f"🔍 **IP Analysis: {ip_address}**\n\n"

        if data.get('hostname'):
            output += f"**Hostname:** {data['hostname']}\n"

        output += f"**Location:** {data.get('country', 'Unknown')}\n"
        output += f"**Type:** {'Internal' if data.get('is_internal') else 'External'}\n\n"

        output += f"**Threat Score:** {data.get('threat_score', 0)}/100\n"
        output += f"**Risk Level:** {risk_emoji} {data.get('risk_level', 'UNKNOWN')}\n\n"

        output += f"**Alert Count:** {data.get('alert_count', 0)} (last {hours}h)\n"

        threat_types = data.get('threat_types', [])
        if threat_types:
            output += f"**Threat Types:** {', '.join(threat_types)}\n\n"

        severity_counts = data.get('severity_counts', {})
        if severity_counts:
            output += "**Severity Breakdown:**\n"
            for sev, count in severity_counts.items():
                output += f"  • {sev}: {count}\n"
            output += "\n"

        # Recommendation
        recommendation = data.get('recommendation', 'No recommendation')
        output += f"**💡 Recommendation:**\n{recommendation}\n"

        return output

    def get_sensor_status(self) -> str:
        """
        Get status of all remote NetMonitor sensors

        Use this to check if sensors are online, offline, or having issues.

        Returns:
            Status of all sensors with online/offline counts

        Example:
            "What sensors are online?"
            get_sensor_status()
        """
        result = self._call_mcp_api('get_sensor_status', {})

        if not result.get('success'):
            return f"❌ Error: {result.get('error', 'Unknown error')}"

        data = result.get('data', {})

        if data.get('error'):
            return f"❌ Error: {data['error']}"

        output = f"🖥️  **Sensor Status Report**\n\n"
        output += f"**Total Sensors:** {data.get('total', 0)}\n"
        output += f"**Online:** ✅ {data.get('online', 0)}\n"
        output += f"**Offline:** ❌ {data.get('offline', 0)}\n\n"

        sensors = data.get('sensors', [])
        if sensors:
            output += "**Sensor Details:**\n"
            for sensor in sensors:
                status_emoji = '✅' if sensor.get('status') == 'online' else '❌'
                output += f"\n{status_emoji} **{sensor.get('name', 'Unknown')}**\n"
                output += f"  Location: {sensor.get('location', 'Unknown')}\n"
                output += f"  Status: {sensor.get('status', 'Unknown')}\n"

                if sensor.get('last_seen'):
                    output += f"  Last seen: {sensor.get('last_seen')}\n"

        return output

    def get_dashboard_summary(self) -> str:
        """
        Get NetMonitor security dashboard summary

        Use this to get a quick overview of the current security situation.

        Returns:
            Dashboard summary with key metrics

        Example:
            "Show me the security dashboard"
            get_dashboard_summary()
        """
        try:
            response = requests.get(
                f"{self.valves.MCP_API_URL}/mcp/resources/dashboard/summary",
                headers={
                    'Authorization': f'Bearer {self.valves.MCP_API_TOKEN}',
                },
                verify=self.valves.VERIFY_SSL,
                timeout=30
            )

            response.raise_for_status()
            data = response.json()

            return f"📊 **Dashboard Summary**\n\n```\n{data.get('content', 'No data')}\n```"

        except requests.exceptions.RequestException as e:
            return f"❌ Error: {str(e)}"
