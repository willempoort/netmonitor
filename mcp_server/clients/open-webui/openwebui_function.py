"""
title: NetMonitor Security Tools
author: NetMonitor
version: 2.0.0
description: 60 security tools via REST API
required_open_webui_version: 0.3.0
"""

import requests
import json
from typing import Optional
from pydantic import BaseModel, Field


class Tools:
    """NetMonitor REST API Tools"""

    class Valves(BaseModel):
        """Configuration"""
        API_URL: str = Field(
            default="https://soc.poort.net/openwebui",
            description="NetMonitor REST API URL"
        )
        API_TOKEN: str = Field(
            default="",
            description="API Bearer token"
        )

    def __init__(self):
        self.valves = self.Valves()

    def _call_api(self, endpoint: str, data: dict = None) -> dict:
        """Internal API caller"""
        if not self.valves.API_TOKEN:
            return {"error": "API_TOKEN not configured"}

        url = f"{self.valves.API_URL.rstrip('/')}/{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.valves.API_TOKEN}',
            'Content-Type': 'application/json'
        }

        try:
            if data:
                response = requests.post(url, headers=headers, json=data, timeout=30, verify=True)
            else:
                response = requests.get(url, headers=headers, timeout=30, verify=True)

            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def get_recent_threats(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Get recent security threats from NetMonitor

        Args:
            hours: Lookback period in hours (default: 24)
            severity: Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            limit: Maximum number of results (default: 50)

        Example: "Show me critical threats from the last 6 hours"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'get_recent_threats',
            'parameters': {'hours': hours, 'severity': severity, 'limit': limit}
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error', 'Unknown error')}"

        data = result.get('data', {})
        output = f"📊 **Security Threats Report** (last {hours}h)\n\n"
        output += f"**Total Alerts:** {data.get('total_alerts', 0)}\n\n"

        stats = data.get('statistics', {})
        if stats.get('by_severity'):
            output += "**By Severity:**\n"
            for sev, count in stats['by_severity'].items():
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}.get(sev, '•')
                output += f"  {emoji} {sev}: {count}\n"
            output += "\n"

        if stats.get('by_type'):
            output += "**Top Threat Types:**\n"
            for threat_type, count in list(stats['by_type'].items())[:5]:
                output += f"  • {threat_type}: {count}\n"

        return output

    def analyze_ip(self, ip_address: str, hours: int = 24) -> str:
        """
        Analyze a specific IP address for security threats

        Args:
            ip_address: IP address to analyze (e.g., "192.168.1.50")
            hours: Lookback period in hours (default: 24)

        Example: "Analyze IP 185.220.101.50"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'analyze_ip',
            'parameters': {'ip_address': ip_address, 'hours': hours}
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error')}"

        data = result.get('data', {})
        risk_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(data.get('risk_level'), '❓')

        output = f"🔍 **IP Analysis: {ip_address}**\n\n"
        if data.get('hostname'):
            output += f"**Hostname:** {data['hostname']}\n"
        output += f"**Location:** {data.get('country', 'Unknown')}\n"
        output += f"**Type:** {'Internal' if data.get('is_internal') else 'External'}\n\n"
        output += f"**Threat Score:** {data.get('threat_score', 0)}/100\n"
        output += f"**Risk Level:** {risk_emoji} {data.get('risk_level')}\n"
        output += f"**Alert Count:** {data.get('alert_count', 0)} (last {hours}h)\n\n"
        output += f"**💡 Recommendation:**\n{data.get('recommendation', 'No recommendation')}\n"

        return output

    def get_sensor_status(self) -> str:
        """
        Get status of all remote NetMonitor sensors

        Example: "Which sensors are online?"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'get_sensor_status',
            'parameters': {}
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error')}"

        data = result.get('data', {})
        if data.get('error'):
            return f"❌ Error: {data['error']}"

        output = f"🖥️  **Sensor Status Report**\n\n"
        output += f"**Total Sensors:** {data.get('total', 0)}\n"
        output += f"**Online:** ✅ {data.get('online', 0)}\n"
        output += f"**Offline:** ❌ {data.get('offline', 0)}\n"

        return output

    def check_indicator(self, indicator: str, indicator_type: str) -> str:
        """
        Check if an IP, domain, or hash matches any threat feeds

        Args:
            indicator: IP address, domain, URL, or hash to check
            indicator_type: Type of indicator (ip, domain, url, hash)

        Example: "Check if 185.220.101.50 is malicious"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'check_indicator',
            'parameters': {
                'indicator': indicator,
                'indicator_type': indicator_type
            }
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error')}"

        data = result.get('data', {})
        if data.get('found'):
            output = f"⚠️ **Threat Detected: {indicator}**\n\n"
            output += f"**Feeds:** {', '.join(data.get('feeds', []))}\n"
            output += f"**Threat Types:** {', '.join(data.get('threat_types', []))}\n"
            return output
        else:
            return f"✅ **{indicator}** - No threats found in feeds"

    def get_devices(self, include_inactive: bool = False) -> str:
        """
        Get all discovered network devices

        Args:
            include_inactive: Include inactive devices (default: False)

        Example: "Show me all network devices"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'get_devices',
            'parameters': {'include_inactive': include_inactive}
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error')}"

        data = result.get('data', {})
        devices = data.get('devices', [])
        
        output = f"🖥️  **Network Devices** ({len(devices)} total)\n\n"
        
        for device in devices[:10]:  # Show first 10
            output += f"• **{device.get('ip_address')}**"
            if device.get('hostname'):
                output += f" ({device['hostname']})"
            if device.get('template_name'):
                output += f" - {device['template_name']}"
            output += "\n"
        
        if len(devices) > 10:
            output += f"\n... and {len(devices) - 10} more devices"
        
        return output
