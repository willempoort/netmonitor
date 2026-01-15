# Open-WebUI met NetMonitor REST API

**✅ WERKENDE OPLOSSING** - Deze REST wrapper omzeilt Open-WebUI's native MCP bugs

## Waarom REST in plaats van native MCP?

Open-WebUI heeft een bug in de native MCP Streamable HTTP implementatie die resulteert in:
```
cannot pickle '_asyncio.Future' object
```

De REST wrapper biedt:
- ✅ Stabiele REST endpoints (geen SSE streaming complexiteit)
- ✅ Alle 60 NetMonitor tools beschikbaar
- ✅ Token authenticatie + rate limiting  
- ✅ Eenvoudige setup

## 🚀 Setup

### Stap 1: Installeer Open-WebUI (op je laptop)

```bash
# Met Docker (aanbevolen):
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -v open-webui:/app/backend/data \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  --restart always \
  ghcr.io/open-webui/open-webui:main
```

Open: **http://localhost:3000**  
Maak een admin account aan (eerste gebruiker = admin)

### Stap 2: Maak API Token aan (op de server)

```bash
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
  --name "Open-WebUI" \
  --scope read_only \
  --rate-minute 120
```

Kopieer de token - je hebt hem nodig voor stap 3.

### Stap 3: Configureer NetMonitor Function in Open-WebUI

1. **Open Open-WebUI**: http://localhost:3000
2. **Ga naar**: Workspace → Functions (of Werkruimte → Functies)
3. **Klik**: "+" om nieuwe function toe te voegen
4. **Plak deze code**:

```python
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
                response = requests.post(url, headers=headers, json=data, timeout=30)
            else:
                response = requests.get(url, headers=headers, timeout=30)

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
        Get recent security threats

        Args:
            hours: Lookback period in hours
            severity: Filter: CRITICAL, HIGH, MEDIUM, LOW, INFO
            limit: Maximum results

        Example: "Show critical threats from last 6 hours"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'get_recent_threats',
            'parameters': {'hours': hours, 'severity': severity, 'limit': limit}
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error', 'Unknown error')}"

        data = result.get('data', {})
        output = f"📊 **Security Threats** (last {hours}h)\n\n"
        output += f"Total Alerts: {data.get('total_alerts', 0)}\n"

        stats = data.get('statistics', {})
        if stats.get('by_severity'):
            output += "\n**By Severity:**\n"
            for sev, count in stats['by_severity'].items():
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(sev, '•')
                output += f"  {emoji} {sev}: {count}\n"

        alerts = data.get('alerts', [])[:5]
        if alerts:
            output += "\n**Recent Alerts:**\n"
            for alert in alerts:
                output += f"\n• **{alert.get('threat_type')}** ({alert.get('severity')})\n"
                output += f"  {alert.get('source_ip')} → {alert.get('destination_ip')}\n"

        return output

    def analyze_ip(self, ip_address: str, hours: int = 24) -> str:
        """
        Analyze IP for threats

        Args:
            ip_address: IP to analyze
            hours: Lookback hours

        Example: "Analyze IP 192.168.1.50"
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
        output += f"Location: {data.get('country', 'Unknown')}\n"
        output += f"Type: {'Internal' if data.get('is_internal') else 'External'}\n"
        output += f"Threat Score: {data.get('threat_score', 0)}/100\n"
        output += f"Risk Level: {risk_emoji} {data.get('risk_level')}\n"
        output += f"Alert Count: {data.get('alert_count', 0)}\n\n"
        output += f"💡 **Recommendation:**\n{data.get('recommendation', 'No recommendation')}\n"

        return output

    def get_sensor_status(self) -> str:
        """
        Get status of remote sensors

        Example: "Which sensors are online?"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'get_sensor_status',
            'parameters': {}
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error')}"

        data = result.get('data', {})
        output = f"🖥️  **Sensor Status**\n\n"
        output += f"Total: {data.get('total', 0)}\n"
        output += f"Online: ✅ {data.get('online', 0)}\n"
        output += f"Offline: ❌ {data.get('offline', 0)}\n"

        return output

    def check_indicator(self, indicator: str, indicator_type: str) -> str:
        """
        Check if IP/domain/hash matches threat feeds

        Args:
            indicator: IP, domain, URL, or hash
            indicator_type: Type (ip, domain, url, hash)

        Example: "Check if 185.220.101.50 is malicious"
        """
        result = self._call_api('tools/execute', {
            'tool_name': 'check_indicator',
            'parameters': {'indicator': indicator, 'indicator_type': indicator_type}
        })

        if not result.get('success'):
            return f"❌ Error: {result.get('error')}"

        data = result.get('data', {})
        if data.get('found'):
            output = f"⚠️ **Threat Detected: {indicator}**\n\n"
            output += f"Feeds: {', '.join(data.get('feeds', []))}\n"
            output += f"Threat Types: {', '.join(data.get('threat_types', []))}\n"
            return output
        else:
            return f"✅ **{indicator}** - No threats found"
```

5. **Klik "Save"**
6. **Configureer de Valves** (tandwiel icoon bij de function):
   - **API_URL**: `https://soc.poort.net/openwebui`
   - **API_TOKEN**: `<plak je token hier>`
7. **Save**

### Stap 4: Test in Open-WebUI

Start een nieuwe chat en vraag:

```
What NetMonitor tools do you have? Show me recent threats.
```

De AI zal automatisch de functions aanroepen en NetMonitor data tonen!

## 🎯 Voorbeeld Queries

```
"Show me critical threats from the last hour"
"Analyze IP 192.168.1.100"
"Which sensors are offline?"
"Check if 185.220.101.50 is malicious"
```

## 🔧 Troubleshooting

### Function verschijnt niet
- Check of je in **Workspace → Functions** bent (NIET Admin Panel → Functions)
- Herstart Open-WebUI: `docker restart open-webui`

### API errors
```bash
# Test token:
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://soc.poort.net/openwebui/health
```

### SSL errors
Als je self-signed certificaat gebruikt:
```python
# In _call_api functie, voeg toe:
response = requests.post(..., verify=False)
```

## 📊 Alle 60 Tools

De wrapper biedt toegang tot alle 60 NetMonitor tools:
- Threat Analysis (analyze_ip, get_recent_threats, ...)
- Device Management (get_devices, assign_template, ...)
- TLS/SSL Analysis (get_tls_metadata, check_ja3, ...)
- PCAP Management (export_flow_pcap, ...)
- Kerberos Detection (get_kerberos_attacks, ...)
- Risk Scoring (get_top_risk_assets, ...)
- SOAR Integration (get_soar_playbooks, ...)
- En 40+ meer...

Voeg functies toe aan de `Tools` class voor de tools die je wilt gebruiken.

## 📚 Referenties

- Full tool list: `curl https://soc.poort.net/openwebui/tools`
- Token management: `/opt/netmonitor/mcp_server/manage_tokens.py`
- Service status: `systemctl status netmonitor-openwebui-rest`
- Logs: `journalctl -u netmonitor-openwebui-rest -f`

---

**✅ Veel plezier met je AI-powered SOC!** 🚀
