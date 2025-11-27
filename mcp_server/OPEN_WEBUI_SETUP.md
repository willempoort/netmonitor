# Open WebUI + NetMonitor MCP Integration

**Gebruik Ollama models met NetMonitor security tools via web interface**

---

## 📋 Overzicht

Open WebUI is een moderne web interface voor Ollama die custom functions ondersteunt. Deze setup combineert:

- 🤖 **Ollama** - Lokale LLM models (llama3.2, mistral, etc.)
- 🌐 **Open WebUI** - Mooie chat interface
- 🔧 **Custom Functions** - NetMonitor MCP API integratie
- 🔐 **Token Auth** - Veilige API toegang

**Het Resultaat:**
Een web-based security assistant die:
- Natuurlijke taal begrijpt (Ollama)
- NetMonitor tools kan gebruiken (MCP API)
- In je browser werkt
- Volledig lokaal draait (behalve MCP API calls)

---

## 🚀 Installatie

### Stap 1: Installeer Open WebUI

**Met Docker (Aanbevolen):**

```bash
# Op je Mac/laptop
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -v open-webui:/app/backend/data \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  --restart always \
  ghcr.io/open-webui/open-webui:main
```

**Of zonder Docker (Python):**

```bash
# Clone repository
git clone https://github.com/open-webui/open-webui.git
cd open-webui

# Backend setup
cd backend
pip install -r requirements.txt

# Frontend setup
cd ../
npm install
npm run build

# Start
cd backend
bash start.sh
```

### Stap 2: First-Time Setup

1. **Open browser:** http://localhost:3000
2. **Maak admin account** (eerste gebruiker wordt admin)
3. **Verifieer Ollama connectie:**
   - Settings → Connections
   - Ollama API URL: `http://localhost:11434`
   - Test connection

---

## 🔧 NetMonitor MCP Functions

### Stap 1: Maak Function File

Sla dit op als `netmonitor_mcp.py`:

```python
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


class Function:
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
```

### Stap 2: Installeer Function in Open WebUI

1. **Open Open WebUI:** http://localhost:3000
2. **Ga naar Workspace → Functions**
3. **Klik "+ Add Function"**
4. **Plak de code** van `netmonitor_mcp.py`
5. **Klik "Save"**

### Stap 3: Configureer MCP API Token

1. **Ga naar Function Settings** (tandwiel icoon bij de function)
2. **Vul in:**
   - **MCP_API_URL:** `https://soc.poort.net:8000`
   - **MCP_API_TOKEN:** `your_api_token_here`
   - **VERIFY_SSL:** `True` (of `False` voor self-signed cert)
3. **Save**

**Token krijgen:**
```bash
# Op de MCP server
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
    --name "Open WebUI" \
    --scope read_only \
    --description "Token for Open WebUI Ollama integration"
```

---

## 🎯 Gebruik

### Voorbeeld Conversaties

**1. Security Overview:**
```
You: What's the current security situation?

AI: Let me check the dashboard and recent threats for you.
[Calls get_dashboard_summary() and get_recent_threats()]

📊 **Security Dashboard Summary**
- Total Alerts (24h): 1,247
- Critical: 🔴 23
- High: 🟠 156
- Medium: 🟡 892
- Active Sensors: 12/14 online

**Top Threats:**
- Port Scan: 342 incidents
- Brute Force SSH: 89 incidents
- Malware Communication: 12 incidents

The situation is relatively stable with expected levels of scanning activity.
However, I noticed 23 CRITICAL alerts - would you like me to analyze those?
```

**2. Investigate Suspicious IP:**
```
You: Analyze IP 185.220.101.50

AI: I'll analyze that IP for you.
[Calls analyze_ip("185.220.101.50")]

🔍 **IP Analysis: 185.220.101.50**

**Hostname:** tor-exit-node-12.example.org
**Location:** Russia (RU)
**Type:** External

**Threat Score:** 85/100
**Risk Level:** 🔴 CRITICAL

**Alert Count:** 47 (last 24h)
**Threat Types:** Port Scan, Brute Force SSH, Malware C2

**Severity Breakdown:**
  • CRITICAL: 12
  • HIGH: 23
  • MEDIUM: 12

**💡 Recommendation:**
Block this IP immediately. It's a known Tor exit node from Russia with
multiple brute force attempts and malware command & control activity.

Would you like me to check if this IP is already blocked?
```

**3. Sensor Management:**
```
You: Which sensors are offline?

AI: Let me check the sensor status.
[Calls get_sensor_status()]

🖥️  **Sensor Status Report**

**Total Sensors:** 14
**Online:** ✅ 12
**Offline:** ❌ 2

**Offline Sensors:**

❌ **Sensor-Amsterdam-3**
  Location: Amsterdam DC
  Status: offline
  Last seen: 2024-11-27 12:45:23 (2 hours ago)

❌ **Sensor-Rotterdam-1**
  Location: Rotterdam Office
  Status: offline
  Last seen: 2024-11-27 08:15:10 (6 hours ago)

The Rotterdam sensor has been offline for 6 hours - this might require
immediate attention. Should I check for recent alerts from that location?
```

**4. Threat Timeline:**
```
You: Show me what happened in the last hour with critical threats

AI: I'll get the critical threats from the last hour.
[Calls get_recent_threats(hours=1, severity="CRITICAL")]

📊 **Security Threats Report**

**Period:** Last 1 hours
**Total Alerts:** 3

**By Severity:**
  🔴 CRITICAL: 3

**Recent Alerts:**

• **Malware Command & Control** (CRITICAL)
  Source: 45.129.56.200 → Dest: 192.168.10.50
  Time: 2024-11-27 14:23:11

• **Brute Force SSH** (CRITICAL)
  Source: 185.220.101.50 → Dest: 10.0.1.100
  Time: 2024-11-27 14:15:45

• **Port Scan** (CRITICAL)
  Source: 103.45.12.88 → Dest: 10.0.0.0/24
  Time: 2024-11-27 13:58:32

All three are from external IPs. The malware C2 connection to 192.168.10.50
is particularly concerning. Would you like me to analyze that internal host?
```

**5. Natural Language Questions:**
```
You: Are we under attack?

AI: Let me check recent threat activity.
[Calls get_recent_threats(hours=1)]

Based on the last hour of data:
- 47 total alerts (normal baseline: 40-60/hour)
- 3 CRITICAL alerts (slightly elevated)
- 12 unique source IPs

**Assessment:** No active large-scale attack detected. The alert volume is
within normal ranges. The 3 critical alerts are concerning but appear to be
opportunistic scanning rather than targeted attacks.

**Recommendations:**
1. Monitor the malware C2 connection from 45.129.56.200
2. Block the persistent SSH brute forcer (185.220.101.50)
3. Continue monitoring for pattern changes

Would you like me to analyze any of these IPs in detail?
```

---

## 🔧 Advanced Configuration

### Multiple MCP Servers

Je kunt meerdere functions maken voor verschillende MCP servers:

```python
# Maak twee aparte function files in Open WebUI

# File 1: netmonitor_production.py
class Function:
    class Valves(BaseModel):
        MCP_API_URL: str = Field(default="https://soc.poort.net:8000")
        MCP_API_TOKEN: str = Field(default="prod_token_here")
    # ... rest van de function code

# File 2: netmonitor_development.py
class Function:
    class Valves(BaseModel):
        MCP_API_URL: str = Field(default="https://dev.poort.net:8000")
        MCP_API_TOKEN: str = Field(default="dev_token_here")
    # ... rest van de function code
```

### Custom Formatting

Pas de output formatting aan naar jouw voorkeur:

```python
def get_recent_threats(self, hours: int = 24, severity: Optional[str] = None, limit: int = 50) -> str:
    result = self._call_mcp_api('get_recent_threats', {...})

    # Custom JSON output
    if self.valves.OUTPUT_FORMAT == "json":
        return f"```json\n{json.dumps(result.get('data'), indent=2)}\n```"

    # Custom table format
    if self.valves.OUTPUT_FORMAT == "table":
        alerts = result.get('data', {}).get('alerts', [])
        table = "| Time | Type | Source | Severity |\n|------|------|--------|----------|\n"
        for alert in alerts[:10]:
            table += f"| {alert['timestamp']} | {alert['threat_type']} | {alert['source_ip']} | {alert['severity']} |\n"
        return table

    # Default markdown format
    return formatted_output
```

### Rate Limiting Handling

Als je rate limits raakt, voeg retry logic toe:

```python
import time

def _call_mcp_api(self, tool_name: str, parameters: dict) -> dict:
    max_retries = 3
    retry_delay = 2

    for attempt in range(max_retries):
        try:
            response = requests.post(...)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:  # Rate limited
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
            raise
```

---

## 🐛 Troubleshooting

### Function wordt niet geladen

**Symptoom:** Function verschijnt niet in de lijst

**Oplossingen:**
```bash
# 1. Check Python syntax
python3 -m py_compile netmonitor_mcp.py

# 2. Check Open WebUI logs
docker logs open-webui

# 3. Herstart Open WebUI
docker restart open-webui
```

### MCP API token errors

**Symptoom:** "MCP_API_TOKEN not configured" of 401 errors

**Oplossingen:**
```bash
# 1. Verify token in function settings
# Ga naar Function Settings en check of MCP_API_TOKEN is ingevuld

# 2. Test token handmatig
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://soc.poort.net:8000/mcp/tools

# 3. Maak nieuwe token
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
    --name "Open WebUI" \
    --scope read_only
```

### SSL certificate errors

**Symptoom:** "SSL: CERTIFICATE_VERIFY_FAILED"

**Oplossingen:**

**Optie A - Disable SSL verificatie (development only):**
```python
class Valves(BaseModel):
    VERIFY_SSL: bool = Field(default=False)
```

**Optie B - Voeg certificaat toe:**
```bash
# Download certificaat
openssl s_client -connect soc.poort.net:8000 -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > soc_poort_net.crt

# In Open WebUI container
docker cp soc_poort_net.crt open-webui:/usr/local/share/ca-certificates/
docker exec open-webui update-ca-certificates
docker restart open-webui
```

**Optie C - Gebruik Let's Encrypt (aanbevolen):**
Zie `CLAUDE_DESKTOP_CONFIG.md` voor nginx reverse proxy setup.

### Timeout errors

**Symptoom:** Requests duren te lang

**Oplossingen:**
```python
# Verhoog timeout in function
response = requests.post(
    ...,
    timeout=60  # Verhoog van 30 naar 60 seconden
)

# Of pas MCP server rate limiting aan
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
    --rate-minute 120  # Verhoog rate limit
```

### Ollama model laadt niet

**Symptoom:** Ollama antwoorden zijn traag of missen

**Oplossingen:**
```bash
# Check Ollama status
ollama list
ollama ps

# Pull model opnieuw
ollama pull llama3.2

# Check Ollama logs
docker logs ollama  # Als je Ollama in Docker draait

# Test Ollama direct
curl http://localhost:11434/api/generate -d '{
  "model": "llama3.2",
  "prompt": "Hello"
}'
```

### Function wordt niet aangeroepen

**Symptoom:** AI gebruikt de function niet automatisch

**Oplossingen:**

1. **Wees expliciet in je vragen:**
   - ❌ "What's happening?"
   - ✅ "Show me recent security threats"
   - ✅ "Analyze IP 185.220.101.50"

2. **Enable function calling in model settings:**
   - Open WebUI → Settings → Models
   - Selecteer je model
   - Enable "Function Calling"

3. **Gebruik kleinere, snellere models:**
   - `llama3.2:latest` (sneller met functions)
   - `mistral:latest` (goed in tool gebruik)
   - Niet: zeer grote models (70B+) kunnen trager zijn

---

## 📊 Performance Tips

### Caching voor snelheid

Voeg caching toe aan de function:

```python
from datetime import datetime, timedelta

class Function:
    def __init__(self):
        self.valves = self.Valves()
        self.cache = {}
        self.cache_ttl = 60  # 60 seconden

    def _get_cached(self, cache_key: str, fetch_func):
        """Get from cache or fetch fresh"""
        now = datetime.now()

        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if (now - cached_time).seconds < self.cache_ttl:
                return cached_data

        # Cache miss, fetch fresh data
        data = fetch_func()
        self.cache[cache_key] = (data, now)
        return data

    def get_sensor_status(self) -> str:
        return self._get_cached(
            'sensor_status',
            lambda: self._call_mcp_api('get_sensor_status', {})
        )
```

### Async Requests (Advanced)

Voor meerdere API calls tegelijk:

```python
import asyncio
import aiohttp

async def _call_mcp_api_async(self, tool_name: str, parameters: dict) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{self.valves.MCP_API_URL}/mcp/tools/execute",
            headers={'Authorization': f'Bearer {self.valves.MCP_API_TOKEN}'},
            json={'tool_name': tool_name, 'parameters': parameters}
        ) as response:
            return await response.json()

def get_dashboard_summary(self) -> str:
    # Run multiple API calls in parallel
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(asyncio.gather(
        self._call_mcp_api_async('get_recent_threats', {}),
        self._call_mcp_api_async('get_sensor_status', {}),
        self._call_mcp_api_async('get_dashboard_summary', {})
    ))

    # Combine results
    return formatted_output
```

---

## 🔒 Security Best Practices

### Token Management

```bash
# 1. Gebruik read_only voor Open WebUI
python3 mcp_server/manage_tokens.py create \
    --name "Open WebUI Production" \
    --scope read_only \
    --rate-minute 60 \
    --expires-days 90

# 2. Roteer tokens regelmatig
python3 mcp_server/manage_tokens.py revoke 5
python3 mcp_server/manage_tokens.py create --name "Open WebUI (rotated)"

# 3. Monitor usage
python3 mcp_server/manage_tokens.py stats
```

### Environment Variables (voor Docker)

Sla tokens niet hardcoded op, gebruik environment variables:

```bash
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -e MCP_API_TOKEN="your_token_here" \
  -v open-webui:/app/backend/data \
  ghcr.io/open-webui/open-webui:main
```

In de function:
```python
import os

class Valves(BaseModel):
    MCP_API_TOKEN: str = Field(
        default=os.environ.get('MCP_API_TOKEN', ''),
        description="MCP API Bearer token"
    )
```

---

## 📚 Meer Informatie

**NetMonitor MCP Documentatie:**
- HTTP API Quick Start: `mcp_server/HTTP_API_QUICKSTART.md`
- Complete API Docs: `MCP_HTTP_API.md`
- Claude Desktop Setup: `mcp_server/CLAUDE_DESKTOP_CONFIG.md`
- Installation Guide: `mcp_server/INSTALLATION.md`

**Open WebUI Resources:**
- Documentation: https://docs.openwebui.com
- Functions Guide: https://docs.openwebui.com/features/plugin/functions
- GitHub: https://github.com/open-webui/open-webui
- Discord: https://discord.gg/openwebui

**Ollama Models:**
- Model Library: https://ollama.com/library
- Llama 3.2: https://ollama.com/library/llama3.2
- Mistral: https://ollama.com/library/mistral

**MCP Protocol:**
- Token Management: `python3 mcp_server/manage_tokens.py --help`
- Live API Docs: https://soc.poort.net:8000/docs
- Health Check: https://soc.poort.net:8000/health

---

## ✅ Checklist Setup

- [ ] Ollama geïnstalleerd en draait (`ollama list`)
- [ ] Model gepulled (`ollama pull llama3.2`)
- [ ] Open WebUI geïnstalleerd en toegankelijk (http://localhost:3000)
- [ ] Admin account aangemaakt in Open WebUI
- [ ] MCP API token aangemaakt (`manage_tokens.py create`)
- [ ] Function code gekopieerd en opgeslagen in Open WebUI
- [ ] MCP_API_TOKEN ingevuld in Function Settings
- [ ] MCP_API_URL correct ingesteld
- [ ] SSL verificatie geconfigureerd (VERIFY_SSL)
- [ ] Test query uitgevoerd ("Show me sensor status")
- [ ] Function aangeroepen en resultaat ontvangen

---

## 🎉 Conclusie

Je hebt nu een krachtige setup:

- 🤖 **Ollama** - Lokale LLM models zonder cloud dependency
- 🌐 **Open WebUI** - Moderne, gebruiksvriendelijke interface
- 🔧 **NetMonitor Functions** - Directe toegang tot security tools
- 🔐 **Token Auth** - Veilige API toegang met rate limiting
- 📊 **Real-time Data** - Live security monitoring via AI

**Wat je kunt doen:**
- "Show me critical threats from the last hour"
- "Analyze IP 185.220.101.50"
- "Which sensors are offline?"
- "What's the current security situation?"
- "Are we under attack?"

De AI begrijpt natuurlijke taal, roept de juiste NetMonitor tools aan, en geeft je duidelijke antwoorden met data uit je eigen SOC.

**Veel plezier met je AI-powered Security Operations Center!** 🚀

---

**Vragen of problemen?**
Check de troubleshooting sectie of test de API direct:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://soc.poort.net:8000/mcp/tools
```