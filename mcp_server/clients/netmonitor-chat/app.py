#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025
"""
NetMonitor Chat - Hybrid Web Interface (Native Streamable HTTP MCP)

Optimized on-prem chat interface with:
- Native MCP client (no bridge subprocess overhead)
- Hybrid intent matching (fast path for common queries)
- Real-time status feedback to prevent "nothing happening" feeling
- Streaming MCP support (SSE)

Architecture:
  User Question
       |
       v
  [Quick Intent Match] ---> Direct Tool Call (< 2 sec)
       |                         |
       | (no match)              v
       v                    [LLM Format Response]
  [LLM + Tools] (slower)         |
       |                         v
       v                    Stream to User
  Stream to User

Start:
    uvicorn app:app --host 0.0.0.0 --port 8000
"""

import os
import sys
import json
import asyncio
import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator, Any, Tuple
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import httpx
import uvicorn

# ------------------------------------------------------------
# Config & helpers
# ------------------------------------------------------------

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "https://soc.poort.net/mcp")
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")


def load_mcp_configurations() -> List[Dict[str, str]]:
    """Load MCP server configurations from environment variables."""
    configs: List[Dict[str, str]] = []
    config_indices = set()

    for key in os.environ:
        if key.startswith("MCP_CONFIG_") and key.endswith("_NAME"):
            try:
                idx = key.replace("MCP_CONFIG_", "").replace("_NAME", "")
                config_indices.add(idx)
            except Exception:
                pass

    for idx in sorted(config_indices):
        name = os.getenv(f"MCP_CONFIG_{idx}_NAME", "")
        url = os.getenv(f"MCP_CONFIG_{idx}_URL", "")
        token = os.getenv(f"MCP_CONFIG_{idx}_TOKEN", "")
        if name and url:
            configs.append({"name": name, "url": url, "token": token})

    if not configs and MCP_SERVER_URL:
        configs.append({"name": "Default", "url": MCP_SERVER_URL, "token": MCP_AUTH_TOKEN})

    return configs


MCP_CONFIGURATIONS = load_mcp_configurations()
DEFAULT_MCP_CONFIG = MCP_CONFIGURATIONS[0] if MCP_CONFIGURATIONS else {
    "name": "Default", "url": MCP_SERVER_URL, "token": MCP_AUTH_TOKEN
}


def get_mcp_config_by_name(name: str) -> Optional[Dict[str, str]]:
    for cfg in MCP_CONFIGURATIONS:
        if cfg["name"] == name:
            return cfg
    return None


# ------------------------------------------------------------
# Quick Intent Matching (Hybrid Fast Path)
# ------------------------------------------------------------

# Common query patterns mapped to tools with default arguments
# Format: (regex_pattern, tool_name, default_args, description)
# NOTE: Tool names must match exactly what's defined in shared_tools.py
QUICK_INTENTS: List[Tuple[str, str, Dict[str, Any], str]] = [
    # Sensor status
    (r"(toon|show|geef|laat.*zien|list).*(sensor|sensors)",
     "get_sensor_status", {}, "sensor status ophalen"),
    (r"(sensor|sensors).*(status|actief|active)",
     "get_sensor_status", {}, "sensor status ophalen"),

    # Threats / Detections
    (r"(recente|laatste|recent).*(threat|dreig|bedreiging|alert|detectie)",
     "get_threat_detections", {"hours": 24, "limit": 20}, "recente bedreigingen ophalen"),
    (r"(toon|show|geef).*(threat|dreig|bedreiging|alert|detectie)",
     "get_threat_detections", {"hours": 24, "limit": 20}, "bedreigingen ophalen"),
    (r"(threat|dreig|bedreiging|alert).*(vandaag|today|recent)",
     "get_threat_detections", {"hours": 24, "limit": 20}, "bedreigingen ophalen"),

    # Top talkers / bandwidth
    (r"(top|grootste|meeste).*(talker|bandwidth|traffic|verkeer)",
     "get_top_talkers", {"hours": 1, "limit": 10}, "top talkers ophalen"),
    (r"(wie|welke).*(meeste|grootste).*(bandwidth|traffic|data)",
     "get_top_talkers", {"hours": 1, "limit": 10}, "top talkers ophalen"),

    # Devices
    (r"(toon|show|geef|list).*(device|devices|apparaat|apparaten)",
     "get_devices", {"limit": 50}, "devices ophalen"),
    (r"(hoeveel|aantal).*(device|devices|apparaat|apparaten)",
     "get_devices", {"limit": 100}, "devices tellen"),

    # Memory / System status
    (r"(memory|geheugen).*(status|gebruik|usage)",
     "get_memory_status", {}, "geheugen status ophalen"),
    (r"(systeem|system).*(status|health|gezondheid)",
     "get_memory_status", {}, "systeem status ophalen"),

    # Risk assets
    (r"(risico|risk).*(asset|assets|apparaat|apparaten)",
     "get_top_risk_assets", {"limit": 10}, "risicovolle assets ophalen"),
    (r"(top|hoogste).*(risico|risk)",
     "get_top_risk_assets", {"limit": 10}, "hoogste risico assets ophalen"),

    # TLS stats
    (r"(tls|ssl|https).*(stat|status|overzicht)",
     "get_tls_stats", {}, "TLS statistieken ophalen"),

    # Kerberos
    (r"(kerberos).*(stat|attack|aanval)",
     "get_kerberos_stats", {}, "Kerberos statistieken ophalen"),

    # PCAP
    (r"(pcap|packet|capture).*(stat|status|overzicht)",
     "get_pcap_stats", {}, "PCAP statistieken ophalen"),

    # Whitelist
    (r"(whitelist|witte.*lijst).*(toon|show|geef|list)",
     "get_whitelist_entries", {}, "whitelist entries ophalen"),
    (r"(toon|show|geef).*(whitelist|witte.*lijst)",
     "get_whitelist_entries", {}, "whitelist entries ophalen"),

    # Threat Intel lookups
    (r"(intel|info|informatie|reputation|reputatie).*(over|voor|van).*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
     "lookup_threat_intel", {}, "threat intel opzoeken"),
    (r"(is|check|controleer).*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(malicious|kwaadaardig|gevaarlijk|verdacht)",
     "lookup_threat_intel", {}, "IP reputatie controleren"),

    # Security recommendations
    (r"(aanbevel|recommend|advies|advice).*(voor|for|bij).*(brute|force|login|auth)",
     "get_security_recommendation", {"threat_type": "brute_force"}, "aanbevelingen voor brute force"),
    (r"(aanbevel|recommend|advies|advice).*(voor|for|bij).*(malware|c2|command|control)",
     "get_security_recommendation", {"threat_type": "malware_c2"}, "aanbevelingen voor malware C2"),
    (r"(aanbevel|recommend|advies|advice).*(voor|for|bij).*(exfil|datalek|data.*leak)",
     "get_security_recommendation", {"threat_type": "data_exfiltration"}, "aanbevelingen voor data exfiltratie"),
    (r"(aanbevel|recommend|advies|advice).*(voor|for|bij).*(ransom|gijzel)",
     "get_security_recommendation", {"threat_type": "ransomware_indicator"}, "aanbevelingen voor ransomware"),
    (r"(aanbevel|recommend|advies|advice).*(voor|for|bij).*(lateral|beweging|movement)",
     "get_security_recommendation", {"threat_type": "lateral_movement"}, "aanbevelingen voor laterale beweging"),
    (r"(aanbevel|recommend|advies|advice).*(voor|for|bij).*(phish)",
     "get_security_recommendation", {"threat_type": "phishing"}, "aanbevelingen voor phishing"),

    # Web search - REMOVED: web_search requires a query parameter that must be
    # determined by the LLM based on context. Quick intents can't provide this.
    # The LLM will call web_search with appropriate query when needed.

    # DNS lookup
    (r"(wat.*is|geef|vind).*(ip|ip-adres|ip.*address).*(van|voor|of)",
     "dns_lookup", {}, "DNS lookup uitvoeren"),
    (r"(dns|resolve|lookup).*(domain|domein|hostname)",
     "dns_lookup", {}, "DNS lookup uitvoeren"),
]


def quick_intent_match(message: str) -> Optional[Tuple[str, Dict[str, Any], str]]:
    """
    Try to match message against quick intent patterns.

    Returns:
        (tool_name, arguments, description) if matched, None otherwise
    """
    message_lower = message.lower().strip()

    for pattern, tool_name, default_args, description in QUICK_INTENTS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            # Extract any numbers from the message for hours/limit parameters
            args = default_args.copy()

            # Try to extract time period (e.g., "laatste 2 uur", "last 24 hours")
            time_match = re.search(r'(\d+)\s*(uur|hour|h|dag|day|d|min|minute|m)', message_lower)
            if time_match:
                num = int(time_match.group(1))
                unit = time_match.group(2)
                if unit in ('dag', 'day', 'd'):
                    num *= 24
                elif unit in ('min', 'minute', 'm'):
                    num = max(1, num // 60)  # Convert to hours, min 1
                if 'hours' in args:
                    args['hours'] = num

            # Try to extract limit (e.g., "top 5", "laatste 20")
            limit_match = re.search(r'(top|laatste|first|limit)\s*(\d+)', message_lower)
            if limit_match:
                if 'limit' in args:
                    args['limit'] = int(limit_match.group(2))

            # Try to extract IP address for threat intel lookups
            if tool_name == "lookup_threat_intel" and 'ip' not in args:
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                if ip_match:
                    args['ip'] = ip_match.group(1)

            print(f"[QuickMatch] Matched '{message}' -> {tool_name}({args})")
            return (tool_name, args, description)

    return None


# ------------------------------------------------------------
# Native MCP Streamable HTTP Client
# ------------------------------------------------------------

class MCPStreamableHTTPClient:
    """
    Native MCP client using Streamable HTTP transport.

    Features:
    - Direct HTTP communication (no subprocess overhead)
    - SSE streaming support for progress/notifications
    - Session management via Mcp-Session-Id header
    - Connection reuse for efficiency
    """

    def __init__(self, server_url: str, auth_token: str, timeout: float = 120.0):
        self.server_url = server_url.rstrip("/")
        self.auth_token = auth_token or ""
        self._session_id: Optional[str] = None
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=timeout, write=30.0, pool=5.0)
        )

    async def close(self):
        try:
            await self._client.aclose()
        except Exception:
            pass

    def _base_headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    async def initialize(self) -> Dict[str, Any]:
        """Initialize MCP session and capture session ID."""
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "initialize",
            "params": {}
        }
        r = await self._client.post(self.server_url, headers=self._base_headers(), json=payload)
        r.raise_for_status()
        sid = r.headers.get("Mcp-Session-Id")
        if sid:
            self._session_id = sid
        return r.json()

    async def _ensure_initialized(self):
        if not self._session_id:
            try:
                await self.initialize()
            except Exception:
                pass  # Not all servers require initialization

    async def rpc_stream(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Execute JSON-RPC call with SSE streaming support.

        Yields:
            Dict for each response message (JSON or SSE event)
        """
        await self._ensure_initialized()
        rid = request_id or str(uuid.uuid4())
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params

        async with self._client.stream("POST", self.server_url, headers=self._base_headers(), json=payload) as r:
            r.raise_for_status()
            ctype = r.headers.get("content-type", "")

            if "text/event-stream" in ctype:
                # SSE stream
                async for line in r.aiter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data = line[6:]
                        if data.strip() == "[DONE]":
                            break
                        try:
                            msg = json.loads(data)
                            yield msg
                        except json.JSONDecodeError:
                            continue
            else:
                # Single JSON response
                try:
                    raw = await r.aread()
                    msg = json.loads(raw)
                except Exception:
                    msg = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32700, "message": "Parse error"}}
                yield msg

    async def rpc_collect(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute RPC and wait for final response."""
        rid = str(uuid.uuid4())
        final: Optional[Dict[str, Any]] = None
        async for msg in self.rpc_stream(method, params, request_id=rid):
            if isinstance(msg, dict) and msg.get("id") == rid and ("result" in msg or "error" in msg):
                final = msg
                break
        return final or {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "No response"}}

    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available MCP tools."""
        resp = await self.rpc_collect("tools/list", {})
        if "error" in resp:
            return []
        return resp.get("result", {}).get("tools", []) or []

    async def call_tool_stream(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Call tool with streaming support for progress notifications.

        Yields:
            {'type': 'notification', 'message': {...}} for progress updates
            {'type': 'result', 'result': {...}} for final result
        """
        rid = str(uuid.uuid4())
        params = {"name": name, "arguments": arguments or {}}
        async for msg in self.rpc_stream("tools/call", params, request_id=rid):
            if "id" not in msg and "method" in msg:
                # Server notification (progress, etc.)
                yield {"type": "notification", "message": msg}
            elif msg.get("id") == rid and ("result" in msg or "error" in msg):
                yield {"type": "result", **msg}
                break

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call tool and return result (non-streaming)."""
        resp = await self.rpc_collect("tools/call", {"name": name, "arguments": arguments or {}})
        if "error" in resp:
            return {"success": False, "error": resp["error"].get("message", "Unknown error")}
        content = resp.get("result", {}).get("content", [])
        if content and isinstance(content, list) and content[0].get("type") == "text":
            txt = content[0].get("text", "")
            try:
                return {"success": True, "data": json.loads(txt)}
            except json.JSONDecodeError:
                return {"success": True, "data": txt}
        return {"success": True, "data": resp.get("result")}


# ------------------------------------------------------------
# RAG Enrichment: Extract and lookup threat context
# ------------------------------------------------------------

def extract_ips_from_result(result: Any, max_ips: int = 5) -> List[str]:
    """Extract unique IP addresses from tool result data."""
    ips: set = set()
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

    def search_recursive(obj):
        if len(ips) >= max_ips:
            return
        if isinstance(obj, str):
            for match in ip_pattern.findall(obj):
                if not match.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                         '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                                         '127.', '0.')):
                    ips.add(match)
        elif isinstance(obj, dict):
            for key, val in obj.items():
                if key in ('src_ip', 'dest_ip', 'ip', 'source_ip', 'destination_ip', 'remote_ip', 'external_ip'):
                    if isinstance(val, str) and ip_pattern.match(val):
                        if not val.startswith(('10.', '192.168.', '172.16.', '127.', '0.')):
                            ips.add(val)
                else:
                    search_recursive(val)
        elif isinstance(obj, list):
            for item in obj:
                search_recursive(item)

    search_recursive(result)
    return list(ips)[:max_ips]


def extract_threat_types_from_result(result: Any) -> List[str]:
    """Extract threat type keywords from tool result for recommendation lookup."""
    threat_types: set = set()

    # Keywords that map to knowledge base categories
    keyword_mappings = {
        'malware': 'malware_c2',
        'c2': 'malware_c2',
        'command': 'malware_c2',
        'control': 'malware_c2',
        'brute': 'brute_force',
        'login': 'brute_force',
        'auth': 'brute_force',
        'scan': 'port_scan',
        'reconnaissance': 'port_scan',
        'exfil': 'data_exfiltration',
        'transfer': 'data_exfiltration',
        'lateral': 'lateral_movement',
        'movement': 'lateral_movement',
        'dns': 'dns_tunneling',
        'tunnel': 'dns_tunneling',
        'crypto': 'cryptomining',
        'mining': 'cryptomining',
        'miner': 'cryptomining',
        'phish': 'phishing',
        'tor': 'tor_usage',
        'ransom': 'ransomware_indicator',
        'encrypt': 'ransomware_indicator',
    }

    def search_recursive(obj):
        if isinstance(obj, str):
            obj_lower = obj.lower()
            for keyword, threat_type in keyword_mappings.items():
                if keyword in obj_lower:
                    threat_types.add(threat_type)
        elif isinstance(obj, dict):
            for key, val in obj.items():
                if key in ('threat_type', 'category', 'alert_type', 'signature', 'rule', 'description'):
                    search_recursive(val)
                elif key in ('threats', 'alerts', 'detections', 'data'):
                    search_recursive(val)
        elif isinstance(obj, list):
            for item in obj:
                search_recursive(item)

    search_recursive(result)
    return list(threat_types)[:3]  # Max 3 threat types


async def enrich_with_threat_intel(
    mcp_client: 'MCPStreamableHTTPClient',
    tool_result: Dict[str, Any],
    send_status_func
) -> str:
    """
    Enrich tool results with threat intelligence and security recommendations.

    Returns context string to add to LLM prompt.
    """
    enrichment_parts = []

    if not tool_result.get("success"):
        return ""

    data = tool_result.get("data", {})

    # Extract and lookup IPs
    ips = extract_ips_from_result(data)
    if ips:
        await send_status_func(f"Threat intel opzoeken voor {len(ips)} IP(s)...", "enriching")
        for ip in ips[:3]:  # Limit to 3 lookups
            try:
                intel_result = await mcp_client.call_tool("lookup_threat_intel", {"ip": ip})
                if intel_result.get("success") and intel_result.get("data"):
                    intel_data = intel_result["data"]
                    if isinstance(intel_data, dict):
                        # Check if threat found
                        if intel_data.get("is_known_threat") or intel_data.get("threat_level") in ("high", "critical"):
                            enrichment_parts.append(f"⚠️ Threat Intel voor {ip}: {json.dumps(intel_data, ensure_ascii=False)[:500]}")
                        elif intel_data.get("cached_info") or intel_data.get("sources"):
                            enrichment_parts.append(f"ℹ️ Intel voor {ip}: {json.dumps(intel_data, ensure_ascii=False)[:300]}")
            except Exception as e:
                print(f"[RAG] Error looking up IP {ip}: {e}")

    # Extract and lookup threat types for recommendations
    threat_types = extract_threat_types_from_result(data)
    if threat_types:
        await send_status_func("Aanbevelingen ophalen...", "enriching")
        for threat_type in threat_types:
            try:
                rec_result = await mcp_client.call_tool("get_security_recommendation", {"threat_type": threat_type})
                if rec_result.get("success") and rec_result.get("data"):
                    rec_data = rec_result["data"]
                    if isinstance(rec_data, dict) and rec_data.get("recommendations"):
                        recs = rec_data["recommendations"][:5]  # Top 5 recommendations
                        mitre = rec_data.get("mitre_techniques", [])
                        enrichment_parts.append(f"📋 Aanbevelingen voor {threat_type}:")
                        enrichment_parts.append(f"   MITRE: {', '.join(mitre[:3]) if mitre else 'N/A'}")
                        for rec in recs:
                            enrichment_parts.append(f"   • {rec}")
            except Exception as e:
                print(f"[RAG] Error getting recommendations for {threat_type}: {e}")

    if enrichment_parts:
        return "\n\n--- SECURITY CONTEXT (uit knowledge base) ---\n" + "\n".join(enrichment_parts)
    return ""


# ------------------------------------------------------------
# Tool helpers
# ------------------------------------------------------------

def extract_tool_call_from_text(text: str) -> Optional[Dict[str, Any]]:
    """Extract tool call JSON from model output text."""
    text = text.strip()

    # Try pure JSON (starts with {)
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if "name" in data:
                return {"name": data["name"], "arguments": data.get("arguments", data.get("params", {}))}
        except json.JSONDecodeError:
            pass

    # Try ```json ... ```
    json_block_match = re.search(r'```(?:json)?\s*(\{[^`]+\})\s*```', text, re.DOTALL)
    if json_block_match:
        try:
            data = json.loads(json_block_match.group(1))
            if "name" in data:
                return {"name": data["name"], "arguments": data.get("arguments", data.get("params", {}))}
        except json.JSONDecodeError:
            pass

    # Find JSON with "name" field - handle nested braces by finding balanced JSON
    # Look for {"name": and then try to parse balanced JSON from that position
    name_match = re.search(r'\{"name"\s*:', text)
    if name_match:
        start_pos = name_match.start()
        # Try to find balanced braces
        brace_count = 0
        end_pos = start_pos
        for i, char in enumerate(text[start_pos:], start_pos):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break

        if end_pos > start_pos:
            try:
                json_str = text[start_pos:end_pos]
                data = json.loads(json_str)
                if "name" in data:
                    return {"name": data["name"], "arguments": data.get("arguments", data.get("params", {}))}
            except json.JSONDecodeError:
                pass

    # Last resort: try to find any JSON object in the text
    for match in re.finditer(r'\{', text):
        start_pos = match.start()
        brace_count = 0
        for i, char in enumerate(text[start_pos:], start_pos):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    try:
                        json_str = text[start_pos:i + 1]
                        data = json.loads(json_str)
                        if "name" in data:
                            return {"name": data["name"], "arguments": data.get("arguments", data.get("params", {}))}
                    except json.JSONDecodeError:
                        pass
                    break

    return None


def build_tool_prompt(tools: List[Dict[str, Any]], user_system_prompt: str = "") -> str:
    """Build system prompt with tool instructions for JSON fallback mode."""
    tool_descriptions = []
    for tool in tools[:10]:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "No description")[:100]
        params = tool.get("inputSchema", {}).get("properties", {})
        param_names = list(params.keys())[:3]
        tool_descriptions.append(f"- {name}: {desc} (params: {param_names})")

    tools_text = "\n".join(tool_descriptions)

    return f"""{user_system_prompt}

Je bent een security assistent voor NetMonitor. Je kunt tools aanroepen om actuele netwerkdata op te halen.

BESCHIKBARE TOOLS:
{tools_text}

BELANGRIJKE TOOL PARAMETERS:
- web_search VEREIST query: {{"name": "web_search", "arguments": {{"query": "zoekterm hier"}}}}
- dns_lookup VEREIST domain: {{"name": "dns_lookup", "arguments": {{"domain": "example.com"}}}}
- get_top_talkers: hours=168 voor week, hours=24 voor dag
- get_sensor_status: geen arguments nodig {{}}

HOE TOOLS TE GEBRUIKEN:
1. Antwoord met ALLEEN JSON (geen tekst ervoor of erna):
   {{"name": "tool_naam", "arguments": {{"param": "waarde"}}}}

2. Na het resultaat kun je:
   - Nog een tool aanroepen (weer alleen JSON)
   - Of een eindantwoord geven (geen JSON, gewoon Nederlands)

3. Roep tools ÉÉN VOOR ÉÉN aan.

WORKFLOW VOOR RAPPORTAGES:
Stap 1: {{"name": "get_sensor_status", "arguments": {{}}}}
Stap 2: {{"name": "get_top_talkers", "arguments": {{"hours": 168, "limit": 10}}}}
Stap 3: {{"name": "get_threat_detections", "arguments": {{"hours": 24}}}}
Stap 4: {{"name": "web_search", "arguments": {{"query": "network security recommendations"}}}}
Stap 5: Nederlands rapport met alle data (GEEN JSON)

BELANGRIJK: Start DIRECT met JSON, geen tekst ervoor."""


def filter_relevant_tools(user_message: str, all_tools: List[Dict[str, Any]], max_tools: int = 10) -> List[Dict[str, Any]]:
    """Filter tools based on keyword relevance to user message."""
    if not all_tools:
        return []

    message_lower = user_message.lower()

    keyword_mappings = {
        'threat': (['threat', 'detection', 'alert', 'malware', 'attack', 'bedreig', 'dreig'],
                   ['threat', 'detection', 'alert', 'malware', 'attack']),
        'ip':     (['ip', 'address', 'adres'], ['ip', 'address', 'addr']),
        'sensor': (['sensor', 'sensors'], ['sensor', 'zeek', 'suricata']),
        'log':    (['log', 'logs'], ['log', 'syslog', 'event']),
        'network':(['network', 'netwerk', 'traffic', 'verkeer'], ['network', 'traffic', 'flow', 'connection']),
        'toptalker': (['top', 'talker', 'talkers', 'meeste', 'grootste', 'bandwidth', 'volume'],
                      ['traffic', 'stats', 'top', 'bandwidth', 'volume', 'bytes']),
        'dns':    (['dns', 'domain'], ['dns', 'domain', 'query']),
        'file':   (['file', 'bestand'], ['file', 'hash', 'executable']),
        'user':   (['user', 'gebruiker', 'account'], ['user', 'account', 'authentication', 'auth']),
        'port':   (['port', 'poort', 'service'], ['port', 'service', 'scan']),
        'status': (['status', 'actieve', 'active', 'running'], ['status', 'state', 'active', 'running']),
        'show':   (['toon', 'laat', 'zie', 'show', 'list', 'geef'], ['get', 'list', 'show', 'fetch'])
    }

    scored_tools = []
    for tool in all_tools:
        score = 0
        tool_name_lower = tool.get('name', '').lower()
        tool_desc_lower = tool.get('description', '').lower()

        for category, (user_keywords, tool_keywords) in keyword_mappings.items():
            user_mentioned = any(kw in message_lower for kw in user_keywords)
            if user_mentioned:
                tool_has_category = any(kw in tool_name_lower or kw in tool_desc_lower for kw in tool_keywords)
                if tool_has_category:
                    score += 10
                    matches = sum(1 for kw in tool_keywords if kw in tool_name_lower or kw in tool_desc_lower)
                    if matches > 1:
                        score += 5

        words_in_message = set(re.findall(r'\w+', message_lower))
        words_in_tool = set(re.findall(r'\w+', tool_name_lower))
        overlap = words_in_message & words_in_tool
        if overlap:
            score += len(overlap) * 5

        if any(essential in tool_name_lower for essential in ['get', 'list', 'show', 'fetch']):
            score += 1

        scored_tools.append((score, tool))

    scored_tools.sort(reverse=True, key=lambda x: x[0])
    relevant_tools = [tool for score, tool in scored_tools if score > 0][:max_tools]

    if len(relevant_tools) == 0:
        relevant_tools = [tool for score, tool in scored_tools[:max_tools]]

    return relevant_tools


# ------------------------------------------------------------
# LLM Clients
# ------------------------------------------------------------

class OllamaClient:
    """Client for Ollama API"""

    def __init__(self, base_url: str = OLLAMA_BASE_URL):
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=120.0)

    async def list_models(self) -> List[Dict[str, Any]]:
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            return response.json().get("models", [])
        except Exception as e:
            print(f"[Ollama] Error: {e}")
            return []

    async def chat(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        stream: bool = True,
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "options": {"temperature": temperature}
        }
        if tools:
            payload["tools"] = tools

        try:
            async with self.client.stream("POST", f"{self.base_url}/api/chat", json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.strip():
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            yield {"error": str(e)}

    async def close(self):
        await self.client.aclose()


class LMStudioClient:
    """Client for LM Studio (OpenAI-compatible API)"""

    def __init__(self, base_url: str = "http://localhost:1234"):
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=300.0)

    async def list_models(self) -> List[Dict[str, Any]]:
        try:
            response = await self.client.get(f"{self.base_url}/v1/models")
            response.raise_for_status()
            models = response.json().get("data", [])
            return [{"name": m.get("id", "unknown")} for m in models]
        except Exception as e:
            print(f"[LM Studio] Error: {e}")
            return []

    async def chat(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        stream: bool = True,
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "temperature": temperature
        }
        if tools:
            payload["tools"] = tools

        try:
            async with self.client.stream("POST", f"{self.base_url}/v1/chat/completions", json=payload) as response:
                if response.status_code != 200:
                    error_text = await response.aread()
                    yield {"error": f"LM Studio error {response.status_code}: {error_text.decode()}"}
                    return

                buffer = ""
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    if line.startswith("event:"):
                        continue
                    if line.startswith("data: "):
                        line = line[6:]
                    if line.strip() == "[DONE]":
                        yield {"done": True}
                        continue

                    buffer += line.strip()
                    if not buffer.endswith("}"):
                        continue

                    try:
                        chunk = json.loads(buffer)
                        buffer = ""
                        choices = chunk.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            content = delta.get("content", "")
                            tool_calls = delta.get("tool_calls", [])

                            ollama_chunk: Dict[str, Any] = {
                                "message": {
                                    "role": delta.get("role", "assistant"),
                                    "content": content
                                },
                                "done": choices[0].get("finish_reason") is not None
                            }

                            if tool_calls:
                                ollama_chunk["message"]["tool_calls"] = [
                                    {
                                        "id": tc.get("id", f"call_{tc.get('index', 0)}"),
                                        "index": tc.get("index", 0),
                                        "type": tc.get("type", "function"),
                                        "function": {
                                            "name": tc.get("function", {}).get("name", ""),
                                            "arguments": tc.get("function", {}).get("arguments", "")
                                        }
                                    }
                                    for tc in tool_calls
                                ]

                            yield ollama_chunk
                    except json.JSONDecodeError:
                        continue

        except httpx.TimeoutException:
            yield {"error": "LM Studio timeout"}
        except Exception as e:
            yield {"error": str(e)}

    async def close(self):
        await self.client.aclose()


# ------------------------------------------------------------
# FastAPI App
# ------------------------------------------------------------

class LLMConfig(BaseModel):
    provider: str = "ollama"
    url: str = "http://localhost:11434"

class MCPConfig(BaseModel):
    url: str = DEFAULT_MCP_CONFIG["url"]
    token: str = DEFAULT_MCP_CONFIG["token"]
    config_name: Optional[str] = None

class HealthConfig(BaseModel):
    llm_provider: str = "ollama"
    llm_url: str = "http://localhost:11434"
    mcp_url: str = DEFAULT_MCP_CONFIG["url"]
    mcp_token: str = DEFAULT_MCP_CONFIG["token"]
    mcp_config_name: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="NetMonitor Chat",
    description="On-premise chat interface with NetMonitor MCP tools",
    version="2.0.0",
    lifespan=lifespan
)

app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


# ------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------

@app.get("/")
async def root():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/mcp-configs")
async def get_mcp_configs():
    safe_configs = [{"name": c["name"], "url": c["url"], "has_token": bool(c["token"])} for c in MCP_CONFIGURATIONS]
    return {"configs": safe_configs, "default": DEFAULT_MCP_CONFIG["name"] if MCP_CONFIGURATIONS else None}


@app.post("/api/models")
async def post_models(config: LLMConfig):
    try:
        client = LMStudioClient(config.url) if config.provider == "lmstudio" else OllamaClient(config.url)
        models = await client.list_models()
        await client.close()
        return {"models": models}
    except Exception as e:
        print(f"Error getting models: {e}")
        return {"models": []}


@app.post("/api/tools")
async def post_tools(config: MCPConfig):
    try:
        url, token = config.url, config.token
        if config.config_name:
            named_config = get_mcp_config_by_name(config.config_name)
            if named_config:
                url, token = named_config["url"], named_config["token"]

        mcp = MCPStreamableHTTPClient(url, token)
        tools = await mcp.list_tools()
        await mcp.close()
        return {"tools": tools, "count": len(tools)}
    except Exception as e:
        print(f"Error getting tools: {e}")
        return {"tools": [], "count": 0}


@app.post("/api/health")
async def post_health(config: HealthConfig):
    try:
        llm_client = LMStudioClient(config.llm_url) if config.llm_provider == "lmstudio" else OllamaClient(config.llm_url)
        llm_ok = len(await llm_client.list_models()) > 0
        await llm_client.close()

        mcp_url, mcp_token = config.mcp_url, config.mcp_token
        if config.mcp_config_name:
            named_config = get_mcp_config_by_name(config.mcp_config_name)
            if named_config:
                mcp_url, mcp_token = named_config["url"], named_config["token"]

        mcp = MCPStreamableHTTPClient(mcp_url, mcp_token)
        mcp_ok = len(await mcp.list_tools()) > 0
        await mcp.close()

        return {
            "status": "healthy" if (llm_ok and mcp_ok) else "degraded",
            "ollama": "connected" if llm_ok else "disconnected",
            "mcp": "connected" if mcp_ok else "disconnected",
            "mcp_config": config.mcp_config_name or "custom",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error in health check: {e}")
        return {"status": "error", "ollama": "disconnected", "mcp": "disconnected", "timestamp": datetime.now().isoformat()}


# Backwards compatibility
@app.get("/api/models")
async def get_models():
    return await post_models(LLMConfig())

@app.get("/api/tools")
async def get_tools():
    return await post_tools(MCPConfig())

@app.get("/api/health")
async def get_health():
    return await post_health(HealthConfig())


# ------------------------------------------------------------
# WebSocket Chat with Hybrid Processing
# ------------------------------------------------------------

@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    """
    WebSocket endpoint with hybrid processing and status feedback.

    Protocol (server -> client):
      - {"type": "status", "message": "...", "phase": "..."}  # Status update
      - {"type": "token", "content": "..."}                   # LLM tokens
      - {"type": "tool_call", "tool": "...", "args": {...}}   # Tool being called
      - {"type": "tool_progress", "data": {...}}              # MCP progress
      - {"type": "tool_result", "tool": "...", "result": {...}}
      - {"type": "error", "content": "..."}
      - {"type": "done"}
    """
    await websocket.accept()

    async def send_status(message: str, phase: str = "processing"):
        """Send status update to client."""
        await websocket.send_json({"type": "status", "message": message, "phase": phase})

    try:
        while True:
            data = await websocket.receive_json()

            model = data.get("model", "llama3.1:8b")
            message = data.get("message", "")
            history = data.get("history", [])
            temperature = data.get("temperature", 0.3)
            system_prompt = data.get("system_prompt", "")

            llm_provider = data.get("llm_provider", "ollama")
            llm_url = data.get("llm_url", OLLAMA_BASE_URL)
            mcp_url = data.get("mcp_url", MCP_SERVER_URL)
            mcp_token = data.get("mcp_token", MCP_AUTH_TOKEN)
            mcp_config_name = data.get("mcp_config_name")
            force_tools_lmstudio = data.get("force_tools_lmstudio", False)

            if mcp_config_name:
                named_config = get_mcp_config_by_name(mcp_config_name)
                if named_config:
                    mcp_url, mcp_token = named_config["url"], named_config["token"]

            print(f"[WebSocket] Provider: {llm_provider}, Model: {model}")

            # Create clients
            llm_client = LMStudioClient(llm_url) if llm_provider == "lmstudio" else OllamaClient(llm_url)
            mcp_client = MCPStreamableHTTPClient(mcp_url, mcp_token)

            # ============================================================
            # HYBRID PATH: Try quick intent match first
            # ============================================================
            quick_match = quick_intent_match(message)

            if quick_match:
                tool_name, tool_args, description = quick_match

                await send_status(f"Herkenning: {description}", "quick_match")
                await asyncio.sleep(0.1)  # Brief pause so user sees status

                await send_status(f"Tool uitvoeren: {tool_name}", "tool_call")
                await websocket.send_json({"type": "tool_call", "tool": tool_name, "args": tool_args})

                # Execute tool with streaming
                final_result: Optional[Dict[str, Any]] = None
                async for evt in mcp_client.call_tool_stream(tool_name, tool_args):
                    if evt.get("type") == "notification":
                        msg = evt["message"]
                        if msg.get("method") == "progress":
                            await websocket.send_json({"type": "tool_progress", "data": msg.get("params", {})})
                    elif evt.get("type") == "result":
                        if "error" in evt:
                            final_result = {"success": False, "error": evt["error"].get("message", "Unknown error")}
                        else:
                            content = evt.get("result", {}).get("content", [])
                            if content and isinstance(content, list) and content[0].get("type") == "text":
                                txt = content[0].get("text", "")
                                try:
                                    final_result = {"success": True, "data": json.loads(txt)}
                                except json.JSONDecodeError:
                                    final_result = {"success": True, "data": txt}
                            else:
                                final_result = {"success": True, "data": evt.get("result")}
                        break

                await websocket.send_json({"type": "tool_result", "tool": tool_name, "result": final_result})

                # RAG Enrichment: Add threat intel and recommendations for relevant tools
                enrichment_context = ""
                threat_related_tools = ('get_threat_detections', 'get_threat_stats', 'get_top_risk_assets',
                                        'lookup_ip', 'search_threats', 'get_alerts')
                if tool_name in threat_related_tools and final_result:
                    enrichment_context = await enrich_with_threat_intel(mcp_client, final_result, send_status)

                # Format response with LLM (no tools = fast)
                await send_status("Antwoord formuleren...", "formatting")

                format_prompt = f"""De gebruiker vroeg: "{message}"

De tool {tool_name} gaf dit resultaat:
{json.dumps(final_result, indent=2, default=str)[:4000]}
{enrichment_context}

Geef een duidelijk en beknopt Nederlands antwoord gebaseerd op deze data.
Regels:
- Gebruik opsommingstekens voor lijsten
- Geen JSON in je antwoord
- Voeg GEEN opmerkingen toe over ontbrekende of afgebroken data
- Geef alleen een samenvatting van wat er WEL in de data staat
- Als er security context/aanbevelingen zijn, neem deze mee in je antwoord
- Eindig niet met waarschuwingen of disclaimers"""

                format_messages = [
                    {"role": "system", "content": system_prompt or "Je bent een security expert die duidelijke Nederlandse antwoorden geeft."},
                    {"role": "user", "content": format_prompt}
                ]

                async for chunk in llm_client.chat(model, format_messages, stream=True, temperature=temperature, tools=None):
                    if "error" in chunk:
                        await websocket.send_json({"type": "error", "content": chunk["error"]})
                        break
                    if "message" in chunk:
                        content = chunk["message"].get("content", "")
                        if content:
                            await websocket.send_json({"type": "token", "content": content})
                    if chunk.get("done"):
                        break

                await websocket.send_json({"type": "done"})
                await llm_client.close()
                await mcp_client.close()
                continue  # Wait for next message

            # ============================================================
            # SLOW PATH: Full LLM with tools
            # ============================================================
            await send_status("Vraag analyseren...", "analyzing")

            # Get and filter tools
            all_mcp_tools = await mcp_client.list_tools()
            max_tools = 10 if llm_provider == "lmstudio" else 15
            filtered_mcp_tools = filter_relevant_tools(message, all_mcp_tools, max_tools=max_tools)

            ollama_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool.get("inputSchema", {})
                    }
                }
                for tool in filtered_mcp_tools
            ]

            # Determine tool mode
            use_tools = None
            use_json_fallback = False

            if llm_provider == "ollama":
                use_tools = ollama_tools if ollama_tools else None
                await send_status(f"Model inschakelen met {len(ollama_tools)} tools...", "llm_thinking")
            elif llm_provider == "lmstudio" and force_tools_lmstudio:
                use_json_fallback = True
                await send_status(f"Model inschakelen (JSON fallback, {len(filtered_mcp_tools)} tools)...", "llm_thinking")
            else:
                await send_status("Model inschakelen...", "llm_thinking")

            # Build messages with appropriate system prompt
            messages: List[Dict[str, Any]] = []
            if use_json_fallback and filtered_mcp_tools:
                # JSON fallback mode - detailed tool instructions
                messages.append({"role": "system", "content": build_tool_prompt(filtered_mcp_tools, system_prompt)})
            elif use_tools:
                # Native tool calling mode - also needs multi-tool instructions
                native_tool_prompt = f"""{system_prompt}

Je bent een security assistent voor NetMonitor met toegang tot {len(ollama_tools)} tools.

BELANGRIJKE TOOL PARAMETERS:
- web_search(query="zoekterm") - VEREIST een query parameter, bijv: query="network security best practices"
- dns_lookup(domain="example.com") - VEREIST een domain parameter
- get_top_talkers(hours=168, limit=10) - hours=168 voor een week, hours=24 voor een dag
- get_threat_detections(hours=24, limit=20) - recente bedreigingen
- get_sensor_status() - geen parameters nodig

WORKFLOW VOOR RAPPORTAGES:
1. EERST netwerk data ophalen: get_sensor_status, get_top_talkers, get_threat_detections
2. DAARNA internet zoeken voor aanbevelingen: web_search(query="relevante zoekterm")
3. TENSLOTTE een compleet rapport schrijven met alle verzamelde informatie

Roep tools ÉÉN VOOR ÉÉN aan. Geef pas een eindantwoord als je ALLE benodigde data hebt."""
                messages.append({"role": "system", "content": native_tool_prompt})
            elif system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.extend(history + [{"role": "user", "content": message}])

            # Multi-tool loop: keep calling LLM until no more tool calls
            MAX_TOOL_ITERATIONS = 10  # Prevent infinite loops
            tool_iteration = 0
            called_tools: List[str] = []  # Track called tools to detect loops
            force_final_report = False  # Flag to force LLM to generate final report
            collected_tool_results: List[Dict[str, Any]] = []  # Track all tool results for final report

            while tool_iteration < MAX_TOOL_ITERATIONS:
                tool_iteration += 1
                full_response = ""
                has_tool_call = False
                accumulated_tool_calls: Dict[int, Dict[str, Any]] = {}
                buffer_tokens = bool(use_tools) and tool_iteration == 1
                buffered_content = ""
                first_token_sent = False
                llm_error = False

                if tool_iteration > 1:
                    await send_status(f"Volgende stap bepalen... ({tool_iteration}/{MAX_TOOL_ITERATIONS})", "llm_thinking")

                # If forced to generate final report, disable tools
                current_tools = None if force_final_report else use_tools

                async for chunk in llm_client.chat(model, messages, stream=True, temperature=temperature, tools=current_tools):
                    if "error" in chunk:
                        await websocket.send_json({"type": "error", "content": chunk["error"]})
                        llm_error = True
                        break

                    if "message" in chunk:
                        msg = chunk["message"]
                        content = msg.get("content", "")

                        if content:
                            full_response += content

                            if not first_token_sent and not has_tool_call:
                                await send_status("Antwoord genereren...", "generating")
                                first_token_sent = True

                            if not has_tool_call:
                                if buffer_tokens:
                                    buffered_content += content
                                elif force_final_report or not full_response.strip().startswith("{"):
                                    # Always stream tokens when forcing final report, even if response looks like JSON
                                    await websocket.send_json({"type": "token", "content": content})

                        # Accumulate tool calls
                        tool_calls = msg.get("tool_calls")
                        if tool_calls:
                            has_tool_call = True
                            if not first_token_sent:
                                await send_status("Tool selecteren...", "tool_selection")
                                first_token_sent = True

                            for tc_chunk in tool_calls:
                                idx = tc_chunk.get("index", 0)
                                if idx not in accumulated_tool_calls:
                                    accumulated_tool_calls[idx] = {
                                        "id": tc_chunk.get("id", f"call_{idx}"),
                                        "type": tc_chunk.get("type", "function"),
                                        "function": {"name": "", "arguments": ""}
                                    }
                                if "id" in tc_chunk and tc_chunk["id"]:
                                    new_id = tc_chunk["id"]
                                    if new_id and str(new_id).startswith("call_"):
                                        accumulated_tool_calls[idx]["id"] = new_id
                                    elif not str(accumulated_tool_calls[idx]["id"]).startswith("call_"):
                                        accumulated_tool_calls[idx]["id"] = new_id
                                if "type" in tc_chunk and tc_chunk["type"]:
                                    accumulated_tool_calls[idx]["type"] = tc_chunk["type"]
                                if "function" in tc_chunk:
                                    func_chunk = tc_chunk["function"]
                                    if "name" in func_chunk and func_chunk["name"]:
                                        accumulated_tool_calls[idx]["function"]["name"] = func_chunk["name"]
                                    if "arguments" in func_chunk and func_chunk["arguments"]:
                                        accumulated_tool_calls[idx]["function"]["arguments"] += func_chunk["arguments"]

                    if chunk.get("done"):
                        break

                # Handle errors
                if llm_error:
                    break

                # Process accumulated tool calls
                if accumulated_tool_calls:
                    for idx in sorted(accumulated_tool_calls.keys()):
                        tool_call = accumulated_tool_calls[idx]
                        func = tool_call.get("function", {})
                        tool_name = func.get("name", "")
                        tool_args_str = func.get("arguments", "{}")
                        tool_call_id = tool_call.get("id", f"call_{idx}")

                        try:
                            tool_args = json.loads(tool_args_str) if isinstance(tool_args_str, str) else tool_args_str
                        except json.JSONDecodeError:
                            tool_args = {}

                        if not tool_name:
                            continue

                        # Check for loop (same tool with same args)
                        tool_signature = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
                        if tool_signature in called_tools:
                            await websocket.send_json({
                                "type": "token",
                                "content": f"\n\n*Loop gedetecteerd: {tool_name} werd al aangeroepen. Rapport wordt gegenereerd...*\n\n"
                            })
                            # Force final report generation with collected data
                            force_final_report = True
                            if collected_tool_results:
                                summary = "\n".join([f"- {r['tool']}: {json.dumps(r['result'], ensure_ascii=False)[:500]}" for r in collected_tool_results[-5:]])
                                messages.append({"role": "assistant", "content": "[Alle benodigde data verzameld]"})
                                messages.append({"role": "user", "content": f"STOP met tools aanroepen. Genereer NU een compleet rapport in het Nederlands met de volgende verzamelde data:\n{summary}\n\nGeef een duidelijke samenvatting en aanbevelingen."})
                            break  # Break inner loop, outer loop will continue with report generation
                        called_tools.append(tool_signature)

                        await send_status(f"Tool uitvoeren: {tool_name} ({idx + 1}/{len(accumulated_tool_calls)})", "tool_call")
                        await websocket.send_json({"type": "tool_call", "tool": tool_name, "args": tool_args})

                        # Execute tool with streaming
                        final_result = None
                        async for evt in mcp_client.call_tool_stream(tool_name, tool_args):
                            if evt.get("type") == "notification":
                                msg_evt = evt["message"]
                                if msg_evt.get("method") == "progress":
                                    await websocket.send_json({"type": "tool_progress", "data": msg_evt.get("params", {})})
                            elif evt.get("type") == "result":
                                if "error" in evt:
                                    final_result = {"success": False, "error": evt["error"].get("message", "Unknown")}
                                else:
                                    content_list = evt.get("result", {}).get("content", [])
                                    if content_list and isinstance(content_list, list) and content_list[0].get("type") == "text":
                                        txt = content_list[0].get("text", "")
                                        try:
                                            final_result = {"success": True, "data": json.loads(txt)}
                                        except json.JSONDecodeError:
                                            final_result = {"success": True, "data": txt}
                                    else:
                                        final_result = {"success": True, "data": evt.get("result")}
                                break

                        await websocket.send_json({"type": "tool_result", "tool": tool_name, "result": final_result})

                        # Track collected results for final report generation
                        collected_tool_results.append({"tool": tool_name, "result": final_result})

                        # RAG Enrichment for threat-related tool results
                        enrichment_context = ""
                        threat_related = ('threat', 'risk', 'alert', 'detection', 'malware', 'ip')
                        if any(kw in tool_name.lower() for kw in threat_related) and final_result:
                            enrichment_context = await enrich_with_threat_intel(mcp_client, final_result, send_status)

                        # Add to conversation
                        complete_tool_call = {
                            "id": tool_call_id,
                            "type": "function",
                            "function": {"name": tool_name, "arguments": tool_args_str}
                        }
                        messages.append({"role": "assistant", "content": "", "tool_calls": [complete_tool_call]})

                        tool_content = json.dumps(final_result) if final_result else "{}"
                        if enrichment_context:
                            tool_content += f"\n\n{enrichment_context}"
                        tool_message: Dict[str, Any] = {"role": "tool", "content": tool_content}
                        if llm_provider == "lmstudio":
                            tool_message["tool_call_id"] = tool_call_id
                            tool_message["name"] = tool_name
                        messages.append(tool_message)

                    # Continue loop to let LLM decide if more tools needed
                    continue

                # JSON fallback tool call (works on all iterations for JSON fallback mode)
                # Skip tool parsing if we're forcing final report generation
                if not has_tool_call and full_response.strip() and not force_final_report:
                    response_stripped = full_response.strip()
                    tool_data = extract_tool_call_from_text(response_stripped)

                    if tool_data:
                        tool_name = tool_data["name"]
                        tool_args = tool_data.get("arguments", {})

                        # Create a signature to detect repeated calls
                        tool_signature = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
                        if tool_signature in called_tools:
                            # Same tool with same args called again - likely stuck in loop
                            await websocket.send_json({
                                "type": "token",
                                "content": f"\n\n*Loop gedetecteerd: {tool_name} werd al aangeroepen. Rapport wordt gegenereerd...*\n\n"
                            })
                            # Force final report generation with collected data
                            force_final_report = True
                            if collected_tool_results:
                                summary = "\n".join([f"- {r['tool']}: {json.dumps(r['result'], ensure_ascii=False)[:500]}" for r in collected_tool_results[-5:]])
                                messages.append({"role": "assistant", "content": "[Alle benodigde data verzameld]"})
                                messages.append({"role": "user", "content": f"STOP met tools aanroepen. Genereer NU een compleet rapport in het Nederlands met de volgende verzamelde data:\n{summary}\n\nGeef een duidelijke samenvatting en aanbevelingen. Antwoord in gewoon Nederlands, GEEN JSON."})
                            continue  # Continue to next iteration which will generate report without tools
                        called_tools.append(tool_signature)

                        await send_status(f"Tool uitvoeren: {tool_name}", "tool_call")
                        await websocket.send_json({"type": "tool_call", "tool": tool_name, "args": tool_args})

                        result = await mcp_client.call_tool(tool_name, tool_args)
                        await websocket.send_json({"type": "tool_result", "tool": tool_name, "result": result})

                        # Track collected results for final report generation
                        collected_tool_results.append({"tool": tool_name, "result": result})

                        # RAG Enrichment for JSON fallback path
                        enrichment_context = ""
                        threat_related = ('threat', 'risk', 'alert', 'detection', 'malware', 'ip')
                        if any(kw in tool_name.lower() for kw in threat_related) and result:
                            enrichment_context = await enrich_with_threat_intel(mcp_client, result, send_status)

                        result_with_context = json.dumps(result)
                        if enrichment_context:
                            result_with_context += f"\n\n{enrichment_context}"

                        # Add tool result to conversation for LLM context
                        messages.append({"role": "assistant", "content": f"[Tool {tool_name} aangeroepen]"})
                        messages.append({
                            "role": "user",
                            "content": f"Resultaat van {tool_name}: {result_with_context}"
                        })

                        # Continue loop - keep current tool mode (don't switch modes mid-conversation)
                        continue
                    elif response_stripped.startswith("{"):
                        await websocket.send_json({"type": "token", "content": full_response})

                # No tool calls - send buffered content and exit loop
                if buffered_content and not accumulated_tool_calls:
                    await websocket.send_json({"type": "token", "content": buffered_content})

                # Done - no more tool calls
                break

            await websocket.send_json({"type": "done"})
            await llm_client.close()
            await mcp_client.close()

    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"WebSocket error: {e}")
        try:
            await websocket.send_json({"type": "error", "content": str(e)})
        except Exception:
            pass


# ------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("NetMonitor Chat v2.0 - Hybrid Mode")
    print("=" * 70)
    print(f"Ollama: {OLLAMA_BASE_URL}")
    if MCP_CONFIGURATIONS:
        print(f"MCP Configs: {len(MCP_CONFIGURATIONS)} loaded")
        for cfg in MCP_CONFIGURATIONS:
            print(f"  - {cfg['name']}: {cfg['url']}")
    print(f"Quick intents: {len(QUICK_INTENTS)} patterns")
    print(f"Interface: http://localhost:8000")
    print("=" * 70)

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
