#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
NetMonitor Chat - Custom Web Interface

Simple, reliable web interface for Ollama + NetMonitor MCP Tools.
Built after discovering Open-WebUI doesn't support Streamable HTTP MCP servers.

Features:
- Clean chat interface
- Ollama integration (any model)
- Automatic tool calling via mcp_bridge.py
- Real-time streaming
- 100% on-premise
"""

import os
import sys
import json
import asyncio
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import httpx
import uvicorn

# Load .env file
load_dotenv()

# Add parent directory to path for mcp_bridge import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Configuration
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Legacy single MCP config (backwards compatible)
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "https://soc.poort.net/mcp")
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")


def load_mcp_configurations() -> List[Dict[str, str]]:
    """
    Load MCP server configurations from environment variables.

    Supports multiple configurations with format:
        MCP_CONFIG_1_NAME=Production
        MCP_CONFIG_1_URL=https://soc.poort.net/mcp
        MCP_CONFIG_1_TOKEN=secret_token

        MCP_CONFIG_2_NAME=Development
        MCP_CONFIG_2_URL=http://localhost:8000/mcp
        MCP_CONFIG_2_TOKEN=dev_token

    Also supports legacy single config:
        MCP_SERVER_URL=https://soc.poort.net/mcp
        MCP_AUTH_TOKEN=secret_token

    Returns:
        List of configuration dicts with keys: name, url, token
    """
    configs = []

    # Find all MCP_CONFIG_X_NAME entries
    config_indices = set()
    for key in os.environ:
        if key.startswith("MCP_CONFIG_") and key.endswith("_NAME"):
            # Extract the index (e.g., "1" from "MCP_CONFIG_1_NAME")
            try:
                idx = key.replace("MCP_CONFIG_", "").replace("_NAME", "")
                config_indices.add(idx)
            except:
                pass

    # Load each configuration
    for idx in sorted(config_indices):
        name = os.getenv(f"MCP_CONFIG_{idx}_NAME", "")
        url = os.getenv(f"MCP_CONFIG_{idx}_URL", "")
        token = os.getenv(f"MCP_CONFIG_{idx}_TOKEN", "")

        if name and url:
            configs.append({
                "name": name,
                "url": url,
                "token": token
            })

    # If no configs found, use legacy single config
    if not configs and MCP_SERVER_URL:
        configs.append({
            "name": "Default",
            "url": MCP_SERVER_URL,
            "token": MCP_AUTH_TOKEN
        })

    return configs


# Load MCP configurations at startup
MCP_CONFIGURATIONS = load_mcp_configurations()

# Get default config (first one, or empty)
DEFAULT_MCP_CONFIG = MCP_CONFIGURATIONS[0] if MCP_CONFIGURATIONS else {
    "name": "Default",
    "url": "https://soc.poort.net/mcp",
    "token": ""
}


# MCP Bridge path - configurable for different deployments
_mcp_bridge_env = os.getenv("MCP_BRIDGE_PATH")
if _mcp_bridge_env:
    MCP_BRIDGE_PATH = Path(_mcp_bridge_env)
else:
    # Default: relative to this file (Linux server layout)
    MCP_BRIDGE_PATH = Path(__file__).parent.parent / "ollama-mcp-bridge" / "mcp_bridge.py"


# Helper Functions

def extract_tool_call_from_text(text: str) -> Optional[Dict]:
    """
    Try to extract a tool call from text that might contain JSON.
    Handles cases where the model outputs text mixed with JSON.

    Returns:
        Dict with 'name' and 'arguments' if found, None otherwise
    """
    import re

    text = text.strip()

    # Try 1: Pure JSON response
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if "name" in data:
                return {
                    "name": data["name"],
                    "arguments": data.get("arguments", data.get("params", {}))
                }
        except json.JSONDecodeError:
            pass

    # Try 2: Find JSON block in text (```json ... ```)
    json_block_match = re.search(r'```(?:json)?\s*(\{[^`]+\})\s*```', text, re.DOTALL)
    if json_block_match:
        try:
            data = json.loads(json_block_match.group(1))
            if "name" in data:
                return {
                    "name": data["name"],
                    "arguments": data.get("arguments", data.get("params", {}))
                }
        except json.JSONDecodeError:
            pass

    # Try 3: Find any JSON object with "name" field
    json_match = re.search(r'\{[^{}]*"name"\s*:\s*"[^"]+"\s*[^{}]*\}', text)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            if "name" in data:
                return {
                    "name": data["name"],
                    "arguments": data.get("arguments", data.get("params", {}))
                }
        except json.JSONDecodeError:
            pass

    # Try 4: Find nested JSON with arguments
    json_match = re.search(r'\{[^{}]*"name"\s*:[^{}]*"arguments"\s*:\s*\{[^{}]*\}[^{}]*\}', text)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            if "name" in data:
                return {
                    "name": data["name"],
                    "arguments": data.get("arguments", {})
                }
        except json.JSONDecodeError:
            pass

    return None


def build_tool_prompt(tools: List[Dict], user_system_prompt: str = "") -> str:
    """
    Build a system prompt that instructs the model to use tools via JSON output.
    Used as fallback for models without native function calling.
    """
    tool_descriptions = []
    for tool in tools[:10]:  # Limit to 10 tools to avoid context overflow
        name = tool.get("name", "unknown")
        desc = tool.get("description", "No description")[:100]
        params = tool.get("inputSchema", {}).get("properties", {})
        param_names = list(params.keys())[:3]  # First 3 params
        tool_descriptions.append(f"- {name}: {desc} (params: {param_names})")

    tools_text = "\n".join(tool_descriptions)

    prompt = f"""{user_system_prompt}

BELANGRIJK: Je hebt toegang tot de volgende tools om actuele data op te halen:

{tools_text}

Als je een tool wilt gebruiken, antwoord dan ALLEEN met JSON in dit formaat:
{{"name": "tool_naam", "arguments": {{"param": "waarde"}}}}

Voorbeeld voor recente threats:
{{"name": "get_recent_threats", "arguments": {{"hours": 1}}}}

Geef GEEN tekst buiten de JSON als je een tool aanroept.
Als je geen tool nodig hebt, antwoord dan gewoon in het Nederlands."""

    return prompt


def filter_relevant_tools(user_message: str, all_tools: List[Dict], max_tools: int = 10) -> List[Dict]:
    """
    Filter tools based on relevance to user message.
    Uses keyword matching on tool names and descriptions.

    Args:
        user_message: The user's question/request
        all_tools: List of all available tools
        max_tools: Maximum number of tools to return

    Returns:
        List of most relevant tools
    """
    if not all_tools:
        return []

    message_lower = user_message.lower()

    print(f"[Tool Filter] Input message: '{user_message}'")
    print(f"[Tool Filter] Total tools available: {len(all_tools)}")
    if all_tools:
        print(f"[Tool Filter] Sample tool names: {[t.get('name', 'unknown') for t in all_tools[:5]]}")

    # Map user keywords (including Dutch) to tool keywords (English in tool names)
    # This allows "toon sensors" to match tools with "get" + "sensor"
    keyword_mappings = {
        # Category: (user_keywords, tool_keywords)
        'threat': (
            ['threat', 'detection', 'alert', 'malware', 'attack', 'bedreig', 'dreig'],
            ['threat', 'detection', 'alert', 'malware', 'attack']
        ),
        'ip': (
            ['ip', 'address', 'adres'],
            ['ip', 'address', 'addr']
        ),
        'sensor': (
            ['sensor', 'sensors'],
            ['sensor', 'zeek', 'suricata']
        ),
        'log': (
            ['log', 'logs'],
            ['log', 'syslog', 'event']
        ),
        'network': (
            ['network', 'netwerk', 'traffic', 'verkeer'],
            ['network', 'traffic', 'flow', 'connection']
        ),
        'toptalker': (
            ['top', 'talker', 'talkers', 'meeste', 'grootste', 'bandwidth', 'volume'],
            ['traffic', 'stats', 'top', 'bandwidth', 'volume', 'bytes']
        ),
        'dns': (
            ['dns', 'domain'],
            ['dns', 'domain', 'query']
        ),
        'file': (
            ['file', 'bestand'],
            ['file', 'hash', 'executable']
        ),
        'user': (
            ['user', 'gebruiker', 'account'],
            ['user', 'account', 'authentication', 'auth']
        ),
        'port': (
            ['port', 'poort', 'service'],
            ['port', 'service', 'scan']
        ),
        'status': (
            ['status', 'actieve', 'active', 'running'],
            ['status', 'state', 'active', 'running']
        ),
        'show': (
            ['toon', 'laat', 'zie', 'show', 'list', 'geef'],
            ['get', 'list', 'show', 'fetch']
        )
    }

    # Score each tool based on keyword matches
    scored_tools = []
    for tool in all_tools:
        score = 0
        tool_name_lower = tool.get('name', '').lower()
        tool_desc_lower = tool.get('description', '').lower()

        # Check for category matches
        for category, (user_keywords, tool_keywords) in keyword_mappings.items():
            # Check if user mentioned this category
            user_mentioned = any(kw in message_lower for kw in user_keywords)

            if user_mentioned:
                # Check if tool has keywords from this category
                tool_has_category = any(
                    kw in tool_name_lower or kw in tool_desc_lower
                    for kw in tool_keywords
                )

                if tool_has_category:
                    score += 10
                    # Extra bonus if multiple words from category match
                    matches = sum(1 for kw in tool_keywords if kw in tool_name_lower or kw in tool_desc_lower)
                    if matches > 1:
                        score += 5

        # Bonus for exact word matches in tool name (case-insensitive)
        words_in_message = set(re.findall(r'\w+', message_lower))
        words_in_tool = set(re.findall(r'\w+', tool_name_lower))
        overlap = words_in_message & words_in_tool
        if overlap:
            score += len(overlap) * 5

        # Small base score for common query tools
        if any(essential in tool_name_lower for essential in ['get', 'list', 'show', 'fetch']):
            score += 1

        scored_tools.append((score, tool))

    # Sort by score (descending)
    scored_tools.sort(reverse=True, key=lambda x: x[0])

    # Debug: show top scores
    print(f"[Tool Filter] Top 10 scores:")
    for i, (score, tool) in enumerate(scored_tools[:10]):
        print(f"  {i+1}. {tool.get('name', 'unknown')}: {score} points")

    # Filter out tools with score 0 (completely irrelevant)
    relevant_tools = [tool for score, tool in scored_tools if score > 0][:max_tools]

    # If we got no tools with score > 0, take top scoring ones anyway
    if len(relevant_tools) == 0:
        print(f"[Tool Filter] WARNING: No tools scored > 0, taking top {max_tools} by default")
        relevant_tools = [tool for score, tool in scored_tools[:max_tools]]

    print(f"[Tool Filter] Filtered {len(all_tools)} tools down to {len(relevant_tools)}")
    if relevant_tools:
        print(f"[Tool Filter] Selected tools: {[t.get('name') for t in relevant_tools]}")

    return relevant_tools


# Pydantic models for request bodies
class LLMConfig(BaseModel):
    provider: str = "ollama"
    url: str = "http://localhost:11434"

class MCPConfig(BaseModel):
    url: str = DEFAULT_MCP_CONFIG["url"]
    token: str = DEFAULT_MCP_CONFIG["token"]
    config_name: Optional[str] = None  # If set, look up config by name

class HealthConfig(BaseModel):
    llm_provider: str = "ollama"
    llm_url: str = "http://localhost:11434"
    mcp_url: str = DEFAULT_MCP_CONFIG["url"]
    mcp_token: str = DEFAULT_MCP_CONFIG["token"]
    mcp_config_name: Optional[str] = None  # If set, look up config by name


# Lifespan event handler (replaces on_event)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown - nothing to clean up as clients are created per-request now
    pass


# Initialize FastAPI
app = FastAPI(
    title="NetMonitor Chat",
    description="On-premise chat interface with NetMonitor MCP tools",
    version="1.0.0",
    lifespan=lifespan
)

# Mount static files
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


class OllamaClient:
    """Client for Ollama API"""

    def __init__(self, base_url: str = OLLAMA_BASE_URL):
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=120.0)

    async def list_models(self) -> List[Dict]:
        """List available Ollama models"""
        try:
            print(f"[Ollama] Fetching models from {self.base_url}/api/tags")
            response = await self.client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            data = response.json()
            models = data.get("models", [])
            print(f"[Ollama] Found {len(models)} models")
            return models
        except httpx.ConnectError as e:
            print(f"[Ollama] Connection failed - is Ollama running on {self.base_url}? Error: {e}")
            return []
        except Exception as e:
            print(f"[Ollama] Error listing models: {type(e).__name__}: {e}")
            return []

    async def chat(
        self,
        model: str,
        messages: List[Dict],
        stream: bool = True,
        temperature: float = 0.7,
        tools: Optional[List[Dict]] = None
    ) -> AsyncGenerator:
        """
        Chat with Ollama model

        Args:
            model: Model name
            messages: Chat messages
            stream: Stream responses
            temperature: Sampling temperature
            tools: Available tools (for native tool calling)

        Yields:
            Response chunks
        """
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "options": {
                "temperature": temperature
            }
        }

        if tools:
            payload["tools"] = tools

        try:
            async with self.client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.strip():
                        try:
                            chunk = json.loads(line)
                            yield chunk
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"Error in chat: {e}")
            yield {"error": str(e)}

    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()


class LMStudioClient:
    """Client for LM Studio (OpenAI-compatible API)"""

    def __init__(self, base_url: str = "http://localhost:1234"):
        self.base_url = base_url.rstrip('/')
        # Longer timeout for LM Studio (models can be slow to start generating)
        self.client = httpx.AsyncClient(timeout=300.0)

    async def list_models(self) -> List[Dict]:
        """List available LM Studio models"""
        try:
            print(f"[LM Studio] Fetching models from {self.base_url}/v1/models")
            response = await self.client.get(f"{self.base_url}/v1/models")
            response.raise_for_status()
            data = response.json()
            models = data.get("data", [])
            print(f"[LM Studio] Found {len(models)} models")
            # Convert OpenAI format to Ollama format for consistency
            return [{"name": m.get("id", "unknown")} for m in models]
        except httpx.ConnectError as e:
            print(f"[LM Studio] Connection failed - is LM Studio running on {self.base_url}? Error: {e}")
            return []
        except Exception as e:
            print(f"[LM Studio] Error listing models: {type(e).__name__}: {e}")
            return []

    async def chat(
        self,
        model: str,
        messages: List[Dict],
        stream: bool = True,
        temperature: float = 0.7,
        tools: Optional[List[Dict]] = None
    ) -> AsyncGenerator:
        """
        Chat with LM Studio model using OpenAI-compatible API

        Args:
            model: Model name
            messages: Chat messages
            stream: Stream responses
            temperature: Sampling temperature
            tools: Available tools (for function calling)

        Yields:
            Response chunks in Ollama format for compatibility
        """
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "temperature": temperature
        }

        # Add tools if explicitly provided (when force_tools is enabled)
        if tools:
            payload["tools"] = tools
            print(f"[LM Studio] Adding {len(tools)} tools to request (experimental)")

        try:
            print(f"[LM Studio] Sending request to {self.base_url}/v1/chat/completions")
            print(f"[LM Studio] Model: {model}, Messages: {len(messages)}, Temperature: {temperature}")

            async with self.client.stream(
                "POST",
                f"{self.base_url}/v1/chat/completions",
                json=payload
            ) as response:
                print(f"[LM Studio] Response status: {response.status_code}")

                # Better error logging
                if response.status_code != 200:
                    error_text = await response.aread()
                    print(f"[LM Studio] Error {response.status_code}: {error_text.decode()}")
                    yield {"error": f"LM Studio error {response.status_code}: {error_text.decode()}"}
                    return

                response.raise_for_status()

                print("[LM Studio] Starting to read stream...")
                line_count = 0
                buffer = ""  # Buffer for incomplete JSON
                async for line in response.aiter_lines():
                    line_count += 1
                    if line_count <= 3:  # Log first 3 lines for debugging
                        print(f"[LM Studio] Line {line_count}: {line[:100] if line else 'empty'}")

                    # Skip empty lines
                    if not line.strip():
                        continue

                    # Skip SSE event lines (LM Studio sends "event: error" etc.)
                    if line.startswith("event:"):
                        if line_count <= 5:
                            print(f"[LM Studio] Skipping event line: {line}")
                        continue

                    # Remove "data: " prefix if present
                    if line.startswith("data: "):
                        line = line[6:]
                    elif not line.strip():
                        # After removing prefix, if line is empty, skip
                        continue

                    # Check for [DONE]
                    if line.strip() == "[DONE]":
                        print("[LM Studio] Stream finished with [DONE]")
                        yield {"done": True}
                        continue

                    # Add to buffer
                    buffer += line.strip()

                    # Try to parse only if line ends with } (complete JSON)
                    if not buffer.endswith("}"):
                        if line_count <= 5:
                            print(f"[LM Studio] Buffering incomplete JSON: {buffer[:80]}...")
                        continue

                    try:
                        chunk = json.loads(buffer)
                        buffer = ""  # Clear buffer on successful parse

                        # Convert OpenAI format to Ollama format
                        choices = chunk.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            content = delta.get("content", "")
                            tool_calls = delta.get("tool_calls", [])

                            # Build Ollama-compatible response
                            ollama_chunk = {
                                "message": {
                                    "role": delta.get("role", "assistant"),
                                    "content": content
                                },
                                "done": choices[0].get("finish_reason") is not None
                            }

                            # Add tool calls if present (preserve ID for LM Studio)
                            if tool_calls:
                                ollama_chunk["message"]["tool_calls"] = [
                                    {
                                        "id": tc.get("id", f"call_{tc.get('index', 0)}"),  # Preserve tool_call_id
                                        "index": tc.get("index", 0),  # Add index for accumulation
                                        "type": tc.get("type", "function"),
                                        "function": {
                                            "name": tc.get("function", {}).get("name", ""),
                                            # Keep arguments as STRING for streaming accumulation
                                            # Will be parsed to JSON later when complete
                                            "arguments": tc.get("function", {}).get("arguments", "")
                                        }
                                    }
                                    for tc in tool_calls
                                ]

                                # Debug: print first tool call
                                if tool_calls and line_count <= 10:
                                    first_tc = ollama_chunk["message"]["tool_calls"][0]
                                    print(f"[LM Studio] Tool call: {first_tc.get('function', {}).get('name')} (id: {first_tc.get('id')})")

                            if line_count <= 5:
                                print(f"[LM Studio] Yielding chunk: {content[:50] if content else 'no content'}")
                            yield ollama_chunk
                    except json.JSONDecodeError as e:
                        print(f"[LM Studio] JSON decode error: {e}, buffer: {buffer[:100]}")
                        # Don't clear buffer, wait for more data
                        continue

                print(f"[LM Studio] Stream finished, total lines: {line_count}")

        except httpx.TimeoutException as e:
            print(f"[LM Studio] Timeout error: {e}")
            yield {"error": f"LM Studio timeout - model might be loading or too slow"}
        except Exception as e:
            print(f"[LM Studio] Error in chat: {type(e).__name__}: {e}")
            yield {"error": str(e)}

    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()


class MCPBridgeClient:
    """Client for MCP Bridge (STDIO)"""

    def __init__(self, bridge_path: Path, server_url: str, auth_token: str):
        self.bridge_path = bridge_path
        self.server_url = server_url
        self.auth_token = auth_token

    async def call_tool(self, tool_name: str, arguments: Dict) -> Dict:
        """
        Call a tool via mcp_bridge.py

        Args:
            tool_name: Tool name
            arguments: Tool arguments

        Returns:
            Tool result
        """
        # Prepare JSON-RPC request
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": 1
        }

        try:
            # Call bridge via subprocess using same Python as this script
            env = os.environ.copy()
            env.update({
                "MCP_SERVER_URL": self.server_url,
                "MCP_AUTH_TOKEN": self.auth_token
            })

            process = await asyncio.create_subprocess_exec(
                sys.executable,
                str(self.bridge_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            # Send request and get response
            stdout, stderr = await process.communicate(
                input=json.dumps(request).encode()
            )

            if process.returncode != 0:
                return {
                    "error": f"Bridge failed: {stderr.decode()}",
                    "success": False
                }

            # Parse response
            response = json.loads(stdout.decode())

            if "error" in response:
                return {
                    "error": response["error"].get("message", "Unknown error"),
                    "success": False
                }

            # Extract tool result from MCP response
            result = response.get("result", {})
            content = result.get("content", [])

            if content and len(content) > 0:
                text = content[0].get("text", "")
                try:
                    # Tool result is JSON string
                    data = json.loads(text)
                    return {"success": True, "data": data}
                except json.JSONDecodeError:
                    return {"success": True, "data": text}

            return {"error": "No data returned", "success": False}

        except Exception as e:
            return {"error": str(e), "success": False}

    async def list_tools(self) -> List[Dict]:
        """List available tools"""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        }

        try:
            env = os.environ.copy()
            env.update({
                "MCP_SERVER_URL": self.server_url,
                "MCP_AUTH_TOKEN": self.auth_token
            })

            # Use the same Python interpreter that's running this script
            python_executable = sys.executable
            print(f"[Bridge] Calling {self.bridge_path} with {python_executable}")
            print(f"[Bridge] Server URL: {self.server_url}")

            process = await asyncio.create_subprocess_exec(
                python_executable,
                str(self.bridge_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            stdout, stderr = await process.communicate(
                input=json.dumps(request).encode()
            )

            if stderr:
                print(f"[Bridge] stderr: {stderr.decode()[:500]}")

            if process.returncode != 0:
                print(f"[Bridge] Process failed with code {process.returncode}")
                print(f"[Bridge] stdout: {stdout.decode()[:500]}")
                return []

            response = json.loads(stdout.decode())

            if "error" in response:
                print(f"[Bridge] Error response: {response['error']}")
                return []

            tools = response.get("result", {}).get("tools", [])
            return tools

        except FileNotFoundError:
            print(f"[Bridge] ERROR: Bridge not found at {self.bridge_path}")
            return []
        except json.JSONDecodeError as e:
            print(f"[Bridge] Invalid JSON response: {e}")
            print(f"[Bridge] Raw output: {stdout.decode()[:500]}")
            return []
        except Exception as e:
            print(f"[Bridge] Error: {type(e).__name__}: {e}")
            return []


# REST Endpoints

@app.get("/")
async def root():
    """Serve main page"""
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/mcp-configs")
async def get_mcp_configs():
    """
    Get available MCP server configurations.

    These are loaded from environment variables at startup:
        MCP_CONFIG_1_NAME, MCP_CONFIG_1_URL, MCP_CONFIG_1_TOKEN
        MCP_CONFIG_2_NAME, MCP_CONFIG_2_URL, MCP_CONFIG_2_TOKEN
        etc.

    Returns configs without exposing tokens (only name and url).
    """
    # Return configs without tokens for security
    safe_configs = [
        {"name": c["name"], "url": c["url"], "has_token": bool(c["token"])}
        for c in MCP_CONFIGURATIONS
    ]
    return {
        "configs": safe_configs,
        "default": DEFAULT_MCP_CONFIG["name"] if MCP_CONFIGURATIONS else None
    }


def get_mcp_config_by_name(name: str) -> Optional[Dict[str, str]]:
    """Look up MCP config by name"""
    for config in MCP_CONFIGURATIONS:
        if config["name"] == name:
            return config
    return None


@app.post("/api/models")
async def post_models(config: LLMConfig):
    """Get available models from configured LLM provider"""
    try:
        if config.provider == "lmstudio":
            client = LMStudioClient(config.url)
        else:
            client = OllamaClient(config.url)

        models = await client.list_models()
        await client.close()
        return {"models": models}
    except Exception as e:
        print(f"Error getting models: {e}")
        return {"models": []}


@app.post("/api/tools")
async def post_tools(config: MCPConfig):
    """Get available MCP tools from configured server"""
    try:
        # If config_name is provided, look up the config
        url = config.url
        token = config.token
        if config.config_name:
            named_config = get_mcp_config_by_name(config.config_name)
            if named_config:
                url = named_config["url"]
                token = named_config["token"]
                print(f"[API] Using MCP config '{config.config_name}': {url}")
            else:
                print(f"[API] WARNING: MCP config '{config.config_name}' not found, using defaults")

        print(f"[API] Loading tools from {url} (token: {'set' if token else 'empty'})")
        bridge = MCPBridgeClient(
            bridge_path=MCP_BRIDGE_PATH,
            server_url=url,
            auth_token=token
        )
        tools = await bridge.list_tools()
        print(f"[API] Loaded {len(tools)} tools")
        return {"tools": tools, "count": len(tools)}
    except Exception as e:
        print(f"Error getting tools: {e}")
        return {"tools": [], "count": 0}


@app.post("/api/health")
async def post_health(config: HealthConfig):
    """Health check with configured servers"""
    try:
        # Check LLM provider
        if config.llm_provider == "lmstudio":
            llm_client = LMStudioClient(config.llm_url)
        else:
            llm_client = OllamaClient(config.llm_url)

        llm_ok = len(await llm_client.list_models()) > 0
        await llm_client.close()

        # If mcp_config_name is provided, look up the config
        mcp_url = config.mcp_url
        mcp_token = config.mcp_token
        if config.mcp_config_name:
            named_config = get_mcp_config_by_name(config.mcp_config_name)
            if named_config:
                mcp_url = named_config["url"]
                mcp_token = named_config["token"]
                print(f"[Health] Using MCP config '{config.mcp_config_name}': {mcp_url}")
            else:
                print(f"[Health] WARNING: MCP config '{config.mcp_config_name}' not found")

        # Check MCP server
        print(f"[Health] Checking MCP at {mcp_url} (token: {'set' if mcp_token else 'empty'})")
        mcp_client = MCPBridgeClient(
            bridge_path=MCP_BRIDGE_PATH,
            server_url=mcp_url,
            auth_token=mcp_token
        )
        tools_count = len(await mcp_client.list_tools())
        mcp_ok = tools_count > 0
        print(f"[Health] MCP returned {tools_count} tools, status: {'connected' if mcp_ok else 'disconnected'}")

        return {
            "status": "healthy" if (llm_ok and mcp_ok) else "degraded",
            "ollama": "connected" if llm_ok else "disconnected",
            "mcp": "connected" if mcp_ok else "disconnected",
            "mcp_config": config.mcp_config_name or "custom",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error in health check: {e}")
        return {
            "status": "error",
            "ollama": "disconnected",
            "mcp": "disconnected",
            "timestamp": datetime.now().isoformat()
        }


# Backwards compatibility - GET endpoints with default config
@app.get("/api/models")
async def get_models():
    """Get available models (default config)"""
    return await post_models(LLMConfig())


@app.get("/api/tools")
async def get_tools():
    """Get available tools (default config)"""
    return await post_tools(MCPConfig())


@app.get("/api/health")
async def get_health():
    """Health check (default config)"""
    return await post_health(HealthConfig())


# WebSocket Endpoint

@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    """
    WebSocket endpoint for streaming chat

    Protocol:
    - Client sends: {"model": "...", "message": "...", "history": [...], "llm_provider": "...", "llm_url": "...", "mcp_url": "...", "mcp_token": "..."}
    - Server sends: {"type": "token", "content": "..."}
    - Server sends: {"type": "tool_call", "tool": "...", "args": {...}}
    - Server sends: {"type": "tool_result", "result": {...}}
    - Server sends: {"type": "done"}
    """
    await websocket.accept()

    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()

            model = data.get("model", "llama3.1:8b")
            message = data.get("message", "")
            history = data.get("history", [])
            temperature = data.get("temperature", 0.3)
            system_prompt = data.get("system_prompt", "")

            # Get configuration from client
            llm_provider = data.get("llm_provider", "ollama")
            llm_url = data.get("llm_url", OLLAMA_BASE_URL)
            mcp_url = data.get("mcp_url", MCP_SERVER_URL)
            mcp_token = data.get("mcp_token", MCP_AUTH_TOKEN)
            mcp_config_name = data.get("mcp_config_name")  # Named config lookup
            force_tools_lmstudio = data.get("force_tools_lmstudio", False)

            # If mcp_config_name is provided, look up the config
            if mcp_config_name:
                named_config = get_mcp_config_by_name(mcp_config_name)
                if named_config:
                    mcp_url = named_config["url"]
                    mcp_token = named_config["token"]
                    print(f"[WebSocket] Using MCP config '{mcp_config_name}': {mcp_url}")

            print(f"[WebSocket] Provider: {llm_provider}, Model: {model}, URL: {llm_url}")
            if llm_provider == "lmstudio" and force_tools_lmstudio:
                print("[WebSocket] Force tools enabled for LM Studio")

            # Create LLM client based on provider
            if llm_provider == "lmstudio":
                llm_client = LMStudioClient(llm_url)
            else:
                llm_client = OllamaClient(llm_url)

            # Create MCP bridge client with configured server
            mcp_client = MCPBridgeClient(
                bridge_path=MCP_BRIDGE_PATH,
                server_url=mcp_url,
                auth_token=mcp_token
            )

            # Get available tools and filter to most relevant ones
            all_mcp_tools = await mcp_client.list_tools()

            # Smart filtering: reduce tools from 60 to ~10 most relevant
            # This dramatically reduces context size and speeds up responses
            max_tools_for_provider = 10 if llm_provider == "lmstudio" else 15
            filtered_mcp_tools = filter_relevant_tools(message, all_mcp_tools, max_tools=max_tools_for_provider)

            # Convert filtered tools to function calling format
            ollama_tools = []
            for tool in filtered_mcp_tools:
                ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool.get("inputSchema", {})
                    }
                })

            # Determine tool mode
            use_native_tools = False
            use_json_fallback = False

            if llm_provider == "ollama":
                use_native_tools = True
                use_tools = ollama_tools if ollama_tools else None
            elif llm_provider == "lmstudio" and force_tools_lmstudio:
                # For LM Studio with Force Tools: use JSON fallback mode
                # This works better than native function calling for most models
                use_json_fallback = True
                use_tools = None  # Don't pass tools natively
                print(f"[WebSocket] LM Studio JSON fallback mode ({len(filtered_mcp_tools)} tools in prompt)")
            else:
                use_tools = None
                print("[WebSocket] LM Studio detected - function calling disabled (use Force Tools to enable)")

            # Build messages with system prompt
            messages = []

            # For JSON fallback mode: inject tool instructions into system prompt
            if use_json_fallback and filtered_mcp_tools:
                enhanced_prompt = build_tool_prompt(filtered_mcp_tools, system_prompt)
                messages.append({"role": "system", "content": enhanced_prompt})
            elif system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            messages.extend(history + [{"role": "user", "content": message}])

            # Stream response from LLM
            full_response = ""
            has_tool_call = False
            accumulated_tool_calls = {}  # Dict to accumulate tool calls by index

            async for chunk in llm_client.chat(
                model,
                messages,
                stream=True,
                temperature=temperature,
                tools=use_tools
            ):
                if "error" in chunk:
                    await websocket.send_json({
                        "type": "error",
                        "content": chunk["error"]
                    })
                    break

                if "message" in chunk:
                    msg = chunk["message"]
                    content = msg.get("content", "")

                    # Accumulate response
                    if content:
                        full_response += content

                    # Only stream content if we're sure it's not a tool call
                    # (tool calls starting with { won't be streamed until we verify)
                    if content and not has_tool_call:
                        # If response looks like JSON, wait until end to determine if tool call
                        if not full_response.strip().startswith("{"):
                            await websocket.send_json({
                                "type": "token",
                                "content": content
                            })

                    # Check for native tool calls (LM Studio streams them incrementally)
                    tool_calls = msg.get("tool_calls")

                    # Accumulate tool calls across chunks (LM Studio sends them piece by piece)
                    if tool_calls:
                        has_tool_call = True
                        for tc_chunk in tool_calls:
                            # Get index (default to 0 if not specified)
                            idx = tc_chunk.get("index", 0)

                            # Initialize if first time seeing this index
                            if idx not in accumulated_tool_calls:
                                accumulated_tool_calls[idx] = {
                                    "id": tc_chunk.get("id", f"call_{idx}"),
                                    "type": tc_chunk.get("type", "function"),
                                    "function": {"name": "", "arguments": ""}
                                }

                            # Update ID if present and non-empty (prefer string IDs like "call_0" over numeric)
                            if "id" in tc_chunk and tc_chunk["id"]:
                                new_id = tc_chunk["id"]
                                # Only update if new ID is non-empty
                                if new_id and str(new_id).startswith("call_"):
                                    # Prefer "call_X" format over numeric IDs
                                    accumulated_tool_calls[idx]["id"] = new_id
                                elif not str(accumulated_tool_calls[idx]["id"]).startswith("call_"):
                                    # Keep first non-empty ID if current doesn't have call_ prefix
                                    accumulated_tool_calls[idx]["id"] = new_id

                            # Update type if present and non-empty
                            if "type" in tc_chunk and tc_chunk["type"]:
                                accumulated_tool_calls[idx]["type"] = tc_chunk["type"]

                            # Accumulate function data
                            if "function" in tc_chunk:
                                func_chunk = tc_chunk["function"]
                                # Only update name if new one is non-empty (don't overwrite with "")
                                if "name" in func_chunk and func_chunk["name"]:
                                    accumulated_tool_calls[idx]["function"]["name"] = func_chunk["name"]
                                # Arguments are streamed incrementally, always append
                                if "arguments" in func_chunk and func_chunk["arguments"]:
                                    accumulated_tool_calls[idx]["function"]["arguments"] += func_chunk["arguments"]

                # Check if done - process accumulated tool calls
                if chunk.get("done"):
                    # Process accumulated tool calls (for LM Studio streaming)
                    if accumulated_tool_calls:
                        print(f"[WebSocket] Stream finished, processing {len(accumulated_tool_calls)} accumulated tool call(s)")
                        for idx in sorted(accumulated_tool_calls.keys()):
                            tool_call = accumulated_tool_calls[idx]
                            print(f"[WebSocket] Accumulated tool call: {tool_call}")

                            func = tool_call.get("function", {})
                            tool_name = func.get("name", "")
                            tool_args_str = func.get("arguments", "{}")
                            tool_call_id = tool_call.get("id", "call_1")

                            # Parse arguments if string
                            try:
                                tool_args = json.loads(tool_args_str) if isinstance(tool_args_str, str) else tool_args_str
                            except json.JSONDecodeError:
                                print(f"[WebSocket] Failed to parse arguments: {tool_args_str}")
                                tool_args = {}

                            # Skip if name is empty (incomplete tool call)
                            if not tool_name:
                                print(f"[WebSocket] Skipping tool call with empty name: {tool_call}")
                                continue

                            print(f"[WebSocket] Executing - name: '{tool_name}', args: {tool_args}, id: '{tool_call_id}'")

                            # Notify client of tool call
                            await websocket.send_json({
                                "type": "tool_call",
                                "tool": tool_name,
                                "args": tool_args
                            })

                            # Execute tool via MCP client
                            result = await mcp_client.call_tool(tool_name, tool_args)

                            # Send result to client
                            await websocket.send_json({
                                "type": "tool_result",
                                "tool": tool_name,
                                "result": result
                            })

                            # Prepare complete tool call for conversation history
                            # For OpenAI/LM Studio: arguments must be JSON STRING, not dict
                            complete_tool_call = {
                                "id": tool_call_id,
                                "type": "function",
                                "function": {
                                    "name": tool_name,
                                    "arguments": tool_args_str  # Keep as string for OpenAI format
                                }
                            }

                            # Add tool result to conversation for LM Studio/OpenAI format
                            messages.append({"role": "assistant", "content": "", "tool_calls": [complete_tool_call]})

                            # OpenAI/LM Studio requires tool_call_id and name in tool message
                            tool_message = {
                                "role": "tool",
                                "content": json.dumps(result) if result else "{}"
                            }

                            # Add tool_call_id for OpenAI-compatible APIs (LM Studio)
                            if llm_provider == "lmstudio":
                                tool_message["tool_call_id"] = tool_call_id
                                tool_message["name"] = tool_name

                            messages.append(tool_message)

                            # Get final response with tool result
                            print(f"[WebSocket] Requesting follow-up response with tool result")
                            async for chunk2 in llm_client.chat(
                                model,
                                messages,
                                stream=True,
                                temperature=temperature,
                                tools=ollama_tools if ollama_tools else None
                            ):
                                if "message" in chunk2:
                                    content2 = chunk2["message"].get("content", "")
                                    if content2:
                                        await websocket.send_json({
                                            "type": "token",
                                            "content": content2
                                        })

                    # For models without native tool calling: parse JSON from response
                    elif not has_tool_call and full_response.strip():
                        response_stripped = full_response.strip()
                        is_tool_call = False

                        # Try to extract tool call from response (handles various formats)
                        tool_data = extract_tool_call_from_text(response_stripped)

                        if tool_data:
                            is_tool_call = True
                            tool_name = tool_data["name"]
                            tool_args = tool_data.get("arguments", {})

                            print(f"[WebSocket] JSON fallback detected tool call: {tool_name}")

                            # Notify client of tool call
                            await websocket.send_json({
                                "type": "tool_call",
                                "tool": tool_name,
                                "args": tool_args
                            })

                            # Execute tool
                            result = await mcp_client.call_tool(tool_name, tool_args)

                            # Send result to client
                            await websocket.send_json({
                                "type": "tool_result",
                                "tool": tool_name,
                                "result": result
                            })

                            # Add tool result to conversation and get final response
                            messages.append({"role": "assistant", "content": full_response})
                            messages.append({
                                "role": "user",
                                "content": f"Tool {tool_name} returned: {json.dumps(result)}. Geef een duidelijk Nederlands antwoord gebaseerd op deze data. Gebruik GEEN JSON meer."
                            })

                            # Get final natural language response
                            async for chunk2 in llm_client.chat(
                                model,
                                messages,
                                stream=True,
                                temperature=temperature,
                                tools=None  # No tools on follow-up to avoid loop
                            ):
                                if "message" in chunk2:
                                    content2 = chunk2["message"].get("content", "")
                                    if content2:
                                        await websocket.send_json({
                                            "type": "token",
                                            "content": content2
                                        })
                                if chunk2.get("done"):
                                    break

                        # If response looked like JSON but wasn't a tool call, send it now
                        if not is_tool_call and response_stripped.startswith("{"):
                            await websocket.send_json({
                                "type": "token",
                                "content": full_response
                            })

                    await websocket.send_json({"type": "done"})

                    # Clean up LLM client
                    try:
                        await llm_client.close()
                    except:
                        pass

                    break

    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"WebSocket error: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "content": str(e)
            })
        except:
            pass


if __name__ == "__main__":
    # Check configuration - only warn if no config at all
    if not MCP_AUTH_TOKEN and not MCP_CONFIGURATIONS:
        print("WARNING: No MCP configuration found!")
        print("Set MCP_CONFIG_1_NAME, MCP_CONFIG_1_URL, MCP_CONFIG_1_TOKEN")
        print("Or use legacy: MCP_AUTH_TOKEN='your_token_here'")

    if not MCP_BRIDGE_PATH.exists():
        print(f"ERROR: MCP bridge not found at {MCP_BRIDGE_PATH}")
        print("Make sure mcp_bridge.py exists")
        sys.exit(1)

    print("=" * 70)
    print("NetMonitor Chat Starting")
    print("=" * 70)
    print(f"Ollama: {OLLAMA_BASE_URL}")
    print(f"MCP Bridge: {MCP_BRIDGE_PATH}")
    if MCP_CONFIGURATIONS:
        print(f"MCP Configs: {len(MCP_CONFIGURATIONS)} loaded")
        for cfg in MCP_CONFIGURATIONS:
            print(f"  - {cfg['name']}: {cfg['url']} (token: {'set' if cfg['token'] else 'empty'})")
    else:
        print(f"MCP Server: {MCP_SERVER_URL} (legacy)")
    print(f"Interface: http://localhost:8000")
    print("=" * 70)

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
