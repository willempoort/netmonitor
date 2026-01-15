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
from pathlib import Path
from typing import Dict, List, Optional, AsyncGenerator
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from dotenv import load_dotenv
import httpx
import uvicorn

# Load .env file
load_dotenv()

# Add parent directory to path for mcp_bridge import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Configuration
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "https://soc.poort.net/mcp")
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")

# MCP Bridge path - configurable for different deployments
_mcp_bridge_env = os.getenv("MCP_BRIDGE_PATH")
if _mcp_bridge_env:
    MCP_BRIDGE_PATH = Path(_mcp_bridge_env)
else:
    # Default: relative to this file (Linux server layout)
    MCP_BRIDGE_PATH = Path(__file__).parent.parent / "ollama-mcp-bridge" / "mcp_bridge.py"


# Lifespan event handler (replaces on_event)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown
    await ollama.close()


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
            response = await self.client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            data = response.json()
            return data.get("models", [])
        except Exception as e:
            print(f"Error listing models: {e}")
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
            # Call bridge via subprocess
            env = os.environ.copy()
            env.update({
                "MCP_SERVER_URL": self.server_url,
                "MCP_AUTH_TOKEN": self.auth_token
            })

            process = await asyncio.create_subprocess_exec(
                "python3",
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

            process = await asyncio.create_subprocess_exec(
                "python3",
                str(self.bridge_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            stdout, stderr = await process.communicate(
                input=json.dumps(request).encode()
            )

            if process.returncode != 0:
                return []

            response = json.loads(stdout.decode())
            tools = response.get("result", {}).get("tools", [])
            return tools

        except Exception as e:
            print(f"Error listing tools: {e}")
            return []


# Initialize clients
ollama = OllamaClient()
mcp_bridge = MCPBridgeClient(
    bridge_path=MCP_BRIDGE_PATH,
    server_url=MCP_SERVER_URL,
    auth_token=MCP_AUTH_TOKEN
)


# REST Endpoints

@app.get("/")
async def root():
    """Serve main page"""
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/models")
async def get_models():
    """Get available Ollama models"""
    models = await ollama.list_models()
    return {"models": models}


@app.get("/api/tools")
async def get_tools():
    """Get available MCP tools"""
    tools = await mcp_bridge.list_tools()
    return {"tools": tools, "count": len(tools)}


@app.get("/api/health")
async def health():
    """Health check"""
    ollama_ok = len(await ollama.list_models()) > 0
    tools_ok = len(await mcp_bridge.list_tools()) > 0

    return {
        "status": "healthy" if (ollama_ok and tools_ok) else "degraded",
        "ollama": "connected" if ollama_ok else "disconnected",
        "mcp": "connected" if tools_ok else "disconnected",
        "timestamp": datetime.now().isoformat()
    }


# WebSocket Endpoint

@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    """
    WebSocket endpoint for streaming chat

    Protocol:
    - Client sends: {"model": "llama3.1:8b", "message": "Hello", "history": [...]}
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

            # Build messages
            messages = history + [{"role": "user", "content": message}]

            # Get available tools and convert to Ollama format
            mcp_tools = await mcp_bridge.list_tools()
            ollama_tools = []

            for tool in mcp_tools:
                # Convert MCP tool schema to Ollama function calling format
                ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool.get("inputSchema", {})
                    }
                })

            # Stream response from Ollama with tools
            full_response = ""
            async for chunk in ollama.chat(
                model,
                messages,
                stream=True,
                temperature=temperature,
                tools=ollama_tools if ollama_tools else None
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

                    if content:
                        full_response += content
                        await websocket.send_json({
                            "type": "token",
                            "content": content
                        })

                    # Check for tool calls (if model supports it)
                    if "tool_calls" in msg and msg["tool_calls"]:
                        for tool_call in msg["tool_calls"]:
                            func = tool_call.get("function", {})
                            tool_name = func.get("name")
                            tool_args = func.get("arguments", {})

                            # Notify client of tool call
                            await websocket.send_json({
                                "type": "tool_call",
                                "tool": tool_name,
                                "args": tool_args
                            })

                            # Execute tool via MCP bridge
                            result = await mcp_bridge.call_tool(tool_name, tool_args)

                            # Send result to client
                            await websocket.send_json({
                                "type": "tool_result",
                                "tool": tool_name,
                                "result": result
                            })

                            # Add tool result to conversation and continue
                            messages.append({"role": "assistant", "content": "", "tool_calls": [tool_call]})
                            messages.append({
                                "role": "tool",
                                "content": json.dumps(result)
                            })

                            # Get final response with tool result
                            async for chunk2 in ollama.chat(
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

                # Check if done
                if chunk.get("done"):
                    await websocket.send_json({"type": "done"})
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
    # Check configuration
    if not MCP_AUTH_TOKEN:
        print("WARNING: MCP_AUTH_TOKEN not set!")
        print("Set with: export MCP_AUTH_TOKEN='your_token_here'")

    if not MCP_BRIDGE_PATH.exists():
        print(f"ERROR: MCP bridge not found at {MCP_BRIDGE_PATH}")
        print("Make sure mcp_bridge.py exists")
        sys.exit(1)

    print("=" * 70)
    print("NetMonitor Chat Starting")
    print("=" * 70)
    print(f"Ollama: {OLLAMA_BASE_URL}")
    print(f"MCP Server: {MCP_SERVER_URL}")
    print(f"MCP Bridge: {MCP_BRIDGE_PATH}")
    print(f"Interface: http://localhost:8000")
    print("=" * 70)

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
