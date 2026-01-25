#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
NetMonitor MCP Streamable HTTP Server (FastAPI Edition)

Modern MCP server implementing the Streamable HTTP protocol with FastAPI.
Supports both Claude Desktop and Open-WebUI with token authentication.

Features:
- Single endpoint (/mcp) for all MCP communication
- Stateless operation (fresh transport per request)
- Token-based authentication with rate limiting
- All 60 NetMonitor tools available
- SSE streaming support (GET /mcp)
- JSON-RPC over HTTP (POST /mcp)
- OpenAPI/Swagger docs (/docs and /redoc) - PUBLIC ACCESS
"""

import os
import sys
import logging
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence, Dict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from starlette.types import Receive, Scope, Send
from starlette.routing import Mount, Route
from starlette.responses import Response
import uvicorn

# MCP SDK imports
from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import Tool, TextContent

# NetMonitor imports
from shared_tools import NetMonitorTools, TOOL_DEFINITIONS
from database_client import MCPDatabaseClient
from ollama_client import OllamaClient
from token_auth import TokenAuthManager
from streamable_http_middleware import TokenAuthMiddleware
from streamable_http_config import load_config, validate_config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/mcp_streamable_http.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NetMonitor.MCP.StreamableHTTP')


class NetMonitorStreamableHTTPServer:
    """
    Production-ready MCP Streamable HTTP server for NetMonitor (FastAPI Edition)

    Implements the MCP Streamable HTTP protocol with:
    - Token authentication and rate limiting
    - All 60 NetMonitor security tools
    - Support for Claude Desktop and Open-WebUI
    - Stateless operation (no session persistence)
    - OpenAPI/Swagger documentation (public access)
    """

    def __init__(self):
        """Initialize MCP Streamable HTTP server"""
        logger.info("Initializing NetMonitor MCP Streamable HTTP Server (FastAPI)...")

        # Load configuration
        self.config = load_config()
        validate_config(self.config)

        # Initialize MCP Server core
        self.mcp_server = Server("netmonitor-soc")
        logger.info("MCP Server core initialized")

        # Initialize database client
        try:
            self.db = MCPDatabaseClient(**self.config['database'])
            logger.info(f"Database connected: {self.config['database']['database']}@{self.config['database']['host']}")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

        # Initialize Ollama client (optional)
        try:
            self.ollama = OllamaClient(**self.config['ollama'])
            if self.ollama.available:
                logger.info(f"Ollama initialized: {self.config['ollama']['model']}")
            else:
                logger.warning("Ollama not available - AI analysis tools will be disabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Ollama: {e}")
            self.ollama = None

        # Initialize token manager
        try:
            self.token_manager = TokenAuthManager(self.config['database'])
            logger.info("Token authentication manager initialized")
        except Exception as e:
            logger.error(f"Failed to initialize token manager: {e}")
            raise

        # Initialize shared tools
        dashboard_host = os.getenv('DASHBOARD_HOST', '127.0.0.1')
        dashboard_port = os.getenv('DASHBOARD_PORT', '8080')
        dashboard_url = f"http://{dashboard_host}:{dashboard_port}"

        self.tools = NetMonitorTools(self.db, self.ollama, dashboard_url=dashboard_url)
        logger.info(f"Loaded {len(TOOL_DEFINITIONS)} tools")

        # Register MCP protocol handlers
        self._register_mcp_handlers()

        # Create StreamableHTTP session manager (stateless mode)
        self.session_manager = StreamableHTTPSessionManager(
            app=self.mcp_server,
            event_store=None,  # No resumability (stateless)
            json_response=False,  # Use SSE streaming
            stateless=True,  # Fresh transport per request
        )
        logger.info("StreamableHTTP session manager created (stateless mode)")

    def _register_mcp_handlers(self):
        """Register MCP protocol handlers for tools and resources"""

        @self.mcp_server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available tools"""
            return [
                Tool(
                    name=tool_def['name'],
                    description=tool_def['description'],
                    inputSchema=tool_def['input_schema']
                )
                for tool_def in TOOL_DEFINITIONS
            ]

        @self.mcp_server.call_tool()
        async def call_tool(name: str, arguments: Any) -> Sequence[TextContent]:
            """Call a tool by name with arguments"""
            logger.info(f"Tool called: {name} with args: {json.dumps(arguments, default=str)[:100]}")

            # Find tool definition
            tool_def = next((t for t in TOOL_DEFINITIONS if t['name'] == name), None)
            if not tool_def:
                error_msg = f"Unknown tool: {name}"
                logger.error(error_msg)
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": error_msg}, indent=2)
                )]

            try:
                # Call corresponding method on tools instance
                method = getattr(self.tools, name)
                result = await method(arguments)

                logger.info(f"Tool {name} executed successfully")

                # Return result as TextContent
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, default=str)
                )]

            except Exception as e:
                error_msg = f"Tool execution error in {name}: {str(e)}"
                logger.error(error_msg, exc_info=True)
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "error": error_msg,
                        "tool": name,
                        "timestamp": datetime.now().isoformat()
                    }, indent=2)
                )]

        logger.info(f"Registered {len(TOOL_DEFINITIONS)} tools with MCP server")

    def create_app(self) -> FastAPI:
        """Create FastAPI application with MCP Streamable HTTP support + OpenAPI docs"""

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            """Manage StreamableHTTP session manager lifecycle"""
            logger.info("Starting StreamableHTTP session manager...")
            async with self.session_manager.run():
                logger.info("StreamableHTTP session manager running")
                yield
            logger.info("StreamableHTTP session manager stopped")

        # Get root_path from environment for reverse proxy support
        root_path = os.environ.get('MCP_ROOT_PATH', '')

        # Create FastAPI app
        # redirect_slashes=False prevents 307 redirect from /mcp to /mcp/
        app = FastAPI(
            title="NetMonitor MCP API",
            description="MCP Streamable HTTP API for NetMonitor Security Operations Center\n\n"
                       "Provides 60+ AI tools for security monitoring, threat detection, and SOC management.\n\n"
                       "**Authentication:** Bearer token required for all endpoints except /health and docs.\n\n"
                       "**MCP Protocol:** GET /mcp (SSE streaming) or POST /mcp (JSON-RPC).",
            version="2.0.0",
            docs_url="/docs",
            redoc_url="/redoc",
            root_path=root_path,
            lifespan=lifespan,
            debug=self.config['debug']
            # Note: redirect_slashes is left as default (True)
        )

        # Note: MCP middleware will be added at the end of create_app()
        # to intercept /mcp requests before FastAPI's redirect_slashes

        # ==================== FastAPI Routes (for docs) ====================

        @app.get("/", tags=["Info"])
        async def root():
            """
            API root endpoint - Get API information

            Returns server info, authentication requirements, and available endpoints.
            """
            return {
                "name": "NetMonitor MCP API",
                "version": "2.0.0",
                "description": "MCP Streamable HTTP API for NetMonitor SOC",
                "protocol": "MCP Streamable HTTP (spec 2025-03-26)",
                "mcp_endpoint": "/mcp",
                "docs": "/docs",
                "redoc": "/redoc",
                "health": "/health",
                "authentication": "Bearer token required (except /health, /docs, /redoc)",
                "tools_available": len(TOOL_DEFINITIONS)
            }

        @app.get("/health", tags=["Health"])
        async def health_check():
            """
            Health check endpoint - No authentication required

            Returns server health status, database connectivity, and component availability.
            """
            return {
                "status": "healthy",
                "server": "NetMonitor MCP Streamable HTTP (FastAPI)",
                "version": "2.0.0",
                "database": "connected" if self.db else "disconnected",
                "ollama": "available" if self.ollama and self.ollama.available else "unavailable",
                "tools": len(TOOL_DEFINITIONS),
                "timestamp": datetime.now().isoformat()
            }

        @app.get("/metrics", tags=["Monitoring"])
        async def metrics(request: Request):
            """
            Metrics endpoint - Requires authentication

            Returns metrics and statistics about the MCP server.
            Requires valid Bearer token.
            """
            # Get token details from middleware
            if not hasattr(request.state, 'token_details'):
                return JSONResponse({"error": "Not authenticated"}, status_code=401)

            token_details = request.state.token_details

            return {
                "token_name": token_details['name'],
                "token_scope": token_details['scope'],
                "server_uptime": "N/A",  # TODO: track server start time
                "total_tools": len(TOOL_DEFINITIONS),
                "timestamp": datetime.now().isoformat()
            }

        @app.get("/tools", tags=["MCP Tools"])
        async def list_tools():
            """
            List all available MCP tools - No authentication required

            Returns comprehensive list of all 60+ NetMonitor security tools with:
            - Tool names and descriptions
            - Input parameter schemas
            - Usage examples

            This endpoint is public to allow exploration of available tools.
            Tool execution via /mcp endpoint requires authentication.
            """
            # TOOL_DEFINITIONS is a list of dicts, not a dict itself
            tools_list = []
            for tool_def in TOOL_DEFINITIONS:
                tools_list.append({
                    "name": tool_def.get('name', 'unknown'),
                    "description": tool_def.get('description', 'No description available'),
                    "inputSchema": tool_def.get('input_schema', {
                        "type": "object",
                        "properties": {},
                        "required": []
                    })
                })

            # Sort by name for easier browsing
            tools_list.sort(key=lambda x: x['name'])

            return {
                "total": len(tools_list),
                "tools": tools_list,
                "usage": {
                    "endpoint": "/mcp",
                    "method": "POST",
                    "authentication": "Bearer token required",
                    "example_request": {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "name": "list_devices",
                            "arguments": {}
                        },
                        "id": 1
                    }
                }
            }

        # ==================== Middleware Configuration ====================

        # Add CORS middleware
        if self.config['cors']['enabled']:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=self.config['cors']['origins'],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            logger.info(f"CORS enabled for origins: {self.config['cors']['origins']}")

        # Token authentication middleware for non-MCP endpoints
        # Note: /mcp is handled by MCPInterceptMiddleware with its own auth
        if self.config['auth']['required']:
            app.add_middleware(
                TokenAuthMiddleware,
                token_manager=self.token_manager,
                exempt_paths=['/health', '/docs', '/redoc', '/openapi.json', '/tools', '/mcp', '/mcp/']
            )
            logger.info("Token authentication enabled for FastAPI routes")

        # ==================== Custom OpenAPI Schema ====================
        # Add MCP tools to OpenAPI schema (they don't appear automatically since /mcp is mounted)
        def custom_openapi():
            if app.openapi_schema:
                return app.openapi_schema

            try:
                # Get default OpenAPI schema from FastAPI using get_openapi utility
                openapi_schema = get_openapi(
                    title=app.title,
                    version=app.version,
                    description=app.description,
                    routes=app.routes,
                )

                # Ensure components exists
                if "components" not in openapi_schema:
                    openapi_schema["components"] = {}
                if "securitySchemes" not in openapi_schema["components"]:
                    openapi_schema["components"]["securitySchemes"] = {}
                if "schemas" not in openapi_schema["components"]:
                    openapi_schema["components"]["schemas"] = {}

                # Set servers array for correct URL generation in Swagger UI
                # This ensures Swagger UI generates URLs like /mcp/tools instead of /tools
                if root_path:
                    openapi_schema["servers"] = [
                        {
                            "url": root_path,
                            "description": "MCP API (via nginx reverse proxy)"
                        }
                    ]
                else:
                    openapi_schema["servers"] = [
                        {
                            "url": "/",
                            "description": "MCP API (direct access)"
                        }
                    ]

                # Add security scheme for Bearer token
                openapi_schema["components"]["securitySchemes"]["bearerAuth"] = {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "Token",
                    "description": "MCP API token from token management system"
                }

                # Add MCP tools documentation
                openapi_schema["paths"]["/mcp"] = {
                    "post": {
                        "tags": ["MCP Tools"],
                        "summary": "MCP JSON-RPC Endpoint",
                        "description": (
                            f"Execute MCP tools via JSON-RPC protocol.\n\n"
                            f"**Available Tools:** {len(TOOL_DEFINITIONS)} tools for security monitoring\n\n"
                            f"**Authentication:** Bearer token required in Authorization header\n\n"
                            f"**Protocol:** MCP Streamable HTTP (spec 2025-03-26)\n\n"
                            f"**Request Format:**\n```json\n{{\n"
                            f'  "jsonrpc": "2.0",\n'
                            f'  "method": "tools/call",\n'
                            f'  "params": {{\n'
                            f'    "name": "tool_name",\n'
                            f'    "arguments": {{}}\n'
                            f'  }},\n'
                            f'  "id": 1\n'
                            f"}}\n```"
                        ),
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "jsonrpc": {"type": "string", "example": "2.0"},
                                            "method": {"type": "string", "example": "tools/call"},
                                            "params": {"type": "object"},
                                            "id": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Tool execution result"},
                            "401": {"description": "Missing or invalid Bearer token"},
                            "429": {"description": "Rate limit exceeded"}
                        }
                    },
                    "get": {
                        "tags": ["MCP Tools"],
                        "summary": "MCP SSE Streaming Endpoint",
                        "description": (
                            "Server-Sent Events (SSE) streaming for MCP protocol.\n\n"
                            "Used by Claude Desktop and other SSE-compatible clients.\n\n"
                            "**Authentication:** Bearer token required in Authorization header"
                        ),
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "SSE stream established"},
                            "401": {"description": "Missing or invalid Bearer token"}
                        }
                    }
                }

                # Add tools list as a separate schema component for reference
                # TOOL_DEFINITIONS is a list of dicts, not a dict itself
                tools_list = []
                for tool_def in TOOL_DEFINITIONS:
                    tools_list.append({
                        "name": tool_def.get('name', 'unknown'),
                        "description": tool_def.get('description', 'No description'),
                        "inputSchema": tool_def.get('input_schema', {})
                    })

                openapi_schema["components"]["schemas"]["MCPTools"] = {
                    "type": "object",
                    "description": f"Available MCP Tools ({len(TOOL_DEFINITIONS)} tools)",
                    "properties": {
                        "tools": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "description": {"type": "string"},
                                    "inputSchema": {"type": "object"}
                                }
                            },
                            "example": tools_list[:5]  # Show first 5 tools as example
                        }
                    }
                }

                app.openapi_schema = openapi_schema
                return app.openapi_schema

            except Exception as e:
                logger.error(f"Error generating OpenAPI schema: {e}", exc_info=True)
                # Return minimal schema on error
                return {
                    "openapi": "3.1.0",
                    "info": {
                        "title": app.title,
                        "version": app.version
                    },
                    "paths": {}
                }

        app.openapi = custom_openapi

        logger.info("FastAPI application created with OpenAPI docs")

        # Create pure ASGI middleware to intercept /mcp requests
        # This bypasses FastAPI's redirect_slashes feature completely
        session_manager = self.session_manager
        token_manager = self.token_manager
        auth_required = self.config['auth']['required']

        class MCPInterceptMiddleware:
            """ASGI middleware that intercepts /mcp requests before FastAPI routing"""
            def __init__(self, app):
                self.app = app

            async def __call__(self, scope: Scope, receive: Receive, send: Send):
                if scope["type"] == "http":
                    path = scope.get("path", "")
                    # Handle both /mcp and /mcp/
                    if path == "/mcp" or path == "/mcp/":
                        # Authenticate the request if auth is required
                        if auth_required:
                            headers = dict(scope.get("headers", []))
                            auth_header = headers.get(b"authorization", b"").decode()

                            if not auth_header.startswith("Bearer "):
                                # Return 401 Unauthorized
                                await self._send_error(send, 401, {
                                    "error": "missing_token",
                                    "message": "Missing or invalid Authorization header. Use: Authorization: Bearer <token>"
                                })
                                return

                            token = auth_header[7:]  # Remove "Bearer " prefix
                            token_details = token_manager.validate_token(token)

                            if not token_details:
                                await self._send_error(send, 401, {
                                    "error": "invalid_token",
                                    "message": "Invalid or expired token"
                                })
                                return

                            # Check rate limits
                            if not token_manager.check_rate_limit(token_details['id'], token_details):
                                await self._send_error(send, 429, {
                                    "error": "rate_limit_exceeded",
                                    "message": "Rate limit exceeded. Please try again later."
                                })
                                return

                            logger.info(f"MCP middleware handling: {scope.get('method')} {path} (token: {token_details['name']})")
                        else:
                            logger.info(f"MCP middleware handling: {scope.get('method')} {path}")

                        await session_manager.handle_request(scope, receive, send)
                        return
                await self.app(scope, receive, send)

            async def _send_error(self, send, status_code: int, error_body: dict):
                """Send an error response"""
                import json
                body = json.dumps(error_body).encode()
                await send({
                    "type": "http.response.start",
                    "status": status_code,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"www-authenticate", b"Bearer"] if status_code == 401 else [b"x-error", b"true"]
                    ]
                })
                await send({
                    "type": "http.response.body",
                    "body": body
                })

        # Wrap FastAPI app with MCP middleware
        wrapped_app = MCPInterceptMiddleware(app)
        # Store original FastAPI app for reference
        wrapped_app.fastapi_app = app

        logger.info("MCP intercept middleware registered for /mcp and /mcp/")
        return wrapped_app

    def run(self):
        """Run the server with uvicorn"""
        app = self.create_app()
        # Get original FastAPI app for logging
        fastapi_app = getattr(app, 'fastapi_app', app)

        logger.info("=" * 70)
        logger.info("NetMonitor MCP Streamable HTTP Server (FastAPI Edition)")
        logger.info("=" * 70)
        logger.info(f"Server: http://{self.config['host']}:{self.config['port']}")
        logger.info(f"MCP Endpoint: http://{self.config['host']}:{self.config['port']}/mcp")
        logger.info(f"OpenAPI Docs: http://{self.config['host']}:{self.config['port']}/docs")
        logger.info(f"ReDoc: http://{self.config['host']}:{self.config['port']}/redoc")
        logger.info(f"Health Check: http://{self.config['host']}:{self.config['port']}/health")
        logger.info(f"Tools Available: {len(TOOL_DEFINITIONS)}")
        logger.info(f"Authentication: {'Enabled' if self.config['auth']['required'] else 'Disabled'}")
        logger.info(f"Debug Mode: {self.config['debug']}")
        logger.info("=" * 70)

        # Create uvicorn config
        config = uvicorn.Config(
            app,
            host=self.config['host'],
            port=self.config['port'],
            log_level=self.config['log_level'].lower(),
            access_log=True,
        )

        # Run server
        server = uvicorn.Server(config)
        server.run()


def main():
    """Main entry point"""
    try:
        server = NetMonitorStreamableHTTPServer()
        server.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
