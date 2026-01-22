#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
NetMonitor MCP Streamable HTTP Server

Modern MCP server implementing the Streamable HTTP protocol (spec 2025-03-26).
Supports both Claude Desktop and Open-WebUI with token authentication.

Features:
- Single endpoint (/mcp) for all MCP communication
- Stateless operation (fresh transport per request)
- Token-based authentication with rate limiting
- All 60 NetMonitor tools available
- SSE streaming support (GET /mcp)
- JSON-RPC over HTTP (POST /mcp)
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

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.types import Receive, Scope, Send
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
    Production-ready MCP Streamable HTTP server for NetMonitor

    Implements the MCP Streamable HTTP protocol with:
    - Token authentication and rate limiting
    - All 60 NetMonitor security tools
    - Support for Claude Desktop and Open-WebUI
    - Stateless operation (no session persistence)
    """

    def __init__(self):
        """Initialize MCP Streamable HTTP server"""
        logger.info("Initializing NetMonitor MCP Streamable HTTP Server...")

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
        # Dashboard URL for memory management tools
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

    def create_app(self) -> Starlette:
        """Create Starlette ASGI application with MCP Streamable HTTP support"""

        @asynccontextmanager
        async def lifespan(app: Starlette):
            """Manage StreamableHTTP session manager lifecycle"""
            logger.info("Starting StreamableHTTP session manager...")
            async with self.session_manager.run():
                logger.info("StreamableHTTP session manager running")
                yield
            logger.info("StreamableHTTP session manager stopped")

        # Create ASGI app for MCP endpoint
        async def mcp_asgi_app(scope: Scope, receive: Receive, send: Send):
            """Raw ASGI app for MCP Streamable HTTP requests"""
            await self.session_manager.handle_request(scope, receive, send)

        async def health_check(request):
            """Health check endpoint"""
            return JSONResponse({
                "status": "healthy",
                "server": "NetMonitor MCP Streamable HTTP",
                "version": "1.0.0",
                "database": "connected" if self.db else "disconnected",
                "ollama": "available" if self.ollama and self.ollama.available else "unavailable",
                "tools": len(TOOL_DEFINITIONS),
                "timestamp": datetime.now().isoformat()
            })

        async def metrics(request):
            """Metrics endpoint (requires auth)"""
            # Get token details from middleware
            if not hasattr(request.state, 'token_details'):
                return JSONResponse({"error": "Not authenticated"}, status_code=401)

            token_details = request.state.token_details

            return JSONResponse({
                "token_name": token_details['name'],
                "token_scope": token_details['scope'],
                "server_uptime": "N/A",  # TODO: track server start time
                "total_tools": len(TOOL_DEFINITIONS),
                "timestamp": datetime.now().isoformat()
            })

        # Routes
        # Order matters: specific routes first, then mount points
        from starlette.routing import Mount
        routes = [
            # Specific routes (must come before Mount points)
            Route("/health", endpoint=health_check, methods=["GET"]),
            Route("/metrics", endpoint=metrics, methods=["GET"]),
            # MCP endpoint
            Mount("/mcp", app=mcp_asgi_app),
            # Also mount on root for Open-WebUI compatibility
            Mount("/", app=mcp_asgi_app),
        ]

        # Create app with middleware
        app = Starlette(
            debug=self.config['debug'],
            routes=routes,
            lifespan=lifespan
        )

        # Add CORS middleware (must be added BEFORE TokenAuthMiddleware)
        if self.config['cors']['enabled']:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=self.config['cors']['origins'],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            logger.info(f"CORS enabled for origins: {self.config['cors']['origins']}")

        # Add token authentication middleware
        if self.config['auth']['required']:
            app.add_middleware(
                TokenAuthMiddleware,
                token_manager=self.token_manager,
                exempt_paths=['/health', '/docs', '/redoc', '/openapi.json']
            )
            logger.info("Token authentication enabled (docs accessible without auth)")

        logger.info("Starlette ASGI application created")
        return app

    def run(self):
        """Run the server with uvicorn"""
        app = self.create_app()

        logger.info("=" * 70)
        logger.info("NetMonitor MCP Streamable HTTP Server")
        logger.info("=" * 70)
        logger.info(f"Server: http://{self.config['host']}:{self.config['port']}")
        logger.info(f"MCP Endpoint: http://{self.config['host']}:{self.config['port']}/mcp")
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
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
