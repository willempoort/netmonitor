#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
REST API Wrapper for Open-WebUI Custom Functions

Wraps MCP Streamable HTTP server with simple REST endpoints that Open-WebUI
custom functions can call. Avoids Open-WebUI's MCP native bugs (pickle errors).

Endpoints:
  GET  /tools           - List all available tools
  POST /tools/execute   - Execute a tool
  GET  /health          - Health check
"""

import os
import sys
import json
import logging
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
import uvicorn

# MCP imports
from mcp_server.shared_tools import NetMonitorTools, TOOL_DEFINITIONS
from database_client import MCPDatabaseClient
from ollama_client import OllamaClient
from mcp_server.token_auth import TokenAuthManager
from mcp_server.streamable_http_config import load_config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/openwebui_rest_wrapper.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NetMonitor.OpenWebUI.REST')


class OpenWebUIRestWrapper:
    """REST API wrapper for Open-WebUI custom functions"""

    def __init__(self):
        """Initialize REST wrapper"""
        logger.info("Initializing Open-WebUI REST Wrapper...")

        # Load config
        self.config = load_config()
        
        # Initialize database client
        db_config = self.config['database']
        self.db = MCPDatabaseClient(
            host=db_config['host'],
            port=db_config['port'],
            database=db_config['database'],
            user=db_config['user'],
            password=db_config['password']
        )
        logger.info("Database client initialized")

        # Initialize Ollama (optional)
        try:
            ollama_config = self.config.get('ollama', {})
            if ollama_config.get('enabled', False):
                self.ollama = OllamaClient(
                    base_url=ollama_config.get('base_url', 'http://localhost:11434'),
                    model=ollama_config.get('model', 'llama3.2')
                )
                logger.info("Ollama client initialized")
            else:
                self.ollama = None
                logger.info("Ollama disabled")
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
            self.ollama = None

        # Initialize token manager for auth (needs write access for usage tracking)
        # Use full credentials, not read-only
        token_db_config = {
            'host': self.config['database']['host'],
            'port': self.config['database']['port'],
            'database': self.config['database']['database'],
            'user': os.getenv('DB_USER', 'netmonitor'),  # Full user, not readonly
            'password': os.getenv('DB_PASSWORD', 'netmonitor')
        }
        self.token_manager = TokenAuthManager(token_db_config)
        logger.info("Token manager initialized")

        # Initialize tools
        dashboard_host = os.getenv('DASHBOARD_HOST', '127.0.0.1')
        dashboard_port = os.getenv('DASHBOARD_PORT', '8080')
        dashboard_url = f"http://{dashboard_host}:{dashboard_port}"
        self.tools = NetMonitorTools(self.db, self.ollama, dashboard_url=dashboard_url)
        logger.info(f"Tools initialized: {len(TOOL_DEFINITIONS)} tools available")

    def _authenticate(self, auth_header: Optional[str]) -> tuple[bool, Optional[str], Optional[Dict]]:
        """
        Authenticate request using Bearer token
        
        Returns:
            (success, error_message, token_info)
        """
        if not auth_header:
            return False, "Missing Authorization header", None
        
        if not auth_header.startswith('Bearer '):
            return False, "Invalid Authorization format. Use: Bearer <token>", None
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Validate token
        token_info = self.token_manager.validate_token(token)

        if token_info is None:
            return False, "Invalid or expired token", None

        return True, None, token_info

    async def list_tools(self, request):
        """List all available tools"""
        # Authenticate
        auth_header = request.headers.get('Authorization')
        is_valid, error, token_info = self._authenticate(auth_header)
        
        if not is_valid:
            return JSONResponse(
                {"error": error, "code": 401},
                status_code=401
            )
        
        logger.info(f"list_tools called by token: {token_info.get('name')}")
        
        # Return tool list
        tools = [
            {
                "name": tool["name"],
                "description": tool["description"],
                "input_schema": tool["input_schema"]
            }
            for tool in TOOL_DEFINITIONS
        ]
        
        return JSONResponse({
            "success": True,
            "tools": tools,
            "count": len(tools)
        })

    async def execute_tool(self, request):
        """Execute a tool"""
        # Authenticate
        auth_header = request.headers.get('Authorization')
        is_valid, error, token_info = self._authenticate(auth_header)
        
        if not is_valid:
            return JSONResponse(
                {"error": error, "code": 401},
                status_code=401
            )
        
        # Parse request
        try:
            body = await request.json()
        except Exception as e:
            return JSONResponse(
                {"error": f"Invalid JSON: {str(e)}", "code": 400},
                status_code=400
            )
        
        tool_name = body.get('tool_name')
        parameters = body.get('parameters', {})
        
        if not tool_name:
            return JSONResponse(
                {"error": "Missing 'tool_name' parameter", "code": 400},
                status_code=400
            )
        
        logger.info(f"execute_tool: {tool_name} by {token_info.get('name')}")
        
        # Find tool
        tool_def = next((t for t in TOOL_DEFINITIONS if t['name'] == tool_name), None)
        if not tool_def:
            return JSONResponse(
                {"error": f"Unknown tool: {tool_name}", "code": 404},
                status_code=404
            )
        
        # Check scope
        required_scope = tool_def.get('scope_required', 'read_only')
        token_scope = token_info.get('scope', 'read_only')
        
        scope_hierarchy = {'read_only': 0, 'read_write': 1, 'admin': 2}
        if scope_hierarchy.get(token_scope, 0) < scope_hierarchy.get(required_scope, 0):
            return JSONResponse(
                {
                    "error": f"Insufficient permissions. Tool requires '{required_scope}', token has '{token_scope}'",
                    "code": 403
                },
                status_code=403
            )
        
        # Execute tool
        try:
            method = getattr(self.tools, tool_name)
            result = await method(parameters)
            
            logger.info(f"Tool {tool_name} executed successfully")
            
            return JSONResponse({
                "success": True,
                "data": result
            })
        
        except Exception as e:
            logger.error(f"Tool execution error in {tool_name}: {str(e)}", exc_info=True)
            return JSONResponse(
                {
                    "error": f"Tool execution failed: {str(e)}",
                    "code": 500,
                    "tool": tool_name
                },
                status_code=500
            )

    async def health_check(self, request):
        """Health check endpoint"""
        return JSONResponse({
            "status": "healthy",
            "service": "NetMonitor Open-WebUI REST Wrapper",
            "tools": len(TOOL_DEFINITIONS),
            "timestamp": datetime.now().isoformat()
        })


def create_app():
    """Create Starlette app"""
    wrapper = OpenWebUIRestWrapper()
    
    # Create routes
    routes = [
        Route('/tools', wrapper.list_tools, methods=['GET']),
        Route('/tools/execute', wrapper.execute_tool, methods=['POST']),
        Route('/health', wrapper.health_check, methods=['GET']),
    ]
    
    # Create app
    app = Starlette(debug=False, routes=routes)
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    logger.info("App created successfully")
    return app


def main():
    """Main entry point"""
    logger.info("=" * 70)
    logger.info("NetMonitor Open-WebUI REST Wrapper Starting")
    logger.info("=" * 70)
    
    # Get config
    host = os.getenv('OPENWEBUI_REST_HOST', '127.0.0.1')
    port = int(os.getenv('OPENWEBUI_REST_PORT', '8001'))
    
    logger.info(f"Host: {host}")
    logger.info(f"Port: {port}")
    logger.info("=" * 70)
    
    # Create app
    app = create_app()
    
    # Run server
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )


if __name__ == "__main__":
    main()
