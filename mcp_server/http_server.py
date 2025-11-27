#!/usr/bin/env python3
"""
MCP HTTP API Server

Modern HTTP-based MCP server with token authentication.
Provides RESTful API access to NetMonitor MCP tools.
"""

import os
import sys
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
import asyncio

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Import MCP components
from database_client import MCPDatabaseClient
from geoip_helper import get_country_for_ip, is_private_ip
from ollama_client import OllamaClient
from token_auth import TokenAuthManager, verify_token

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/mcp_http_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NetMonitor.MCP.HTTP')


# ==================== Pydantic Models ====================

class ToolRequest(BaseModel):
    """Request model for tool execution"""
    tool_name: str = Field(..., description="Name of the tool to execute")
    parameters: Dict[str, Any] = Field(default={}, description="Tool parameters")


class ToolResponse(BaseModel):
    """Response model for tool execution"""
    success: bool
    tool_name: str
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: Optional[int] = None
    timestamp: str


class ToolInfo(BaseModel):
    """Tool metadata"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    scope_required: str  # read_only, read_write, admin


class ResourceInfo(BaseModel):
    """Resource metadata"""
    uri: str
    name: str
    mime_type: str
    description: str


# ==================== MCP HTTP Server ====================

class MCPHTTPServer:
    """HTTP-based MCP Server with token authentication"""

    def __init__(self):
        """Initialize MCP HTTP server"""
        self.app = FastAPI(
            title="NetMonitor MCP API",
            description="HTTP API for NetMonitor Security Operations Center via Model Context Protocol",
            version="2.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )

        self.db = None
        self.ollama = None
        self.token_manager = None

        # Initialize components
        self._init_database()
        self._init_ollama()
        self._init_token_manager()

        # Configure middleware
        self._configure_middleware()

        # Register routes
        self._register_routes()

        # Attach token manager to verify_token function
        verify_token.token_manager = self.token_manager

        logger.info("MCP HTTP Server initialized")

    def _init_database(self):
        """Initialize database connection"""
        try:
            host = os.environ.get('NETMONITOR_DB_HOST', 'localhost')
            port = int(os.environ.get('NETMONITOR_DB_PORT', '5432'))
            database = os.environ.get('NETMONITOR_DB_NAME', 'netmonitor')
            user = os.environ.get('NETMONITOR_DB_USER', 'mcp_readonly')
            password = os.environ.get('NETMONITOR_DB_PASSWORD', 'mcp_netmonitor_readonly_2024')

            self.db = MCPDatabaseClient(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )

            logger.info(f"Connected to database: {database}@{host}")

        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def _init_ollama(self):
        """Initialize Ollama client (optional)"""
        try:
            ollama_url = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434')
            ollama_model = os.environ.get('OLLAMA_MODEL', 'llama3.2')

            self.ollama = OllamaClient(base_url=ollama_url, model=ollama_model)

            if self.ollama.available:
                logger.info(f"Ollama initialized: {ollama_model} at {ollama_url}")
            else:
                logger.warning("Ollama not available - AI analysis tools will be disabled")

        except Exception as e:
            logger.warning(f"Failed to initialize Ollama: {e}")
            self.ollama = None

    def _init_token_manager(self):
        """Initialize token authentication manager"""
        try:
            host = os.environ.get('NETMONITOR_DB_HOST', 'localhost')
            port = int(os.environ.get('NETMONITOR_DB_PORT', '5432'))
            database = os.environ.get('NETMONITOR_DB_NAME', 'netmonitor')
            user = os.environ.get('NETMONITOR_DB_USER', 'mcp_readonly')
            password = os.environ.get('NETMONITOR_DB_PASSWORD', 'mcp_netmonitor_readonly_2024')

            self.token_manager = TokenAuthManager({
                'host': host,
                'port': port,
                'database': database,
                'user': user,
                'password': password
            })

            logger.info("Token authentication manager initialized")

        except Exception as e:
            logger.error(f"Failed to initialize token manager: {e}")
            raise

    def _configure_middleware(self):
        """Configure FastAPI middleware"""

        # CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            start_time = time.time()

            # Process request
            response = await call_next(request)

            # Calculate response time
            response_time_ms = int((time.time() - start_time) * 1000)

            # Log request (if authenticated)
            token = request.headers.get('authorization', '').replace('Bearer ', '')
            if token and self.token_manager:
                token_details = self.token_manager.validate_token(token)
                if token_details:
                    self.token_manager.log_request(
                        token_id=token_details['id'],
                        endpoint=str(request.url.path),
                        method=request.method,
                        ip_address=request.client.host,
                        user_agent=request.headers.get('user-agent'),
                        status_code=response.status_code,
                        response_time_ms=response_time_ms
                    )

            # Add response time header
            response.headers['X-Response-Time'] = f"{response_time_ms}ms"

            return response

    def _register_routes(self):
        """Register API routes"""

        # ==================== Public Endpoints ====================

        @self.app.get("/")
        async def root():
            """API root endpoint"""
            return {
                "name": "NetMonitor MCP API",
                "version": "2.0.0",
                "description": "HTTP API for Model Context Protocol",
                "docs": "/docs",
                "authentication": "Bearer token required"
            }

        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "database": "connected" if self.db else "disconnected",
                "ollama": "available" if (self.ollama and self.ollama.available) else "unavailable"
            }

        # ==================== MCP Protocol Endpoints ====================

        @self.app.get("/mcp/tools", response_model=List[ToolInfo])
        async def list_tools(token_details: Dict = Depends(verify_token)):
            """
            List all available MCP tools

            Returns detailed information about each tool including:
            - Name and description
            - Input schema
            - Required permission scope
            """
            return self._get_tools_list()

        @self.app.get("/mcp/resources", response_model=List[ResourceInfo])
        async def list_resources(token_details: Dict = Depends(verify_token)):
            """
            List all available MCP resources

            Resources provide context data that can be read by AI assistants.
            """
            return [
                {
                    "uri": "dashboard://summary",
                    "name": "Dashboard Summary",
                    "mime_type": "text/plain",
                    "description": "Real-time security dashboard overview with statistics and top threats"
                }
            ]

        @self.app.get("/mcp/resources/dashboard/summary")
        async def get_dashboard_resource(token_details: Dict = Depends(verify_token)):
            """
            Get dashboard summary resource

            Returns formatted text summary of security dashboard.
            """
            try:
                summary = await self._get_dashboard_summary()
                return {
                    "success": True,
                    "uri": "dashboard://summary",
                    "mime_type": "text/plain",
                    "content": summary
                }
            except Exception as e:
                logger.error(f"Error getting dashboard summary: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/mcp/tools/execute", response_model=ToolResponse)
        async def execute_tool(
            tool_request: ToolRequest,
            request: Request,
            token_details: Dict = Depends(verify_token)
        ):
            """
            Execute an MCP tool

            Executes the specified tool with the provided parameters.
            Tool access is controlled by the token's permission scope.
            """
            start_time = time.time()

            try:
                # Get tool info
                tool = self._get_tool_by_name(tool_request.tool_name)
                if not tool:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Tool '{tool_request.tool_name}' not found"
                    )

                # Check permissions
                if not self._check_tool_permission(token_details['scope'], tool['scope_required']):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Insufficient permissions. Tool requires '{tool['scope_required']}', token has '{token_details['scope']}'"
                    )

                # Execute tool
                result = await self._execute_tool(tool_request.tool_name, tool_request.parameters)

                execution_time_ms = int((time.time() - start_time) * 1000)

                return ToolResponse(
                    success=True,
                    tool_name=tool_request.tool_name,
                    data=result,
                    execution_time_ms=execution_time_ms,
                    timestamp=datetime.now().isoformat()
                )

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error executing tool '{tool_request.tool_name}': {e}")
                execution_time_ms = int((time.time() - start_time) * 1000)

                return ToolResponse(
                    success=False,
                    tool_name=tool_request.tool_name,
                    error=str(e),
                    execution_time_ms=execution_time_ms,
                    timestamp=datetime.now().isoformat()
                )

        # ==================== Token Management Endpoints (Admin only) ====================

        @self.app.get("/admin/tokens")
        async def list_tokens_endpoint(token_details: Dict = Depends(verify_token)):
            """List all API tokens (admin only)"""
            if token_details['scope'] != 'admin':
                raise HTTPException(status_code=403, detail="Admin access required")

            tokens = self.token_manager.list_tokens(include_disabled=True)
            return {"success": True, "tokens": tokens}

        @self.app.get("/admin/tokens/{token_id}/stats")
        async def get_token_stats(token_id: int, token_details: Dict = Depends(verify_token)):
            """Get usage statistics for a token (admin only)"""
            if token_details['scope'] != 'admin':
                raise HTTPException(status_code=403, detail="Admin access required")

            stats = self.token_manager.get_token_stats(token_id)
            return {"success": True, "stats": stats}

    def _get_tools_list(self) -> List[Dict]:
        """Get list of all available tools with metadata"""
        # This is a simplified version - in production, this would dynamically
        # generate from the actual tool implementations
        tools = [
            {
                "name": "analyze_ip",
                "description": "Analyze a specific IP address to get detailed threat intelligence",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address to analyze"},
                        "hours": {"type": "number", "description": "Lookback period in hours", "default": 24}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_recent_threats",
                "description": "Get recent security threats from the monitoring system",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "number", "default": 24},
                        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                        "threat_type": {"type": "string"},
                        "limit": {"type": "number", "default": 50}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_sensor_status",
                "description": "Get status of all remote sensors",
                "input_schema": {"type": "object", "properties": {}},
                "scope_required": "read_only"
            },
            {
                "name": "set_config_parameter",
                "description": "Set a configuration parameter (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "parameter_name": {"type": "string"},
                        "value": {"type": "string"},
                        "scope": {"type": "string", "enum": ["global", "sensor"], "default": "global"},
                        "sensor_name": {"type": "string"}
                    },
                    "required": ["parameter_name", "value"]
                },
                "scope_required": "read_write"
            }
        ]
        return tools

    def _get_tool_by_name(self, tool_name: str) -> Optional[Dict]:
        """Get tool metadata by name"""
        tools = self._get_tools_list()
        return next((t for t in tools if t['name'] == tool_name), None)

    def _check_tool_permission(self, token_scope: str, required_scope: str) -> bool:
        """Check if token has permission to execute tool"""
        scope_hierarchy = {'read_only': 0, 'read_write': 1, 'admin': 2}
        return scope_hierarchy.get(token_scope, 0) >= scope_hierarchy.get(required_scope, 0)

    async def _execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Any:
        """Execute a tool with the given parameters"""

        # Map tool names to implementation methods
        tool_map = {
            'analyze_ip': self._tool_analyze_ip,
            'get_recent_threats': self._tool_get_recent_threats,
            'get_sensor_status': self._tool_get_sensor_status,
            'set_config_parameter': self._tool_set_config_parameter,
        }

        if tool_name not in tool_map:
            raise ValueError(f"Tool implementation not found: {tool_name}")

        return await tool_map[tool_name](parameters)

    # ==================== Tool Implementations ====================

    async def _tool_analyze_ip(self, params: Dict) -> Dict:
        """Implement analyze_ip tool"""
        ip_address = params.get('ip_address')
        hours = params.get('hours', 24)

        result = self.db.analyze_ip(ip_address, hours)
        return result

    async def _tool_get_recent_threats(self, params: Dict) -> Dict:
        """Implement get_recent_threats tool"""
        hours = params.get('hours', 24)
        severity = params.get('severity')
        threat_type = params.get('threat_type')
        limit = params.get('limit', 50)

        result = self.db.get_recent_threats(
            hours=hours,
            severity=severity,
            threat_type=threat_type,
            limit=limit
        )
        return result

    async def _tool_get_sensor_status(self, params: Dict) -> Dict:
        """Implement get_sensor_status tool"""
        result = self.db.get_sensor_status()
        return result

    async def _tool_set_config_parameter(self, params: Dict) -> Dict:
        """Implement set_config_parameter tool"""
        parameter_name = params.get('parameter_name')
        value = params.get('value')
        scope = params.get('scope', 'global')
        sensor_name = params.get('sensor_name')

        result = self.db.set_config_parameter(
            parameter_name=parameter_name,
            value=value,
            scope=scope,
            sensor_name=sensor_name
        )
        return result

    async def _get_dashboard_summary(self) -> str:
        """Get dashboard summary text"""
        data = self.db.get_dashboard_summary()

        # Format as readable text
        summary = f"""=== NetMonitor Security Dashboard Summary ===

Period: Last 24 hours
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

TOTAL ALERTS: {data.get('total_alerts', 0)}

ALERTS BY SEVERITY:
  CRITICAL: {data.get('by_severity', {}).get('CRITICAL', 0)}
  HIGH: {data.get('by_severity', {}).get('HIGH', 0)}
  MEDIUM: {data.get('by_severity', {}).get('MEDIUM', 0)}
  LOW: {data.get('by_severity', {}).get('LOW', 0)}
  INFO: {data.get('by_severity', {}).get('INFO', 0)}

TOP THREAT TYPES:
"""
        for threat_type, count in data.get('by_type', {}).items():
            summary += f"  {threat_type}: {count}\n"

        summary += "\nTOP SOURCE IPs:\n"
        for ip_info in data.get('top_ips', []):
            summary += f"  {ip_info['ip']}: {ip_info['count']} alerts\n"

        return summary

    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the HTTP server"""
        logger.info(f"Starting MCP HTTP Server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port, log_level="info")


# ==================== Main ====================

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='NetMonitor MCP HTTP API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on (default: 8000)')

    args = parser.parse_args()

    # Create and run server
    server = MCPHTTPServer()
    server.run(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
