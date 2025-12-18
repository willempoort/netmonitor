#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
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

# Try to load .env file
try:
    from env_loader import get_db_config, load_env_into_environ
    # Load .env into os.environ for easy access
    load_env_into_environ()
    _env_available = True
except ImportError:
    _env_available = False

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
        # Get root_path from environment for reverse proxy support
        root_path = os.environ.get('MCP_ROOT_PATH', '')

        self.app = FastAPI(
            title="NetMonitor MCP API",
            description="HTTP API for NetMonitor Security Operations Center via Model Context Protocol",
            version="2.0.0",
            docs_url="/docs",
            redoc_url="/redoc",
            root_path=root_path,  # Support for reverse proxy (e.g., /mcp)
            redirect_slashes=False  # Prevent 307 redirects on trailing slashes
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
            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            port = int(os.environ.get('NETMONITOR_DB_PORT', os.environ.get('DB_PORT', '5432')))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'mcp_readonly'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'mcp_netmonitor_readonly_2024'))

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
            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            port = int(os.environ.get('NETMONITOR_DB_PORT', os.environ.get('DB_PORT', '5432')))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'mcp_readonly'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'mcp_netmonitor_readonly_2024'))

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

        @self.app.get("/tools", response_model=List[ToolInfo])
        async def list_tools(token_details: Dict = Depends(verify_token)):
            """
            List all available MCP tools

            Returns detailed information about each tool including:
            - Name and description
            - Input schema
            - Required permission scope
            """
            return self._get_tools_list()

        @self.app.get("/resources", response_model=List[ResourceInfo])
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

        @self.app.get("/resources/dashboard/summary")
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

        @self.app.post("/tools/execute", response_model=ToolResponse)
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
            },
            {
                "name": "get_config_parameters",
                "description": "Get all configuration parameters with their values and metadata",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Optional sensor ID to get sensor-specific config"}
                    }
                },
                "scope_required": "read_only"
            },
            # Device Classification Tools
            {
                "name": "get_device_templates",
                "description": "Get all device templates (predefined device types like Camera, Smart TV, Server, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "enum": ["iot", "server", "endpoint", "other"], "description": "Filter by category"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_template_details",
                "description": "Get detailed information about a specific device template including its expected behaviors",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "template_id": {"type": "number", "description": "Template ID to retrieve"}
                    },
                    "required": ["template_id"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_devices",
                "description": "Get all discovered/registered network devices with their classification status",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sensor_id": {"type": "string", "description": "Filter by sensor ID"},
                        "template_id": {"type": "number", "description": "Filter by template ID"},
                        "include_inactive": {"type": "boolean", "default": False}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_by_ip",
                "description": "Get detailed information about a specific device by its IP address",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"},
                        "sensor_id": {"type": "string", "description": "Sensor ID (optional)"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_service_providers",
                "description": "Get all service providers (streaming services, CDN providers, etc.) used for filtering false positives",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "enum": ["streaming", "cdn", "cloud", "social", "gaming", "other"], "description": "Filter by category"}
                    }
                },
                "scope_required": "read_only"
            },
            {
                "name": "check_ip_service_provider",
                "description": "Check if an IP address belongs to a known service provider (streaming, CDN, etc.)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address to check"},
                        "category": {"type": "string", "description": "Category to check (optional)"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_classification_stats",
                "description": "Get statistics about device classification (total devices, classified vs unclassified, by category)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "assign_device_template",
                "description": "Assign a device template to a device (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "device_id": {"type": "number", "description": "Device ID"},
                        "template_id": {"type": "number", "description": "Template ID to assign"}
                    },
                    "required": ["device_id", "template_id"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "create_service_provider",
                "description": "Create a new service provider entry (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Provider name"},
                        "category": {"type": "string", "enum": ["streaming", "cdn", "cloud", "social", "gaming", "other"]},
                        "ip_ranges": {"type": "array", "items": {"type": "string"}, "description": "List of IP ranges (CIDR notation)"},
                        "description": {"type": "string", "description": "Description of the provider"}
                    },
                    "required": ["name", "category", "ip_ranges"]
                },
                "scope_required": "read_write"
            },
            # Device Discovery Tools
            {
                "name": "get_device_traffic_stats",
                "description": "Get traffic statistics for a device (ports, protocols, bytes, communication partners)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "get_device_classification_hints",
                "description": "Get automatic classification suggestions for a device based on observed traffic patterns",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "create_template_from_device",
                "description": "Create a new device template based on observed behavior of a specific device (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device to learn from"},
                        "template_name": {"type": "string", "description": "Name for the new template"},
                        "category": {"type": "string", "enum": ["iot", "server", "endpoint", "other"]}
                    },
                    "required": ["ip_address", "template_name"]
                },
                "scope_required": "read_write"
            },
            # Alert Suppression Tools
            {
                "name": "get_alert_suppression_stats",
                "description": "Get statistics about template-based alert suppression (alerts checked, suppressed, rates)",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                },
                "scope_required": "read_only"
            },
            {
                "name": "test_alert_suppression",
                "description": "Test if an alert would be suppressed for a specific device based on its template",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "source_ip": {"type": "string", "description": "Source IP address of the device"},
                        "destination_ip": {"type": "string", "description": "Destination IP address"},
                        "alert_type": {"type": "string", "description": "Alert type (e.g., PORT_SCAN, BEACONING, CONNECTION_FLOOD)"},
                        "destination_port": {"type": "number", "description": "Destination port (optional)"}
                    },
                    "required": ["source_ip", "alert_type"]
                },
                "scope_required": "read_only"
            },
            # Behavior Learning Tools
            {
                "name": "get_device_learning_status",
                "description": "Get the learning status for a device, showing how much traffic has been analyzed and if enough data is available for template generation",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
            },
            {
                "name": "save_device_learned_behavior",
                "description": "Save the learned behavior profile to the database for a device (requires write access)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_write"
            },
            {
                "name": "get_device_learned_behavior",
                "description": "Get the learned behavior profile for a device including typical ports, protocols, destinations, and traffic patterns",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "IP address of the device"}
                    },
                    "required": ["ip_address"]
                },
                "scope_required": "read_only"
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
            'get_config_parameters': self._tool_get_config_parameters,
            # Device Classification Tools
            'get_device_templates': self._tool_get_device_templates,
            'get_device_template_details': self._tool_get_device_template_details,
            'get_devices': self._tool_get_devices,
            'get_device_by_ip': self._tool_get_device_by_ip,
            'get_service_providers': self._tool_get_service_providers,
            'check_ip_service_provider': self._tool_check_ip_service_provider,
            'get_device_classification_stats': self._tool_get_device_classification_stats,
            'assign_device_template': self._tool_assign_device_template,
            'create_service_provider': self._tool_create_service_provider,
            # Device Discovery Tools
            'get_device_traffic_stats': self._tool_get_device_traffic_stats,
            'get_device_classification_hints': self._tool_get_device_classification_hints,
            'create_template_from_device': self._tool_create_template_from_device,
            # Alert Suppression Tools
            'get_alert_suppression_stats': self._tool_get_alert_suppression_stats,
            'test_alert_suppression': self._tool_test_alert_suppression,
            # Behavior Learning Tools
            'get_device_learning_status': self._tool_get_device_learning_status,
            'save_device_learned_behavior': self._tool_save_device_learned_behavior,
            'get_device_learned_behavior': self._tool_get_device_learned_behavior,
        }

        if tool_name not in tool_map:
            raise ValueError(f"Tool implementation not found: {tool_name}")

        return await tool_map[tool_name](parameters)

    # ==================== Tool Implementations ====================

    async def _tool_analyze_ip(self, params: Dict) -> Dict:
        """Implement analyze_ip tool"""
        import socket
        from geoip_helper import get_country_for_ip, is_private_ip

        ip_address = params.get('ip_address')
        hours = params.get('hours', 24)

        # Get all alerts for this IP
        alerts = self.db.get_alerts_by_ip(ip_address, hours)

        # Get geolocation
        country = get_country_for_ip(ip_address)

        # Determine if internal
        internal = is_private_ip(ip_address)

        # Try hostname resolution
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except:
            pass

        # Analyze alerts
        threat_types = list(set(a['threat_type'] for a in alerts))
        severity_counts = {}
        for alert in alerts:
            sev = alert['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Calculate threat score (0-100)
        threat_score = min(100, len(alerts) * 5 + len(threat_types) * 10)

        # Determine risk level
        if threat_score >= 80:
            risk_level = "CRITICAL"
            recommendation = "URGENT: Block this IP immediately and investigate affected systems"
        elif threat_score >= 60:
            risk_level = "HIGH"
            recommendation = "High priority: Review and consider blocking this IP"
        elif threat_score >= 40:
            risk_level = "MEDIUM"
            recommendation = "Monitor this IP closely for suspicious activity"
        elif threat_score >= 20:
            risk_level = "LOW"
            recommendation = "Informational: Minor suspicious activity detected"
        else:
            risk_level = "INFO"
            recommendation = "No significant threats detected"

        return {
            'ip_address': ip_address,
            'hostname': hostname,
            'country': country,
            'is_internal': internal,
            'alert_count': len(alerts),
            'threat_types': threat_types,
            'severity_counts': severity_counts,
            'threat_score': threat_score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'recent_alerts': alerts[:10] if len(alerts) > 10 else alerts
        }

    async def _tool_get_recent_threats(self, params: Dict) -> Dict:
        """Implement get_recent_threats tool"""
        hours = params.get('hours', 24)
        severity = params.get('severity')
        threat_type = params.get('threat_type')
        limit = params.get('limit', 50)

        alerts = self.db.get_recent_alerts(
            limit=limit,
            hours=hours,
            severity=severity,
            threat_type=threat_type
        )

        # Calculate statistics
        total = len(alerts)
        by_severity = {}
        by_type = {}
        unique_sources = set()

        for alert in alerts:
            by_severity[alert['severity']] = by_severity.get(alert['severity'], 0) + 1
            by_type[alert['threat_type']] = by_type.get(alert['threat_type'], 0) + 1
            unique_sources.add(alert.get('source_ip', 'unknown'))

        return {
            'total_alerts': total,
            'statistics': {
                'by_severity': by_severity,
                'by_type': by_type
            },
            'unique_source_ips': len(unique_sources),
            'alerts': alerts
        }

    async def _tool_get_sensor_status(self, params: Dict) -> Dict:
        """Implement get_sensor_status tool"""
        import sys
        from pathlib import Path

        # Import main database module for sensor access
        sys.path.insert(0, str(Path(__file__).parent.parent))

        try:
            from database import DatabaseManager

            # Create DB connection with main credentials
            # Support both NETMONITOR_DB_* and DB_* env variables (.env uses DB_*)
            host = os.environ.get('NETMONITOR_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
            database = os.environ.get('NETMONITOR_DB_NAME', os.environ.get('DB_NAME', 'netmonitor'))
            user = os.environ.get('NETMONITOR_DB_USER', os.environ.get('DB_USER', 'netmonitor'))
            password = os.environ.get('NETMONITOR_DB_PASSWORD', os.environ.get('DB_PASSWORD', 'netmonitor'))

            db_main = DatabaseManager(
                host=host,
                database=database,
                user=user,
                password=password
            )

            sensors = db_main.get_sensors()
            db_main.close()

            return {
                'sensors': sensors,
                'total': len(sensors),
                'online': len([s for s in sensors if s.get('status') == 'online']),
                'offline': len([s for s in sensors if s.get('status') == 'offline'])
            }

        except Exception as e:
            logger.error(f"Error getting sensor status: {e}")
            return {
                'error': str(e),
                'sensors': [],
                'total': 0
            }

    async def _tool_set_config_parameter(self, params: Dict) -> Dict:
        """Implement set_config_parameter tool"""
        import requests

        parameter_name = params.get('parameter_name')
        value = params.get('value')
        scope = params.get('scope', 'global')
        sensor_name = params.get('sensor_name')

        # Configuration changes go through the dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/config/set",
                json={
                    'parameter': parameter_name,
                    'value': value,
                    'scope': scope,
                    'sensor_name': sensor_name
                },
                timeout=10
            )

            response.raise_for_status()

            return {
                'success': True,
                'message': f"Configuration parameter '{parameter_name}' updated successfully"
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error setting config parameter: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to update configuration. Ensure the dashboard API is running.'
            }

    async def _tool_get_config_parameters(self, params: Dict) -> Dict:
        """Implement get_config_parameters tool"""
        import requests

        sensor_id = params.get('sensor_id')

        # Get config from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            query_params = {}
            if sensor_id:
                query_params['sensor_id'] = sensor_id

            response = requests.get(
                f"{dashboard_url}/api/config/parameters",
                params=query_params,
                timeout=10
            )

            response.raise_for_status()
            data = response.json()

            if data.get('success'):
                parameters = data.get('parameters', [])
                return {
                    'success': True,
                    'parameters': parameters,
                    'count': len(parameters)
                }
            else:
                return {
                    'success': False,
                    'error': data.get('error', 'Unknown error')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting config parameters: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve configuration. Ensure the dashboard API is running.'
            }

    # ==================== Device Classification Tool Implementations ====================

    async def _tool_get_device_templates(self, params: Dict) -> Dict:
        """Implement get_device_templates tool"""
        category = params.get('category')

        templates = self.db.get_device_templates(category=category)

        return {
            'success': True,
            'templates': templates,
            'count': len(templates)
        }

    async def _tool_get_device_template_details(self, params: Dict) -> Dict:
        """Implement get_device_template_details tool"""
        template_id = params.get('template_id')

        if not template_id:
            return {'success': False, 'error': 'template_id is required'}

        template = self.db.get_device_template_by_id(template_id)

        if not template:
            return {'success': False, 'error': f'Template with ID {template_id} not found'}

        return {
            'success': True,
            'template': template
        }

    async def _tool_get_devices(self, params: Dict) -> Dict:
        """Implement get_devices tool"""
        sensor_id = params.get('sensor_id')
        template_id = params.get('template_id')
        include_inactive = params.get('include_inactive', False)

        devices = self.db.get_devices(
            sensor_id=sensor_id,
            template_id=template_id,
            include_inactive=include_inactive
        )

        # Calculate summary
        classified = len([d for d in devices if d.get('template_id')])
        unclassified = len(devices) - classified

        return {
            'success': True,
            'devices': devices,
            'count': len(devices),
            'summary': {
                'total': len(devices),
                'classified': classified,
                'unclassified': unclassified
            }
        }

    async def _tool_get_device_by_ip(self, params: Dict) -> Dict:
        """Implement get_device_by_ip tool"""
        ip_address = params.get('ip_address')
        sensor_id = params.get('sensor_id')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        device = self.db.get_device_by_ip(ip_address, sensor_id=sensor_id)

        if not device:
            # Check if IP belongs to a service provider
            provider_match = self.db.check_ip_in_service_providers(ip_address)
            if provider_match:
                return {
                    'success': True,
                    'device': None,
                    'service_provider': provider_match,
                    'message': f"IP belongs to service provider: {provider_match['provider_name']}"
                }

            return {
                'success': True,
                'device': None,
                'message': f'No device found with IP {ip_address}'
            }

        return {
            'success': True,
            'device': device
        }

    async def _tool_get_service_providers(self, params: Dict) -> Dict:
        """Implement get_service_providers tool"""
        category = params.get('category')

        providers = self.db.get_service_providers(category=category)

        # Group by category for summary
        by_category = {}
        for p in providers:
            cat = p.get('category', 'other')
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            'success': True,
            'providers': providers,
            'count': len(providers),
            'by_category': by_category
        }

    async def _tool_check_ip_service_provider(self, params: Dict) -> Dict:
        """Implement check_ip_service_provider tool"""
        ip_address = params.get('ip_address')
        category = params.get('category')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        match = self.db.check_ip_in_service_providers(ip_address, category=category)

        if match:
            return {
                'success': True,
                'is_service_provider': True,
                'provider': match,
                'message': f"IP {ip_address} belongs to {match['provider_name']} ({match['category']})"
            }
        else:
            return {
                'success': True,
                'is_service_provider': False,
                'provider': None,
                'message': f"IP {ip_address} does not match any known service provider"
            }

    async def _tool_get_device_classification_stats(self, params: Dict) -> Dict:
        """Implement get_device_classification_stats tool"""
        stats = self.db.get_device_classification_stats()

        return {
            'success': True,
            'statistics': stats
        }

    async def _tool_assign_device_template(self, params: Dict) -> Dict:
        """Implement assign_device_template tool (requires write access)"""
        device_id = params.get('device_id')
        template_id = params.get('template_id')

        if not device_id or not template_id:
            return {'success': False, 'error': 'device_id and template_id are required'}

        # This requires write access to the main database
        # Route through dashboard API or use write-enabled connection
        import requests
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/devices/{device_id}/assign-template",
                json={'template_id': template_id},
                timeout=10
            )

            response.raise_for_status()
            return {
                'success': True,
                'message': f'Template {template_id} assigned to device {device_id}'
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error assigning device template: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to assign template. Ensure the dashboard API is running.'
            }

    async def _tool_create_service_provider(self, params: Dict) -> Dict:
        """Implement create_service_provider tool (requires write access)"""
        name = params.get('name')
        category = params.get('category')
        ip_ranges = params.get('ip_ranges', [])
        description = params.get('description')

        if not name or not category or not ip_ranges:
            return {'success': False, 'error': 'name, category, and ip_ranges are required'}

        # Route through dashboard API
        import requests
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/service-providers",
                json={
                    'name': name,
                    'category': category,
                    'ip_ranges': ip_ranges,
                    'description': description
                },
                timeout=10
            )

            response.raise_for_status()
            data = response.json()

            return {
                'success': True,
                'provider_id': data.get('id'),
                'message': f'Service provider "{name}" created successfully'
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating service provider: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to create service provider. Ensure the dashboard API is running.'
            }

    # ==================== Device Discovery Tool Implementations ====================

    async def _tool_get_device_traffic_stats(self, params: Dict) -> Dict:
        """Implement get_device_traffic_stats tool"""
        import requests

        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Get traffic stats from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/devices/{ip_address}/traffic-stats",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'traffic_stats': data.get('stats', {})
                }
            elif response.status_code == 404:
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'traffic_stats': None,
                    'message': f'No traffic statistics available for {ip_address}'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting device traffic stats: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve traffic stats. Ensure the dashboard API is running.'
            }

    async def _tool_get_device_classification_hints(self, params: Dict) -> Dict:
        """Implement get_device_classification_hints tool"""
        import requests

        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Get classification hints from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/devices/{ip_address}/classification-hints",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                hints = data.get('hints', {})

                return {
                    'success': True,
                    'ip_address': ip_address,
                    'hints': hints,
                    'suggested_templates': hints.get('suggested_templates', []),
                    'confidence': hints.get('confidence', 0.0),
                    'reasoning': hints.get('reasoning', [])
                }
            elif response.status_code == 404:
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'hints': None,
                    'message': f'No classification hints available for {ip_address}. Device may not have enough observed traffic.'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}'
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting device classification hints: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve classification hints. Ensure the dashboard API is running.'
            }

    async def _tool_create_template_from_device(self, params: Dict) -> Dict:
        """Implement create_template_from_device tool (requires write access)"""
        import requests

        ip_address = params.get('ip_address')
        template_name = params.get('template_name')
        category = params.get('category', 'other')

        if not ip_address or not template_name:
            return {'success': False, 'error': 'ip_address and template_name are required'}

        # Create template via dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/device-templates/from-device",
                json={
                    'ip_address': ip_address,
                    'template_name': template_name,
                    'category': category
                },
                timeout=15
            )

            if response.status_code == 200 or response.status_code == 201:
                data = response.json()
                return {
                    'success': True,
                    'template_id': data.get('template_id'),
                    'template_name': template_name,
                    'message': f'Template "{template_name}" created from device {ip_address}',
                    'behaviors_added': data.get('behaviors_added', 0)
                }
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                return {
                    'success': False,
                    'error': data.get('error', f'API returned status {response.status_code}')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating template from device: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to create template. Ensure the dashboard API is running.'
            }

    # ==================== Alert Suppression Tool Implementations ====================

    async def _tool_get_alert_suppression_stats(self, params: Dict) -> Dict:
        """Implement get_alert_suppression_stats tool"""
        import requests

        # Get suppression stats from dashboard API
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.get(
                f"{dashboard_url}/api/suppression/stats",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'statistics': data.get('stats', {}),
                    'message': 'Alert suppression statistics retrieved successfully'
                }
            else:
                # If API not available, return basic info
                return {
                    'success': True,
                    'statistics': {
                        'alerts_checked': 0,
                        'alerts_suppressed': 0,
                        'suppression_rate': 0,
                        'note': 'Live statistics require dashboard API'
                    },
                    'message': 'Statistics unavailable from live system'
                }

        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not get suppression stats from dashboard: {e}")
            return {
                'success': True,
                'statistics': {
                    'alerts_checked': 0,
                    'alerts_suppressed': 0,
                    'suppression_rate': 0,
                    'note': 'Live statistics require dashboard API'
                },
                'message': 'Statistics unavailable - dashboard API not responding'
            }

    async def _tool_test_alert_suppression(self, params: Dict) -> Dict:
        """Implement test_alert_suppression tool"""
        source_ip = params.get('source_ip')
        destination_ip = params.get('destination_ip', '')
        alert_type = params.get('alert_type')
        destination_port = params.get('destination_port')

        if not source_ip or not alert_type:
            return {'success': False, 'error': 'source_ip and alert_type are required'}

        # Get device template for source IP
        device = self.db.get_device_by_ip(source_ip)

        if not device:
            return {
                'success': True,
                'would_suppress': False,
                'reason': f'No registered device found for IP {source_ip}',
                'device': None,
                'template': None
            }

        if not device.get('template_id'):
            return {
                'success': True,
                'would_suppress': False,
                'reason': f'Device {source_ip} has no assigned template',
                'device': {
                    'ip_address': device.get('ip_address'),
                    'hostname': device.get('hostname'),
                    'mac_address': device.get('mac_address')
                },
                'template': None
            }

        template = self.db.get_device_template_by_id(device['template_id'])
        if not template:
            return {
                'success': True,
                'would_suppress': False,
                'reason': 'Template not found',
                'device': device,
                'template': None
            }

        # Check behaviors
        behaviors = template.get('behaviors', [])
        matching_behaviors = []

        for behavior in behaviors:
            if behavior.get('action') != 'allow':
                continue

            behavior_type = behavior.get('behavior_type')
            params_b = behavior.get('parameters', {})

            # Check for matching rules
            match_reason = None

            if behavior_type == 'allowed_ports' and destination_port:
                allowed_ports = params_b.get('ports', [])
                if destination_port in allowed_ports:
                    match_reason = f"Port {destination_port} is in allowed ports list"

            elif behavior_type == 'expected_destinations' and destination_ip:
                # Check if destination is a service provider
                provider = self.db.check_ip_in_service_providers(destination_ip)
                allowed_categories = params_b.get('categories', [])
                if provider and provider['category'] in allowed_categories:
                    match_reason = f"Destination is {provider['provider_name']} ({provider['category']})"

            elif behavior_type == 'traffic_pattern':
                if params_b.get('high_bandwidth') and alert_type in ('HIGH_OUTBOUND_VOLUME', 'UNUSUAL_PACKET_SIZE'):
                    match_reason = "High bandwidth traffic is expected"
                if params_b.get('continuous') and alert_type == 'BEACONING':
                    match_reason = "Continuous streaming is expected"

            elif behavior_type == 'connection_behavior':
                if params_b.get('high_connection_rate') and alert_type == 'CONNECTION_FLOOD':
                    match_reason = "High connection rate is expected for servers"

            if match_reason:
                matching_behaviors.append({
                    'behavior_type': behavior_type,
                    'reason': match_reason
                })

        would_suppress = len(matching_behaviors) > 0

        return {
            'success': True,
            'would_suppress': would_suppress,
            'reason': matching_behaviors[0]['reason'] if matching_behaviors else f'No matching behavior rules for {alert_type}',
            'matching_behaviors': matching_behaviors,
            'device': {
                'ip_address': device.get('ip_address'),
                'hostname': device.get('hostname'),
                'mac_address': device.get('mac_address'),
                'template_name': template.get('name')
            },
            'template': {
                'id': template.get('id'),
                'name': template.get('name'),
                'category': template.get('category'),
                'behaviors_count': len(behaviors)
            }
        }

    # ==================== Behavior Learning Tool Implementations ====================

    async def _tool_get_device_learning_status(self, params: Dict) -> Dict:
        """Implement get_device_learning_status tool"""
        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Get device from database
        device = self.db.get_device_by_ip(ip_address)

        if not device:
            return {
                'success': True,
                'ip_address': ip_address,
                'learning_status': 'not_found',
                'message': f'Device {ip_address} not found in database. It may not have been discovered yet.'
            }

        learned_behavior = device.get('learned_behavior', {})

        # Analyze learning status
        has_behavior = bool(learned_behavior)
        packet_count = learned_behavior.get('packet_count', 0) if has_behavior else 0
        unique_ports = len(learned_behavior.get('typical_ports', [])) if has_behavior else 0
        unique_destinations = len(learned_behavior.get('typical_destinations', [])) if has_behavior else 0
        protocols = learned_behavior.get('protocols', []) if has_behavior else []

        # Determine learning status
        if not has_behavior:
            status = 'not_started'
            message = 'No traffic has been analyzed yet. Device needs active monitoring.'
        elif packet_count < 100:
            status = 'insufficient_data'
            message = f'Only {packet_count} packets analyzed. Need more traffic for reliable behavior profile.'
        elif unique_ports < 2 and unique_destinations < 3:
            status = 'learning'
            message = 'Basic traffic pattern detected. More diverse traffic would improve accuracy.'
        else:
            status = 'ready'
            message = 'Sufficient data available for behavior-based template generation.'

        return {
            'success': True,
            'ip_address': ip_address,
            'device': {
                'hostname': device.get('hostname'),
                'mac_address': device.get('mac_address'),
                'vendor': device.get('vendor'),
                'template_name': device.get('template_name'),
                'first_seen': str(device.get('first_seen')) if device.get('first_seen') else None,
                'last_seen': str(device.get('last_seen')) if device.get('last_seen') else None
            },
            'learning_status': status,
            'message': message,
            'statistics': {
                'has_learned_behavior': has_behavior,
                'packet_count': packet_count,
                'unique_ports': unique_ports,
                'unique_destinations': unique_destinations,
                'protocols': protocols
            }
        }

    async def _tool_save_device_learned_behavior(self, params: Dict) -> Dict:
        """Implement save_device_learned_behavior tool (requires write access)"""
        import requests

        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Call dashboard API to save learned behavior
        dashboard_url = os.environ.get('DASHBOARD_URL', 'http://localhost:8080')

        try:
            response = requests.post(
                f"{dashboard_url}/api/devices/{ip_address}/save-learned-behavior",
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'message': f'Learned behavior saved successfully for {ip_address}',
                    'saved_behavior': data.get('learned_behavior', {})
                }
            elif response.status_code == 404:
                return {
                    'success': False,
                    'error': f'Device {ip_address} not found'
                }
            else:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                return {
                    'success': False,
                    'error': data.get('error', f'API returned status {response.status_code}')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error saving learned behavior: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to save learned behavior. Ensure the dashboard API is running.'
            }

    async def _tool_get_device_learned_behavior(self, params: Dict) -> Dict:
        """Implement get_device_learned_behavior tool"""
        ip_address = params.get('ip_address')

        if not ip_address:
            return {'success': False, 'error': 'ip_address is required'}

        # Get device from database
        device = self.db.get_device_by_ip(ip_address)

        if not device:
            return {
                'success': True,
                'ip_address': ip_address,
                'learned_behavior': None,
                'message': f'Device {ip_address} not found in database'
            }

        learned_behavior = device.get('learned_behavior', {})

        if not learned_behavior:
            return {
                'success': True,
                'ip_address': ip_address,
                'learned_behavior': None,
                'message': 'No learned behavior available. Device needs active monitoring to collect traffic data.'
            }

        # Format learned behavior for display
        formatted_behavior = {
            'protocols': learned_behavior.get('protocols', []),
            'traffic_pattern': learned_behavior.get('traffic_pattern'),
            'typical_ports': [
                {'port': p['port'], 'protocol': p.get('protocol', 'TCP'), 'connections': p.get('count', 0)}
                for p in learned_behavior.get('typical_ports', [])[:15]
            ],
            'server_ports': [
                {'port': p['port'], 'protocol': p.get('protocol', 'TCP'), 'inbound_connections': p.get('count', 0)}
                for p in learned_behavior.get('server_ports', [])[:10]
            ],
            'typical_destinations': learned_behavior.get('typical_destinations', [])[:20],
            'bytes_in': learned_behavior.get('bytes_in', 0),
            'bytes_out': learned_behavior.get('bytes_out', 0),
            'packet_count': learned_behavior.get('packet_count', 0),
            'observation_period': learned_behavior.get('observation_period'),
            'generated_at': learned_behavior.get('generated_at')
        }

        return {
            'success': True,
            'ip_address': ip_address,
            'device': {
                'hostname': device.get('hostname'),
                'mac_address': device.get('mac_address'),
                'vendor': device.get('vendor'),
                'template_name': device.get('template_name')
            },
            'learned_behavior': formatted_behavior,
            'can_create_template': learned_behavior.get('packet_count', 0) >= 100
        }

    async def _get_dashboard_summary(self) -> str:
        """Get dashboard summary text"""
        data = self.db.get_dashboard_stats()

        # Format as readable text
        summary = f"""=== NetMonitor Security Dashboard Summary ===

Period: Last {data.get('period_hours', 24)} hours
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

TOTAL ALERTS: {data.get('total', 0)}

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
        for ip_info in data.get('top_sources', []):
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
