#!/usr/bin/env python3
"""
MCP HTTP Bridge Client for Claude Desktop

This bridge allows Claude Desktop to connect to the MCP HTTP API server.
Claude Desktop expects STDIO transport, this script translates STDIO <-> HTTP API.

Configuration via environment variables:
  MCP_HTTP_URL: Base URL of MCP HTTP API
    - Direct access: https://soc.poort.net:8000
    - Via nginx proxy: https://soc.poort.net/mcp
  MCP_HTTP_TOKEN: Bearer token for authentication
  MCP_VERIFY_SSL: Verify SSL certificates (default: true)
    - Set to 'false' to disable SSL verification (e.g., for self-signed certs)

The bridge will append route paths like /tools, /resources, etc. to the base URL.
"""

import sys
import json
import os
import logging
from typing import Any, Dict
import requests
import urllib3

# Setup logging to file (Claude Desktop hides stdout/stderr)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/mcp_http_bridge.log'),
    ]
)
logger = logging.getLogger('MCP.HTTPBridge')


class MCPHTTPBridge:
    """Bridge between Claude Desktop (STDIO) and MCP HTTP API"""

    def __init__(self, api_url: str, api_token: str, verify_ssl: bool = True):
        """
        Initialize bridge

        Args:
            api_url: Base URL of MCP HTTP API (e.g., https://soc.poort.net:8000)
            api_token: Bearer token for authentication
            verify_ssl: Whether to verify SSL certificates (default: True)
        """
        self.api_url = api_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
        logger.info(f"Initialized MCP HTTP Bridge to {api_url}")
        if not verify_ssl:
            logger.warning("SSL certificate verification is DISABLED")
            # Suppress SSL warnings when verification is disabled
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make HTTP request to MCP API"""
        url = f"{self.api_url}{endpoint}"

        try:
            if method == 'GET':
                response = requests.get(url, headers=self.headers, verify=self.verify_ssl, timeout=30)
            elif method == 'POST':
                response = requests.post(url, headers=self.headers, json=data, verify=self.verify_ssl, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request failed: {e}")
            raise

    def list_resources(self) -> Dict:
        """List available MCP resources"""
        return self._make_request('GET', '/resources')

    def read_resource(self, uri: str) -> Dict:
        """Read a specific resource"""
        # Map resource URI to endpoint
        if uri == 'dashboard://summary':
            return self._make_request('GET', '/resources/dashboard/summary')
        else:
            raise ValueError(f"Unknown resource: {uri}")

    def list_tools(self) -> Dict:
        """List available MCP tools"""
        return self._make_request('GET', '/tools')

    def call_tool(self, tool_name: str, parameters: Dict) -> Dict:
        """Execute a tool"""
        data = {
            'tool_name': tool_name,
            'parameters': parameters
        }
        return self._make_request('POST', '/tools/execute', data)

    def handle_stdio(self):
        """
        Handle STDIO communication with Claude Desktop

        Claude Desktop sends JSON-RPC messages via stdin and expects
        responses via stdout. This translates those to HTTP API calls.
        """
        logger.info("Starting STDIO handler")

        while True:
            try:
                # Read JSON-RPC request from stdin
                line = sys.stdin.readline()
                if not line:
                    logger.info("EOF on stdin, exiting")
                    break

                request = json.loads(line)
                logger.info(f"Received request: {request.get('method')}")

                # Handle different MCP methods
                method = request.get('method')
                params = request.get('params', {})
                request_id = request.get('id')

                try:
                    # Handle notifications (no response needed)
                    if method and method.startswith('notifications/'):
                        logger.info(f"Received notification: {method}")
                        continue  # No response for notifications

                    if method == 'initialize':
                        result = {
                            'protocolVersion': '2024-11-05',
                            'serverInfo': {
                                'name': 'netmonitor-soc-http',
                                'version': '2.0.0'
                            },
                            'capabilities': {
                                'resources': {},
                                'tools': {}
                            }
                        }

                    elif method == 'resources/list':
                        resources = self.list_resources()
                        result = {'resources': resources}

                    elif method == 'resources/read':
                        uri = params.get('uri')
                        resource_data = self.read_resource(uri)
                        result = {
                            'contents': [{
                                'uri': uri,
                                'mimeType': 'text/plain',
                                'text': resource_data.get('content', '')
                            }]
                        }

                    elif method == 'tools/list':
                        tools = self.list_tools()
                        # Convert to MCP format
                        mcp_tools = []
                        for tool in tools:
                            mcp_tools.append({
                                'name': tool['name'],
                                'description': tool['description'],
                                'inputSchema': tool['input_schema']
                            })
                        result = {'tools': mcp_tools}

                    elif method == 'tools/call':
                        tool_name = params.get('name')
                        arguments = params.get('arguments', {})
                        tool_result = self.call_tool(tool_name, arguments)

                        if tool_result.get('success'):
                            result = {
                                'content': [{
                                    'type': 'text',
                                    'text': json.dumps(tool_result.get('data'), indent=2)
                                }]
                            }
                        else:
                            result = {
                                'isError': True,
                                'content': [{
                                    'type': 'text',
                                    'text': f"Error: {tool_result.get('error')}"
                                }]
                            }

                    else:
                        logger.warning(f"Unknown method: {method}")
                        result = {'error': f'Unknown method: {method}'}

                    # Only send response if request has an ID (not a notification)
                    if request_id is not None:
                        # Send JSON-RPC response
                        response = {
                            'jsonrpc': '2.0',
                            'id': request_id,
                            'result': result
                        }

                        # Write response to stdout
                        sys.stdout.write(json.dumps(response) + '\n')
                        sys.stdout.flush()
                        logger.info(f"Sent response for request {request_id}")

                except Exception as e:
                    logger.error(f"Error handling request: {e}", exc_info=True)

                    # Only send error response if request has an ID
                    if request_id is not None:
                        response = {
                            'jsonrpc': '2.0',
                            'id': request_id,
                            'error': {
                                'code': -32603,
                                'message': str(e)
                            }
                        }

                        # Write response to stdout
                        sys.stdout.write(json.dumps(response) + '\n')
                        sys.stdout.flush()
                        logger.info(f"Sent error response for request {request_id}")

            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)


def main():
    """Main entry point"""
    # Get configuration from environment
    api_url = os.environ.get('MCP_HTTP_URL', 'https://soc.poort.net:8000')
    api_token = os.environ.get('MCP_HTTP_TOKEN')
    verify_ssl = os.environ.get('MCP_VERIFY_SSL', 'true').lower() in ('true', '1', 'yes')

    if not api_token:
        logger.error("MCP_HTTP_TOKEN environment variable not set")
        sys.stderr.write("Error: MCP_HTTP_TOKEN environment variable required\n")
        sys.exit(1)

    # Create and run bridge
    bridge = MCPHTTPBridge(api_url, api_token, verify_ssl=verify_ssl)

    try:
        bridge.handle_stdio()
    except KeyboardInterrupt:
        logger.info("Bridge stopped by user")
    except Exception as e:
        logger.error(f"Bridge error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
