#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
MCP Streamable HTTP Bridge Client for Claude Desktop

This bridge allows Claude Desktop (which uses STDIO) to communicate with
a remote MCP Streamable HTTP server over HTTPS.

Usage:
    python3 mcp_streamable_http_bridge.py

Configuration via environment variables:
    MCP_SERVER_URL: MCP server URL (default: https://soc.poort.net/mcp)
    MCP_AUTH_TOKEN: Bearer token for authentication (required)
    MCP_DEBUG: Enable debug logging (default: false)
"""

import os
import sys
import json
import logging
import requests
from typing import Any, Dict, Optional
from datetime import datetime

# Configure logging
LOG_FILE = os.path.expanduser("~/.mcp_bridge.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger('MCP.Bridge')


class MCPStreamableHTTPBridge:
    """
    Bridge between Claude Desktop (STDIO) and MCP Streamable HTTP server
    """

    def __init__(self, server_url: str, auth_token: str):
        """
        Initialize the bridge

        Args:
            server_url: MCP Streamable HTTP server URL
            auth_token: Bearer token for authentication
        """
        self.server_url = server_url.rstrip('/')
        self.auth_token = auth_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream'
        })
        self.protocol_version = "2025-06-18"
        self.initialized = False

        logger.info(f"MCP Bridge initialized")
        logger.info(f"Server URL: {self.server_url}")
        logger.info(f"Protocol version: {self.protocol_version}")

    def send_mcp_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send a JSON-RPC request to the MCP server via HTTP

        Args:
            method: JSON-RPC method name
            params: Method parameters

        Returns:
            JSON-RPC response
        """
        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "id": 1
        }

        if params is not None:
            request_data["params"] = params

        logger.debug(f"Sending request: {method}")

        try:
            response = self.session.post(
                self.server_url,
                json=request_data,
                timeout=30
            )
            response.raise_for_status()

            # Handle SSE response (text/event-stream)
            if 'text/event-stream' in response.headers.get('content-type', ''):
                return self._parse_sse_response(response.text)

            # Handle JSON response
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request failed: {e}")
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32000,
                    "message": f"HTTP request failed: {str(e)}"
                }
            }

    def _parse_sse_response(self, sse_text: str) -> Dict[str, Any]:
        """
        Parse SSE (Server-Sent Events) response

        Args:
            sse_text: SSE formatted text

        Returns:
            Parsed JSON response
        """
        lines = sse_text.strip().split('\n')
        for line in lines:
            if line.startswith('data: '):
                data_str = line[6:]  # Remove 'data: ' prefix
                try:
                    return json.loads(data_str)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse SSE data: {e}")
                    return {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": -32700,
                            "message": "Parse error"
                        }
                    }

        return {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": "No data in SSE response"
            }
        }

    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle initialize request from Claude Desktop

        Args:
            params: Initialize parameters

        Returns:
            Initialize response
        """
        logger.info("Handling initialize request")

        # Send initialize to server
        response = self.send_mcp_request("initialize", params)

        if "error" not in response:
            self.initialized = True
            logger.info("Successfully initialized")

        return response

    def handle_tools_list(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Handle tools/list request from Claude Desktop

        Args:
            params: Request parameters

        Returns:
            Tools list response
        """
        logger.info("Handling tools/list request")
        return self.send_mcp_request("tools/list", params)

    def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle tools/call request from Claude Desktop

        Args:
            params: Tool call parameters (name, arguments)

        Returns:
            Tool execution result
        """
        tool_name = params.get("name", "unknown")
        logger.info(f"Handling tools/call request: {tool_name}")
        return self.send_mcp_request("tools/call", params)

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Route incoming JSON-RPC request to appropriate handler

        Args:
            request: JSON-RPC request

        Returns:
            JSON-RPC response or None for notifications
        """
        method = request.get("method")
        params = request.get("params")
        request_id = request.get("id")

        logger.debug(f"Received request: {method}")

        # Handle notifications (no response needed)
        if method and method.startswith("notifications/"):
            logger.debug(f"Ignoring notification: {method}")
            return None

        # Route to handler
        if method == "initialize":
            response = self.handle_initialize(params or {})
        elif method == "tools/list":
            response = self.handle_tools_list(params)
        elif method == "tools/call":
            response = self.handle_tools_call(params or {})
        elif method == "ping":
            # Handle ping locally
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {}
            }
        else:
            logger.warning(f"Unknown method: {method}")
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }

        # Ensure response has correct ID
        if response and "id" not in response:
            response["id"] = request_id
        elif response and response.get("id") != request_id:
            response["id"] = request_id

        return response

    def run(self):
        """
        Main bridge loop - read from STDIN, write to STDOUT
        """
        logger.info("=" * 70)
        logger.info("MCP Streamable HTTP Bridge Starting")
        logger.info("=" * 70)
        logger.info(f"Server: {self.server_url}")
        logger.info(f"Log file: {LOG_FILE}")
        logger.info("Waiting for requests from Claude Desktop...")
        logger.info("=" * 70)

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue

                try:
                    # Parse JSON-RPC request
                    request = json.loads(line)

                    # Handle request
                    response = self.handle_request(request)

                    # Send response to STDOUT (skip if None, e.g., notifications)
                    if response is not None:
                        print(json.dumps(response), flush=True)

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON received: {e}")
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32700,
                            "message": "Parse error"
                        }
                    }
                    print(json.dumps(error_response), flush=True)

                except Exception as e:
                    logger.error(f"Error handling request: {e}", exc_info=True)
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32603,
                            "message": f"Internal error: {str(e)}"
                        }
                    }
                    print(json.dumps(error_response), flush=True)

        except KeyboardInterrupt:
            logger.info("Bridge interrupted by user")
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            sys.exit(1)


def main():
    """Main entry point"""
    # Get configuration from environment
    server_url = os.getenv('MCP_SERVER_URL', 'https://soc.poort.net/mcp')
    auth_token = os.getenv('MCP_AUTH_TOKEN', '')
    debug = os.getenv('MCP_DEBUG', 'false').lower() == 'true'

    if debug:
        logger.setLevel(logging.DEBUG)

    # Validate configuration
    if not auth_token:
        logger.error("MCP_AUTH_TOKEN environment variable is required")
        sys.stderr.write("ERROR: MCP_AUTH_TOKEN environment variable is required\n")
        sys.stderr.write("\nUsage:\n")
        sys.stderr.write("  export MCP_SERVER_URL='https://soc.poort.net/mcp'\n")
        sys.stderr.write("  export MCP_AUTH_TOKEN='your_bearer_token_here'\n")
        sys.stderr.write("  python3 mcp_streamable_http_bridge.py\n")
        sys.exit(1)

    # Create and run bridge
    bridge = MCPStreamableHTTPBridge(server_url, auth_token)
    bridge.run()


if __name__ == "__main__":
    main()
