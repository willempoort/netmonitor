#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
MCP SSE Bridge for Claude Desktop

Bridges between Claude Desktop (stdio) and remote MCP server (SSE).
This allows Claude Desktop to connect to remote SSE servers.

Usage:
  python3 mcp_sse_bridge.py --url http://soc.poort.net:3000/sse
"""

import sys
import json
import asyncio
import argparse
import logging
from typing import Optional
import aiohttp

# Setup logging to stderr (stdout is used for MCP protocol)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger('MCP.SSE.Bridge')


class SSEBridge:
    """Bridge between stdio (Claude Desktop) and SSE (remote MCP server)"""

    def __init__(self, sse_url: str):
        self.sse_url = sse_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.running = True
        logger.info(f"SSE Bridge initialized for: {sse_url}")

    async def read_stdin(self):
        """Read JSON-RPC messages from stdin (from Claude Desktop)"""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while self.running:
            try:
                # Read line from stdin
                line = await reader.readline()
                if not line:
                    logger.info("stdin closed, exiting")
                    self.running = False
                    break

                # Parse JSON-RPC message
                message = json.loads(line.decode('utf-8'))
                logger.debug(f"Received from Claude Desktop: {message}")

                # Forward to remote SSE server
                await self.forward_to_sse(message)

            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
            except Exception as e:
                logger.error(f"Error reading stdin: {e}")
                self.running = False

    async def forward_to_sse(self, message: dict):
        """Forward message to remote SSE server and get response"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            # Send request to SSE endpoint
            async with self.session.post(
                self.sse_url.replace('/sse', '/message'),  # Adjust endpoint
                json=message,
                headers={'Content-Type': 'application/json'}
            ) as resp:
                if resp.status == 200:
                    response = await resp.json()
                    # Send response to stdout (to Claude Desktop)
                    self.write_stdout(response)
                else:
                    logger.error(f"SSE server error: {resp.status}")

        except Exception as e:
            logger.error(f"Error forwarding to SSE: {e}")
            # Send error response to Claude Desktop
            error_response = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {
                    "code": -32603,
                    "message": f"SSE connection error: {str(e)}"
                }
            }
            self.write_stdout(error_response)

    async def listen_sse(self):
        """Listen to SSE events from remote server"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            logger.info(f"Connecting to SSE endpoint: {self.sse_url}")

            async with self.session.get(self.sse_url) as resp:
                if resp.status != 200:
                    logger.error(f"SSE connection failed: {resp.status}")
                    return

                logger.info("SSE connection established")

                # Read SSE events
                async for line in resp.content:
                    if not self.running:
                        break

                    line = line.decode('utf-8').strip()

                    # Parse SSE format
                    if line.startswith('data: '):
                        try:
                            data = json.loads(line[6:])
                            logger.debug(f"SSE event received: {data}")
                            # Forward to Claude Desktop
                            self.write_stdout(data)
                        except json.JSONDecodeError as e:
                            logger.error(f"Invalid SSE data: {e}")

        except Exception as e:
            logger.error(f"SSE listening error: {e}")

    def write_stdout(self, message: dict):
        """Write JSON-RPC message to stdout (to Claude Desktop)"""
        try:
            output = json.dumps(message) + '\n'
            sys.stdout.write(output)
            sys.stdout.flush()
            logger.debug(f"Sent to Claude Desktop: {message}")
        except Exception as e:
            logger.error(f"Error writing to stdout: {e}")

    async def run(self):
        """Run the bridge"""
        try:
            # Start both stdin reader and SSE listener
            await asyncio.gather(
                self.read_stdin(),
                self.listen_sse(),
                return_exceptions=True
            )
        finally:
            if self.session:
                await self.session.close()
            logger.info("Bridge stopped")


def main():
    parser = argparse.ArgumentParser(description='MCP SSE Bridge for Claude Desktop')
    parser.add_argument(
        '--url',
        required=True,
        help='SSE server URL (e.g., http://soc.poort.net:3000/sse)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Create and run bridge
    bridge = SSEBridge(args.url)

    try:
        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        logger.info("Bridge interrupted")
    except Exception as e:
        logger.error(f"Bridge error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
