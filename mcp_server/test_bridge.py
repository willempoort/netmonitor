#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
CLI tool to test MCP HTTP Bridge
Sends JSON-RPC messages to the bridge and shows responses
"""

import sys
import json
import subprocess
import os

def send_jsonrpc(bridge_process, method, params=None, request_id=1):
    """Send a JSON-RPC request and get response"""
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method
    }
    if params:
        request["params"] = params

    # Send request
    request_json = json.dumps(request) + "\n"
    print(f"\n📤 Sending: {method}")
    print(f"   {request_json.strip()}")

    bridge_process.stdin.write(request_json)
    bridge_process.stdin.flush()

    # Read response
    response_line = bridge_process.stdout.readline()
    if response_line:
        response = json.loads(response_line)
        print(f"\n📥 Response:")
        print(json.dumps(response, indent=2))
        return response
    else:
        print("❌ No response received")
        return None

def main():
    # Get configuration
    api_url = os.environ.get('MCP_HTTP_URL', 'http://localhost:8000')
    api_token = os.environ.get('MCP_HTTP_TOKEN')

    if not api_token:
        print("❌ Error: MCP_HTTP_TOKEN environment variable not set")
        print("\nUsage:")
        print("  export MCP_HTTP_URL='https://soc.poort.net/mcp'")
        print("  export MCP_HTTP_TOKEN='your-token-here'")
        print("  python3 test_bridge.py")
        sys.exit(1)

    print(f"🔗 Testing MCP HTTP Bridge")
    print(f"   API URL: {api_url}")
    print(f"   Token: {api_token[:20]}...")

    # Start bridge process
    bridge_script = os.path.join(os.path.dirname(__file__), 'http_bridge_client.py')
    env = os.environ.copy()
    env['MCP_HTTP_URL'] = api_url
    env['MCP_HTTP_TOKEN'] = api_token

    try:
        process = subprocess.Popen(
            ['python3', bridge_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env
        )

        print("\n✅ Bridge process started")

        # Test 1: Initialize
        print("\n" + "="*60)
        print("Test 1: Initialize")
        print("="*60)
        send_jsonrpc(process, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }, request_id=1)

        # Test 2: List tools
        print("\n" + "="*60)
        print("Test 2: List Tools")
        print("="*60)
        send_jsonrpc(process, "tools/list", {}, request_id=2)

        # Test 3: List resources
        print("\n" + "="*60)
        print("Test 3: List Resources")
        print("="*60)
        send_jsonrpc(process, "resources/list", {}, request_id=3)

        # Test 4: Call a tool (get_config_parameters)
        print("\n" + "="*60)
        print("Test 4: Call get_config_parameters tool")
        print("="*60)
        send_jsonrpc(process, "tools/call", {
            "name": "get_config_parameters",
            "arguments": {}
        }, request_id=4)

        # Close
        process.stdin.close()
        process.wait(timeout=5)

        print("\n✅ All tests completed")

        # Check for errors in stderr
        stderr = process.stderr.read()
        if stderr:
            print(f"\n⚠️  Stderr output:\n{stderr}")

        # Check log file
        if os.path.exists('/tmp/mcp_http_bridge.log'):
            print("\n📋 Last 20 lines from log file:")
            with open('/tmp/mcp_http_bridge.log', 'r') as f:
                lines = f.readlines()
                for line in lines[-20:]:
                    print(f"   {line.rstrip()}")

    except subprocess.TimeoutExpired:
        print("\n⚠️  Process timeout")
        process.kill()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        if 'process' in locals():
            process.kill()

if __name__ == '__main__':
    main()
