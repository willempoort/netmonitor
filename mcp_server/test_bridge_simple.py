#!/usr/bin/env python3
"""Simple test to see stderr output from bridge"""

import sys
import os
import subprocess

# Configuration
api_url = os.environ.get('MCP_HTTP_URL', 'https://soc.poort.net/mcp')
api_token = os.environ.get('MCP_HTTP_TOKEN')

if not api_token:
    print("Error: MCP_HTTP_TOKEN not set")
    sys.exit(1)

print(f"Testing bridge with URL: {api_url}")
print(f"Token: {api_token[:20]}...\n")

# Start bridge and send initialize
bridge_script = os.path.join(os.path.dirname(__file__), 'http_bridge_client.py')

env = os.environ.copy()
env['MCP_HTTP_URL'] = api_url
env['MCP_HTTP_TOKEN'] = api_token

process = subprocess.Popen(
    ['python3', bridge_script],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    env=env
)

# Send initialize message
message = '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}}\n'
print(f"Sending: {message.strip()}")

try:
    process.stdin.write(message)
    process.stdin.flush()
    process.stdin.close()

    # Wait and collect output
    stdout, stderr = process.communicate(timeout=5)

    print("\n=== STDOUT ===")
    print(stdout if stdout else "(empty)")

    print("\n=== STDERR ===")
    print(stderr if stderr else "(empty)")

    print(f"\n=== EXIT CODE: {process.returncode} ===")

except subprocess.TimeoutExpired:
    print("\nTimeout!")
    process.kill()
    stdout, stderr = process.communicate()
    print("\n=== STDOUT ===")
    print(stdout if stdout else "(empty)")
    print("\n=== STDERR ===")
    print(stderr if stderr else "(empty)")
except Exception as e:
    print(f"\nError: {e}")
    import traceback
    traceback.print_exc()
