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
    # Write the message
    process.stdin.write(message)
    process.stdin.flush()

    # Wait a bit for response
    import time
    time.sleep(2)

    # Try to read response (non-blocking check)
    import select
    if select.select([process.stdout], [], [], 0)[0]:
        response = process.stdout.readline()
        print("\n=== STDOUT ===")
        print(response if response else "(empty)")
    else:
        print("\n=== STDOUT ===")
        print("(no response yet)")

    # Check if process is still running
    poll_result = process.poll()
    if poll_result is not None:
        print(f"\n⚠️  Process exited with code: {poll_result}")

        # Read any remaining output
        remaining_stdout = process.stdout.read()
        remaining_stderr = process.stderr.read()

        if remaining_stdout:
            print(f"\nRemaining STDOUT:\n{remaining_stdout}")
        if remaining_stderr:
            print(f"\n=== STDERR ===\n{remaining_stderr}")
    else:
        print("\n✅ Process still running")

        # Kill it gracefully
        process.stdin.close()
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=2)
            if stderr:
                print(f"\n=== STDERR ===\n{stderr}")
        except:
            process.kill()

except Exception as e:
    print(f"\nError: {e}")
    import traceback
    traceback.print_exc()
    try:
        process.kill()
    except:
        pass
