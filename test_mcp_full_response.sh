#!/bin/bash
# Full MCP Response Test - shows complete JSON-RPC response
# Run this ON THE SERVER: ssh root@soc.poort.net
# Or run it locally but may fail due to network/proxy issues

MCP_URL="https://soc.poort.net/mcp"
TOKEN="725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f"

echo "=== Full MCP JSON-RPC Response Test ==="
echo "NOTE: This must run on the server or a machine with access to soc.poort.net"
echo ""

echo "1. Testing get_recent_threats (full response)..."
echo "Request: tools/call -> get_recent_threats(hours=24, limit=5)"
echo ""
RESPONSE=$(curl -s -X POST "$MCP_URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "get_recent_threats",
      "arguments": {
        "hours": 24,
        "limit": 5
      }
    },
    "id": 1
  }')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "Raw response: $RESPONSE"

echo ""
echo "2. Check if result.content exists..."
echo "$RESPONSE" | python3 -c "import json, sys; d=json.loads(sys.stdin.read()); print('Has result:', 'result' in d); print('Result keys:', list(d.get('result',{}).keys()) if 'result' in d else 'N/A'); print('Content type:', type(d.get('result',{}).get('content')))"

echo ""
echo "3. Testing analyze_ip 10.100.0.1..."
curl -s -X POST "$MCP_URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "analyze_ip",
      "arguments": {
        "ip_address": "10.100.0.1"
      }
    },
    "id": 1
  }' | python3 -c "import json, sys; d=json.loads(sys.stdin.read()); print(json.dumps(d, indent=2))" | head -60

echo ""
echo "Done!"
echo ""
echo "If you see proxy errors or connection refused, run this script ON THE SERVER:"
echo "  ssh root@soc.poort.net"
echo "  cd /opt/netmonitor"
echo "  ./test_mcp_full_response.sh"
