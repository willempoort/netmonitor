#!/bin/bash
# Test MCP Tools Direct

MCP_URL="https://soc.poort.net/mcp"
TOKEN="725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f"

echo "=== Testing MCP Server Tools ==="
echo ""

echo "1. Testing get_recent_threats..."
curl -s -X POST "$MCP_URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
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
  }' | jq -r '.result.content[0].text' | head -20

echo ""
echo "2. Testing analyze_ip with 10.100.0.1..."
curl -s -X POST "$MCP_URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
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
  }' | jq -r '.result.content[0].text' | head -20

echo ""
echo "3. Testing get_sensor_status..."
curl -s -X POST "$MCP_URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "get_sensor_status",
      "arguments": {}
    },
    "id": 1
  }' | jq -r '.result.content[0].text' | head -20

echo ""
echo "Done!"
