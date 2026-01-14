# Claude Desktop Setup for NetMonitor MCP

Connect Claude Desktop to the NetMonitor MCP server to give Claude access to all 60 security tools.

## Prerequisites

- Claude Desktop installed ([Download](https://claude.ai/download))
- Python 3.11+ on your system
- Network access to soc.poort.net
- MCP API token (get from server admin)

## Quick Setup (5 minutes)

### Step 1: Copy Bridge Script

Copy `mcp_streamable_http_bridge.py` to a location on your machine:

**macOS/Linux:**
```bash
mkdir -p ~/.mcp/netmonitor
cp mcp_streamable_http_bridge.py ~/.mcp/netmonitor/
chmod +x ~/.mcp/netmonitor/mcp_streamable_http_bridge.py
```

**Windows:**
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.mcp\netmonitor"
Copy-Item mcp_streamable_http_bridge.py "$env:USERPROFILE\.mcp\netmonitor\"
```

### Step 2: Configure Claude Desktop

Edit your Claude Desktop config file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

Add this configuration:

```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "python3",
      "args": [
        "/Users/YOUR_USERNAME/.mcp/netmonitor/mcp_streamable_http_bridge.py"
      ],
      "env": {
        "MCP_SERVER_URL": "https://soc.poort.net/mcp",
        "MCP_AUTH_TOKEN": "YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**Important:**
- Replace `/Users/YOUR_USERNAME/` with your actual home directory path
- Replace `YOUR_TOKEN_HERE` with your MCP token
- On Windows, use backslashes: `C:\\Users\\YOUR_USERNAME\\.mcp\\netmonitor\\mcp_streamable_http_bridge.py`
- Use `python3` or `python` depending on your system

### Step 3: Restart Claude Desktop

Quit Claude Desktop completely and restart it.

### Step 4: Verify Connection

In Claude Desktop, type:
```
What NetMonitor tools do you have available?
```

Claude should list all 60 security tools.

## Example Queries

Once connected, you can ask Claude:

**Security Threats:**
```
Show me critical security threats from the last 6 hours
Get recent security threats with high severity
```

**IP Analysis:**
```
Analyze IP 192.168.1.50 for threats
Check if 185.220.101.50 is malicious
What's the risk level of 10.0.0.5?
```

**Sensor Monitoring:**
```
Which sensors are offline?
Get sensor status report
Show me all sensor statuses
```

**Device Management:**
```
List all network devices
Get devices without templates
Show me device classification statistics
```

**Threat Intelligence:**
```
Check if malware.example.com is in threat feeds
Get threat feed statistics
Show recent threat detections
```

## Troubleshooting

### "Failed to connect to server"

**Check bridge logs:**
```bash
tail -f ~/.mcp_bridge.log
```

**Test connection manually:**
```bash
export MCP_SERVER_URL="https://soc.poort.net/mcp"
export MCP_AUTH_TOKEN="your_token_here"
python3 ~/.mcp/netmonitor/mcp_streamable_http_bridge.py
```

Then in another terminal:
```bash
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 -c "import sys, json; sys.stdout.write(sys.stdin.read())"
```

### "Authentication failed"

- Verify your token is correct
- Check if token is still valid: `python3 manage_tokens.py list`
- Create a new token if needed

### "No tools showing up"

1. Check Claude Desktop logs (Help → View Logs)
2. Restart Claude Desktop completely
3. Verify config file syntax is valid JSON
4. Check Python is accessible: `which python3`

### SSL Certificate Errors

If you get SSL errors with self-signed certificates, you can disable verification (⚠️ **only for testing**):

Edit `mcp_streamable_http_bridge.py` and add `verify=False`:
```python
response = self.session.post(
    self.server_url,
    json=request_data,
    timeout=30,
    verify=False  # ⚠️ Only for testing!
)
```

## Configuration Options

### Environment Variables

- `MCP_SERVER_URL`: MCP server URL (default: https://soc.poort.net/mcp)
- `MCP_AUTH_TOKEN`: Bearer token for authentication (required)
- `MCP_DEBUG`: Enable debug logging (true/false)

### Debug Mode

Enable debug logging:
```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "python3",
      "args": ["..."],
      "env": {
        "MCP_SERVER_URL": "https://soc.poort.net/mcp",
        "MCP_AUTH_TOKEN": "your_token",
        "MCP_DEBUG": "true"
      }
    }
  }
}
```

Check logs at: `~/.mcp_bridge.log`

## Available Tools (60 total)

**Threat Analysis:**
- analyze_ip - Analyze IP addresses for threats
- get_recent_threats - Get recent security threats
- check_indicator - Check IoCs against threat feeds
- get_threat_detections - Get threat feed detections
- get_threat_feed_stats - Get threat feed statistics

**Device Management:**
- get_devices - List all network devices
- get_device_by_ip - Get device details by IP
- assign_device_template - Assign template to device
- touch_device - Mark device as active
- create_template_from_device - Create template from device

**Sensor Management:**
- get_sensor_status - Get sensor online/offline status
- send_sensor_command - Send command to sensor
- get_sensor_command_history - Get sensor command history

**TLS/SSL Analysis:**
- get_tls_metadata - Get TLS certificate metadata
- get_tls_stats - Get TLS statistics
- check_ja3_fingerprint - Check JA3 fingerprints

**PCAP Management:**
- get_pcap_captures - List PCAP captures
- export_flow_pcap - Export flow as PCAP
- delete_pcap_capture - Delete PCAP file

**Kerberos Security:**
- get_kerberos_stats - Get Kerberos statistics
- get_kerberos_attacks - Get Kerberos attacks
- check_weak_encryption - Check for weak encryption

**Risk Assessment:**
- get_top_risk_assets - Get highest risk assets
- get_asset_risk - Get risk score for asset
- get_risk_trends - Get risk trends over time

**SOAR Integration:**
- get_soar_playbooks - Get available playbooks
- get_pending_approvals - Get pending approvals
- approve_soar_action - Approve SOAR action

**And 30+ more tools** for configuration, whitelisting, alert management, attack chain analysis, MITRE mapping, etc.

## Architecture

```
┌─────────────────┐
│ Claude Desktop  │  (Your laptop)
└────────┬────────┘
         │ STDIO
         ▼
┌─────────────────┐
│  Python Bridge  │  (mcp_streamable_http_bridge.py)
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│ NetMonitor MCP  │  (soc.poort.net:8000)
│     Server      │  → PostgreSQL
└─────────────────┘  → 60 Tools
```

## Security Notes

- Bridge runs locally on your machine
- All communication over HTTPS
- Bearer token authentication
- Tokens can be rate-limited and scoped
- All API calls are logged on the server

## Next Steps

Once working, you can:
- Add more MCP servers (filesystem, web search, etc.)
- Create dedicated tokens for different use cases
- Share configurations with your team
- Build custom workflows using Claude + NetMonitor

## Support

- Server logs: `journalctl -u netmonitor-mcp-streamable -f`
- Bridge logs: `tail -f ~/.mcp_bridge.log`
- Token management: `python3 manage_tokens.py --help`

---

**Enjoy your AI-powered SOC with Claude Desktop!** 🚀🛡️
