# NetMonitor MCP Client Configuration Guide

## ✅ Server Status

- **Public URL:** `https://soc.poort.net/mcp` (via nginx reverse proxy)
- **Direct Backend:** `http://127.0.0.1:8000` (local access only)
- **SSL/TLS:** Enabled with HSTS
- **CORS:** Configured for AI clients
- **Tools Available:** 60 security tools

---

## 1. Claude Desktop Configuration (Recommended)

Claude Desktop requires the `mcp-remote` package to connect to HTTP MCP servers.

### Configuration File Location

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

### Remote Access (via Nginx - Recommended)

Use this if Claude Desktop is running on a different machine:

```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://soc.poort.net/mcp",
        "--header",
        "Authorization: Bearer YOUR_TOKEN_HERE"
      ]
    }
  }
}
```

### Local Access (Direct Backend)

Use this if Claude Desktop is running on the SOC server itself:

```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://127.0.0.1:8000/mcp",
        "--header",
        "Authorization: Bearer YOUR_TOKEN_HERE"
      ]
    }
  }
}
```

**Important Notes:**
- Replace `YOUR_TOKEN_HERE` with your actual Bearer token
- Make sure `npx` is installed (comes with Node.js)
- Restart Claude Desktop after changing the config
- For remote access, ensure firewall allows HTTPS (port 443)

**Get Your Token:**
```bash
python3 /opt/netmonitor/mcp_server/manage_tokens.py list
```

**Testing:**
1. Restart Claude Desktop
2. Open a new conversation
3. Type: "What tools do you have access to?"
4. You should see 60 NetMonitor security tools

---

## 2. Open-WebUI Configuration

Open-WebUI has native MCP Streamable HTTP support (since v0.6.31).

### Configuration Steps

1. **Login to Open-WebUI** as admin
2. **Navigate to:** Settings → Admin Settings → MCP Servers
3. **Click:** "Add Server"
4. **Fill in:**
   - **Name:** `NetMonitor SOC`
   - **Type:** Select "MCP (Streamable HTTP)"
   - **Server URL:** `https://soc.poort.net/mcp`
   - **Authentication:**
     - **Type:** Bearer Token
     - **Token:** `YOUR_TOKEN_HERE`

**Important Notes:**
- Use the public URL: `https://soc.poort.net/mcp`
- Don't add trailing slashes
- Make sure Open-WebUI can reach your server (test with curl first)
- Save and enable the server

**Testing:**
1. Create a new chat in Open-WebUI
2. Type: "Show me recent security threats"
3. The tools should be called automatically

### If Open-WebUI is on the same server

Only use this if Open-WebUI and NetMonitor run on the same machine:

- **Server URL:** `http://127.0.0.1:8000/mcp`

---

## 3. Testing Connection

### Test via Public URL (Through Nginx)

```bash
# Test tools list
curl -X POST https://soc.poort.net/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | head -20

# Test sensor status
curl -X POST https://soc.poort.net/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_sensor_status","arguments":{}},"id":2}'
```

### Test Direct Backend (Bypass Nginx)

```bash
# Health check (no auth)
curl http://127.0.0.1:8000/health

# Tools list
curl -X POST http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

---

## 3. Testing Connection

### Manual Test (curl)

Test tools list:
```bash
curl -X POST http://YOUR_SERVER_IP:8000/mcp \
  -H "Authorization: Bearer adf417eeff52f2eda5d7474f2c93a7be748181e6cb5aaffd87fac813fbf2fe75" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

Test health check (no auth):
```bash
curl http://YOUR_SERVER_IP:8000/health
```

### Expected Response

Health check should return:
```json
{
  "status": "healthy",
  "server": "NetMonitor MCP Streamable HTTP",
  "version": "1.0.0",
  "database": "connected",
  "tools": 60,
  "timestamp": "2026-01-13T17:53:31.000214"
}
```

---

## 4. Available Tools (60 Total)

### Threat Analysis
- `analyze_ip` - Deep dive into IP threat intel
- `get_recent_threats` - Recent security alerts
- `get_threat_detections` - 60+ threat types across 9 attack phases
- `check_indicator` - Check IPs/domains against threat feeds

### Network Monitoring
- `get_sensor_status` - Remote sensor health
- `get_device_traffic_stats` - Traffic patterns per device
- `get_device_by_ip` - Device details and classification

### Security Detection
- `get_kerberos_attacks` - Kerberoasting, AS-REP, DCSync
- `check_ja3_fingerprint` - TLS fingerprint analysis
- `get_mitre_mapping` - MITRE ATT&CK technique mapping
- `get_attack_chains` - Multi-stage attack detection

### Device Management
- `get_devices` - All network devices
- `assign_device_template` - Classify devices
- `get_device_templates` - Predefined device types

### PCAP Export
- `export_flow_pcap` - Capture traffic for forensics
- `get_pcap_captures` - List saved captures

### Configuration & Management
- `set_config_parameter` - Update system config
- `add_whitelist_entry` - Manage whitelists
- `send_sensor_command` - Remote sensor control

### SOAR Automation
- `get_soar_playbooks` - Automated response workflows
- `approve_soar_action` - Manual approval for actions
- `get_soar_history` - Audit trail

**Full tool list:** See `/opt/netmonitor/mcp_server/STREAMABLE_HTTP_README.md`

---

## 5. Troubleshooting

### Claude Desktop Issues

**Error: "command is required"**
- You used `type: "streamable-http"` instead of the `mcp-remote` package
- Update config to use `"command": "npx"` and `"args": ["mcp-remote", ...]`

**Error: "Connection refused"**
- Check if server is running: `systemctl status netmonitor-mcp-streamable`
- Check if port 8000 is accessible: `curl http://127.0.0.1:8000/health`

**Tools not showing up:**
- Restart Claude Desktop completely
- Check logs: `journalctl -u netmonitor-mcp-streamable -f`

### Open-WebUI Issues

**Error: "Connection failed"**
- Make sure you're using the server IP, not `127.0.0.1` (unless same machine)
- Check firewall: `sudo ufw allow 8000/tcp`
- Verify server is listening on all interfaces: `netstat -tulpn | grep 8000`

**Error: "Authentication failed"**
- Verify token is correct
- Check token status: `python3 /opt/netmonitor/mcp_server/manage_tokens.py list`
- Check server logs for auth errors

**Tools not available:**
- Make sure server type is "MCP (Streamable HTTP)" not "OpenAPI"
- Try without trailing slash in URL
- Check Open-WebUI version (needs v0.6.31+)

---

## 6. Security Considerations

### Firewall Rules

If accessing remotely:
```bash
# Allow MCP server port
sudo ufw allow 8000/tcp

# Or restrict to specific IP
sudo ufw allow from 10.100.0.70 to any port 8000
```

### Token Management

List tokens:
```bash
python3 /opt/netmonitor/mcp_server/manage_tokens.py list
```

Create new token:
```bash
python3 /opt/netmonitor/mcp_server/manage_tokens.py create \
  --name "Claude Desktop" \
  --scope read_only \
  --rate-minute 60 \
  --rate-hour 3000
```

Revoke token:
```bash
python3 /opt/netmonitor/mcp_server/manage_tokens.py revoke <token>
```

### Rate Limiting

Default limits per token:
- **Per minute:** 100 requests
- **Per hour:** 5000 requests
- **Per day:** 50000 requests

Adjust when creating tokens with `--rate-minute`, `--rate-hour`, `--rate-day`

---

## 7. Service Management

```bash
# Check status
sudo systemctl status netmonitor-mcp-streamable

# View logs (live)
sudo journalctl -u netmonitor-mcp-streamable -f

# Restart service
sudo systemctl restart netmonitor-mcp-streamable

# Enable on boot
sudo systemctl enable netmonitor-mcp-streamable
```

---

## 8. References

- [Claude Desktop MCP Documentation](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)
- [Open-WebUI MCP Support](https://docs.openwebui.com/features/mcp/)
- [MCP Streamable HTTP Spec](https://modelcontextprotocol.io/docs/develop/connect-local-servers)
- NetMonitor Documentation: `/opt/netmonitor/mcp_server/STREAMABLE_HTTP_README.md`

---

## Summary

✅ **Claude Desktop:** Use `mcp-remote` package with NPX
✅ **Open-WebUI:** Native MCP support, configure in Admin Settings
✅ **Both work:** Server supports both `/` and `/mcp` endpoints
✅ **60 tools:** Full NetMonitor security toolkit available
✅ **Secure:** Token-based auth with rate limiting
✅ **Production-ready:** Logging, monitoring, health checks

Questions? Check logs or contact support.
