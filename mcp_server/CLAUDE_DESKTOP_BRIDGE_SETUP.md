# Claude Desktop Setup - MCP Streamable HTTP Bridge

## 📋 Overview

This guide explains how to connect Claude Desktop to the NetMonitor MCP server using the Python STDIO bridge.

**What you need:**
- Claude Desktop (Pro, Max, Team, or Enterprise)
- Python 3.8 or newer
- `requests` library
- Your MCP API token

---

## 🚀 Quick Setup

### Step 1: Download the Bridge Script

**On your local machine (where Claude Desktop runs):**

```bash
# Create directory
mkdir -p ~/mcp-clients/netmonitor
cd ~/mcp-clients/netmonitor

# Download bridge from server
scp user@soc.poort.net:/opt/netmonitor/mcp_server/mcp_streamable_http_bridge.py .

# Or download via HTTPS if available
curl -O https://soc.poort.net/path/to/mcp_streamable_http_bridge.py
```

### Step 2: Install Python Dependencies

```bash
# Install requests library
pip3 install requests

# Or with pipx (recommended)
pipx install requests
```

### Step 3: Get Your API Token

**On the SOC server:**

```bash
# List existing tokens
python3 /opt/netmonitor/mcp_server/manage_tokens.py list

# Or create a new token
python3 /opt/netmonitor/mcp_server/manage_tokens.py create \
  --name "Claude Desktop - Your Name" \
  --scope read_only \
  --rate-minute 60 \
  --rate-hour 3000
```

**Copy the token from the output.**

### Step 4: Configure Claude Desktop

**macOS:**
```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Linux:**
```bash
mkdir -p ~/.config/Claude
nano ~/.config/Claude/claude_desktop_config.json
```

**Windows:**
```
notepad %APPDATA%\Claude\claude_desktop_config.json
```

**Configuration:**

```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "python3",
      "args": [
        "/Users/username/mcp-clients/netmonitor/mcp_streamable_http_bridge.py"
      ],
      "env": {
        "MCP_SERVER_URL": "https://soc.poort.net/mcp",
        "MCP_AUTH_TOKEN": "your_token_here"
      }
    }
  }
}
```

**Important:**
- Replace `/Users/username/...` with the actual path to the bridge script
- Replace `your_token_here` with your actual Bearer token
- For Linux, path might be `/home/username/mcp-clients/netmonitor/mcp_streamable_http_bridge.py`
- For Windows, use `python` instead of `python3` and backslashes in path

### Step 5: Restart Claude Desktop

1. Completely quit Claude Desktop (not just close window)
2. Start Claude Desktop again
3. Wait a few seconds for initialization

### Step 6: Test

In Claude Desktop, type:

```
What tools do you have access to?
```

You should see a list of 60 NetMonitor security tools.

**Try a tool:**
```
Show me the status of all sensors
```

---

## 🔧 Troubleshooting

### Bridge doesn't start

**Check logs:**
```bash
tail -f ~/.mcp_bridge.log
```

**Test the bridge manually:**
```bash
export MCP_SERVER_URL="https://soc.poort.net/mcp"
export MCP_AUTH_TOKEN="your_token_here"
python3 ~/mcp-clients/netmonitor/mcp_streamable_http_bridge.py
```

You should see:
```
======================================================================
MCP Streamable HTTP Bridge Starting
======================================================================
Server: https://soc.poort.net/mcp
Log file: /Users/username/.mcp_bridge.log
Waiting for requests from Claude Desktop...
======================================================================
```

Press Ctrl+C to exit.

### SSL Certificate Errors

**macOS - Trust the certificate:**

If using a self-signed certificate:

```bash
# Download certificate
openssl s_client -connect soc.poort.net:443 -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > soc_poort_net.crt

# Add to keychain
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain soc_poort_net.crt
```

**Linux - Trust the certificate:**

```bash
# Download certificate
openssl s_client -connect soc.poort.net:443 -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > soc_poort_net.crt

# Add to system
sudo cp soc_poort_net.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Temporary workaround (NOT RECOMMENDED for production):**

Disable SSL verification in the bridge script (line ~80):
```python
response = self.session.post(
    self.server_url,
    json=request_data,
    timeout=30,
    verify=False  # Add this line
)
```

### Authentication Errors

**Verify token:**
```bash
# On the SOC server
python3 /opt/netmonitor/mcp_server/manage_tokens.py list
```

**Test token with curl:**
```bash
curl -X POST https://soc.poort.net/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### Claude Desktop doesn't show MCP server

**Check:**

1. **JSON syntax is valid:**
   ```bash
   python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

2. **Path to script is correct:**
   ```bash
   ls -la ~/mcp-clients/netmonitor/mcp_streamable_http_bridge.py
   ```

3. **Python is in PATH:**
   ```bash
   which python3
   ```

4. **Restart Claude Desktop completely** (Quit + reopen, not just close window)

### Tools are slow to respond

This is normal for the first request as the bridge establishes connection. Subsequent requests should be faster.

If consistently slow:
- Check network latency: `ping soc.poort.net`
- Check server load on SOC server
- Review logs: `tail -f ~/.mcp_bridge.log`

---

## 🔒 Security Best Practices

1. **Use read_only scope** for Claude Desktop tokens
2. **Set rate limits** appropriate for your usage
3. **Rotate tokens periodically** (every 90 days)
4. **Use HTTPS** (not HTTP)
5. **Keep your token secret** (don't commit to git, don't share)
6. **Review token usage** regularly:
   ```bash
   # On SOC server
   python3 /opt/netmonitor/mcp_server/manage_tokens.py list
   ```

---

## 📊 Available Tools (60 Total)

### Threat Analysis
- `analyze_ip` - Deep dive into IP threat intelligence
- `get_recent_threats` - Recent security alerts
- `get_threat_detections` - 60+ threat types
- `check_indicator` - Check IPs/domains against feeds

### Network Monitoring
- `get_sensor_status` - Remote sensor health
- `get_device_traffic_stats` - Traffic patterns
- `get_device_by_ip` - Device details

### Security Detection
- `get_kerberos_attacks` - AD attack detection
- `check_ja3_fingerprint` - TLS analysis
- `get_mitre_mapping` - MITRE ATT&CK mapping
- `get_attack_chains` - Multi-stage attacks

### Device Management
- `get_devices` - All network devices
- `assign_device_template` - Device classification
- `get_device_templates` - Predefined types

### PCAP Export
- `export_flow_pcap` - Capture traffic
- `get_pcap_captures` - List captures

### Configuration
- `set_config_parameter` - System config
- `add_whitelist_entry` - Manage whitelists
- `send_sensor_command` - Remote control

### SOAR Automation
- `get_soar_playbooks` - Response workflows
- `approve_soar_action` - Manual approvals
- `get_soar_history` - Audit trail

**Full documentation:** See server at https://soc.poort.net/mcp/docs

---

## 📝 Example Queries for Claude Desktop

**Security Overview:**
```
Show me a security summary for the last 24 hours
```

**Threat Analysis:**
```
Analyze IP address 192.168.1.100
```

**Sensor Status:**
```
What sensors are online and what is their status?
```

**Recent Threats:**
```
Show me recent HIGH severity threats
```

**Device Investigation:**
```
What devices are on the network and are there any unclassified devices?
```

**Attack Detection:**
```
Are there any Kerberos attacks detected in the last hour?
```

**MITRE ATT&CK:**
```
What MITRE ATT&CK techniques have been detected recently?
```

---

## 🆘 Getting Help

**Check logs:**
```bash
# Bridge logs
tail -f ~/.mcp_bridge.log

# Claude Desktop logs (macOS)
tail -f ~/Library/Logs/Claude/mcp*.log

# Server logs
ssh user@soc.poort.net "sudo journalctl -u netmonitor-mcp-streamable -f"
```

**Common issues:**
- Token expired → Create new token
- Network issues → Check VPN/firewall
- SSL errors → Trust certificate or disable verify (temp)
- Python not found → Install Python 3.8+
- Requests not found → Run `pip3 install requests`

---

## ✅ Verification Checklist

- [ ] Python 3.8+ installed: `python3 --version`
- [ ] Requests library installed: `pip3 list | grep requests`
- [ ] Bridge script downloaded
- [ ] Bridge script is executable: `chmod +x mcp_streamable_http_bridge.py`
- [ ] API token obtained
- [ ] Token tested with curl
- [ ] Claude Desktop config created
- [ ] Claude Desktop restarted
- [ ] Tools appear in Claude Desktop
- [ ] Test query successful

---

**Success!** You should now be able to use NetMonitor security tools in Claude Desktop. 🎉
