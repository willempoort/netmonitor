# Open-WebUI with NetMonitor REST API

**⚠️ Note:** This integration has limitations due to Open-WebUI's native MCP bugs. For better experience with local models, consider using [Ollama-MCP-Bridge](../ollama-mcp-bridge/) instead.

## Why REST Instead of Native MCP?

Open-WebUI has a bug in native MCP Streamable HTTP that causes:
```
cannot pickle '_asyncio.Future' object
```

This REST wrapper provides:
- ✅ Stable REST endpoints (no SSE streaming complexity)
- ✅ All 60 NetMonitor tools available
- ✅ Token authentication + rate limiting
- ⚠️ **Requires function calling support** (GPT-4, Claude API, etc.)
- ❌ Does NOT work with most local models (qwen, mistral, llama)

## Recommendation

**For local models (qwen2.5, mistral, llama):**
→ Use [Ollama-MCP-Bridge-WebUI](../ollama-mcp-bridge/) instead

**For API-based models (GPT-4, Claude):**
→ Continue with this setup

## Quick Setup (API-based models only)

### Step 1: Install Open-WebUI (on your laptop)

```bash
# With Docker (recommended):
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -v open-webui:/app/backend/data \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  --restart always \
  ghcr.io/open-webui/open-webui:main
```

Open: **http://localhost:3000**
Create admin account (first user = admin)

### Step 2: Get API Token (on server)

If you don't have a token yet:

```bash
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
  --name "Open-WebUI" \
  --scope read_only \
  --rate-minute 120
```

**Example token:** `725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f`

### Step 3: Add NetMonitor Function in Open-WebUI

1. Open Open-WebUI: http://localhost:3000
2. Go to: **Workspace → Functions** (or Werkruimte → Functies)
3. Click: **"+"** to add new function
4. Paste the code from `openwebui_function.py` (included in this directory)
5. Click **"Save"**
6. Configure **Valves** (gear icon):
   - **API_URL**: `https://soc.poort.net/openwebui`
   - **API_TOKEN**: `<your token here>`
7. **Save**

### Step 4: Configure API-based Model

**Important:** Open-WebUI custom functions only work with models that have native function calling support.

**Option A: OpenAI GPT**
1. Go to Settings → Connections → OpenAI API
2. Add your OpenAI API key
3. Select GPT-4 or GPT-3.5-turbo as model

**Option B: Anthropic Claude**
1. Go to Settings → Connections → Anthropic API
2. Add your Anthropic API key
3. Select Claude Sonnet or Opus as model

### Step 5: Enable Function in Chat

1. Start new chat
2. Click model settings (gear icon)
3. Under "Functions", check "NetMonitor Security Tools"
4. Save

### Step 6: Test

Try these queries:
```
What NetMonitor tools do you have?
Show me recent security threats
Analyze IP 192.168.1.50
Which sensors are online?
```

## Files in This Directory

```
open-webui/
├── README.md                      ← You are here
├── OPEN_WEBUI_REST_SETUP.md       ← Detailed Dutch setup guide
└── openwebui_function.py          ← Python function code for Open-WebUI
```

## Architecture

```
┌──────────────┐
│  Open-WebUI  │  http://localhost:3000
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  API Model   │  GPT-4, Claude, etc. (via API)
│ (Function    │  Calls custom functions
│  Calling)    │
└──────┬───────┘
       │ HTTPS
       ▼
┌──────────────┐
│  NetMonitor  │  https://soc.poort.net/openwebui
│ REST Wrapper │  Port 8001
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  NetMonitor  │  All 60 security tools
│     Tools    │
└──────────────┘
```

## Why This is Limited

**The Problem:**
Most local Ollama models (qwen2.5, mistral, llama3) do NOT support function calling in Open-WebUI's implementation. The model sees the function but doesn't know how to call it.

**What happens:**
```
User: Show me recent threats
Model: To help you, I need more information about what function to call...
```

**The Solution:**
Use [Ollama-MCP-Bridge-WebUI](../ollama-mcp-bridge/) which:
- ✅ Works with ANY Ollama model
- ✅ Automatic tool detection
- ✅ No function calling required
- ✅ Better integration with MCP protocol

## Included Custom Function

The `openwebui_function.py` provides these tools:

### Available Tools
1. **get_recent_threats** - Get recent security threats
   - Parameters: hours, severity, limit
   - Example: "Show critical threats from last 6 hours"

2. **analyze_ip** - Analyze IP for threats
   - Parameters: ip_address, hours
   - Example: "Analyze IP 192.168.1.50"

3. **get_sensor_status** - Get sensor statuses
   - Example: "Which sensors are offline?"

4. **check_indicator** - Check IoC against threat feeds
   - Parameters: indicator, indicator_type
   - Example: "Check if 185.220.101.50 is malicious"

5. **get_devices** - List network devices
   - Parameters: include_inactive
   - Example: "Show me all network devices"

**Note:** This is a subset of 5 tools. To add more tools, you need to manually add methods to the Python class.

## Adding More Tools

To add additional tools from NetMonitor's 60 tools:

1. Check available tools:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://soc.poort.net/openwebui/tools
```

2. Add method to `openwebui_function.py`:
```python
def get_kerberos_stats(self, hours: int = 24) -> str:
    """Get Kerberos attack statistics"""
    result = self._call_api('tools/execute', {
        'tool_name': 'get_kerberos_stats',
        'parameters': {'hours': hours}
    })

    if not result.get('success'):
        return f"❌ Error: {result.get('error')}"

    # Format and return data
    return f"Kerberos Stats: {result.get('data')}"
```

3. Save and reload function in Open-WebUI

## REST API Endpoints

The NetMonitor REST wrapper provides:

**GET /health**
- Health check
- No authentication required

**GET /tools**
- List all 60 available tools
- Requires: Bearer token
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://soc.poort.net/openwebui/tools
```

**POST /tools/execute**
- Execute a specific tool
- Requires: Bearer token
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "get_recent_threats",
    "parameters": {"hours": 24}
  }' \
  https://soc.poort.net/openwebui/tools/execute
```

## Troubleshooting

### Function Not Appearing

1. Check you're in **Workspace → Functions** (NOT Admin Panel → Functions)
2. Restart Open-WebUI: `docker restart open-webui`
3. Verify JSON syntax is valid

### API Errors

Test token manually:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://soc.poort.net/openwebui/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "NetMonitor Open-WebUI REST Wrapper",
  "tools": 60
}
```

### SSL Errors

If using self-signed certificate, modify `_call_api` in function:
```python
response = requests.post(
    url,
    headers=headers,
    json=data,
    timeout=30,
    verify=False  # ⚠️ Only for testing!
)
```

### Model Not Calling Functions

**This is the main limitation.** Most local models don't support function calling.

**Solutions:**
1. ✅ **Switch to API model** (GPT-4, Claude) - expensive
2. ✅ **Use Ollama-MCP-Bridge** instead - free, local, better

### Function Returns "API_TOKEN not configured"

1. Click gear icon next to function
2. Enter API_TOKEN in Valves configuration
3. Save
4. Restart chat

## Server Status

Check if REST wrapper is running:

```bash
# On server
systemctl status netmonitor-openwebui-rest

# View logs
journalctl -u netmonitor-openwebui-rest -f
```

## All 60 Available Tools

While the custom function only includes 5 tools by default, the REST API provides all 60:

**Threat Analysis:** analyze_ip, get_recent_threats, check_indicator, get_threat_detections, get_threat_feed_stats, get_attack_chains, get_mitre_mapping, etc.

**Device Management:** get_devices, get_device_by_ip, assign_device_template, create_template_from_device, clone_device_template, get_device_traffic_stats, etc.

**Sensor Operations:** get_sensor_status, send_sensor_command, get_sensor_command_history

**TLS/SSL Analysis:** get_tls_metadata, get_tls_stats, check_ja3_fingerprint, add_ja3_blacklist

**PCAP Management:** get_pcap_captures, export_flow_pcap, delete_pcap_capture

**Kerberos Security:** get_kerberos_stats, get_kerberos_attacks, check_weak_encryption

**Risk Assessment:** get_top_risk_assets, get_asset_risk, get_risk_trends

**SOAR Integration:** get_soar_playbooks, get_pending_approvals, approve_soar_action

**And 30+ more tools...**

See full list:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://soc.poort.net/openwebui/tools | jq -r '.tools[].name'
```

## Comparison with Other Clients

| Feature | Open-WebUI | Ollama-Bridge | Claude Desktop |
|---------|-----------|---------------|----------------|
| Local model support | ⚠️ Limited | ✅ All | ❌ No |
| Function calling required | ✅ Yes | ❌ No | ❌ No |
| All 60 tools (out of box) | ❌ Manual | ✅ Auto | ✅ Auto |
| Setup complexity | Hard | Medium | Easy |
| Cost | API fees | Free | API fees |
| Privacy | Hybrid | Local + HTTPS | Cloud |

## Recommendation

**If you're using local Ollama models:** Switch to [Ollama-MCP-Bridge](../ollama-mcp-bridge/)

**If you're using GPT-4/Claude API:** This setup works fine

**For best experience:** Use [Claude Desktop](../claude-desktop/) with native MCP support

## Resources

- [Full Setup Guide (Dutch)](./OPEN_WEBUI_REST_SETUP.md)
- [Open-WebUI Documentation](https://docs.openwebui.com/)
- [NetMonitor MCP Server](../../README.md)
- [REST Wrapper Source](../../openwebui_rest_wrapper.py)

## Support

- REST wrapper logs: `journalctl -u netmonitor-openwebui-rest -f`
- Token management: `python3 manage_tokens.py --help`
- Open-WebUI issues: Check Open-WebUI GitHub

---

**Note:** This integration is functional but limited. For better experience with local models, see [Ollama-MCP-Bridge](../ollama-mcp-bridge/). 🚀
