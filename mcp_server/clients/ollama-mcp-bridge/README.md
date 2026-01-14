# Ollama-MCP-Bridge-WebUI for NetMonitor

Connect your local Ollama models (qwen2.5, mistral, llama3, etc.) to NetMonitor's 60 security tools via a web interface.

## Why This Bridge?

✅ **Works with ANY Ollama model** - No function calling required
✅ **Privacy-focused** - Model runs locally, only tools make HTTPS calls
✅ **WebUI included** - Clean interface on http://localhost:8080
✅ **Automatic tool detection** - Model chooses the right tool
✅ **All 60 NetMonitor tools** - Full access to security capabilities

## Quick Start (5 minutes)

**1. Download repository (on your laptop):**
```bash
cd ~/Downloads
git clone https://github.com/Rkm1999/Ollama-MCP-Bridge-WebUI.git
cd Ollama-MCP-Bridge-WebUI
```

**2. Get NetMonitor files from server:**
```bash
scp root@soc.poort.net:/opt/netmonitor/mcp_server/clients/ollama-mcp-bridge/mcp_bridge.py .
scp root@soc.poort.net:/opt/netmonitor/mcp_server/clients/ollama-mcp-bridge/bridge_config.json .
scp root@soc.poort.net:/opt/netmonitor/mcp_server/clients/ollama-mcp-bridge/start.sh .
chmod +x start.sh
```

**3. Install and start:**
```bash
npm install
npm run build
./start.sh
```

**4. Open browser:**
http://localhost:8080

**5. Test with queries:**
```
What security tools do you have?
Show me recent threats from the last 24 hours
Analyze IP 192.168.1.50
Which sensors are offline?
```

## Documentation

- **[QUICK_START.md](./QUICK_START.md)** - Fast 5-minute setup
- **[DETAILED_SETUP.md](./DETAILED_SETUP.md)** - Complete guide with troubleshooting
- **[bridge_config.json](./bridge_config.json)** - Ready-to-use configuration
- **[mcp_bridge.py](./mcp_bridge.py)** - Python STDIO bridge to NetMonitor
- **[start.sh](./start.sh)** - Start script with health checks

## Files in This Directory

```
ollama-mcp-bridge/
├── README.md              ← You are here
├── QUICK_START.md         ← Fast setup guide
├── DETAILED_SETUP.md      ← Full instructions
├── mcp_bridge.py          ← Python bridge to NetMonitor
├── bridge_config.json     ← Pre-configured for NetMonitor
└── start.sh               ← Startup script
```

## Architecture

```
┌──────────────┐
│   Browser    │  http://localhost:8080
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Ollama-MCP-  │  TypeScript bridge with WebUI
│ Bridge-WebUI │  (Converts chat → tool calls)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Ollama     │  Your local model (qwen2.5:14b, etc.)
│   Server     │  http://localhost:11434
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ mcp_bridge.py│  Python STDIO → HTTPS converter
└──────┬───────┘
       │ HTTPS
       ▼
┌──────────────┐
│  NetMonitor  │  https://soc.poort.net/mcp
│  MCP Server  │  → 60 Security Tools
└──────────────┘
```

## Supported Models

Any Ollama model works, including:
- **qwen2.5:14b** (Recommended - good balance)
- **qwen2.5-coder:7b** (Fast, code-focused)
- **mistral:7b** (Good general purpose)
- **llama3:8b** (Latest Meta model)
- **mixtral:8x7b** (High quality, slower)

Change in `bridge_config.json`:
```json
{
  "llm": {
    "model": "mistral:7b"  // ← Your model here
  }
}
```

## Configuration

### Pre-configured Settings

The included `bridge_config.json` is ready to use with:
- **MCP Server:** https://soc.poort.net/mcp
- **Token:** Pre-filled (read-only access)
- **Model:** qwen2.5:14b
- **System Prompt:** Optimized for security analysis

### Custom Configuration

Edit `bridge_config.json` to customize:

```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "python3",
      "args": ["./mcp_bridge.py"],
      "env": {
        "MCP_SERVER_URL": "https://soc.poort.net/mcp",
        "MCP_AUTH_TOKEN": "your_token_here"
      }
    }
  },
  "llm": {
    "model": "qwen2.5:14b",
    "temperature": 0.7,
    "maxTokens": 8000
  },
  "systemPrompt": "You are a cybersecurity assistant..."
}
```

## Example Usage

### Security Threat Analysis
```
User: Show me critical threats from the last hour
AI: [Calls get_recent_threats(hours=1, severity="CRITICAL")]
    📊 Security Threats (last 1h)
    Total Alerts: 3
    🔴 CRITICAL: 2
    🟠 HIGH: 1
    ...
```

### IP Investigation
```
User: Is 185.220.101.50 malicious?
AI: [Calls analyze_ip("185.220.101.50")]
    🔍 IP Analysis: 185.220.101.50
    Location: Netherlands
    Threat Score: 85/100
    Risk Level: 🔴 CRITICAL
    💡 Recommendation: Block immediately
```

### Sensor Monitoring
```
User: Which sensors need attention?
AI: [Calls get_sensor_status()]
    🖥️ Sensor Status
    Total: 5
    Online: ✅ 4
    Offline: ❌ 1

    Sensor "Amsterdam-DC" is offline since 2 hours ago
```

## Troubleshooting

### Bridge Won't Start

**Check logs:**
```bash
tail -f ~/.mcp_bridge.log
```

**Common issues:**
- Python not found → Install Python 3.11+
- MCP server unreachable → Check network/firewall
- Token invalid → Get new token from admin

### Ollama Not Found

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull your model
ollama pull qwen2.5:14b

# Verify
ollama list
```

### WebUI Can't Connect to Ollama

```bash
# Start Ollama manually
ollama serve

# Test connection
curl http://localhost:11434/api/tags
```

### Tools Not Working

1. Check bridge logs: `tail -f ~/.mcp_bridge.log`
2. Test MCP server manually:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://soc.poort.net/mcp/health
```
3. Verify bridge config has correct token

## Advanced Usage

### Multiple MCP Servers

Add more servers to `bridge_config.json`:

```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "python3",
      "args": ["./mcp_bridge.py"],
      "env": {...}
    },
    "filesystem": {
      "command": "node",
      "args": [
        "./node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
        "/path/to/workspace"
      ]
    }
  }
}
```

### Debug Mode

Enable debug logging:
```json
{
  "mcpServers": {
    "netmonitor": {
      "env": {
        "MCP_SERVER_URL": "https://soc.poort.net/mcp",
        "MCP_AUTH_TOKEN": "your_token",
        "MCP_DEBUG": "true"
      }
    }
  }
}
```

### Custom System Prompt

Modify the system prompt for specific use cases:

```json
{
  "systemPrompt": "Je bent een Nederlandse security analist met toegang tot NetMonitor. Beantwoord altijd in het Nederlands. Focus op praktische actie-items en duidelijke risico-assessments."
}
```

## Getting a Token

If you need a new token:

```bash
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
  --name "Ollama Bridge" \
  --scope read_only \
  --rate-minute 120
```

## Available Tools (60 total)

The bridge provides access to all NetMonitor tools:

**Threat Analysis (10 tools)**
- analyze_ip, get_recent_threats, check_indicator
- get_threat_detections, get_threat_feed_stats
- get_attack_chains, get_mitre_mapping, etc.

**Device Management (15 tools)**
- get_devices, assign_device_template
- create_template_from_device, clone_device_template
- get_device_traffic_stats, etc.

**Sensor Operations (5 tools)**
- get_sensor_status, send_sensor_command
- get_sensor_command_history, etc.

**TLS/SSL Analysis (5 tools)**
- get_tls_metadata, get_tls_stats
- check_ja3_fingerprint, add_ja3_blacklist, etc.

**And 25+ more tools** for PCAP, Kerberos, risk scoring, SOAR, whitelisting, etc.

## Performance Tips

- **Faster responses:** Use smaller models (qwen2.5-coder:7b)
- **Better quality:** Use larger models (mixtral:8x7b)
- **Balance:** qwen2.5:14b (recommended)
- **Lower temperature** (0.3-0.5) for factual security data
- **Higher temperature** (0.7-0.9) for creative analysis

## Security Notes

- ✅ Model runs 100% locally (privacy)
- ✅ Only tool calls go over HTTPS to NetMonitor
- ✅ Bearer token authentication
- ✅ Rate limiting on server side
- ✅ All API calls logged

## Next Steps

Once working:
1. **Explore tools** - Ask "What tools are available?"
2. **Customize prompt** - Tailor for your use case
3. **Try different models** - Find your ideal balance
4. **Add more MCP servers** - Filesystem, web search, etc.
5. **Build workflows** - Combine multiple tools

## Resources

- [Ollama-MCP-Bridge-WebUI GitHub](https://github.com/Rkm1999/Ollama-MCP-Bridge-WebUI)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Ollama Models](https://ollama.com/library)
- [NetMonitor Documentation](../../README.md)

## Support

- Bridge logs: `~/.mcp_bridge.log`
- Server logs: `journalctl -u netmonitor-mcp-streamable -f`
- Token management: `python3 manage_tokens.py --help`
- GitHub Issues: Report bridge issues to upstream repo

---

**Enjoy your privacy-focused AI security assistant!** 🚀🛡️🔒
