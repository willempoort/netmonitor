# NetMonitor MCP Client Configurations

This directory contains client configurations and setup guides for connecting various AI assistants to the NetMonitor MCP server.

## Available Clients

### 1. Claude Desktop (Anthropic)
- **Directory:** `claude-desktop/`
- **Protocol:** MCP Streamable HTTP via STDIO bridge
- **Status:** ✅ Fully working
- **Model:** Claude Sonnet 4.5
- **Best for:** Professional security analysis, complex investigations

[Setup Guide](./claude-desktop/README.md)

### 2. Ollama-MCP-Bridge-WebUI
- **Directory:** `ollama-mcp-bridge/`
- **Protocol:** MCP via custom bridge with WebUI
- **Status:** ✅ Recommended for local models
- **Models:** Any Ollama model (qwen2.5, mistral, llama3, etc.)
- **Best for:** Privacy-focused local AI with NetMonitor tools

[Setup Guide](./ollama-mcp-bridge/README.md)

### 3. Open-WebUI (REST API)
- **Directory:** `open-webui/`
- **Protocol:** REST wrapper (workaround for Open-WebUI MCP bugs)
- **Status:** ⚠️ Limited - requires function calling support
- **Models:** GPT-4, Claude API, or function-calling capable models
- **Best for:** Web-based interface with API-based models

[Setup Guide](./open-webui/README.md)

## Quick Comparison

| Feature | Claude Desktop | Ollama-MCP-Bridge | Open-WebUI |
|---------|---------------|-------------------|------------|
| All 60 tools | ✅ Yes | ✅ Yes | ⚠️ Manual setup |
| Local model | ❌ No | ✅ Yes | ✅ Yes |
| Function calling required | ❌ No | ❌ No | ✅ Yes |
| Privacy | Cloud | Hybrid | Hybrid |
| Setup complexity | Easy | Medium | Hard |
| WebUI included | ❌ No | ✅ Yes | ✅ Yes |

## Server Information

**MCP Server:** https://soc.poort.net/mcp
**Protocol:** MCP Streamable HTTP (2025-06-18)
**Authentication:** Bearer token (manage with `manage_tokens.py`)
**Available Tools:** 60 security tools

## Getting a Token

```bash
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
  --name "Your Client Name" \
  --scope read_only \
  --rate-minute 120
```

## Architecture

```
┌─────────────────┐
│   AI Client     │  (Claude Desktop, Ollama, Open-WebUI)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  MCP Protocol   │  (STDIO, HTTP, or REST)
└────────┬────────┘
         │
         ▼ HTTPS
┌─────────────────┐
│ NetMonitor MCP  │  (soc.poort.net:8000)
│     Server      │  → 60 Security Tools
└─────────────────┘  → PostgreSQL Database
                     → Threat Feeds
                     → Sensors
```

## Support

For issues or questions:
- Check the specific client README in each subdirectory
- Review server logs: `journalctl -u netmonitor-mcp-streamable -f`
- Token management: `python3 manage_tokens.py --help`

---

**Choose the client that best fits your needs and follow the setup guide in the respective directory.**
