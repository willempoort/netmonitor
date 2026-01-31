# NetMonitor MCP Client Configurations

This directory contains client configurations and setup guides for connecting various AI assistants to the NetMonitor MCP server.

## 📊 Aanbevelingen

**→ [LESSONS_LEARNED.md](./LESSONS_LEARNED.md)** - Uitgebreide analyse van alle geteste oplossingen

### Snel Kiezen:
- **Cloud OK?** → Claude Desktop (perfect, betrouwbaar)
- **On-Premise vereist?** → Open-WebUI 0.7.2 (aanbevolen)
- **Experimenteren?** → Ollama-MCP-Bridge (verwacht issues)

---

## Available Clients

### 1. Claude Desktop (Anthropic)
- **Directory:** `claude-desktop/`
- **Protocol:** MCP Streamable HTTP via STDIO bridge
- **Status:** ✅ Fully working
- **Model:** Claude Sonnet 4.5
- **Best for:** Professional security analysis, complex investigations

[Setup Guide](./claude-desktop/README.md)

### 2. NetMonitor Chat ⭐ **RECOMMENDED FOR LOCAL LLM**
- **Directory:** `netmonitor-chat/`
- **Protocol:** Native MCP Streamable HTTP
- **Status:** ✅ Fully working with multi-tool support
- **Models:** Ollama of LM Studio (qwen2.5-coder:14b recommended)
- **Best for:** On-premise, multi-tool workflows, web search, full privacy

**Key Features:**
- Multi-tool loop (LLM kan meerdere tools sequentieel aanroepen)
- Web search (DuckDuckGo/SearXNG) en DNS lookup
- Device template enrichment voor context-aware analyse
- Smart tool filtering (60 → 10 tools per request)

[Setup Guide](./netmonitor-chat/README.md)

### 3. Open-WebUI 0.7.2 (Docker)
- **Directory:** `open-webui/`
- **Protocol:** Native MCP support
- **Status:** ✅ Good for basic use
- **Models:** Any Ollama model (qwen2.5-coder:14b recommended)
- **Best for:** Users who prefer Docker-based deployments

[Setup Guide](./open-webui/SETUP.md) | [Quick Start](./open-webui/start.sh)

### 4. Ollama-MCP-Bridge-WebUI
- **Directory:** `ollama-mcp-bridge/`
- **Protocol:** MCP via custom Node.js bridge
- **Status:** ⚠️ Experimental - known tool calling issues
- **Models:** Any Ollama model (but tools often fail)
- **Best for:** Testing only, NOT recommended for production

[Troubleshooting](./ollama-mcp-bridge/OLLAMA_TOOL_CALLING_FIX.md)

## Quick Comparison

| Feature | Claude Desktop | NetMonitor Chat | Open-WebUI | Ollama-MCP-Bridge |
|---------|---------------|-----------------|------------|-------------------|
| All 60+ tools | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Tool calling | ✅ Perfect | ✅ Excellent | ✅ Good | ⚠️ Problematic |
| **Multi-tool loop** | ✅ Native | ✅ Yes (max 10) | ❌ No | ❌ No |
| **Web search** | ❌ No | ✅ DuckDuckGo | ❌ No | ❌ No |
| **Device context** | ❌ No | ✅ Yes | ❌ No | ❌ No |
| Local model | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| Privacy | Cloud | 100% On-Premise | 100% On-Premise | 100% On-Premise |
| Setup complexity | Easy | Easy (venv) | Medium (Docker) | Hard |
| WebUI included | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| Production ready | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |

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
