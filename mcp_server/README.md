# NetMonitor MCP Server

AI-toegang tot NetMonitor security-monitoring data via het Model Context
Protocol (Streamable HTTP transport, spec 2025-03-26).

## Waar te beginnen

- **[STREAMABLE_HTTP_README.md](STREAMABLE_HTTP_README.md)** - hoofddocumentatie: installatie, configuratie, tokens aanmaken, beschikbare tools (60+).
- **[CLIENT_CONFIGURATION.md](CLIENT_CONFIGURATION.md)** - client-specifieke configuratie.
- **[CLAUDE_DESKTOP_BRIDGE_SETUP.md](CLAUDE_DESKTOP_BRIDGE_SETUP.md)** - Claude Desktop koppelen.
- **[NGINX_CONFIGURATION.md](NGINX_CONFIGURATION.md)** - reverse proxy setup voor `/mcp`.
- **[clients/](clients/)** - referentie-implementaties (netmonitor-chat, ollama-mcp-bridge, open-webui, claude-desktop).

## Activeren op een bestaande installatie

Als MCP bij de initiële installatie is overgeslagen, activeer je 'm later
met:

```bash
cd mcp_server
sudo ./setup_streamable_http.sh
```

Zie [STREAMABLE_HTTP_README.md](STREAMABLE_HTTP_README.md) voor details.

## Server-implementatie

De actieve server is `streamable_http_server.py` (systemd service
`netmonitor-mcp-streamable`), gedraaid via `shared_tools.py` voor de
tool-definities en -implementaties.

De oudere, inmiddels vervangen HTTP/SSE-implementatie (`http_server.py` +
bijbehorende documentatie en installer) staat, alleen ter referentie, in
[`archive/mcp_legacy_http_api/`](../archive/mcp_legacy_http_api/).
