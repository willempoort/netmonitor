# Legacy STDIO/SSE Implementation

**⚠️ Deze implementatie is verouderd en vervangen door de HTTP API met token authenticatie.**

Deze directory bevat de oude MCP server implementatie die STDIO en SSE transport gebruikte.

## Waarom gearchiveerd?

De oude implementatie had meerdere beperkingen:
- ❌ Geen authenticatie
- ❌ Geen rate limiting  
- ❌ Geen permission control
- ❌ Moeilijk te debuggen
- ❌ Geen audit logging
- ❌ Één client per server instance

## Nieuwe implementatie

Gebruik de moderne HTTP API in plaats daarvan:
- ✅ Token-based authenticatie
- ✅ Rate limiting per token
- ✅ Permission scopes (read/write/admin)
- ✅ Volledige audit trail
- ✅ Multiple concurrent clients
- ✅ Auto-generated API docs

**Documentatie:** Zie `../HTTP_API_QUICKSTART.md` en `/MCP_HTTP_API.md`

## Legacy files

- `server.py` - Oude MCP server (STDIO/SSE)
- `mcp_sse_bridge.py` - SSE bridge voor remote clients
- `claude_desktop_config*.json` - Oude config voorbeelden
- `MCP_SETUP.md` - Oude setup documentatie (STDIO)
- `MCP_NETWORK_SETUP.md` - Oude network setup (SSE)
- `install_mcp_service.sh` - Oude service installer
- `netmonitor-mcp.service` - Oude systemd service

## Migratie

Zie `/MCP_HTTP_API.md` voor migratie instructies van STDIO/SSE naar HTTP API.
