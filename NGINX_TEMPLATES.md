# NetMonitor Nginx Configuration Template

## `nginx-netmonitor.conf.example`

Er is één nginx-template. Het bevat zowel de dashboard-routing als de MCP
`/mcp`-routing, ongeacht of je de MCP-server (nog) geïnstalleerd hebt.

**Features:**
- NetMonitor dashboard op poort 443 (HTTPS)
- HTTP naar HTTPS redirect
- SSL/TLS configuratie (Let's Encrypt/certbot-ready)
- Security headers (HSTS, X-Frame-Options, etc.)
- MCP Streamable HTTP API op `/mcp` en `/mcp/*`
  - OpenAPI/Swagger docs op `/mcp/docs`
  - ReDoc documentatie op `/mcp/redoc`
  - API spec op `/mcp/openapi.json`
  - Tools listing op `/mcp/tools`
  - JSON-RPC endpoint op `/mcp` (POST)
  - SSE streaming op `/mcp` (GET)
- Token authenticatie voor de MCP API (CORS + Authorization/X-API-Key passthrough)

**Upstream configuratie:**
- `netmonitor_dashboard` - poort 8080 (Flask dashboard)
- `netmonitor_mcp_api` - poort 8000 (FastAPI MCP server)

**Heb je de MCP-server (nog) niet geïnstalleerd?** Geen probleem — de
`/mcp`-locaties geven dan gewoon een 502 (niets luistert op poort 8000)
totdat je 'm later alsnog activeert via `mcp_server/setup_streamable_http.sh`.
Je hoeft de nginx-config dan niet opnieuw aan te passen; die routing staat
er al.

**Installatie:**
```bash
# 1. Kopieer het template
sudo cp nginx-netmonitor.conf.example /etc/nginx/sites-available/netmonitor
sudo ln -s /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/

# 2. Wijzig het domein
sudo sed -i 's/soc\.example\.com/JOUW-DOMEIN/g' /etc/nginx/sites-available/netmonitor

# 3. SSL certificaat
sudo certbot --nginx -d JOUW-DOMEIN

# 4. Test en herlaad
sudo nginx -t
sudo systemctl reload nginx
```

`install_complete.sh` (STAP 12/12) doet dit automatisch als je bij de
installatie voor nginx kiest.

## Configuratie-eisen

1. **Domeinnaam** - vervang `soc.example.com` door je eigen domein
2. **SSL certificaten** - via Let's Encrypt (certbot) of eigen certificaten
3. **Upstream services draaiend:**
   - NetMonitor dashboard op poort 8080
   - MCP API op poort 8000 (alleen nodig als je `/mcp` daadwerkelijk gebruikt)

## Testen

### Dashboard:
```bash
curl https://JOUW-DOMEIN
```

### MCP API (alleen als de MCP-server draait):
```bash
# Health check (geen auth nodig)
curl https://JOUW-DOMEIN/mcp/health

# OpenAPI docs (publiek)
curl https://JOUW-DOMEIN/mcp/docs

# Tools list (publiek)
curl https://JOUW-DOMEIN/mcp/tools | jq .

# MCP endpoint (vereist Bearer token)
curl -X POST https://JOUW-DOMEIN/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Gearchiveerde templates

De volgende templates zijn gearchiveerd naar `archive/nginx/` en niet meer
relevant voor nieuwe installaties:

- `nginx-mcp-subdomain.conf` - Aparte subdomain voor MCP (deprecated)
- `nginx-netmonitor-gunicorn.conf` - Gunicorn-specifieke config (gebruik het huidige template)
- `nginx_mcp_location_fixed.conf` - Losse location-block snippet (samengevoegd in het huidige template)

## Troubleshooting

### "405 Method Not Allowed" voor POST /mcp

Check nginx error log:
```bash
sudo tail -f /var/log/nginx/error.log
```

Controleer of `location = /mcp` in je config staat (exact match, niet alleen `/mcp/`).

### "502 Bad Gateway" op /mcp

De MCP-server draait niet of niet op poort 8000:
```bash
sudo systemctl status netmonitor-mcp-streamable
sudo netstat -tlnp | grep :8000
```

Nog niet geactiveerd? Zie `mcp_server/setup_streamable_http.sh`.

### "502 Bad Gateway" op het dashboard

```bash
sudo systemctl status netmonitor-dashboard
sudo netstat -tlnp | grep :8080
```

### SSL certificaatproblemen

```bash
sudo certbot renew
sudo systemctl reload nginx
```

## Zie ook

- [MCP Server Documentatie](mcp_server/STREAMABLE_HTTP_README.md)
- [Service Installation Guide](docs/installation/SERVICE_INSTALLATION.md)
- [Nginx Setup Guide](docs/installation/NGINX_SETUP.md)
