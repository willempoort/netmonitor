# NetMonitor Nginx Configuration Templates

This directory contains nginx configuration templates for different deployment scenarios.

## Available Templates

### 1. `nginx-netmonitor.conf` - Simple Dashboard Setup

**Use when:** You only need the NetMonitor dashboard (no MCP API).

**Features:**
- NetMonitor dashboard on port 443 (HTTPS)
- HTTP to HTTPS redirect
- SSL/TLS configuration (Let's Encrypt ready)
- Security headers (HSTS, X-Frame-Options, etc.)
- CORS support
- Session management

**Does NOT include:**
- MCP API endpoints
- OpenAPI/Swagger documentation
- AI integration endpoints

**Installation:**
```bash
# 1. Edit the template
sudo nano nginx-netmonitor.conf
# Change: soc.example.com -> your actual domain

# 2. Copy to nginx sites
sudo cp nginx-netmonitor.conf /etc/nginx/sites-available/netmonitor
sudo ln -s /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/

# 3. Get SSL certificate
sudo certbot --nginx -d soc.example.com

# 4. Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

---

### 2. `nginx-netmonitor-dual.conf` - Complete Setup (Recommended)

**Use when:** You need both dashboard AND MCP API (AI integration).

**Features:**
- Everything from nginx-netmonitor.conf PLUS:
- MCP Streamable HTTP API on `/mcp` and `/mcp/*`
  - OpenAPI/Swagger docs at `/mcp/docs`
  - ReDoc documentation at `/mcp/redoc`
  - API spec at `/mcp/openapi.json`
  - Tools listing at `/mcp/tools`
  - JSON-RPC endpoint at `/mcp` (POST)
  - SSE streaming at `/mcp` (GET)
- Token authentication for MCP API
- Proper handling of MCP_ROOT_PATH

**Upstream configuration includes:**
- `netmonitor_dashboard` - port 8080 (Flask dashboard)
- `netmonitor_mcp_api` - port 8000 (FastAPI MCP server)

**Installation:**
```bash
# 1. Edit the template
sudo nano nginx-netmonitor-dual.conf
# Change: soc.example.com -> your actual domain

# 2. Ensure both services are running
sudo systemctl status netmonitor
sudo systemctl status netmonitor-mcp-streamable

# 3. Copy to nginx sites
sudo cp nginx-netmonitor-dual.conf /etc/nginx/sites-available/netmonitor
sudo ln -s /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/

# 4. Get SSL certificate
sudo certbot --nginx -d soc.example.com

# 5. Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

---

## Configuration Requirements

Both templates require:

1. **Domain name** - Replace `soc.example.com` with your actual domain
2. **SSL certificates** - Use Let's Encrypt (certbot) or provide your own
3. **Upstream services running:**
   - NetMonitor dashboard on port 8080
   - MCP API on port 8000 (dual config only)

## Testing Your Configuration

### Test Dashboard (both configs):
```bash
curl https://soc.example.com
```

### Test MCP API (dual config only):
```bash
# Health check (no auth required)
curl https://soc.example.com/mcp/health

# OpenAPI docs (public)
curl https://soc.example.com/mcp/docs

# Tools list (public)
curl https://soc.example.com/mcp/tools | jq .

# MCP endpoint (requires Bearer token)
curl -X POST https://soc.example.com/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Archived Templates

The following templates have been archived to `archive/nginx/`:

- `nginx-mcp-subdomain.conf` - Separate subdomain for MCP (deprecated)
- `nginx-netmonitor-gunicorn.conf` - Gunicorn-specific config (use dual instead)
- `nginx_mcp_location_fixed.conf` - Location block snippet (merged into dual)

These are kept for reference but should not be used for new installations.

## Troubleshooting

### "405 Method Not Allowed" for POST /mcp

Check nginx error log:
```bash
sudo tail -f /var/log/nginx/error.log
```

Ensure you're using `nginx-netmonitor-dual.conf` which includes the `location = /mcp` block.

### "502 Bad Gateway"

Check if upstream services are running:
```bash
sudo systemctl status netmonitor
sudo systemctl status netmonitor-mcp-streamable
```

Verify ports match nginx upstream configuration:
```bash
sudo netstat -tlnp | grep -E ':8000|:8080'
```

### SSL Certificate Issues

Renew certificates:
```bash
sudo certbot renew
sudo systemctl reload nginx
```

## See Also

- [MCP Server Documentation](mcp_server/STREAMABLE_HTTP_README.md)
- [Service Installation Guide](docs/installation/SERVICE_INSTALLATION.md)
- [Nginx Setup Guide](docs/installation/NGINX_SETUP.md)
