# NetMonitor MCP - Nginx Reverse Proxy Configuration

## ✅ Current Setup

Your MCP server is running behind an nginx reverse proxy:

- **Public URL:** `https://soc.poort.net/mcp`
- **Backend:** `http://127.0.0.1:8000` (Uvicorn on all interfaces)
- **SSL:** Enabled with HSTS
- **CORS:** Configured for AI clients

---

## Configuration for Clients

### 1. Claude Desktop (Remote Access via Nginx)

**File:** `~/.config/Claude/claude_desktop_config.json`

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

**Important:**
- Use `https://soc.poort.net/mcp` (full public URL)
- Replace `YOUR_TOKEN_HERE` with your actual Bearer token
- Restart Claude Desktop after changing config

---

### 2. Claude Desktop (Local Access - No Nginx)

If you're running Claude Desktop on the SOC server itself:

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

---

### 3. Open-WebUI Configuration

**Admin Settings → MCP Servers → Add Server:**

- **Name:** `NetMonitor SOC`
- **Type:** `MCP (Streamable HTTP)`
- **Server URL:** `https://soc.poort.net/mcp`
- **Authentication:**
  - **Type:** Bearer Token
  - **Token:** `YOUR_TOKEN_HERE`

**Important:**
- Use the full URL: `https://soc.poort.net/mcp`
- Don't add trailing slashes or subdirectories
- Make sure Open-WebUI can reach your server (firewall, network, etc.)

---

## Testing Your Setup

### Test via Public URL (through nginx)

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

### Test Direct Backend (bypass nginx)

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

## Your Nginx Configuration Analysis

### Working Configuration

Your current nginx config correctly handles MCP traffic:

```nginx
# Exact match for /mcp (no trailing slash) → redirect to /
location = /mcp {
    proxy_pass http://netmonitor_mcp_api/;
    # CORS headers
    # Authorization header passthrough
}

# Prefix match for /mcp/* (with trailing slash)
location /mcp/ {
    proxy_pass http://netmonitor_mcp_api;
    # CORS headers
    # Authorization header passthrough
}
```

**How it works:**
- Client requests `https://soc.poort.net/mcp`
- Nginx forwards to `http://127.0.0.1:8000/` (note: trailing slash)
- Backend MCP server handles request on root `/` mount
- Response flows back through nginx to client

**CORS Headers:**
```nginx
add_header Access-Control-Allow-Origin "*" always;
add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
add_header Access-Control-Allow-Headers "Authorization, Content-Type, X-Requested-With, X-API-Key" always;
```

These are correct for MCP clients (Claude Desktop, Open-WebUI).

---

## Backend Configuration

Your MCP server is configured to work behind nginx:

**Environment Variables (.env):**
```bash
MCP_API_HOST=0.0.0.0           # Listen on all interfaces
MCP_API_PORT=8000              # Backend port
MCP_ROOT_PATH=/mcp             # Tells Starlette it's behind proxy at /mcp
```

**Backend Routes:**
- `Mount("/mcp", app=mcp_asgi_app)` - Handles `/mcp/*` requests
- `Mount("/", app=mcp_asgi_app)` - Handles root `/` requests (from nginx rewrite)
- `Route("/health", ...)` - Health check (no auth)
- `Route("/metrics", ...)` - Metrics (requires auth)

---

## Troubleshooting

### Issue: "Connection refused" from Claude Desktop

**Check:**
1. Is nginx running? `systemctl status nginx`
2. Is MCP service running? `systemctl status netmonitor-mcp-streamable`
3. Can you reach the public URL?
   ```bash
   curl -I https://soc.poort.net/mcp
   ```
4. Check nginx logs:
   ```bash
   tail -f /var/log/nginx/netmonitor_error.log
   ```

### Issue: "401 Unauthorized"

**Check:**
1. Is your token valid?
   ```bash
   python3 /opt/netmonitor/mcp_server/manage_tokens.py list
   ```
2. Is the Authorization header being passed through nginx?
   - Check nginx config has `proxy_set_header Authorization $http_authorization;`
3. Test with curl:
   ```bash
   curl -v -X POST https://soc.poort.net/mcp \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
   ```

### Issue: "CORS errors" in browser

**Check:**
1. CORS headers in nginx config (already correct in your setup)
2. Preflight OPTIONS requests handled:
   ```nginx
   if ($request_method = 'OPTIONS') {
       return 204;
   }
   ```

### Issue: Open-WebUI can't connect

**Common Problems:**
1. **Wrong URL format:**
   - ❌ Wrong: `https://soc.poort.net/mcp/`
   - ❌ Wrong: `https://soc.poort.net`
   - ✅ Correct: `https://soc.poort.net/mcp`

2. **Open-WebUI can't reach your server:**
   - Check firewall: `sudo ufw status`
   - Check network routing if Open-WebUI is on different network
   - Try from Open-WebUI server: `curl https://soc.poort.net/mcp`

3. **Wrong MCP server type:**
   - Make sure you selected "MCP (Streamable HTTP)" not "OpenAPI"

---

## Security Considerations

### Firewall Rules

Your current setup exposes:
- **Port 443 (HTTPS):** Nginx reverse proxy
- **Port 8000:** Direct backend access (should be blocked from external)

**Recommended firewall:**
```bash
# Allow nginx (already open)
sudo ufw allow 443/tcp

# Block direct backend access from external
sudo ufw deny 8000/tcp

# Or allow only from localhost
sudo ufw allow from 127.0.0.1 to any port 8000
```

### Token Security

**Best Practices:**
1. Use different tokens for different clients
2. Use `read_only` scope for monitoring clients
3. Use `admin` scope only for trusted automation
4. Rotate tokens periodically

**Create scoped tokens:**
```bash
# Read-only for Claude Desktop
python3 /opt/netmonitor/mcp_server/manage_tokens.py create \
  --name "Claude Desktop - Read Only" \
  --scope read_only \
  --rate-minute 60

# Admin for automation
python3 /opt/netmonitor/mcp_server/manage_tokens.py create \
  --name "Automation - Admin" \
  --scope admin \
  --rate-minute 120
```

### Rate Limiting

Your current token limits:
- **Per minute:** 100 requests
- **Per hour:** 5000 requests
- **Per day:** 50000 requests

Adjust based on usage patterns when creating tokens.

---

## Monitoring

### Check Nginx Logs

```bash
# Access log (successful requests)
tail -f /var/log/nginx/netmonitor_access.log

# Error log (failed requests)
tail -f /var/log/nginx/netmonitor_error.log

# Filter for MCP traffic
grep "POST /mcp" /var/log/nginx/netmonitor_access.log
```

### Check Backend Logs

```bash
# Systemd journal
journalctl -u netmonitor-mcp-streamable -f

# Application log
tail -f /tmp/mcp_streamable_http.log

# Filter for specific tool calls
grep "Tool called" /tmp/mcp_streamable_http.log
```

### Monitor Token Usage

```bash
# View token usage stats
python3 /opt/netmonitor/mcp_server/manage_tokens.py list

# Check rate limits
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://soc.poort.net/mcp/metrics
```

---

## Performance Tuning

### Nginx Keepalive

Your config already has:
```nginx
upstream netmonitor_mcp_api {
    server 127.0.0.1:8000 fail_timeout=0;
    keepalive 32;  # ✅ Good for MCP persistent connections
}
```

### Backend Workers

MCP Streamable HTTP is single-process by default (stateless). To scale:

1. Run multiple backend instances on different ports
2. Update nginx upstream:
   ```nginx
   upstream netmonitor_mcp_api {
       server 127.0.0.1:8000;
       server 127.0.0.1:8001;
       server 127.0.0.1:8002;
       keepalive 32;
   }
   ```

---

## Summary

✅ **Your Setup is Correct:**
- Nginx properly proxies `/mcp` to backend
- CORS headers configured
- Authorization headers passed through
- SSL/TLS configured with HSTS

✅ **Client Configuration:**
- Claude Desktop: `https://soc.poort.net/mcp` via `mcp-remote`
- Open-WebUI: `https://soc.poort.net/mcp` as MCP server

✅ **Tested and Working:**
- Tools list via public URL: ✅
- Backend direct access: ✅
- 60 tools available: ✅

**Next Steps:**
1. Update CLIENT_CONFIGURATION.md with your public URL
2. Configure Claude Desktop with `https://soc.poort.net/mcp`
3. Configure Open-WebUI with same URL
4. Test and monitor logs
