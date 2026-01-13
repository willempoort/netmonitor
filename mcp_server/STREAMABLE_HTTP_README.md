# NetMonitor MCP Streamable HTTP Server

Modern MCP server implementing the **Streamable HTTP protocol (spec 2025-03-26)** for NetMonitor Security Operations Center.

## Features

✅ **60 Security Tools** - Complete NetMonitor toolset
✅ **Streamable HTTP** - Modern MCP protocol (replaces SSE)
✅ **Token Authentication** - Secure with rate limiting
✅ **Stateless Operation** - Scalable and simple
✅ **Claude Desktop** - Full support (Pro/Max/Team/Enterprise)
✅ **Open-WebUI** - Native MCP integration
✅ **Production Ready** - Logging, metrics, health checks

## Quick Start

### 1. Configuration

Copy the example environment file:

```bash
cp /opt/netmonitor/mcp_server/.env.streamable_http.example /opt/netmonitor/.env
```

Edit `/opt/netmonitor/.env` and adjust settings if needed.

### 2. Generate API Token

Create a token for authentication:

```bash
python3 /opt/netmonitor/mcp_server/manage_tokens.py create \
  --name "Claude Desktop" \
  --scope read_only \
  --rate-limit 60
```

Save the generated token - you'll need it for client configuration.

### 3. Start the Server

```bash
cd /opt/netmonitor
/opt/netmonitor/venv/bin/python3 mcp_server/streamable_http_server.py
```

The server will start on `http://127.0.0.1:8000` by default.

### 4. Verify Server is Running

```bash
curl http://127.0.0.1:8000/health
```

Expected output:
```json
{
  "status": "healthy",
  "server": "NetMonitor MCP Streamable HTTP",
  "version": "1.0.0",
  "database": "connected",
  "tools": 60
}
```

## Client Configuration

### Claude Desktop

1. Open Claude Desktop settings
2. Navigate to "Developer" → "Edit Config"
3. Add this configuration:

```json
{
  "mcpServers": {
    "netmonitor": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

4. Replace `YOUR_TOKEN_HERE` with your generated token
5. Restart Claude Desktop
6. Test by asking: "What tools do you have access to?"

### Open-WebUI

1. Open Open-WebUI admin panel
2. Navigate to "Settings" → "MCP Servers"
3. Add new MCP server:
   - **Name**: NetMonitor
   - **URL**: `http://127.0.0.1:8000/mcp`
   - **Token**: YOUR_TOKEN_HERE
4. Save configuration
5. Test by asking: "Show me recent security threats"

## Available Tools (60 total)

### Threat Analysis (3)
- `analyze_ip` - Detailed IP threat intelligence
- `get_recent_threats` - Recent security alerts
- `get_sensor_status` - Remote sensor health

### Device Management (15+)
- `get_devices` - Network device inventory
- `get_device_by_ip` - Device classification lookup
- `touch_device` - Mark device as seen
- `assign_device_template` - Classify device
- `create_template_from_device` - Learn from device
- And many more...

### Configuration (5)
- `set_config_parameter` - Modify settings
- `get_config_parameters` - View all settings
- `get_sensor_status` - Sensor health

### Security Features (10+)
- `get_tls_metadata` - TLS certificate info
- `check_ja3_fingerprint` - Client fingerprinting
- `get_kerberos_attacks` - Kerberos threat detection
- `get_attack_chains` - Multi-stage attack correlation
- `check_indicator` - IOC lookup

### PCAP & Forensics (5)
- `get_pcap_captures` - Available packet captures
- `export_flow_pcap` - Export traffic as PCAP
- `get_packet_buffer_summary` - Buffer status

### Whitelist Management (3)
- `add_whitelist_entry` - Add trusted IPs/domains
- `get_whitelist_entries` - List whitelisted items
- `remove_whitelist_entry` - Remove from whitelist

### Threat Intelligence (5)
- `get_threat_feed_stats` - Threat feed statistics
- `get_threat_detections` - Feed-based detections
- `update_threat_feeds` - Refresh threat data
- `check_indicator` - IOC validation

### Risk & Analytics (8)
- `get_asset_risk` - Asset risk scoring
- `get_risk_trends` - Risk over time
- `get_top_risk_assets` - Highest risk devices
- `get_mitre_mapping` - MITRE ATT&CK mapping
- `get_attack_chains` - Attack correlation

### SOAR Integration (4)
- `get_soar_playbooks` - Available automation playbooks
- `get_pending_approvals` - Actions awaiting approval
- `approve_soar_action` - Approve automated action
- `get_soar_history` - SOAR execution history

### System Management (2)
- `get_memory_status` - Memory usage stats
- `flush_memory` - Clear caches

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Starlette ASGI Application            │
│                                                 │
│  ┌──────────────────────────────────────────┐  │
│  │  TokenAuthMiddleware                     │  │
│  │  - Bearer token validation               │  │
│  │  - Rate limiting                         │  │
│  └──────────────────────────────────────────┘  │
│                    ↓                            │
│  ┌──────────────────────────────────────────┐  │
│  │  StreamableHTTPSessionManager            │  │
│  │  - Protocol negotiation                  │  │
│  │  - Session lifecycle                     │  │
│  └──────────────────────────────────────────┘  │
│                    ↓                            │
│  ┌──────────────────────────────────────────┐  │
│  │  MCP Server Core                         │  │
│  │  - @server.list_tools()                  │  │
│  │  - @server.call_tool()                   │  │
│  └──────────────────────────────────────────┘  │
│                    ↓                            │
│  ┌──────────────────────────────────────────┐  │
│  │  NetMonitorTools (60 methods)           │  │
│  │  - Database queries                      │  │
│  │  - Security analysis                     │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_API_HOST` | `127.0.0.1` | Server bind address |
| `MCP_API_PORT` | `8000` | Server port |
| `MCP_DEBUG` | `false` | Enable debug mode |
| `LOG_LEVEL` | `INFO` | Logging level |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `netmonitor` | Database name |
| `DB_USER` | `mcp_readonly` | Database user |
| `DB_PASSWORD` | - | Database password |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model name |
| `MCP_AUTH_REQUIRED` | `true` | Enable authentication |
| `MCP_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `MCP_CORS_ENABLED` | `true` | Enable CORS |
| `MCP_CORS_ORIGINS` | `*` | CORS allowed origins |

## Token Management

### Create Token

```bash
python3 manage_tokens.py create \
  --name "Token Name" \
  --scope read_only \
  --rate-limit 60 \
  --expires-days 365
```

**Scopes:**
- `read_only` - View data only
- `read_write` - View and modify data
- `admin` - Full access

### List Tokens

```bash
python3 manage_tokens.py list
```

### Revoke Token

```bash
python3 manage_tokens.py revoke --token-id <id>
```

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/netmonitor-mcp-streamable.service`:

```ini
[Unit]
Description=NetMonitor MCP Streamable HTTP Server
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netmonitor
Environment="PATH=/opt/netmonitor/venv/bin:/usr/bin:/bin"
ExecStart=/opt/netmonitor/venv/bin/python3 /opt/netmonitor/mcp_server/streamable_http_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable netmonitor-mcp-streamable
sudo systemctl start netmonitor-mcp-streamable
sudo systemctl status netmonitor-mcp-streamable
```

### Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name netmonitor-mcp.example.com;

    location /mcp {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Required for SSE streaming
        proxy_buffering off;
        proxy_cache off;
    }
}
```

## Troubleshooting

### Server won't start

**Check database connection:**
```bash
psql -h localhost -U mcp_readonly -d netmonitor -c "SELECT 1"
```

**Check port availability:**
```bash
sudo lsof -i :8000
```

**Check logs:**
```bash
tail -f /tmp/mcp_streamable_http.log
```

### Authentication errors

**Verify token exists:**
```bash
python3 manage_tokens.py list
```

**Test token manually:**
```bash
TOKEN="your-token-here"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/metrics
```

### Claude Desktop connection issues

1. Check Claude Desktop logs (Help → View Logs)
2. Verify server is running: `curl http://127.0.0.1:8000/health`
3. Test MCP endpoint manually:
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' \
  http://127.0.0.1:8000/mcp
```

### Rate limiting

If you hit rate limits, increase them:

```bash
python3 manage_tokens.py create \
  --name "High Limit Token" \
  --scope read_only \
  --rate-limit-minute 120 \
  --rate-limit-hour 5000 \
  --rate-limit-day 50000
```

## API Endpoints

### `/mcp` (MCP Protocol)
- **POST**: JSON-RPC requests
- **GET**: SSE streaming
- **Auth**: Required (Bearer token)

### `/health` (Health Check)
- **GET**: Server health status
- **Auth**: Not required

### `/metrics` (Metrics)
- **GET**: Server and token metrics
- **Auth**: Required (Bearer token)

## Security Considerations

1. **Always use HTTPS in production**
2. **Rotate tokens regularly**
3. **Use specific CORS origins** (not `*`)
4. **Monitor rate limit violations**
5. **Review audit logs** (stored in `mcp_api_token_usage` table)
6. **Use read-only database user** for most tokens
7. **Limit network access** to trusted IPs only

## Performance

- **Stateless operation**: No session state = horizontal scaling
- **Connection pooling**: Database connections reused
- **Rate limiting**: Prevents abuse
- **Async I/O**: Non-blocking operations

**Expected performance:**
- 100+ requests/second per instance
- <50ms avg response time (simple queries)
- <500ms avg response time (complex analytics)

## Comparison with Legacy Servers

| Feature | Streamable HTTP | Old HTTP Server | Legacy SSE/stdio |
|---------|----------------|-----------------|------------------|
| **Protocol** | MCP Streamable HTTP | Custom REST | MCP SSE/stdio |
| **Tools** | 60 | 60 | 29 |
| **Standard Compliant** | ✅ Yes | ❌ No | ⚠️ Partial |
| **Claude Desktop** | ✅ Yes | ❌ No | ✅ Yes (stdio only) |
| **Open-WebUI** | ✅ Yes | ❌ No | ❌ No |
| **Token Auth** | ✅ Yes | ✅ Yes | ❌ No |
| **Stateless** | ✅ Yes | ⚠️ Partial | ❌ No |
| **Lines of Code** | ~400 | ~4000 | ~2500 |

## Support

For issues or questions:
1. Check logs: `/tmp/mcp_streamable_http.log`
2. Test health endpoint: `curl http://127.0.0.1:8000/health`
3. Review this documentation

## License

AGPL-3.0-only - Copyright (c) 2025 Willem M. Poort
