# NetMonitor Service Templates

This directory contains systemd service file templates for NetMonitor.

## Template System

Service files in this directory use placeholders that are replaced during installation:

- `__INSTALL_DIR__` - Installation directory (default: `/opt/netmonitor`)
- `__GUNICORN_BIN__` - Path to gunicorn binary (auto-detected)

**Important:** Environment variables in ExecStart use `$VAR` syntax (not `${VAR:-default}`).
Default values are set via `Environment=` directives in the template, which get overridden
by values from `EnvironmentFile` (`.env`).

## Available Templates

| Template | Description | Default Enabled |
|----------|-------------|-----------------|
| `netmonitor.service.template` | Main monitoring engine + embedded dashboard | Yes |
| `netmonitor-dashboard.service.template` | Separate Gunicorn dashboard (production) | Only if `DASHBOARD_SERVER=gunicorn` |
| `netmonitor-mcp-http.service.template` | MCP HTTP API for AI integration | Only if `MCP_API_ENABLED=true` |
| `netmonitor-mcp-sse.service.template` | MCP SSE Server (legacy Claude Desktop) | Manual install |
| `netmonitor-sensor.service.template` | Remote sensor client | Remote sensors only |
| `netmonitor-feed-update.service.template` | Threat feed updates (timer-based) | Yes |

## Installation

Service files are automatically generated from templates by `install_services.sh`:

```bash
cd /opt/netmonitor
sudo bash install_services.sh
```

The script will:
1. Load configuration from `.env`
2. Replace `__INSTALL_DIR__` with actual installation path
3. Generate service files in `/etc/systemd/system/`
4. Enable and start appropriate services

## Manual Installation

If you need to manually install a service:

```bash
# 1. Copy template and replace placeholders
sed 's|__INSTALL_DIR__|/opt/netmonitor|g' \
    services/netmonitor.service.template \
    > /etc/systemd/system/netmonitor.service

# 2. Reload systemd
sudo systemctl daemon-reload

# 3. Enable and start service
sudo systemctl enable netmonitor
sudo systemctl start netmonitor
```

### MCP SSE Server (Manual)

The SSE server is not auto-installed. To use it for Claude Desktop:

```bash
# Generate service file
sed 's|__INSTALL_DIR__|/opt/netmonitor|g' \
    services/netmonitor-mcp-sse.service.template \
    > /etc/systemd/system/netmonitor-mcp-sse.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable netmonitor-mcp-sse
sudo systemctl start netmonitor-mcp-sse
```

## Environment Variables

Service templates use `EnvironmentFile` directive to load variables from:
- `/opt/netmonitor/.env` (primary)
- `/etc/netmonitor/netmonitor.env` (optional system-wide override)

Default values are set in the template via `Environment=` directives.
Values from `.env` override these defaults.

See `.env.example` for all available variables.

## Service Dependencies

```
netmonitor.service (Main engine)
├── Starts: netmonitor.py
└── Includes: Embedded Flask dashboard (if DASHBOARD_SERVER=embedded)

netmonitor-dashboard.service (Optional - Gunicorn)
├── Starts: gunicorn wsgi:application
├── Requires: netmonitor.service
└── Enabled only if: DASHBOARD_SERVER=gunicorn

netmonitor-mcp-http.service (Optional - AI Integration)
├── Starts: mcp_server/http_server.py
├── Wants: postgresql.service
├── Port: MCP_API_PORT (default 8000)
└── Enabled only if: MCP_API_ENABLED=true

netmonitor-mcp-sse.service (Optional - Legacy Claude Desktop)
├── Starts: mcp_server/legacy_stdio_sse/server.py
├── Wants: postgresql.service
├── Port: MCP_SSE_PORT (default 3000)
└── Manual installation only

netmonitor-feed-update.service (Threat Feeds)
├── Starts: update_feeds.py
└── Triggered by: netmonitor-feed-update.timer
```

## Troubleshooting

**Service fails to start:**
```bash
# Check service status
sudo systemctl status netmonitor

# View logs
sudo journalctl -u netmonitor -f

# Verify .env file exists
ls -la /opt/netmonitor/.env

# Test template generation
sudo bash install_services.sh
```

**Port conflicts:**
```bash
# Check which ports are in use
sudo netstat -tlnp | grep -E ':(8000|8080|3000)'

# Verify .env port configuration
grep PORT /opt/netmonitor/.env
```

**Permission errors:**
```bash
# Ensure service files are owned by root
sudo chown root:root /etc/systemd/system/netmonitor*.service

# Reload systemd
sudo systemctl daemon-reload
```

**Environment variable not working:**
```bash
# Systemd doesn't support ${VAR:-default} in ExecStart
# Instead, set defaults via Environment= directives in the template
# Values from EnvironmentFile (.env) will override these defaults
```

## See Also

- [Installation Guide](../docs/installation/SERVICE_INSTALLATION.md)
- [Environment Configuration](../docs/installation/ENVIRONMENT.md)
- [Architecture Documentation](../docs/ARCHITECTURE.md)
