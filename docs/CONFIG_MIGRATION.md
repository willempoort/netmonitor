# Configuration Migration Guide

## Overview

NetMonitor configuration has been consolidated for better security and clarity:

- **Before**: Duplicated settings in `.env` and `config.yaml`, secrets in version control
- **After**: Secrets in `.env` (not in git), application config in `config.yaml` (in git)

## What Changed?

### New Structure

| File | Purpose | Version Control | Contents |
|------|---------|----------------|----------|
| `.env` | Secrets & deployment settings | ❌ No (gitignored) | API keys, passwords, tokens, DASHBOARD_SERVER |
| `config.yaml` | Application config | ✅ Yes (tracked) | Settings, thresholds, features |
| `config_defaults.py` | Best practices | ✅ Yes (tracked) | Default values |

**Why deployment settings are in `.env`:**
- `install_services.sh` reads `DASHBOARD_SERVER` to determine which systemd services to create
- `netmonitor.py` reads `DASHBOARD_SERVER` at startup to decide embedded vs separate dashboard
- These settings are deployment-specific (dev might use embedded, prod uses gunicorn)
- They're not secrets, but they control infrastructure (1 vs 2 services)

### Priority Order

1. **Environment variables** (`.env` or system environment)
2. **config.yaml** (your customizations)
3. **config_defaults.py** (fallback defaults)

## Migration Steps

### Step 1: Create `.env` File

```bash
cd /opt/netmonitor
cp .env.example .env
chmod 600 .env  # Protect secrets
nano .env
```

### Step 2: Move Secrets from `config.yaml` to `.env`

**Check your current `config.yaml` for these secrets:**

```yaml
# OLD - In config.yaml (INSECURE!)
dashboard:
  secret_key: "3bf9aab6fbef3fe1041ea3f1ef9f48ca..."

database:
  postgresql:
    password: "netmonitor"

integrations:
  threat_intel:
    abuseipdb:
      api_key: "4f1da22b7d6a04ad5e185ea..."
    misp:
      api_key: "your-misp-key"
      url: "https://misp.example.com"
```

**Move them to `.env`:**

```bash
# NEW - In .env (SECURE!)
FLASK_SECRET_KEY=3bf9aab6fbef3fe1041ea3f1ef9f48ca...
DB_PASSWORD=netmonitor
ABUSEIPDB_API_KEY=4f1da22b7d6a04ad5e185ea...
MISP_API_KEY=your-misp-key
MISP_URL=https://misp.example.com
```

### Step 3: Clean Up `config.yaml`

**Remove hardcoded secrets from `config.yaml`:**

```yaml
# NEW - In config.yaml (secrets removed)
dashboard:
  secret_key: ""  # Loaded from .env

database:
  postgresql:
    password: ""  # Loaded from .env

integrations:
  enabled: true  # ← IMPORTANT: Change from false to true!
  threat_intel:
    enabled: true  # ← IMPORTANT: Change from false to true!
    abuseipdb:
      enabled: true
      api_key: ""  # Loaded from .env
    misp:
      enabled: false
      api_key: ""  # Loaded from .env
      url: ""      # Loaded from .env
```

**CRITICAL FIX**: The `integrations.threat_intel.enabled: false` in your config was blocking all threat intelligence, even though individual sources were enabled!

### Step 4: Restart Services

```bash
sudo systemctl restart netmonitor

# If using gunicorn for dashboard:
sudo systemctl restart netmonitor-dashboard
```

### Step 5: Verify

Check logs for security warnings:

```bash
# Should see "Using ABUSEIPDB_API_KEY from environment"
sudo journalctl -u netmonitor -n 100 | grep -E "Using|SECURITY"

# Should NOT see "SECURITY: api_key found in config.yaml"
```

## Common Issues

### Issue 1: AbuseIPDB Not Showing in Dashboard

**Symptom**: AbuseIPDB enabled in config but doesn't appear in web UI

**Cause**: Parent setting `integrations.threat_intel.enabled: false`

**Fix**:
```yaml
integrations:
  enabled: true           # ← Must be true
  threat_intel:
    enabled: true         # ← Must be true
    abuseipdb:
      enabled: true       # ← Individual source enabled
```

### Issue 2: Security Warnings in Logs

**Symptom**: `SECURITY: abuseipdb.api_key found in config.yaml`

**Cause**: API key still hardcoded in config.yaml

**Fix**:
1. Copy API key to `.env` as `ABUSEIPDB_API_KEY=...`
2. Remove or clear API key in config.yaml: `api_key: ""`
3. Restart service

### Issue 3: Dashboard Shows "No Credentials"

**Symptom**: Integration shows as enabled but "has_credentials: false"

**Cause**: Environment variable not set or service not restarted

**Fix**:
```bash
# Check environment variable is set
cat .env | grep ABUSEIPDB_API_KEY

# Ensure systemd service loads .env
sudo systemctl cat netmonitor | grep EnvironmentFile

# Restart service
sudo systemctl restart netmonitor
```

## Environment Variable Reference

### Required (Core Functionality)

```bash
# Flask session security (generate new one!)
FLASK_SECRET_KEY=<run: python3 -c "import secrets; print(secrets.token_hex(32))">
```

### Deployment Settings (Infrastructure)

```bash
# Dashboard server mode (controls service architecture)
DASHBOARD_SERVER=embedded  # or 'gunicorn' for production
DASHBOARD_HOST=0.0.0.0     # Network interface
DASHBOARD_PORT=8080        # Dashboard port
DASHBOARD_WORKERS=4        # Gunicorn workers (only if DASHBOARD_SERVER=gunicorn)

# MCP HTTP API (AI integration)
MCP_API_ENABLED=false      # Set to 'true' to enable
MCP_API_PORT=8000          # API port
```

**About DASHBOARD_SERVER:**
- `embedded` = 1 service (netmonitor.service with embedded Flask)
  - Good for: testing, small deployments, 1-10 users
  - Simple setup, lower resource usage
- `gunicorn` = 2 services (netmonitor.service + netmonitor-dashboard.service)
  - Good for: production, 10+ concurrent users, high availability
  - Better performance, process isolation

### Optional (Database)

```bash
# PostgreSQL password (if using PostgreSQL)
DB_PASSWORD=netmonitor
```

### Optional (Threat Intelligence)

```bash
# AbuseIPDB (free tier: 1000 queries/day)
ABUSEIPDB_API_KEY=<your-key>

# MISP Threat Platform
MISP_URL=https://misp.example.com
MISP_API_KEY=<your-key>

# AlienVault OTX
OTX_API_KEY=<your-key>
```

### Optional (SIEM)

```bash
# Wazuh SIEM
WAZUH_API_URL=https://wazuh.example.com
WAZUH_API_USER=admin
WAZUH_API_PASSWORD=<your-password>
```

### Optional (Notifications)

```bash
# Email notifications
SMTP_PASSWORD=<your-password>

# Slack notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## Backwards Compatibility

The new system is **fully backwards compatible**:

- Existing `config.yaml` with hardcoded secrets will still work
- You'll see security warnings in logs
- Environment variables take priority if both are set
- Gradual migration is possible

## Best Practices

### ✅ Do This

1. **Store secrets in `.env`** - Never commit secrets to git
2. **Use environment variables** - Priority over config files
3. **Protect `.env` file** - `chmod 600 .env`
4. **Use strong secrets** - Generate random keys for production
5. **Document in comments** - Mark where secrets should come from

### ❌ Don't Do This

1. **Don't commit `.env`** - Already in `.gitignore`, keep it that way
2. **Don't hardcode secrets in config.yaml** - Use `.env` instead
3. **Don't use example secrets in production** - Generate new ones
4. **Don't share secrets in documentation** - Use placeholders
5. **Don't ignore security warnings** - Fix them promptly

## Example: Complete Migration

**Before (config.yaml):**
```yaml
dashboard:
  secret_key: "insecure-key-123"

integrations:
  enabled: false  # ← Blocking everything!
  threat_intel:
    enabled: false  # ← Blocking everything!
    abuseipdb:
      enabled: true
      api_key: "my-secret-key-exposed-in-git"
```

**After (.env):**
```bash
FLASK_SECRET_KEY=3bf9aab6fbef3fe1041ea3f1ef9f48ca95ce3039bc550ad497ae48a46145db0b
ABUSEIPDB_API_KEY=4f1da22b7d6a04ad5e185ea8232e6949469a10d50f9db44ffb
```

**After (config.yaml):**
```yaml
dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8080
  secret_key: ""  # Loaded from .env as FLASK_SECRET_KEY

integrations:
  enabled: true   # ← Fixed!
  threat_intel:
    enabled: true  # ← Fixed!
    abuseipdb:
      enabled: true
      api_key: ""  # Loaded from .env as ABUSEIPDB_API_KEY
      rate_limit: 1000
      threshold: 50
```

## Need Help?

- **Documentation**: See `/docs/` for more guides
- **Example configs**: `config.yaml.example` and `.env.example`
- **Issue tracker**: https://github.com/anthropics/claude-code/issues
- **Logs**: `sudo journalctl -u netmonitor -f`

## Summary

| What | Where | Why |
|------|-------|-----|
| **Secrets** | | |
| API Keys | `.env` | Not in git, secure |
| Passwords | `.env` | Not in git, secure |
| Tokens | `.env` | Not in git, secure |
| **Deployment** | | |
| DASHBOARD_SERVER | `.env` | Deployment-specific, controls services |
| Host/Port settings | `.env` | Deployment-specific, can differ per env |
| MCP API settings | `.env` | Deployment-specific |
| **Application** | | |
| Thresholds | `config.yaml` | In git, shared config |
| Features | `config.yaml` | In git, tunable |
| Network ranges | `config.yaml` | In git, documented |
| **Defaults** | | |
| Best practices | `config_defaults.py` | In git, fallback values |

**Remember**:
- **Secrets** → `.env` (never commit!)
- **Deployment settings** → `.env` (controls infrastructure)
- **Application logic** → `config.yaml` (shared across deployments)
