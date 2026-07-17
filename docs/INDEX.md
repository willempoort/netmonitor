# NetMonitor Documentation Index

Complete documentatie overzicht voor NetMonitor SOC platform.

---

## 🚀 Getting Started

**New to NetMonitor?** Start here:

1. 📖 [Main README](../README.md) - Project overview en quick start
2. 🔧 [Complete Installation Guide](installation/COMPLETE_INSTALLATION.md) - Volledige setup instructies
3. 👤 [User Manual](usage/USER_MANUAL.md) - Dashboard gebruik
4. 🛠️ [Admin Manual](usage/ADMIN_MANUAL.md) - Beheer en configuratie

---

## 📚 Documentation Sections

### 📢 Marketing & Positioning

Voor partners, klanten en externe communicatie:

- **[Pitch Document](PITCH_DOCUMENT.md)** - Complete product pitch met AI Scout positionering, concrete voorbeelden, en Porsche Principle
- **[Comparison Matrix](COMPARISON_MATRIX.md)** - Eerlijke vergelijking met Wazuh, Suricata, Zeek, Security Onion, Splunk (incl. Expert Mode)

### 🔧 Installation

Alles over installatie en setup:

- **[Complete Installation](installation/COMPLETE_INSTALLATION.md)** - Volledige automated installatie
- **[Virtual Environment Setup](installation/VENV_SETUP.md)** - Python venv configuratie
- **[Service Installation](installation/SERVICE_INSTALLATION.md)** - Systemd service setup
- **[Environment Configuration](installation/ENV_CONFIGURATION.md)** - .env bestand configuratie
- **[PostgreSQL Setup](installation/POSTGRESQL_SETUP.md)** - Database installatie
- **[TimescaleDB Setup](installation/TIMESCALEDB_SETUP.md)** - Time-series extensie
- **[Nginx Setup](installation/NGINX_SETUP.md)** - Reverse proxy configuratie
- **[Gunicorn Setup](installation/GUNICORN_SETUP.md)** - WSGI server configuratie

### 👥 Usage

Voor eindgebruikers en beheerders:

- **[User Manual](usage/USER_MANUAL.md)** - Dashboard gebruik en features
- **[Admin Manual](usage/ADMIN_MANUAL.md)** - Beheer, configuratie, troubleshooting
- **[Dashboard Guide](usage/DASHBOARD.md)** - Web interface documentatie
- **[Configuration Guide](usage/CONFIG_GUIDE.md)** - config.yaml instellingen

### 🚀 Deployment

Production deployment guides:

- **[Production Deployment](deployment/PRODUCTION.md)** - Best practices voor productie
- **[Dashboard Server Comparison](deployment/DASHBOARD_SERVER_COMPARISON.md)** - Embedded Flask vs Gunicorn
- **[Sensor Deployment](deployment/SENSOR_DEPLOYMENT.md)** - Remote sensor setup
- **[Kiosk Mode Deployment](deployment/KIOSK-DEPLOYMENT.md)** - Kiosk display configuratie
- **[Migration Guide](deployment/MIGRATION_GUIDE.md)** - Upgrade en migratie instructies
- **[Config Migration](deployment/CONFIG_MIGRATION.md)** - Configuratie migratie tussen versies

### ⚡ Features

Feature-specifieke documentatie:

- **[Device Classification](features/DEVICE_CLASSIFICATION.md)** - ML-based apparaat classificatie en alert suppression
- **[Detection Features](features/DETECTION_FEATURES.md)** - Alle threat detection capabilities
- **[Threat Feeds](features/THREAT_FEEDS.md)** - Threat intelligence configuratie
- **[MCP Streamable HTTP Server](../mcp_server/STREAMABLE_HTTP_README.md)** - AI integration via MCP Streamable HTTP
- **[MCP Nginx Setup](features/MCP_NGINX_SETUP.md)** - Reverse proxy voor MCP API

### 🔗 Integrations

SIEM en Threat Intelligence integraties:

- **[Integrations Overview](features/INTEGRATIONS.md)** - SIEM & Threat Intel configuratie overzicht
- **[Wazuh Setup](features/WAZUH_SETUP.md)** - Wazuh SIEM installatie en configuratie
- **[MISP Setup](features/MISP_SETUP.md)** - MISP Threat Intelligence Platform setup

### 🧪 Testing

Test documentatie en procedures:

- **[Test Suite Summary](testing/TEST_SUITE_SUMMARY.md)** - Overzicht van alle tests
- **[Fixes Testing](testing/FIXES_TESTING.md)** - Test procedures voor fixes

### 🏗️ Architecture

Architectuur en best practices:

- **[Architecture Best Practices](architecture/ARCHITECTURE_BEST_PRACTICES.md)** - Production netwerk architectuur
- **[Switch Mirror Configuration](architecture/SWITCH_MIRROR_CONFIGURATION.md)** - Port mirroring setup per vendor

---

## 🔍 Quick Reference

### Common Tasks

| Task | Documentation |
|------|---------------|
| Install from scratch | [Complete Installation](installation/COMPLETE_INSTALLATION.md) |
| Setup remote sensor | [Sensor Deployment](deployment/SENSOR_DEPLOYMENT.md) |
| Configure detection rules | [Config Guide](usage/CONFIG_GUIDE.md) |
| Migrate configuration | [Config Migration](deployment/CONFIG_MIGRATION.md) |
| Device classification setup | [Device Classification](features/DEVICE_CLASSIFICATION.md) |
| Switch to Gunicorn | [Dashboard Server Comparison](deployment/DASHBOARD_SERVER_COMPARISON.md) |
| Setup threat feeds | [Threat Feeds](features/THREAT_FEEDS.md) |
| Configure MCP API | [MCP Streamable HTTP Server](../mcp_server/STREAMABLE_HTTP_README.md) |
| Setup SIEM integration | [Integrations Overview](features/INTEGRATIONS.md) |
| Setup Wazuh | [Wazuh Setup](features/WAZUH_SETUP.md) |
| Setup MISP | [MISP Setup](features/MISP_SETUP.md) |
| Configure switch mirroring | [Switch Mirror Configuration](architecture/SWITCH_MIRROR_CONFIGURATION.md) |
| Production deployment | [Production](deployment/PRODUCTION.md) |
| Troubleshooting | [Admin Manual](usage/ADMIN_MANUAL.md) |

### Configuration Files

| File | Purpose | Documentation |
|------|---------|---------------|
| `.env` | Environment variables | [ENV_CONFIGURATION.md](installation/ENV_CONFIGURATION.md) |
| `config.yaml` | Main configuration | [CONFIG_GUIDE.md](usage/CONFIG_GUIDE.md) |
| `gunicorn_config.py` | Gunicorn settings | [GUNICORN_SETUP.md](installation/GUNICORN_SETUP.md) |
| `services/*.template` | Service templates | [SERVICE_INSTALLATION.md](installation/SERVICE_INSTALLATION.md) |

### Service Management

| Service | Purpose | Documentation |
|---------|---------|---------------|
| `netmonitor.service` | Main monitoring engine | [SERVICE_INSTALLATION.md](installation/SERVICE_INSTALLATION.md) |
| `netmonitor-dashboard.service` | Gunicorn dashboard | [Dashboard Server Comparison](deployment/DASHBOARD_SERVER_COMPARISON.md) |
| `netmonitor-mcp-streamable.service` | MCP Streamable HTTP API | [MCP Streamable HTTP Server](../mcp_server/STREAMABLE_HTTP_README.md) |
| `netmonitor-sensor.service` | Remote sensor | [Sensor Deployment](deployment/SENSOR_DEPLOYMENT.md) |
| `netmonitor-feed-update.service` | Threat feed updates | [Threat Feeds](features/THREAT_FEEDS.md) |

---

## 📖 Documentation Standards

### File Organization

```
docs/
├── INDEX.md                    # This file
├── installation/               # Setup en installatie
├── usage/                      # Gebruikers documentatie
├── deployment/                 # Production deployment
├── features/                   # Feature-specifieke docs
├── testing/                    # Test documentatie
└── architecture/               # Architectuur en design
```

### Document Types

- **Guides** - Step-by-step instructies (INSTALLATION.md, SETUP.md)
- **Manuals** - Complete reference (USER_MANUAL.md, ADMIN_MANUAL.md)
- **Comparisons** - Decision-making docs (DASHBOARD_SERVER_COMPARISON.md)
- **References** - Technical details (DETECTION_FEATURES.md, API docs)

---

## 🆘 Getting Help

### Finding Documentation

1. **Check INDEX.md** (this file) - Quick reference to all docs
2. **README.md** - Project overview and quick start
3. **Search by topic** - Use directory structure
4. **Keyword search** - Grep through markdown files

### Common Documentation Patterns

- **Installation questions** → `docs/installation/`
- **Usage questions** → `docs/usage/`
- **Production deployment** → `docs/deployment/`
- **Feature questions** → `docs/features/`
- **Architecture questions** → `docs/architecture/`

### Still Need Help?

- Check [Admin Manual Troubleshooting](usage/ADMIN_MANUAL.md#troubleshooting)
- Review [GitHub Issues](https://github.com/willempoort/netmonitor/issues)
- Consult archived docs in `archive/` folder

---

## 🗂️ Archive

Historical documents not actively maintained:

- `archive/CLEANUP_PROPOSAL.md` - Completed cleanup proposal (Dec 2024)

---

## 📝 Contributing to Documentation

When adding new documentation:

1. **Place in appropriate directory** based on type
2. **Update INDEX.md** with new document link
3. **Update README.md** if it's a major feature
4. **Use consistent formatting** (see existing docs)
5. **Include examples** where appropriate
6. **Test all commands** before documenting

### Markdown Conventions

- **Headers:** Use `#` for title, `##` for sections, `###` for subsections
- **Code blocks:** Use ` ```bash ` for shell commands, ` ```python ` for Python
- **Links:** Use relative paths: `[text](../other/doc.md)`
- **Emojis:** Use sparingly for visual navigation (✅❌⚠️📖🔧)
- **Tables:** For comparisons and quick reference

---

**Last Updated:** Januari 2026
