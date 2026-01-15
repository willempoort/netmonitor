# Open-WebUI 0.7.2 - NetMonitor MCP Integration

⭐ **AANBEVOLEN VOOR ON-PREMISE DEPLOYMENT**

Complete on-premise oplossing met Docker, Ollama en NetMonitor MCP tools.

## 🚀 Quick Start

```bash
cd /opt/netmonitor/mcp_server/clients/open-webui

# 1. Configureer token
cp .env.example .env
nano .env  # Vul je MCP_AUTH_TOKEN in
nano mcp/config.json  # Vul token ook hier in

# 2. Start
./start.sh

# 3. Open browser
# http://localhost:3000
```

## 📖 Volledige Documentatie

**→ [SETUP.md](./SETUP.md)** - Complete stap-voor-stap guide

Bevat:
- Architectuur diagram
- Docker-compose setup
- MCP configuratie
- Token management
- Troubleshooting
- Health checks
- Security notes

## 🎯 Waarom Open-WebUI?

Na testing van meerdere oplossingen:

| Client | Tool Calling | Production Ready | On-Premise |
|--------|--------------|------------------|------------|
| Claude Desktop | ✅ Perfect | ✅ Yes | ❌ Cloud |
| **Open-WebUI 0.7.2** | ✅ Good | ✅ Yes | ✅ Yes |
| Ollama-MCP-Bridge | ⚠️ Problematic | ❌ No | ✅ Yes |

Zie [../LESSONS_LEARNED.md](../LESSONS_LEARNED.md) voor volledige analyse.

## 📂 Directory Structuur

```
open-webui/
├── README.md              # Dit bestand
├── SETUP.md              # ⭐ Complete setup guide
├── docker-compose.yml    # Docker configuratie
├── start.sh             # Quick start script
├── .env.example         # Environment template
├── .gitignore          # Beschermt secrets
├── mcp/
│   ├── mcp_bridge.py   # Python bridge (proven working)
│   └── config.json     # MCP configuratie
├── data/              # (created by container)
└── archive/           # Oude documenten (referentie)
```

## 🔧 Requirements

- Docker & docker-compose
- Ollama (lokaal draaiend)
- MCP auth token
- 4GB+ RAM aanbevolen

## 🆘 Troubleshooting

Zie [SETUP.md - Troubleshooting sectie](./SETUP.md#-troubleshooting)

Of check:
```bash
docker-compose logs -f
tail -f ~/.mcp_bridge.log
```

## 🔗 Links

- **Setup**: [SETUP.md](./SETUP.md)
- **Ervaringen**: [../LESSONS_LEARNED.md](../LESSONS_LEARNED.md)
- **Diagnostics**: `../../diagnose_mcp_database.py`

---

**Ready to start?** → [SETUP.md](./SETUP.md)
