# MCP Server Installatie Instructies

## ✅ Wat is al klaar

De MCP server is volledig geïmplementeerd en klaar voor gebruik:

1. ✅ Read-only database user (`mcp_readonly`)
2. ✅ MCP server code (server.py, database_client.py)
3. ✅ Dependencies geïnstalleerd
4. ✅ 3 Tools geïmplementeerd:
   - `analyze_ip`
   - `get_recent_threats`
   - `get_threat_timeline`
5. ✅ 1 Resource geïmplementeerd:
   - `dashboard://summary`

## 🚀 Stap 1: Installeer Claude Desktop (als nog niet gedaan)

### macOS
Download van: https://claude.ai/download

### Linux
Download van: https://claude.ai/download

## 🔧 Stap 2: Configureer Claude Desktop

### macOS

1. **Open de config file:**
```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

2. **Voeg de MCP server configuratie toe:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "python3",
      "args": [
        "/home/user/netmonitor/mcp_server/server.py"
      ],
      "env": {
        "NETMONITOR_DB_HOST": "localhost",
        "NETMONITOR_DB_PORT": "5432",
        "NETMONITOR_DB_NAME": "netmonitor",
        "NETMONITOR_DB_USER": "mcp_readonly",
        "NETMONITOR_DB_PASSWORD": "mcp_netmonitor_readonly_2024"
      }
    }
  }
}
```

3. **Sla op en sluit**

### Linux

1. **Maak de config directory aan (als die nog niet bestaat):**
```bash
mkdir -p ~/.config/Claude
```

2. **Open/maak de config file:**
```bash
nano ~/.config/Claude/claude_desktop_config.json
```

3. **Voeg dezelfde configuratie toe als hierboven**

4. **Sla op en sluit**

## 🔄 Stap 3: Herstart Claude Desktop

Sluit Claude Desktop volledig af en start opnieuw op.

## ✅ Stap 4: Verificatie

### Test 1: Check of MCP server geladen is

Open Claude Desktop en typ:
```
What MCP servers are available?
```

Je zou "netmonitor-soc" moeten zien in de lijst.

### Test 2: Test de dashboard resource

```
Show me the dashboard summary
```

Claude zou de dashboard resource moeten kunnen lezen en security statistics tonen.

### Test 3: Test een tool

```
Get recent threats from the last hour
```

Claude zou de `get_recent_threats` tool moeten aanroepen en resultaten tonen.

### Test 4: Uitgebreide analyse

```
Analyze IP 192.168.1.50 and show me what you find
```

Claude zou de `analyze_ip` tool moeten gebruiken en gedetailleerde analyse geven.

## 🐛 Troubleshooting

### Probleem: Claude Desktop toont de MCP server niet

**Oplossing:**
1. Check of de config file op de juiste locatie staat
2. Check of het JSON formaat correct is (geen syntax errors)
3. Check de MCP server logs:
```bash
tail -f /tmp/mcp_netmonitor.log
```

### Probleem: Database connectie errors

**Test de database connectie:**
```bash
PGPASSWORD='mcp_netmonitor_readonly_2024' \
  psql -h localhost -U mcp_readonly -d netmonitor -c 'SELECT COUNT(*) FROM alerts;'
```

**Als dat werkt maar MCP niet:**
- Check of PostgreSQL luistert op localhost:5432
- Check firewall settings
- Check of de database service draait

### Probleem: Permission errors

**Voor de MCP server:**
```bash
chmod +x /home/user/netmonitor/mcp_server/server.py
```

**Voor de database user:**
```bash
# Run setup script opnieuw
/home/user/netmonitor/setup_mcp_user.sh
```

### Probleem: Python import errors

**Check of dependencies geïnstalleerd zijn:**
```bash
pip3 list | grep mcp
pip3 list | grep psycopg2
```

**Herinstalleer indien nodig:**
```bash
cd /home/user/netmonitor/mcp_server
pip3 install -r requirements.txt --user
```

## 📋 Snelle Test Script

Maak een test script om de MCP server handmatig te testen:

```bash
#!/bin/bash
# test_mcp.sh

cd /home/user/netmonitor/mcp_server

export NETMONITOR_DB_HOST=localhost
export NETMONITOR_DB_PORT=5432
export NETMONITOR_DB_NAME=netmonitor
export NETMONITOR_DB_USER=mcp_readonly
export NETMONITOR_DB_PASSWORD=mcp_netmonitor_readonly_2024

echo "Testing MCP server..."
python3 server.py
```

Run met:
```bash
chmod +x test_mcp.sh
./test_mcp.sh
```

Als de server start zonder errors, werkt de basis setup.

## 🎯 Volgende Stappen

Na succesvolle installatie kun je:

1. **Test de use cases uit README.md**
2. **Experimenteer met verschillende queries**
3. **Check de security analytics capabilities**
4. **Geef feedback voor verbeteringen**

## 📞 Support

Als je problemen hebt:

1. Check de logs: `/tmp/mcp_netmonitor.log`
2. Check de README.md voor gebruik voorbeelden
3. Test de database connectie handmatig
4. Verify de Claude Desktop config file syntax

## 🔐 Security Notities

- MCP server heeft alleen read-only toegang
- Database user `mcp_readonly` kan GEEN data wijzigen
- Alle queries worden gelogd
- Server draait lokaal (niet remote accessible)

## ✨ Geniet van je AI-powered SOC!

Je hebt nu een AI assistant met directe toegang tot je security data. Stel vragen, onderzoek threats, en laat de AI patterns vinden die je anders zou missen!
