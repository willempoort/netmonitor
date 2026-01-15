# Open-WebUI 0.7.2 met NetMonitor MCP Setup

Complete on-premise oplossing met Ollama + Open-WebUI + NetMonitor MCP Tools.

## 📋 Architectuur

```
┌─────────────────┐
│  Browser :3000  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│  Open-WebUI     │─────▶│  Ollama :11434   │
│  (Container)    │      │  (Host)          │
└────────┬────────┘      └──────────────────┘
         │
         │ MCP Bridge
         ▼
┌─────────────────┐
│  mcp_bridge.py  │
│  (in container) │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│  MCP Server     │
│  soc.poort.net  │
└─────────────────┘
```

## 🚀 Stap 1: Zorg dat Ollama Draait

```bash
# Check of Ollama draait
ollama list

# Als niet, start Ollama
ollama serve &

# Pull een model (kies één)
ollama pull llama3.1:8b          # Goed function calling
ollama pull qwen2.5-coder:14b    # Beste voor tools
ollama pull mistral:7b-instruct  # Lichtgewicht
```

## 📂 Stap 2: Directory Structuur

De huidige directory structuur is:

```
/opt/netmonitor/mcp_server/clients/open-webui/
├── docker-compose.yml          # Docker configuratie
├── mcp/
│   ├── mcp_bridge.py          # Python bridge naar MCP server
│   └── config.json            # MCP server configuratie
└── data/                      # (wordt aangemaakt door container)
    └── ...                    # Open-WebUI data
```

**Locatie van mcp_bridge.py**:
- **Op host**: `/opt/netmonitor/mcp_server/clients/open-webui/mcp/mcp_bridge.py`
- **In container**: `/app/mcp/mcp_bridge.py` (via volume mount)

## 🔧 Stap 3: Start Open-WebUI

```bash
cd /opt/netmonitor/mcp_server/clients/open-webui

# Start de container
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop met Ctrl+C als logs ok zijn
```

**Verwachte log output**:
```
open-webui-mcp  | INFO:     Started server process
open-webui-mcp  | INFO:     Waiting for application startup.
open-webui-mcp  | INFO:     Application startup complete.
open-webui-mcp  | INFO:     Uvicorn running on http://0.0.0.0:8080
```

## 🌐 Stap 4: Open de WebUI

Open in je browser: **http://localhost:3000**

### Eerste Keer Setup

1. **Maak admin account**:
   - Email: `admin@localhost`
   - Password: (kies een veilig wachtwoord)
   - Naam: `Admin`

2. **Configureer Ollama**:
   - Ga naar: **Settings** (tandwiel rechtsbovenin)
   - **Connections** → **Ollama**
   - Base URL: `http://host.docker.internal:11434`
   - Klik **Verify connection**
   - Zou groen moeten worden ✅

## 🔌 Stap 5: Configureer MCP Server

### Via Web Interface:

1. Ga naar **Settings** → **Admin Settings** → **MCP**
2. Enable MCP: **ON**
3. Klik **Add MCP Server**

**Server configuratie**:
```json
{
  "name": "netmonitor",
  "command": "python3",
  "args": ["/app/mcp/mcp_bridge.py"],
  "env": {
    "MCP_SERVER_URL": "https://soc.poort.net/mcp",
    "MCP_AUTH_TOKEN": "725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f"
  }
}
```

4. Klik **Test Connection**
5. Als succesvol, klik **Save**

### Via Config File (Alternatief):

De configuratie staat al in `mcp/config.json`. Open-WebUI leest dit automatisch.

## ✅ Stap 6: Test de Setup

### Test 1: Check Tools

In een nieuwe chat, type:
```
Welke tools heb je beschikbaar?
```

**Verwacht**: Lijst van 60+ NetMonitor tools

### Test 2: Get Recent Threats

```
Laat recente bedreigingen zien
```

**Verwacht**:
```
Er zijn 5 bedreigingen gevonden:

1. CRITICAL - HIGH_RISK_ATTACK_CHAIN
   Source: 10.100.0.4 → Destination: 199.45.154.159

2. HIGH - BEACONING_DETECTED
   Source: 10.100.0.4 → Destination: 92.111.124.154
   ...
```

**Geen** verzonnen 192.168.1.x IPs! ✅

### Test 3: Analyze IP

```
Analyseer IP 10.100.0.4
```

**Verwacht**: Echte data van jouw netwerk

## 🔍 Troubleshooting

### Container start niet

```bash
# Check logs
docker-compose logs

# Check of poort 3000 vrij is
lsof -i :3000

# Herstart
docker-compose restart
```

### Ollama niet bereikbaar

```bash
# Check of Ollama draait
curl http://localhost:11434/api/tags

# Als niet, start Ollama
ollama serve &

# In docker-compose.yml, check extra_hosts:
#   - "host.docker.internal:host-gateway"
```

### MCP Bridge werkt niet

```bash
# Test bridge direct (buiten container)
cd /opt/netmonitor/mcp_server/clients/open-webui/mcp

export MCP_SERVER_URL="https://soc.poort.net/mcp"
export MCP_AUTH_TOKEN="725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f"

echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 mcp_bridge.py
```

**Verwacht**: JSON met lijst van tools

### MCP Tools niet zichtbaar

1. **Check MCP Status** in Open-WebUI:
   - Settings → Admin Settings → MCP
   - Status moet **Connected** zijn ✅

2. **Check Bridge Logs**:
   ```bash
   tail -f ~/.mcp_bridge.log
   ```

3. **Herstart Container**:
   ```bash
   docker-compose restart
   ```

### Model roept tools niet aan

Als het model tools beschrijft maar niet aanroept:

**Probeer een ander model**:
```bash
# In Open-WebUI chat interface, wissel model:
ollama pull qwen2.5-coder:14b  # Beste voor function calling
```

**Of verlaag temperature**:
- Settings → Model Settings → Temperature: `0.0`

## 📊 Health Checks

```bash
# Check of container draait
docker ps | grep open-webui

# Check health status
docker inspect open-webui-mcp | grep -A 5 Health

# Check logs
docker-compose logs --tail=50 -f

# Test API endpoint
curl http://localhost:3000/health
```

## 🔒 Security Notes

**Token in docker-compose.yml**:
- De MCP_AUTH_TOKEN staat in plaintext
- Voor productie: gebruik Docker secrets of .env file
- De token is alleen leesbaar door root

**Alternatief met .env file**:

1. Maak `.env`:
   ```bash
   MCP_AUTH_TOKEN=725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f
   ```

2. In docker-compose.yml:
   ```yaml
   environment:
     - MCP_AUTH_TOKEN=${MCP_AUTH_TOKEN}
   ```

3. Set permissions:
   ```bash
   chmod 600 .env
   ```

## 🔄 Updates & Maintenance

### Update Open-WebUI

```bash
# Pull nieuwste image
docker-compose pull

# Recreate container
docker-compose up -d

# Data blijft behouden in ./data volume
```

### Backup

```bash
# Backup data directory
tar -czf open-webui-backup-$(date +%Y%m%d).tar.gz data/

# Restore
tar -xzf open-webui-backup-YYYYMMDD.tar.gz
```

## 🎯 Performance Tips

1. **Model Selectie**:
   - `qwen2.5-coder:14b` - Beste tool calling, trager
   - `llama3.1:8b` - Goede balans
   - `mistral:7b-instruct` - Snelst, zwakkere tools

2. **Temperature**:
   - `0.0` = Deterministisch, geen hallucinaties
   - `0.3` = Balans tussen creativiteit en precisie
   - `0.7` = Creatief maar kan hallucineren

3. **Resources**:
   ```yaml
   # In docker-compose.yml, voeg toe:
   deploy:
     resources:
       limits:
         memory: 4G
         cpus: '2'
   ```

## 📚 Nuttige Links

- Open-WebUI Docs: https://docs.openwebui.com/
- MCP Protocol: https://spec.modelcontextprotocol.io/
- Ollama Models: https://ollama.com/library

## 🆘 Support

**Als Open-WebUI ook niet werkt**:
- Probeer jonigl/mcp-client-for-ollama (TUI)
- Of vraag me een custom minimale interface te bouwen
- Claude Desktop is altijd de fallback (werkt 100%)

---

**Succes!** Open-WebUI 0.7.2 zou veel stabieler moeten zijn dan Ollama-MCP-Bridge-WebUI. 🚀
