# NetMonitor Chat - Custom MCP Interface

Simple, reliable web interface for Ollama + NetMonitor MCP Tools. Built after discovering Open-WebUI doesn't support Streamable HTTP MCP servers.

## ✨ Features

- 🎨 **Clean Chat Interface** - ChatGPT-style UI met Alpine.js
- 🤖 **Multiple LLM Providers** - Ollama en LM Studio ondersteuning
- ⚙️ **Configureerbare UI** - MCP en LLM servers via web interface
- 🔧 **Automatic Tool Calling** - Via mcp_bridge.py (proven working)
- ⚡ **Smart Tool Filtering** - Automatische selectie van relevante tools (60 → 10) voor snellere responses
- 📡 **Real-time Streaming** - WebSocket-based responses met incrementele tool calls
- 🛡️ **60 Security Tools** - Volledige NetMonitor MCP tool access
- 🏠 **100% On-Premise** - Geen cloud, volledige privacy
- 🎯 **Debug Mode** - Optioneel tool calls en resultaten tonen (standaard uit)
- 💾 **Persistente Configuratie** - Settings blijven bewaard in browser localStorage
- 🌐 **Meertalig** - Nederlands en Engels keyword matching voor tool filtering

## 🏗️ Architectuur

```
┌─────────────────┐
│  Browser :8000  │  (Alpine.js + Tailwind)
└────────┬────────┘
         │ WebSocket
         ▼
┌─────────────────┐      ┌──────────────────┐
│  FastAPI        │─────▶│  Ollama :11434   │
│  (Python)       │      │  (Host)          │
└────────┬────────┘      └──────────────────┘
         │
         │ Subprocess (STDIO)
         ▼
┌─────────────────┐
│  mcp_bridge.py  │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│  MCP Server     │
│  soc.poort.net  │
└─────────────────┘
```

## 📋 Vereisten

1. **Python 3.11+**
2. **Ollama** (draaiend op localhost:11434)
3. **MCP Server** (toegang tot https://soc.poort.net/mcp)
4. **MCP Auth Token**

## 🚀 Quick Start (Development)

### ⚠️ Mac M1/M2 Users - Python Version

**BELANGRIJK voor Mac gebruikers:**

Als je Python 3.14 hebt, krijg je een build error met pydantic. Gebruik Python 3.13 of 3.12:

```bash
# Check welke Python versies je hebt
which -a python3.12 python3.13

# Maak venv met Python 3.13 (aanbevolen)
python3.13 -m venv venv

# Of met Python 3.12
python3.12 -m venv venv
```

**Als je tóch Python 3.14 wilt gebruiken:**
```bash
# Gebruik alternatieve requirements
pip install -r requirements-py314.txt

# Of force build met compatibility flag
PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 pip install -r requirements.txt
```

### Stap 1: Installeer Dependencies

```bash
cd /home/user/netmonitor/mcp_server/clients/netmonitor-chat

# Maak virtual environment
python3 -m venv venv

# Activeer venv
source venv/bin/activate  # Linux/Mac
# of
venv\Scripts\activate     # Windows

# Installeer packages
pip install -r requirements.txt
```

### Stap 2: Configureer Environment

```bash
# Maak .env file
cat > .env << 'EOF'
# Ollama API
OLLAMA_BASE_URL=http://localhost:11434

# MCP Server
MCP_SERVER_URL=https://soc.poort.net/mcp
MCP_AUTH_TOKEN=your_token_here
EOF

# Set permissions
chmod 600 .env
```

**Token verkrijgen:**
```bash
cd /home/user/netmonitor
python3 mcp_server/manage_tokens.py create \
  --name "NetMonitor Chat" \
  --scope read_only \
  --rate-minute 120
```

### Stap 3: Start Ollama of LM Studio

**Optie A: Ollama (aanbevolen)**

```bash
# Check of Ollama draait
ollama list

# Als niet, start Ollama
ollama serve &

# Pull een model (kies één)
ollama pull llama3.1:8b          # Aanbevolen: goede tool calling
ollama pull qwen2.5-coder:14b    # Best: excellente tool support
ollama pull mistral:7b-instruct  # Snelst: basic tool calling
```

**Optie B: LM Studio (sneller op Mac M1/M2/M3)**

1. Download en installeer [LM Studio](https://lmstudio.ai/)
2. Download een model (aanbevolen: Qwen 2.5 Coder 14B Instruct)
3. Start de Local Server in LM Studio:
   - Klik "Local Server" tab
   - Selecteer een model
   - Klik "Start Server" (default poort: 1234)
4. In de NetMonitor Chat web UI:
   - Klik op "⚙️ Server Configuratie"
   - Selecteer "LM Studio" als provider
   - Controleer URL: `http://localhost:1234`
   - **Vink "Force Tools" aan** (nodig voor function calling in LM Studio)
   - (Optioneel) Voeg System Prompt toe voor context
   - Klik "Configuratie Toepassen"

**💡 Tip**: LM Studio is vaak 2-3x sneller dan Ollama op Apple Silicon dankzij Metal optimalisatie!

**⚠️ Belangrijk**: Zonder "Force Tools" zal LM Studio geen tools aanroepen. Deze optie forceert function calling support.

### Stap 4: Start de Interface

```bash
# Vanuit netmonitor-chat directory
python3 app.py
```

**Output:**
```
======================================================================
NetMonitor Chat Starting
======================================================================
Ollama: http://localhost:11434
MCP Server: https://soc.poort.net/mcp
MCP Bridge: /home/user/netmonitor/mcp_server/clients/ollama-mcp-bridge/mcp_bridge.py
Interface: http://localhost:8000
======================================================================
INFO:     Started server process [12345]
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### Stap 5: Open de Interface

Open browser: **http://localhost:8000**

1. **Selecteer Model** - bijv. `llama3.1:8b`
2. **Stel Temperature in** - 0.3 aanbevolen (balans tussen precisie en creativiteit)
3. **Type een vraag** - bijv. "Laat recente bedreigingen zien"

## 🧪 Testen

### Test 1: Check Health

Open http://localhost:8000/api/health

**Verwacht:**
```json
{
  "status": "healthy",
  "ollama": "connected",
  "mcp": "connected",
  "timestamp": "2026-01-15T..."
}
```

### Test 2: List Tools

Open http://localhost:8000/api/tools

**Verwacht:**
```json
{
  "tools": [
    {"name": "get_threat_detections", ...},
    {"name": "analyze_ip", ...},
    ...
  ],
  "count": 60
}
```

### Test 3: Chat with Tools

In de web interface:

**Vraag:** "Laat recente bedreigingen zien"

**Verwacht:**
- 🔧 Tool call: `get_threat_detections({"limit": 5})`
- ✓ Tool result: JSON met echte alerts
- 💬 Assistant: Samenvatting van bedreigingen met ECHTE 10.100.0.x IPs

**GEEN** verzonnen 192.168.1.x IPs! ✅

## 🎨 UI Features

### Status Indicators (Header)
- **LLM Provider**: Toont "Ollama" of "LM Studio" (dynamisch)
- **Status**: Groen = verbonden, Rood = disconnected
- **MCP**: Groen = verbonden, Rood = disconnected
- **Tools count**: Aantal beschikbare MCP tools (60 totaal, 10-15 per request)

### Sidebar Controls
- **Model selectie**: Dropdown met alle beschikbare models (Ollama of LM Studio)
- **Temperature slider**: 0.0 (precies) tot 1.0 (creatief)
- **⚙️ Server Configuratie** (uitklapbaar):
  - **LLM Provider**: Keuze tussen Ollama of LM Studio
  - **Ollama URL**: Configureerbaar endpoint (default: http://localhost:11434)
  - **LM Studio URL**: Configureerbaar endpoint (default: http://localhost:1234)
  - **Force Tools**: ✅ Verplicht voor LM Studio function calling (vink aan!)
  - **System Prompt**: (Optioneel) Custom system instructies voor het model
  - **MCP Server URL**: Configureerbaar MCP endpoint
  - **MCP Auth Token**: API token voor MCP server
  - **Configuratie Toepassen**: Herlaadt models en tools met nieuwe settings
- **Beschikbare Tools** (klik om uit te klappen): Volledige lijst met alle MCP tools + beschrijvingen
- **Debug Mode**: Toggle om tool calls en resultaten te tonen/verbergen (standaard uit)
- **Wis chat**: Reset conversatie

> **💡 Tip**: Alle configuratie wordt automatisch opgeslagen in browser localStorage, dus settings blijven bewaard bij pagina refresh!

### Chat Messages
- **User messages**: Blauw, rechts uitgelijnd
- **Assistant messages**: Grijs, links uitgelijnd
- **Tool calls**: Geel met oranje border (🔧 icoon)
- **Tool results**: Blauw met blauwe border (✓ icoon)
- **Typing indicator**: Animerende dots tijdens response

### Input Area
- **Text input**: Auto-focus, disabled tijdens typing
- **Verstuur button**: Disabled als geen model geselecteerd
- **Validation**: Kan niet versturen zonder model

## 🔧 Troubleshooting

### Interface laadt niet

```bash
# Check of Python app draait
ps aux | grep app.py

# Check logs
tail -f app.log  # (als je logging toevoegt)

# Check of port 8000 vrij is
lsof -i :8000
```

### Ollama niet bereikbaar

**Symptom:** Status indicator rood voor Ollama

```bash
# Check of Ollama draait
curl http://localhost:11434/api/tags

# Als niet, start Ollama
ollama serve &

# Test vanuit Python
python3 -c "import httpx; print(httpx.get('http://localhost:11434/api/tags').json())"
```

### MCP Tools werken niet

**Symptom:** Status indicator rood voor MCP, of tools lijst leeg

```bash
# Test MCP bridge direct
cd /home/user/netmonitor/mcp_server/clients/ollama-mcp-bridge

export MCP_SERVER_URL="https://soc.poort.net/mcp"
export MCP_AUTH_TOKEN="your_token_here"

echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 mcp_bridge.py
```

**Verwacht:** JSON met 60 tools

Als dit werkt maar UI niet → check environment variables in .env

### Model roept tools niet aan

**Symptom:** Assistant beschrijft tools maar roept ze niet aan

**Fixes:**
1. **LM Studio**: Vink "Force Tools" aan in Server Configuratie (essentieel!)
2. **Verlaag temperature** naar 0.0 (meest deterministisch)
3. **Wissel model**: probeer `qwen2.5-coder:14b` (beste tool calling)
4. **Check tool output**: Kijk of tool calls verschijnen in de chat (gele blokken)
5. **Check logs**: Terminal toont `[WebSocket] LM Studio with FORCED tools enabled (10 tools)`

### LM Studio geeft 400 errors

**Symptom:** Console/logs tonen "Invalid 'messages' in payload" of "tokens greater than max"

**Fixes:**
1. **Context size**: Model heeft 32K limit, smart filtering reduceert dit automatisch
2. **Check model**: Zorg dat model function calling ondersteunt (Qwen 2.5, Llama 3.1+)
3. **Terminal logs**: Check `[Tool Filter]` output om te zien welke tools geselecteerd zijn
4. **Force Tools**: Moet aangevinkt zijn voor function calling

### Settings verdwijnen bij refresh

**Symptom:** Na pagina refresh moet je alles opnieuw configureren

**Fix:** Dit is opgelost! Settings worden nu automatisch opgeslagen in localStorage. Als het tóch gebeurt:
1. Check browser console voor localStorage errors
2. Check of browser localStorage niet geblokkeerd is (private mode)
3. Clear cache en probeer opnieuw

### WebSocket errors in console

**Symptom:** Console toont "WebSocket connection failed"

```bash
# Check of FastAPI WebSocket endpoint werkt
python3 << 'EOF'
import asyncio
import websockets
import json

async def test():
    async with websockets.connect('ws://localhost:8000/ws/chat') as ws:
        await ws.send(json.dumps({
            "model": "llama3.1:8b",
            "message": "test",
            "history": []
        }))
        response = await ws.recv()
        print(response)

asyncio.run(test())
EOF
```

## 📦 Productie Deployment (Docker) - TODO

```bash
# Build image
docker build -t netmonitor-chat .

# Run container
docker run -d \
  -p 8000:8000 \
  -e MCP_SERVER_URL=https://soc.poort.net/mcp \
  -e MCP_AUTH_TOKEN=your_token_here \
  --add-host host.docker.internal:host-gateway \
  --name netmonitor-chat \
  netmonitor-chat

# Of via docker-compose
docker-compose up -d
```

*(Dockerfile en docker-compose.yml worden nog toegevoegd)*

## 🔐 Security

### Token Beveiliging
- Tokens in `.env` (niet in git)
- `.env` is in `.gitignore`
- Set permissions: `chmod 600 .env`

### HTTPS (Productie)
Voor productie gebruik, zet een reverse proxy voor FastAPI:

```nginx
# nginx config
server {
    listen 443 ssl;
    server_name chat.example.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 🎯 Performance Tips

### Smart Tool Filtering

NetMonitor Chat gebruikt intelligente tool filtering om context size te reduceren en responses te versnellen:

- **Automatisch**: Selecteert alleen relevante tools per vraag (60 → 10 tools)
- **Keyword Matching**: Nederlands + Engels support
  - "Toon actieve sensors" → matcht `get_sensor_status`, `get_devices`, etc.
  - "Show recent threats" → matcht `get_threat_detections`, `get_recent_alerts`, etc.
- **Performance**: 6x minder context = 2-3x snellere responses
- **Ollama**: Max 15 tools per request
- **LM Studio**: Max 10 tools per request (32K context limit)

**Debug Tip**: Bekijk de terminal logs om te zien welke tools geselecteerd worden:
```
[Tool Filter] Top 10 scores:
  1. get_sensor_status: 31 points
  2. get_device_learning_status: 26 points
  ...
```

### Model Selectie
- **qwen2.5-coder:14b**: Beste tool calling, trager (~5-10s)
- **llama3.1:8b**: Goede balans (~3-5s)
- **mistral:7b-instruct**: Snelst (~2-3s), zwakkere tools

**LM Studio op Mac**: Vaak 2-3x sneller door Metal GPU optimalisatie!

### Temperature Settings
- **0.0**: Deterministisch, geen hallucinaties (aanbevolen)
- **0.3**: Balans tussen creativiteit en precisie (default)
- **0.7**: Creatief, meer kans op hallucinaties

### Browser Performance
- Chat history wordt begrensd tot laatste 10 messages
- WebSocket streaming voorkomt memory leaks
- Alpine.js is zeer lichtgewicht (~15KB)
- localStorage voor configuratie persistentie

## 📊 API Endpoints

### REST Endpoints

**GET /api/models**
```json
{
  "models": [
    {"name": "llama3.1:8b", "size": "4.7GB", ...},
    {"name": "qwen2.5-coder:14b", "size": "9.0GB", ...}
  ]
}
```

**GET /api/tools**
```json
{
  "tools": [
    {"name": "get_threat_detections", "description": "...", "inputSchema": {...}},
    ...
  ],
  "count": 60
}
```

**GET /api/health**
```json
{
  "status": "healthy",
  "ollama": "connected",
  "mcp": "connected",
  "timestamp": "2026-01-15T12:00:00"
}
```

### WebSocket Endpoint

**WS /ws/chat**

**Send:**
```json
{
  "model": "llama3.1:8b",
  "message": "Laat recente bedreigingen zien",
  "history": [...],
  "temperature": 0.3,
  "llm_provider": "ollama",
  "llm_url": "http://localhost:11434",
  "mcp_url": "https://soc.poort.net/mcp",
  "mcp_token": "your_token_here",
  "force_tools_lmstudio": false,
  "system_prompt": ""
}
```

**Parameters:**
- `model`: Model naam (bijv. "llama3.1:8b", "qwen2.5-coder-14b-instruct-mlx:2")
- `message`: User vraag
- `history`: Array van eerdere messages
- `temperature`: 0.0-1.0 (default: 0.3)
- `llm_provider`: "ollama" of "lmstudio" (default: "ollama")
- `llm_url`: LLM endpoint URL
- `mcp_url`: MCP server URL
- `mcp_token`: MCP authenticatie token
- `force_tools_lmstudio`: boolean - Forceer function calling voor LM Studio (default: false)
- `system_prompt`: (Optioneel) Custom system instructies

**Receive:**
```json
{"type": "token", "content": "Ik "}
{"type": "token", "content": "zal "}
{"type": "tool_call", "tool": "get_threat_detections", "args": {"limit": 5}}
{"type": "tool_result", "tool": "get_threat_detections", "result": {...}}
{"type": "token", "content": "Er zijn "}
{"type": "done"}
```

**Message Types:**
- `token`: Streaming text content
- `tool_call`: Tool wordt aangeroepen met args
- `tool_result`: Resultaat van tool execution
- `done`: Stream is compleet
- `error`: Fout opgetreden

## 🆚 Vergelijking met Andere Oplossingen

| Feature | NetMonitor-Chat | Open-WebUI 0.7.2 | Ollama-MCP-Bridge |
|---------|----------------|------------------|-------------------|
| StreamableHTTP MCP | ✅ Yes | ❌ No (STDIO only) | ✅ Yes |
| Tool calling | ✅ Excellent | ✅ Good | ⚠️ Problematic |
| LM Studio support | ✅ Full (w/ tools) | ✅ Basic | ❌ No |
| Smart tool filtering | ✅ Yes (auto) | ❌ No | ❌ No |
| Setup complexity | Easy (venv) | Medium (Docker) | Hard + Debugging |
| Customizable | ✅ 100% | Limited | Limited |
| Production ready | ✅ Yes (after Docker) | ✅ Yes | ❌ No |
| UI/UX | Simple & Clean | Feature-rich | Basic |
| Settings persistence | ✅ localStorage | ✅ Database | ❌ None |
| Multi-language | ✅ NL + EN | ✅ Multi | ❌ EN only |

## 🔮 Roadmap

**Voltooid** ✅
- [x] FastAPI backend met Ollama integration
- [x] Alpine.js frontend met real-time streaming
- [x] Tool calling via mcp_bridge.py
- [x] WebSocket streaming responses
- [x] LM Studio ondersteuning met OpenAI-compatible API
- [x] Configureerbare LLM en MCP servers via UI
- [x] Debug mode toggle voor tool visibility (standaard uit)
- [x] Uitklapbare tools lijst
- [x] localStorage persistentie voor settings
- [x] Force Tools optie voor LM Studio function calling
- [x] System Prompt configuratie
- [x] Smart tool filtering (60 → 10 tools) voor performance
- [x] Nederlands + Engels keyword matching
- [x] Incremental streaming tool calls voor LM Studio
- [x] Dynamic status indicator (Ollama/LM Studio)

**Todo** 📋
- [ ] Dockerfile voor productie deployment
- [ ] docker-compose.yml voor easy setup
- [ ] User authentication (optioneel)
- [ ] Chat history persistence (database)
- [ ] Multi-user support
- [ ] Model comparison mode (side-by-side)
- [ ] Export chat transcripts (JSON/Markdown)
- [ ] RAG integration voor document search
- [ ] Token usage tracking en statistics

## 🐛 Known Issues

Geen bekende issues op dit moment. Als je problemen tegenkomt:

1. Check troubleshooting sectie
2. Test componenten apart (Ollama, MCP, bridge)
3. Check logs in terminal waar je `python3 app.py` draait

## 📚 Credits

- **MCP Protocol**: Model Context Protocol by Anthropic
- **Ollama**: Local LLM runtime
- **FastAPI**: Modern Python web framework
- **Alpine.js**: Lightweight reactive framework
- **Tailwind CSS**: Utility-first CSS framework

## 📄 License

Same as NetMonitor project: AGPL-3.0-only

---

**Built with ❤️ after extensive testing showed Open-WebUI doesn't support StreamableHTTP MCP.**

Voor meer info, zie [LESSONS_LEARNED.md](../LESSONS_LEARNED.md)
