# NetMonitor Chat - Custom MCP Interface

Simple, reliable web interface for Ollama + NetMonitor MCP Tools. Built after discovering Open-WebUI doesn't support Streamable HTTP MCP servers.

## ✨ Features

- 🎨 **Clean Chat Interface** - ChatGPT-style UI met Alpine.js
- 🤖 **Any Ollama Model** - llama3.1, qwen2.5-coder, mistral, etc.
- 🔧 **Automatic Tool Calling** - Via mcp_bridge.py (proven working)
- 📡 **Real-time Streaming** - WebSocket-based responses
- 🛡️ **60 Security Tools** - Volledige NetMonitor MCP tool access
- 🏠 **100% On-Premise** - Geen cloud, volledige privacy

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

### Stap 3: Start Ollama

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
- **Ollama**: Groen = verbonden, Rood = disconnected
- **MCP**: Groen = verbonden, Rood = disconnected
- **Tools count**: Aantal beschikbare MCP tools

### Sidebar Controls
- **Model selectie**: Dropdown met alle beschikbare Ollama models
- **Temperature slider**: 0.0 (precies) tot 1.0 (creatief)
- **Available tools**: Preview van eerste 10 tools
- **Wis chat**: Reset conversatie

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
1. **Verlaag temperature** naar 0.0 (meest deterministisch)
2. **Wissel model**: probeer `qwen2.5-coder:14b` (beste tool calling)
3. **Check tool output**: Kijk of tool calls verschijnen in de chat (gele blokken)

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

### Model Selectie
- **qwen2.5-coder:14b**: Beste tool calling, trager (~5-10s)
- **llama3.1:8b**: Goede balans (~3-5s)
- **mistral:7b-instruct**: Snelst (~2-3s), zwakkere tools

### Temperature Settings
- **0.0**: Deterministisch, geen hallucinaties (aanbevolen)
- **0.3**: Balans tussen creativiteit en precisie (default)
- **0.7**: Creatief, meer kans op hallucinaties

### Browser Performance
- Chat history wordt begrensd tot laatste 10 messages
- WebSocket streaming voorkomt memory leaks
- Alpine.js is zeer lichtgewicht (~15KB)

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
  "temperature": 0.3
}
```

**Receive:**
```json
{"type": "token", "content": "Ik "}
{"type": "token", "content": "zal "}
{"type": "tool_call", "tool": "get_threat_detections", "args": {"limit": 5}}
{"type": "tool_result", "tool": "get_threat_detections", "result": {...}}
{"type": "token", "content": "Er zijn "}
{"type": "done"}
```

## 🆚 Vergelijking met Andere Oplossingen

| Feature | NetMonitor-Chat | Open-WebUI 0.7.2 | Ollama-MCP-Bridge |
|---------|----------------|------------------|-------------------|
| StreamableHTTP MCP | ✅ Yes | ❌ No (STDIO only) | ✅ Yes |
| Tool calling | ✅ Reliable | ✅ Good | ⚠️ Problematic |
| Setup complexity | Easy (venv) | Medium (Docker) | Hard + Debugging |
| Customizable | ✅ 100% | Limited | Limited |
| Production ready | ✅ Yes (after Docker) | ✅ Yes | ❌ No |
| UI/UX | Simple & Clean | Feature-rich | Basic |

## 🔮 Roadmap

- [x] FastAPI backend met Ollama integration
- [x] Alpine.js frontend met real-time streaming
- [x] Tool calling via mcp_bridge.py
- [x] WebSocket streaming responses
- [ ] Dockerfile voor productie deployment
- [ ] docker-compose.yml voor easy setup
- [ ] User authentication (optioneel)
- [ ] Chat history persistence
- [ ] Multi-user support
- [ ] Model comparison mode
- [ ] Export chat transcripts

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
