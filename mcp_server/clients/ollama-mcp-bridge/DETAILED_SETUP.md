# Ollama-MCP-Bridge-WebUI Setup voor NetMonitor

Deze guide installeert de Ollama-MCP-Bridge-WebUI op je laptop om qwen2.5:14b te koppelen aan de NetMonitor MCP server.

## Architectuur

```
[WebUI :8080] <--> [Ollama-MCP-Bridge] <--> [Python STDIO Bridge] <--> [HTTPS] <--> [NetMonitor MCP Server :8000]
                         (localhost)               (localhost)                              (soc.poort.net)
```

## Stap 1: Installeer Dependencies (op je laptop)

```bash
# Node.js en npm (als je die nog niet hebt)
# Op macOS:
brew install node

# Op Ubuntu/Debian:
sudo apt-get update && sudo apt-get install -y nodejs npm

# Download de bridge code
cd ~/Downloads
git clone https://github.com/Rkm1999/Ollama-MCP-Bridge-WebUI.git
cd Ollama-MCP-Bridge-WebUI

# Installeer npm packages
npm install

# Build het TypeScript project
npm run build
```

## Stap 2: Download de Python STDIO Bridge

Download de bridge van de server naar je laptop:

```bash
# Van de server
scp root@soc.poort.net:/opt/netmonitor/mcp_server/mcp_streamable_http_bridge.py ~/Downloads/Ollama-MCP-Bridge-WebUI/
```

Of maak lokaal `mcp_bridge.py` met deze content: (zie hieronder)

## Stap 3: Configureer de Bridge

Maak `bridge_config.json`:

```json
{
  "mcpServers": {
    "netmonitor": {
      "command": "python3",
      "args": [
        "./mcp_streamable_http_bridge.py"
      ],
      "env": {
        "MCP_SERVER_URL": "https://soc.poort.net/mcp",
        "MCP_AUTH_TOKEN": "YOUR_TOKEN_HERE"
      }
    }
  },
  "llm": {
    "model": "qwen2.5:14b",
    "baseUrl": "http://localhost:11434",
    "apiKey": "ollama",
    "temperature": 0.7,
    "maxTokens": 8000
  },
  "systemPrompt": "You are a cybersecurity assistant with access to NetMonitor SOC tools. You can analyze threats, check IPs, monitor sensors, and investigate security incidents. Use the NetMonitor tools when users ask about security, threats, IPs, devices, or network monitoring."
}
```

**Vervang `YOUR_TOKEN_HERE` met je MCP token:**
- Token: `725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f`

## Stap 4: Maak een Start Script

Maak `start.sh`:

```bash
#!/bin/bash
# Start Ollama-MCP-Bridge-WebUI

echo "Starting Ollama-MCP-Bridge-WebUI for NetMonitor..."
echo "WebUI will be available at: http://localhost:8080"
echo ""

# Zorg dat Ollama draait
if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama..."
    ollama serve &
    sleep 2
fi

# Check of qwen2.5:14b beschikbaar is
if ! ollama list | grep -q "qwen2.5:14b"; then
    echo "Model qwen2.5:14b not found!"
    echo "Your available models:"
    ollama list
    echo ""
    echo "Update bridge_config.json with your model name"
fi

# Start de bridge
npm start
```

Maak executable:
```bash
chmod +x start.sh
```

## Stap 5: Start de WebUI

```bash
cd ~/Downloads/Ollama-MCP-Bridge-WebUI
./start.sh
```

Open in je browser: **http://localhost:8080**

## Stap 6: Test NetMonitor Tools

In de WebUI, probeer deze queries:

```
What NetMonitor tools do you have?
Show me recent security threats from the last 24 hours
Analyze IP 192.168.1.50
Which sensors are online?
Get device list
```

Het model zou automatisch de NetMonitor tools moeten herkennen en gebruiken!

## Troubleshooting

### Bridge start niet
```bash
# Check logs
tail -f ~/.mcp_bridge.log
```

### Ollama niet gevonden
```bash
# Check Ollama status
ollama list

# Zorg dat je model draait
ollama run qwen2.5:14b "test"
```

### SSL Certificaat errors
Als je SSL errors krijgt, voeg `verify=False` toe aan de bridge (ALLEEN VOOR TESTING):
```python
# In mcp_streamable_http_bridge.py
response = self.session.post(
    self.server_url,
    json=request_data,
    timeout=30,
    verify=False  # ⚠️ Alleen voor testing met self-signed cert
)
```

### Kan geen verbinding maken met MCP server
Test handmatig:
```bash
export MCP_SERVER_URL="https://soc.poort.net/mcp"
export MCP_AUTH_TOKEN="725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f"
python3 mcp_streamable_http_bridge.py

# In een andere terminal, test met:
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | nc localhost 8080
```

## Voordelen vs Open-WebUI

✅ **Werkt met qwen2.5:14b** - geen function calling vereist
✅ **Tool discovery** - automatisch detecteert welke tools te gebruiken
✅ **Clean WebUI** - gebouwd voor MCP
✅ **Alle 60 NetMonitor tools** - via MCP bridge
✅ **Privacy** - alles lokaal (model) + remote (tools)

## Volgende Stappen

Als de WebUI werkt, kan je:
- Meerdere MCP servers toevoegen (filesystem, brave-search, etc.)
- System prompt aanpassen voor je use case
- Andere Ollama models proberen (mistral, llama3, etc.)
- De bridge draaien als systemd service (optioneel)

---

**Succes!** Als het werkt, heb je een lokale AI assistant met toegang tot alle NetMonitor security tools. 🚀
