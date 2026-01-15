# Quick Start: Ollama-MCP-Bridge-WebUI voor NetMonitor

**Doel:** Gebruik je lokale qwen2.5:14b model met NetMonitor security tools via een WebUI.

## Snelle Setup (5 minuten)

### 1. Download Bestanden (op je laptop)

```bash
# Clone de bridge repository
cd ~/Downloads
git clone https://github.com/Rkm1999/Ollama-MCP-Bridge-WebUI.git
cd Ollama-MCP-Bridge-WebUI

# Download NetMonitor bestanden van server
scp root@soc.poort.net:/tmp/mcp_bridge.py .
scp root@soc.poort.net:/tmp/bridge_config.json .
scp root@soc.poort.net:/tmp/start.sh .
chmod +x start.sh
```

### 2. Installeer Dependencies

```bash
# npm packages
npm install

# Build TypeScript
npm run build
```

### 3. Start de WebUI

```bash
./start.sh
```

Open browser: **http://localhost:8080**

### 4. Test NetMonitor

In de WebUI chat, probeer:

```
What security tools do you have?
Show me recent threats from the last 24 hours
Analyze IP 192.168.1.100
Which sensors are online?
```

## Wat gebeurt er?

1. **Je lokale Ollama** draait qwen2.5:14b (op je laptop)
2. **Ollama-MCP-Bridge** vertaalt tussen Ollama en MCP protocol
3. **Python STDIO Bridge** (`mcp_bridge.py`) verbindt met NetMonitor MCP server
4. **NetMonitor MCP Server** (soc.poort.net:8000) voert de security tools uit
5. **Resultaten** komen terug naar je WebUI

```
[WebUI] <-> [Ollama Bridge] <-> [Python Bridge] <-> [HTTPS] <-> [NetMonitor Server]
  :8080        localhost          localhost                        soc.poort.net
```

## Configuratie Aanpassen

### Ander Ollama Model Gebruiken

Edit `bridge_config.json`:

```json
{
  "llm": {
    "model": "mistral:7b",  // ← Verander hier
    "baseUrl": "http://localhost:11434",
    ...
  }
}
```

### Debug Logging

```bash
# Kijk naar bridge logs
tail -f ~/.mcp_bridge.log
```

### System Prompt Aanpassen

Edit `bridge_config.json` → `systemPrompt` voor specifieke use cases:

```json
{
  "systemPrompt": "Je bent een Nederlandse security analist met toegang tot NetMonitor tools. Beantwoord vragen in het Nederlands..."
}
```

## Troubleshooting

**"Ollama not found"**
```bash
# Installeer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull je model
ollama pull qwen2.5:14b
```

**"Cannot connect to MCP server"**
```bash
# Test handmatig
curl -H "Authorization: Bearer 725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f" \
  https://soc.poort.net/mcp/health
```

**"Python bridge fails"**
```bash
# Check Python dependencies
pip3 install requests

# Test bridge
export MCP_SERVER_URL="https://soc.poort.net/mcp"
export MCP_AUTH_TOKEN="725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f"
python3 mcp_bridge.py
```

## Volgende Stappen

Als het werkt:
- ✅ Je hebt een lokale AI assistant met 60 security tools
- ✅ Privacy: Model draait lokaal, alleen tools maken HTTPS calls
- ✅ Geen vendor lock-in: Gebruik elk Ollama model dat je wilt

Je kan nu:
1. Security incidents onderzoeken via natuurlijke taal
2. IP adressen analyseren
3. Sensor status checken
4. Device inventory opvragen
5. Threat feeds raadplegen
6. En 55 andere security operaties uitvoeren

**Veel plezier met je AI-powered SOC!** 🚀🛡️
