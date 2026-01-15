# Fix: Ollama Tool Calling Issues

## Probleem

De Ollama-MCP-Bridge-WebUI laadt wel alle 60 tools correct, maar Ollama antwoordt met gewone tekst in plaats van JSON tool calls:

```
ERROR: Response is not a structured tool call: Unexpected token 'H', "Here is a "...
ERROR: Response is not a structured tool call: Unexpected token 'E', "Er zijn 34"...
```

## Oorzaak

1. **Zwakke system prompt** - Oorspronkelijke prompt was niet expliciet over JSON format
2. **Verkeerd model** - qwen2.5:14b is te algemeen, niet getraind op function calling
3. **Te hoge temperature** - 0.7 is te creatief voor structured output

## Oplossing: Verbeterde Configuratie

De nieuwe `bridge_config.json` heeft 3 belangrijke aanpassingen:

### 1. Beter Model: qwen2.5-coder:7b

```json
"llm": {
  "model": "qwen2.5-coder:7b",  // Was: qwen2.5:14b
  "temperature": 0.3              // Was: 0.7
}
```

**Waarom qwen2.5-coder?**
- ✅ Gespecialiseerd in code/structured output
- ✅ Beter in JSON formatting
- ✅ Sneller (7b vs 14b)
- ✅ Lager temperature voor deterministische output

### 2. Expliciete System Prompt

De nieuwe prompt bevat:

```
CRITICAL: When you need to use a tool, you MUST respond with ONLY a JSON object in this EXACT format:

{"tool":"tool_name","arguments":{"param1":"value1","param2":"value2"}}

Do NOT add any text before or after the JSON. Do NOT use markdown code blocks. ONLY the raw JSON.
```

Plus **concrete voorbeelden**:

```
User: "Show recent threats"
Assistant: {"tool":"get_recent_threats","arguments":{"hours":24}}

User: "Analyze IP 192.168.1.50"
Assistant: {"tool":"analyze_ip","arguments":{"ip_address":"192.168.1.50"}}
```

### 3. Lagere Temperature

- **Oud**: 0.7 (creatief, variabel)
- **Nieuw**: 0.3 (deterministisch, precies)

## Installatie Instructies

### Stap 1: Download het Model

Als je qwen2.5-coder:7b nog niet hebt:

```bash
ollama pull qwen2.5-coder:7b
```

Of gebruik een ander model dat goed is in function calling:
- `mistral:7b` - Ook goed, iets langzamer
- `qwen2.5-coder:14b` - Nog beter, maar trager
- `llama3.1:8b` - Goede balans

### Stap 2: Update de Config

Kopieer de nieuwe `bridge_config.json` naar je Ollama-MCP-Bridge-WebUI directory:

```bash
# Op je laptop in ~/Downloads/Ollama-MCP-Bridge-WebUI/
cp ~/path/to/netmonitor/mcp_server/clients/ollama-mcp-bridge/bridge_config.json .
```

Of download rechtstreeks van de server:

```bash
cd ~/Downloads/Ollama-MCP-Bridge-WebUI
scp root@soc.poort.net:/opt/netmonitor/mcp_server/clients/ollama-mcp-bridge/bridge_config.json .
```

### Stap 3: Herstart de Bridge

```bash
# Stop de huidige bridge (Ctrl+C)
# Start opnieuw
./start.sh
```

## Testen

Open http://localhost:8080 en probeer:

### Test 1: Simple Tool Call
```
User: Laat recente bedreigingen zien
```

**Verwacht in logs:**
```
DEBUG: Response is a structured tool call
DEBUG: Calling tool: get_recent_threats
```

**NIET meer:**
```
ERROR: Response is not a structured tool call: Unexpected token...
```

### Test 2: IP Analysis
```
User: Analyseer IP 192.168.1.50
```

**Verwacht:**
- Tool call: `analyze_ip`
- Response met IP analyse data

### Test 3: Sensor Status
```
User: Welke sensors zijn online?
```

**Verwacht:**
- Tool call: `get_sensor_status`
- Lijst van sensors met status

## Debug Logs

### Bridge Logs Bekijken

```bash
tail -f ~/.mcp_bridge.log
```

**Goede output:**
```
2026-01-15 01:00:00 - MCP.Bridge - INFO - Handling tools/call request: get_recent_threats
2026-01-15 01:00:01 - MCP.Bridge - INFO - Tool call successful
```

### WebUI Logs

In de terminal waar je `npm start` draaide:

**Goede output:**
```
DEBUG: LLMBridge - Parsed response: {"tool":"get_recent_threats","arguments":{...}}
DEBUG: LLMBridge - Response is a structured tool call
INFO:  LLMBridge - LLM response received, isToolCall: true
```

**Slechte output (oud probleem):**
```
ERROR: Response is not a structured tool call: Unexpected token 'H'
```

## Alternatieve Modellen

Als qwen2.5-coder niet goed werkt, probeer deze alternatieven:

### Optie 1: Mistral (Zeer betrouwbaar)

```json
{
  "llm": {
    "model": "mistral:7b",
    "temperature": 0.2
  }
}
```

```bash
ollama pull mistral:7b
```

### Optie 2: Llama 3.1 (Goede balans)

```json
{
  "llm": {
    "model": "llama3.1:8b",
    "temperature": 0.3
  }
}
```

```bash
ollama pull llama3.1:8b
```

### Optie 3: Qwen2.5-Coder 14b (Best, trager)

```json
{
  "llm": {
    "model": "qwen2.5-coder:14b",
    "temperature": 0.3
  }
}
```

```bash
ollama pull qwen2.5-coder:14b
```

## Veelvoorkomende Problemen

### Probleem: Model geeft nog steeds tekst in plaats van JSON

**Oplossing 1**: Verlaag temperature verder

```json
"temperature": 0.1
```

**Oplossing 2**: Voeg extra instructies toe aan system prompt

Voeg dit toe aan het einde van systemPrompt in `bridge_config.json`:

```
IMPORTANT: You are a function calling assistant. You ONLY output JSON when using tools.
Never say "I will use the tool" or "Let me check" - just output the JSON directly.
```

**Oplossing 3**: Probeer een ander model (zie boven)

### Probleem: Bridge kan model niet vinden

```bash
# Check beschikbare models
ollama list

# Pull het model als het niet bestaat
ollama pull qwen2.5-coder:7b
```

### Probleem: Tool calls werken, maar antwoorden zijn leeg

Check of de MCP bridge correct verbindt:

```bash
# Test de Python bridge direct
export MCP_SERVER_URL="https://soc.poort.net/mcp"
export MCP_AUTH_TOKEN="725de5512afc284f4f2a02de242434ac5170659bbb2614ba4667c6d612dee34f"

python3 mcp_bridge.py

# In andere terminal:
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 -c "import sys; print(sys.stdin.read())"
```

## Performance Vergelijking

| Model | Speed | Quality | Function Calling | Best For |
|-------|-------|---------|------------------|----------|
| **qwen2.5-coder:7b** | ⚡⚡⚡ | ⭐⭐⭐ | ✅✅✅ | **Recommended** |
| qwen2.5:14b | ⚡⚡ | ⭐⭐⭐⭐ | ❌ | General chat only |
| mistral:7b | ⚡⚡ | ⭐⭐⭐ | ✅✅ | Reliable backup |
| llama3.1:8b | ⚡⚡ | ⭐⭐⭐⭐ | ✅✅ | Good balance |
| qwen2.5-coder:14b | ⚡ | ⭐⭐⭐⭐ | ✅✅✅ | Best quality |

## Volgende Stappen

Als het werkt:

1. **Test alle tools** - Probeer verschillende security queries
2. **Tune de prompt** - Pas aan voor je specifieke use case
3. **Monitor performance** - Kijk naar response times
4. **Experimenteer met models** - Vind je optimale balans

## Support

**Bridge logs:** `tail -f ~/.mcp_bridge.log`
**WebUI logs:** Terminal output van `npm start`
**Server logs:** `journalctl -u netmonitor-mcp-streamable -f` (op server)

---

**Na deze fix zou tool calling perfect moeten werken!** 🎯
