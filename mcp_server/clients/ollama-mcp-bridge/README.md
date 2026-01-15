# Ollama-MCP-Bridge-WebUI - Experimenteel ⚠️

**Status**: Niet aanbevolen voor productie gebruik

Deze directory bevat configuratie voor Ollama-MCP-Bridge-WebUI, maar **tool calling werkt niet betrouwbaar**.

## 🚫 Waarom Niet Aanbevolen

Na uitgebreide testing met 4+ verschillende modellen:
- llama3.1:8b
- qwen2.5-coder:7b
- qwen2.5-coder:14b
- mistral:7b-instruct

**Alle modellen faalden** met:
- Tools worden BESCHREVEN maar niet AANGEROEPEN
- LLM hallucinaties (192.168.1.x IPs in plaats van 10.100.0.x)
- Tool results worden genegeerd
- Nep data verzinnen

Zie [OLLAMA_TOOL_CALLING_FIX.md](./OLLAMA_TOOL_CALLING_FIX.md) voor volledige analyse.

## ✅ Alternatieve Oplossingen

### Voor On-Premise
→ **Open-WebUI 0.7.2** in `../open-webui/`
- Native MCP support
- Mature project
- Docker-based
- [Setup Guide](../open-webui/SETUP.md)

### Voor Cloud
→ **Claude Desktop** in `../claude-desktop/`
- Perfect tool calling
- Nooit hallucinaties
- [Setup Guide](../claude-desktop/README.md)

## 📚 Documentatie

- [OLLAMA_TOOL_CALLING_FIX.md](./OLLAMA_TOOL_CALLING_FIX.md) - Alle pogingen en waarom het faalde
- [../LESSONS_LEARNED.md](../LESSONS_LEARNED.md) - Vergelijking van alle geteste oplossingen
- `archive/` - Oude setup documenten (referentie)

## 🔧 Test Setup (Alleen voor Experimenten)

Als je toch wilt testen:

```bash
# Installeer dependencies (in een andere directory)
git clone https://github.com/Rkm1999/Ollama-MCP-Bridge-WebUI.git
cd Ollama-MCP-Bridge-WebUI
npm install

# Kopieer config
cp /pad/naar/bridge_config.json .

# Update token
nano bridge_config.json
# Vervang "YOUR_MCP_TOKEN_HERE"

# Start
npm start
```

**Verwacht**: Tools worden geladen maar niet correct aangeroepen.

---

**Voor productie: Gebruik Open-WebUI 0.7.2** → `../open-webui/`
