# Claude Desktop Setup voor Remote MCP Server

## ⚠️ Belangrijk: Claude Desktop SSE Beperking

**Claude Desktop ondersteunt GEEN directe SSE URLs.**

De error die je kreeg:
```json
{
  "code": "invalid_type",
  "expected": "string",
  "received": "undefined",
  "path": ["mcpServers", "netmonitor-soc", "command"],
  "message": "Required"
}
```

Dit gebeurt omdat Claude Desktop **altijd een `command` field vereist** - het kan alleen lokale processen starten die via stdio communiceren.

---

## ✅ Oplossing: SSH Tunnel (Aanbevolen)

De meest praktische oplossing is een **SSH tunnel** gebruiken die de remote SSE server lokaal beschikbaar maakt.

### Stap 1: Maak SSH Tunnel Script

**Op je Mac:**

```bash
# Maak script directory
mkdir -p ~/scripts

# Maak tunnel script
nano ~/scripts/netmonitor-mcp-tunnel.sh
```

**Inhoud:**
```bash
#!/bin/bash
# SSH Tunnel voor NetMonitor MCP Server

echo "Starting SSH tunnel to soc.poort.net:3000..."
echo "Forwarding localhost:3000 -> soc.poort.net:3000"
echo "Press Ctrl+C to stop"

# SSH tunnel met keep-alive
ssh -N -L 3000:localhost:3000 \
    -o ServerAliveInterval=60 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    user@soc.poort.net

echo "Tunnel closed"
```

**Maak executable:**
```bash
chmod +x ~/scripts/netmonitor-mcp-tunnel.sh
```

### Stap 2: Maak Wrapper Script voor Claude Desktop

**Maak wrapper:**
```bash
nano ~/scripts/netmonitor-mcp-wrapper.sh
```

**Inhoud:**
```bash
#!/bin/bash
# Wrapper script voor Claude Desktop
# Start lokale MCP client die connect naar localhost:3000 (via SSH tunnel)

# Simpele proxy: forward stdio naar HTTP SSE
python3 - << 'PYTHON_EOF'
import sys
import json
import requests
import sseclient
import threading

SSE_URL = "http://localhost:3000/sse"

def read_stdin():
    """Read JSON-RPC from stdin, forward to server"""
    for line in sys.stdin:
        try:
            msg = json.loads(line)
            # Forward to MCP server (you'd implement the actual MCP client here)
            # For now, just echo back
            sys.stdout.write(json.dumps(msg) + '\n')
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")

def listen_sse():
    """Listen to SSE events from server"""
    try:
        response = requests.get(SSE_URL, stream=True)
        client = sseclient.SSEClient(response)
        for event in client.events():
            sys.stdout.write(event.data + '\n')
            sys.stdout.flush()
    except Exception as e:
        sys.stderr.write(f"SSE Error: {e}\n")

# Run both in parallel
threading.Thread(target=listen_sse, daemon=True).start()
read_stdin()
PYTHON_EOF
```

**Maak executable:**
```bash
chmod +x ~/scripts/netmonitor-mcp-wrapper.sh
```

---

## 🎯 Eenvoudiger: Start Server Lokaal via SSH

**Nog betere oplossing:** Start de MCP server lokaal via SSH command.

### Claude Desktop Config

```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "ssh",
      "args": [
        "user@soc.poort.net",
        "cd /path/to/netmonitor/mcp_server && source ../venv/bin/activate && python3 server.py --transport stdio"
      ]
    }
  }
}
```

**Dit doet:**
1. SSH naar je server
2. Activeer venv
3. Start MCP server in **stdio mode** (niet SSE!)
4. Communicatie via SSH tunnel (encrypted!)

**Vereist:**
- SSH key authentication (geen password prompt)
- MCP server ondersteunt `--transport stdio` mode

---

## 🔧 Beste Oplossing: Dual-Mode MCP Server

Ik zie dat de MCP server al beide modes ondersteunt! Check `server.py`:

```python
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--transport', choices=['stdio', 'sse'], default='stdio')
    ...
```

### ✅ Gebruik SSH + stdio Mode

**Claude Desktop config:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "ssh",
      "args": [
        "-t",
        "user@soc.poort.net",
        "cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && exec python3 server.py --transport stdio"
      ]
    }
  }
}
```

**Voordelen:**
- ✅ Werkt out-of-the-box
- ✅ Encrypted via SSH
- ✅ Geen extra scripts nodig
- ✅ Geen SSH tunnel management
- ✅ Claude Desktop start/stopt server automatisch

**Vereist:**
1. **SSH key authentication** (setup hieronder)
2. **Correcte path naar netmonitor** (pas aan naar jouw setup)

---

## 🔑 SSH Key Setup (Belangrijk!)

Claude Desktop kan geen passwords invoeren, dus je hebt SSH key auth nodig:

### Check of je al een SSH key hebt:
```bash
ls -la ~/.ssh/id_*.pub
```

### Maak nieuwe key (als nodig):
```bash
ssh-keygen -t ed25519 -C "netmonitor-mcp"
# Press Enter voor default location
# Press Enter voor empty passphrase (of gebruik passphrase + ssh-agent)
```

### Kopieer key naar server:
```bash
ssh-copy-id user@soc.poort.net
```

### Test passwordless login:
```bash
ssh user@soc.poort.net 'echo "Success!"'
# Zou "Success!" moeten printen zonder password prompt
```

---

## 📝 Complete Claude Desktop Config

**Locatie:**
```bash
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Inhoud:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "ssh",
      "args": [
        "-t",
        "user@soc.poort.net",
        "cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && exec python3 server.py --transport stdio"
      ]
    },
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/willempoort/Documents/Develop",
        "/Users/willempoort/Develop/Websites/Loumax"
      ]
    },
    "kapture": {
      "command": "npx",
      "args": [
        "-y",
        "kapture-mcp@latest",
        "bridge"
      ]
    }
  }
}
```

**Pas aan:**
- `user@soc.poort.net` → jouw SSH user en host
- `/home/user/netmonitor` → jouw NetMonitor path

---

## 🧪 Test de Setup

### 1. Test SSH connection eerst:
```bash
ssh user@soc.poort.net 'cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && python3 server.py --transport stdio --help'
```

Zou help tekst moeten tonen zonder password prompt.

### 2. Test MCP server stdio mode:
```bash
ssh -t user@soc.poort.net 'cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && python3 server.py --transport stdio' <<< '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

Zou JSON response moeten geven.

### 3. Restart Claude Desktop:
```bash
killall Claude
open -a Claude
```

### 4. Test in Claude Desktop:
```
What MCP servers are available?
```

---

## 🐛 Troubleshooting

### Error: "Permission denied (publickey)"

**Oorzaak:** SSH key niet correct opgezet

**Oplossing:**
```bash
# Check SSH config
cat ~/.ssh/config

# Test verbose
ssh -v user@soc.poort.net

# Ensure key is added to ssh-agent
ssh-add ~/.ssh/id_ed25519
```

### Error: "command not found: python3"

**Oorzaak:** PATH niet correct in non-interactive SSH session

**Oplossing:**
```json
{
  "command": "ssh",
  "args": [
    "-t",
    "user@soc.poort.net",
    "bash -l -c 'cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && exec python3 server.py --transport stdio'"
  ]
}
```

### Error: "No such file or directory"

**Oorzaak:** Verkeerd pad naar netmonitor

**Oplossing:**
```bash
# Check correct path op server
ssh user@soc.poort.net 'pwd; ls -la /home/user/netmonitor'

# Update config met correct pad
```

### Error: "ModuleNotFoundError: No module named 'mcp'"

**Oorzaak:** venv niet correct geactiveerd

**Oplossing:**
```bash
# Op de server, check venv:
ssh user@soc.poort.net
cd /home/user/netmonitor
source venv/bin/activate
python3 -c "import mcp; print('OK')"

# Als dit werkt, check je SSH command syntax in config
```

---

## 🔒 Security Notes

### Voordelen van SSH + stdio:
- ✅ **Encrypted**: All traffic via SSH tunnel
- ✅ **Authenticated**: SSH key required
- ✅ **Firewall-friendly**: Alleen SSH port (22) hoeft open
- ✅ **No exposed HTTP port**: MCP server SSE mode niet nodig

### SSE Service

Je kunt de SSE service (poort 3000) nu **disablen** of alleen voor andere clients gebruiken:

```bash
# Optioneel: stop SSE service (alleen SSH wordt gebruikt)
sudo systemctl stop netmonitor-mcp
sudo systemctl disable netmonitor-mcp

# Of laat draaien voor toekomstig Ollama gebruik
```

---

## 📊 Wat Gebeurt Er?

```
┌─────────────────┐
│  Claude Desktop │
│    (Mac)        │
└────────┬────────┘
         │ stdio
         ├──► ssh command
         │
    ╔════▼════════════════════════╗
    ║  SSH Encrypted Tunnel       ║
    ║  Mac ←──────────→ Server    ║
    ╚════╤════════════════════════╝
         │
┌────────▼────────┐
│  MCP Server     │
│  (stdio mode)   │
│  soc.poort.net  │
└────────┬────────┘
         │
┌────────▼────────┐
│   PostgreSQL    │
│   (netmonitor)  │
└─────────────────┘
```

---

## ✅ Quick Reference

**Minimum werkende config:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "ssh",
      "args": [
        "user@soc.poort.net",
        "cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && python3 server.py --transport stdio"
      ]
    }
  }
}
```

**Met terminal allocation (als je "Pseudo-terminal" error krijgt):**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "ssh",
      "args": [
        "-tt",
        "user@soc.poort.net",
        "cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && exec python3 server.py --transport stdio"
      ]
    }
  }
}
```

**Debug mode:**
```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "ssh",
      "args": [
        "-vv",
        "user@soc.poort.net",
        "cd /home/user/netmonitor/mcp_server && source ../venv/bin/activate && python3 server.py --transport stdio 2>/tmp/mcp_debug.log"
      ]
    }
  }
}
```

---

**Dit zou moeten werken! SSH + stdio is de meest betrouwbare methode voor remote MCP servers.** 🚀
