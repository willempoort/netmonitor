# SSH Host Key Fix voor Claude Desktop

## 🔴 Probleem

Je ziet in de logs:
```
Host key verification failed.
```

Dit gebeurt omdat SSH de host key van `soc.poort.net` nog niet heeft geaccepteerd in de `known_hosts` file.

## ✅ Oplossing

### Stap 1: Accepteer Host Key (Op je Mac)

Open Terminal en run:

```bash
ssh root@soc.poort.net
```

Je zult een prompt zien zoals:
```
The authenticity of host 'soc.poort.net (xxx.xxx.xxx.xxx)' can't be established.
ED25519 key fingerprint is SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Type: **`yes`** en druk Enter.

Dit voegt de host key toe aan `~/.ssh/known_hosts`.

### Stap 2: Controleer de Connection

Test dat SSH nu werkt zonder waarschuwing:

```bash
ssh root@soc.poort.net 'echo "Success"'
```

Zou moeten printen: `Success` zonder host key warning.

### Stap 3: Test de Volledige Command

Test het volledige MCP commando:

```bash
ssh root@soc.poort.net 'cd /opt/netmonitor/mcp_server && source ../venv/bin/activate && python3 server.py --transport stdio --help'
```

Dit zou help tekst moeten tonen.

### Stap 4: Herstart Claude Desktop

```bash
killall Claude
open -a Claude
```

---

## 🔧 Alternatieve Fix: Disable StrictHostKeyChecking (Niet Aanbevolen!)

Als je de host key niet handmatig wilt accepteren (niet veilig!), kun je StrictHostKeyChecking uitschakelen:

**SSH Config:**
```bash
nano ~/.ssh/config
```

Voeg toe:
```
Host soc.poort.net
    StrictHostKeyChecking no
    UserKnownHostsFile=/dev/null
```

**⚠️ WAARSCHUWING:** Dit is NIET VEILIG - je bent kwetsbaar voor MITM attacks!

---

## 📝 Updated Claude Desktop Config

**Na het accepteren van de host key, gebruik deze config:**

```json
{
  "mcpServers": {
    "netmonitor-soc": {
      "command": "ssh",
      "args": [
        "root@soc.poort.net",
        "cd /opt/netmonitor/mcp_server && source ../venv/bin/activate && python3 server.py --transport stdio 2>&1"
      ]
    }
  }
}
```

**Belangrijke wijzigingen van jouw huidige config:**
- ❌ **Verwijder** `-t` flag (veroorzaakt "Pseudo-terminal" warning)
- ❌ **Verwijder** `exec`
- ✅ **Voeg toe** `2>&1` voor error logging
- ✅ Pull de laatste server.py (nu gefixed voor async context manager)

---

## 🔍 Verificatie

**Check known_hosts:**
```bash
grep soc.poort.net ~/.ssh/known_hosts
```

Zou een regel moeten tonen met de host key.

**Test SSH zonder password:**
```bash
ssh root@soc.poort.net 'whoami'
```

Moet `root` printen zonder password prompt of host key warning.

---

## ✅ Checklist

Voordat Claude Desktop werkt:

- [ ] SSH host key geaccepteerd: `ssh root@soc.poort.net` (type 'yes')
- [ ] SSH werkt passwordless: `ssh root@soc.poort.net 'echo OK'`
- [ ] Latest code gepulled op server: `ssh root@soc.poort.net 'cd /opt/netmonitor && git pull'`
- [ ] server.py gefixed (async context manager)
- [ ] Claude Desktop config updated (geen -t, geen exec, wel 2>&1)
- [ ] Claude Desktop herstart

---

**Na deze stappen zou het moeten werken!** 🎉
