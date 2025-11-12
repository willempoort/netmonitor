# Ollama AI & Configuration Management Tools

## Overzicht

Er zijn **6 nieuwe MCP tools** toegevoegd in twee categorieën:

### 🤖 **Ollama AI Tools (4 tools)** - Optie 1A ✅
Lokale AI-powered threat analysis zonder cloud APIs

### ⚙️ **Configuration Modification Tools (2 tools)**
Live tuning van detection rules via Claude Desktop

---

# 🤖 Ollama AI Tools

## Vereisten

### Ollama installeren op de server:

```bash
# Op de server
curl -fsSL https://ollama.com/install.sh | sh

# Download een model (bijvoorbeeld llama3.2)
ollama pull llama3.2

# Start Ollama service
ollama serve
# Of als systemd service:
sudo systemctl start ollama
```

### Configuratie via environment variables:

```bash
# In /etc/systemd/system/netmonitor-mcp.service
Environment="OLLAMA_BASE_URL=http://localhost:11434"
Environment="OLLAMA_MODEL=llama3.2"
```

---

## Tool 1: `analyze_threat_with_ollama`

**Doel:** AI-powered analyse van een security threat

**Parameters:**
- `alert_id` (required): Alert ID om te analyseren

**Gebruik via Claude Desktop:**
```
"Analyze alert 1234 with Ollama"
"Use AI to analyze this port scan alert (ID 5678)"
"What does Ollama think about alert 91011?"
```

**Output:**
- Threat assessment (severity en risk)
- Potential attack vector en tactics
- Recommended immediate actions
- Investigation steps
- Indicators to monitor

**Voorbeeld response:**
```json
{
  "alert_id": 1234,
  "alert": {
    "threat_type": "PORT_SCAN",
    "severity": "HIGH",
    "source_ip": "185.220.101.50"
  },
  "ai_analysis": {
    "analysis": "**Threat Assessment:**\n• Severity: HIGH - Systematic port scanning indicates reconnaissance\n• Risk: Active network mapping, likely precursor to exploitation\n\n**Attack Vector:**\n• Horizontal port scanning across multiple targets\n• Testing for open services and vulnerabilities\n• Typical reconnaissance phase of kill chain\n\n**Immediate Actions:**\n1. Block source IP at perimeter firewall\n2. Check if any ports responded\n3. Review logs for additional IPs from same /24\n\n**Investigation:**\n• Correlate with threat intelligence feeds\n• Check for any successful connections\n• Review historical data for same source\n\n**Monitor:**\n• Watch for exploitation attempts\n• Monitor for lateral movement\n• Check for data exfiltration attempts"
  },
  "success": true
}
```

**Use Cases:**
- Diepere analyse van complexe alerts
- Incident response planning
- Training junio security analysts
- Management briefings (AI legt uit in begrijpelijke taal)

---

## Tool 2: `suggest_incident_response`

**Doel:** Genereer incident response plan volgens NIST framework

**Parameters:**
- `alert_id` (required): Alert ID voor response planning
- `context` (optional): Extra context voor het plan

**Gebruik via Claude Desktop:**
```
"Generate incident response plan for alert 1234"
"Create NIST response plan for this beaconing alert"
"Suggest incident response for alert 5678 - customer reported slowness"
```

**Output:**
NIST Incident Response framework stappen:
1. **Preparation** - Wat moet klaar staan?
2. **Detection & Analysis** - Verdere analyse stappen
3. **Containment** - Hoe inperken?
4. **Eradication** - Hoe verwijderen?
5. **Recovery** - Hoe herstellen?
6. **Post-Incident** - Wat geleerd?

**Voorbeeld response:**
```json
{
  "incident_response": {
    "response_plan": "**1. PREPARATION**\n• Ensure forensic tools ready\n• Contact list: IR team, legal, PR\n• Evidence preservation procedures\n\n**2. DETECTION & ANALYSIS**\n• Collect full packet captures\n• Timeline reconstruction\n• Scope assessment - other affected systems?\n\n**3. CONTAINMENT**\n• Immediate: Block C2 IP at firewall\n• Short-term: Isolate affected workstation\n• Network segmentation verification\n\n**4. ERADICATION**\n• Malware removal with EDR\n• Scheduled task/persistence removal\n• Registry cleanup\n\n**5. RECOVERY**\n• System reimaging (preferred)\n• Credential rotation\n• Enhanced monitoring deployment\n\n**6. POST-INCIDENT**\n• Root cause analysis\n• Update detection rules\n• User awareness training"
  },
  "success": true
}
```

**Use Cases:**
- Structured incident response
- Compliance met NIST/ISO frameworks
- Training documentation
- Playbook generation

---

## Tool 3: `explain_ioc`

**Doel:** Leg een Indicator of Compromise uit in simpele taal voor niet-technische mensen

**Parameters:**
- `ioc` (required): De IOC value (IP, domain, hash, URL)
- `ioc_type` (optional): Type IOC - "ip", "domain", "hash", "url" (default: "ip")

**Gebruik via Claude Desktop:**
```
"Explain this IP address: 185.220.101.50"
"What does this malicious domain mean: evil.com"
"Explain this file hash in simple terms: abc123def456..."
"Translate this IOC for management: suspicious-url.com"
```

**Output:**
Eenvoudige uitleg zonder jargon:
- Wat het indicator betekent
- Waarom het verdacht/malicious is
- Wat het typisch aangeeft
- Real-world context en voorbeelden

**Voorbeeld response:**
```json
{
  "ioc": "185.220.101.50",
  "ioc_type": "ip",
  "explanation": {
    "explanation": "**What is this?**\nThis IP address (like a phone number for computers) belongs to a known Tor exit node. Think of Tor as a 'privacy tunnel' on the internet.\n\n**Why is it suspicious?**\nWhile Tor has legitimate uses (privacy, censorship circumvention), attackers often use it to hide their real location when attacking systems - like wearing a mask during a robbery.\n\n**What does it indicate?**\n• Someone is trying to hide their identity\n• Could be reconnaissance (scouting your defenses)\n• Might be command & control (attacker controlling infected computer)\n• Or data theft (stealing information while masked)\n\n**Real-world analogy:**\nImagine getting a phone call from a 'burner phone' - technically legal, but suspicious if you weren't expecting it. Same with Tor traffic.\n\n**What to do?**\nTreat with caution - block if not expected, investigate if from inside your network."
  },
  "success": true
}
```

**Use Cases:**
- Management briefings
- Board presentations
- User awareness training
- Customer communications
- Compliance reports voor niet-technische auditors

---

## Tool 4: `get_ollama_status`

**Doel:** Check of Ollama beschikbaar is en welke modellen er zijn

**Parameters:** Geen

**Gebruik via Claude Desktop:**
```
"Check Ollama status"
"Is Ollama available?"
"List available AI models"
```

**Output:**
```json
{
  "available": true,
  "base_url": "http://localhost:11434",
  "current_model": "llama3.2",
  "models_available": 3,
  "models": [
    "llama3.2:latest",
    "mistral:latest",
    "codellama:7b"
  ],
  "message": "Ollama is ready"
}
```

**Use Cases:**
- Troubleshooting ("Waarom werken AI tools niet?")
- Documentatie ("Welke modellen gebruiken we?")
- Monitoring

---

# ⚙️ Configuration Modification Tools

## ⚠️ Belangrijke Veiligheidsnota

Deze tools **WIJZIGEN** de `config.yaml` file. Ze zijn:
- ✅ **Veilig**: Automatische backups, type validatie, rollback mogelijk
- ⚠️ **Potent**: Kunnen detection regels uitschakelen
- 📝 **Gelogd**: Alle wijzigingen worden gelogd
- 🔄 **Require restart**: NetMonitor moet herstart worden om wijzigingen toe te passen

---

## Tool 5: `update_threshold`

**Doel:** Wijzig een detection threshold instelling

**Parameters:**
- `detection_type` (required): Welke detectie ("port_scan", "connection_flood", etc.)
- `setting` (required): Welke instelling ("unique_ports", "connections_per_second", etc.)
- `value` (required): Nieuwe waarde (moet juiste type zijn!)

**Gebruik via Claude Desktop:**
```
"Increase port scan threshold to 30 unique ports"
"Set connection flood limit to 150 connections per second"
"Change beaconing min_connections to 10"
"Update outbound volume threshold to 200 MB"
```

**Beschikbare detection types:**
- `port_scan` - Port scan detection
- `connection_flood` - Connection flooding
- `packet_size` - Unusual packet sizes
- `dns_tunnel` - DNS tunneling
- `beaconing` - C&C beaconing
- `outbound_volume` - Data exfiltration
- `lateral_movement` - Internal scanning

**Output:**
```json
{
  "success": true,
  "detection_type": "port_scan",
  "setting": "unique_ports",
  "old_value": 20,
  "new_value": 30,
  "backup_file": "/home/user/netmonitor/config.yaml.backup.1731358800",
  "message": "Updated port_scan.unique_ports from 20 to 30",
  "note": "⚠️ Restart NetMonitor service to apply changes: sudo systemctl restart netmonitor"
}
```

**Safety features:**
- ✅ **Type validation**: Voorkomt int waar bool verwacht wordt
- ✅ **Setting validation**: Alleen bestaande settings kunnen gewijzigd
- ✅ **Automatic backup**: config.yaml.backup.timestamp
- ✅ **Rollback support**: Herstel oude versie als iets mis gaat
- ✅ **Clear messages**: Weet precies wat gewijzigd is

**Use Cases:**
- **Te veel false positives?** Verhoog threshold
- **Te weinig detecties?** Verlaag threshold
- **Fine-tuning na implementatie**
- **A/B testing van verschillende settings**
- **Seasonal adjustments** (meer verkeer = hogere thresholds)

**Voorbeeld scenario:**
```
User: "We keep getting port scan alerts from our vulnerability scanner"
Claude: "Let me increase the port scan threshold"
[Uses update_threshold: port_scan, unique_ports, 40]
Claude: "I've increased the threshold from 20 to 40 unique ports.
        Your scanner should no longer trigger false positives.
        Restart NetMonitor to apply: sudo systemctl restart netmonitor"
```

---

## Tool 6: `toggle_detection_rule`

**Doel:** Enable of disable een detection rule volledig

**Parameters:**
- `detection_type` (required): Welke detectie
- `enabled` (required): true om te enablen, false om te disablen

**Gebruik via Claude Desktop:**
```
"Disable beaconing detection temporarily"
"Enable lateral movement detection"
"Turn off DNS tunnel detection for maintenance"
"Re-enable all disabled rules"
```

**Output:**
```json
{
  "success": true,
  "detection_type": "beaconing",
  "old_enabled": true,
  "new_enabled": false,
  "backup_file": "/home/user/netmonitor/config.yaml.backup.1731358900",
  "message": "Detection rule 'beaconing' disabled",
  "changed": true,
  "note": "⚠️ Restart NetMonitor service to apply changes: sudo systemctl restart netmonitor"
}
```

**Use Cases:**
- **Te veel false positives?** Disable tijdelijk tijdens troubleshooting
- **Maintenance window**: Disable bepaalde checks
- **New deployment**: Gradueel rules enablen
- **Problem isolation**: Disable suspect rule om te testen
- **Compliance**: Disable niet-relevante checks

**Safety:**
- ✅ **Idempotent**: Kan veilig herhaald worden
- ✅ **Backup**: Automatisch voor elke wijziging
- ✅ **Clear status**: "already enabled/disabled" message als geen change
- ✅ **Logged**: Alle enable/disable acties worden gelogd

**Voorbeeld scenario:**
```
User: "Beaconing detection keeps firing during our scheduled backups"
Claude: "I can temporarily disable beaconing detection during the backup window"
[Uses toggle_detection_rule: beaconing, false]
Claude: "Beaconing detection is now disabled. Remember to re-enable it after backups!"
```

---

# 🚀 Hoe te gebruiken

## 1. Update de server

```bash
ssh root@soc.poort.net
cd /opt/netmonitor
git pull

# Installeer dependencies
source venv/bin/activate
pip install -r mcp_server/requirements.txt

# Herstart MCP server (als systemd service)
sudo systemctl restart netmonitor-mcp
```

## 2. Installeer Ollama (optioneel)

```bash
# Download en installeer
curl -fsSL https://ollama.com/install.sh | sh

# Download gewenst model
ollama pull llama3.2
# Of een ander model:
# ollama pull mistral
# ollama pull codellama

# Start Ollama
ollama serve
# Of als systemd service configureren
```

## 3. Configureer Ollama voor MCP (optioneel)

```bash
# Edit MCP service
sudo nano /etc/systemd/system/netmonitor-mcp.service

# Voeg toe onder [Service]:
Environment="OLLAMA_BASE_URL=http://localhost:11434"
Environment="OLLAMA_MODEL=llama3.2"

# Reload en restart
sudo systemctl daemon-reload
sudo systemctl restart netmonitor-mcp
```

## 4. Herstart Claude Desktop

```bash
# Op je Mac
killall Claude
open -a Claude
```

---

# 📊 Tool Overview

| Tool | Type | Purpose | Risk |
|------|------|---------|------|
| `analyze_threat_with_ollama` | AI | Threat analysis | ✅ Safe (Read-only) |
| `suggest_incident_response` | AI | Response planning | ✅ Safe (Read-only) |
| `explain_ioc` | AI | IOC explanation | ✅ Safe (Read-only) |
| `get_ollama_status` | AI | Status check | ✅ Safe (Read-only) |
| `update_threshold` | Config | Modify thresholds | ⚠️ WRITE operation |
| `toggle_detection_rule` | Config | Enable/disable rules | ⚠️ WRITE operation |

---

# 🔒 Security Considerations

## Ollama AI Tools
- ✅ **Privacy**: Alles lokaal, geen cloud APIs
- ✅ **Data privacy**: Security data blijft op eigen server
- ✅ **Graceful degradation**: Werkt ook zonder Ollama
- ⚠️ **Resource usage**: AI inference kan CPU intensief zijn
- ⚠️ **Model trust**: Gebruik alleen trusted models

## Configuration Modification Tools
- ✅ **Automatic backups**: Voor elke wijziging
- ✅ **Type validation**: Voorkomt invalid configs
- ✅ **Audit trail**: Alle wijzigingen gelogd
- ⚠️ **Requires restart**: NetMonitor moet herstart
- ⚠️ **Write access**: Kan detection regels uitschakelen
- 🔴 **Recommendation**: Gebruik alleen tijdens normale werkuren

---

# ❓ Troubleshooting

## Ollama niet beschikbaar

**Probleem:**
```json
{
  "error": "Ollama is not available",
  "message": "Please install and start Ollama: https://ollama.ai"
}
```

**Oplossing:**
```bash
# Check of Ollama draait
curl http://localhost:11434/api/tags

# Niet? Start Ollama:
ollama serve

# Of check systemd:
sudo systemctl status ollama
sudo systemctl start ollama
```

## Config wijzigingen worden niet toegepast

**Probleem:** Threshold aangepast maar detectie werkt nog met oude waarde

**Oplossing:**
```bash
# NetMonitor moet herstart worden!
sudo systemctl restart netmonitor

# Check of het werkt:
sudo systemctl status netmonitor
```

## Backup restore

**Probleem:** Config wijziging veroorzaakt problemen

**Oplossing:**
```bash
# Vind backups
ls -ltr /opt/netmonitor/config.yaml.backup.*

# Restore laatste backup
cp /opt/netmonitor/config.yaml.backup.1731358900 /opt/netmonitor/config.yaml

# Herstart
sudo systemctl restart netmonitor
```

---

# 🎯 Next Steps: Hybrid Ollama (Optie 1C)

De huidige implementatie is **Optie 1A**: On-demand AI analysis via Claude Desktop.

**Volgende fase - Optie 1C: Hybrid approach:**
- Background service voor automatische enrichment
- Alle HIGH/CRITICAL alerts krijgen automatisch AI analyse
- Database kolom `ai_analysis` voor persistence
- Dashboard toont AI insights direct bij alert
- Configureerbaar per severity level

Wil je verder met Optie 1C?

---

# 📚 Referenties

- **Ollama**: https://ollama.ai
- **MCP Protocol**: https://modelcontextprotocol.io
- **NIST Incident Response**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- **NetMonitor Docs**: Zie andere README files in deze directory

---

**Gemaakt**: 2025-11-12
**Status**: ✅ Production Ready
**Tools**: 6 nieuwe MCP tools (4 AI + 2 Config)
**Dependencies**: requests >= 2.31.0 (voor Ollama HTTP API)
