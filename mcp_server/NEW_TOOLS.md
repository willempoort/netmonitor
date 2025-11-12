# Nieuwe MCP Tools - NetMonitor SOC

## Overzicht

Er zijn **8 nieuwe MCP tools** toegevoegd aan de NetMonitor MCP server, verdeeld over 3 categorieën:
- **3 Statistiek Tools** - Voor trend analyse en capacity planning
- **3 Export Tools** - Voor CSV rapporten en data export
- **2 Configuratie Tools** - Voor inzicht in NetMonitor instellingen

---

## 📊 Statistiek Tools

### 1. `get_traffic_trends`
**Doel:** Netwerk verkeer trends over tijd analyseren voor capacity planning

**Parameters:**
- `hours` (optioneel): Terugkijk periode in uren (default: 24)
- `interval` (optioneel): Aggregatie interval - 'hourly' of 'daily' (default: hourly)

**Gebruik:**
```
Get traffic trends for the last 7 days with daily intervals
```

**Output:**
- Totaal packets en bytes per tijdsperiode
- Inbound/outbound breakdown
- Gemiddelden per periode
- Totalen in GB/MB

**Use Cases:**
- Identificeer piek tijden voor verkeer
- Monitor groei trends over tijd
- Capacity planning voor netwerk upgrades
- Detecteer abnormale verkeer volumes

---

### 2. `get_top_talkers_stats`
**Doel:** Identificeer hosts die de meeste bandwidth gebruiken

**Parameters:**
- `hours` (optioneel): Terugkijk periode (default: 24)
- `limit` (optioneel): Max aantal resultaten (default: 20)
- `direction` (optioneel): Filter op 'inbound' of 'outbound'

**Gebruik:**
```
Show me the top 10 outbound bandwidth consumers over the last week
```

**Output:**
- IP adres + hostname
- Totaal packets en bytes
- Eerste/laatste waarneming
- Data in GB/MB

**Use Cases:**
- Bandwidth hogs identificeren
- Data exfiltration detecteren (hoog outbound)
- P2P/streaming detectie
- Anomaly detection (plotselinge spikes)

---

### 3. `get_alert_statistics`
**Doel:** Alert statistieken en trends voor security posture overview

**Parameters:**
- `hours` (optioneel): Terugkijk periode (default: 24)
- `group_by` (optioneel): Groepeer op 'severity', 'threat_type', of 'hour' (default: severity)

**Gebruik:**
```
Show alert statistics for the last month grouped by threat type
```

**Output:**
- Totaal aantal alerts
- Breakdown per categorie
- Meest voorkomende type
- Laatste occurrence per type

**Use Cases:**
- Wekelijkse/maandelijkse security rapportage
- Trend analyse (stijgen/dalen alerts?)
- Identificeer meest voorkomende threats
- Prioriteer waar aandacht nodig is

---

## 📁 Export Tools (CSV)

### 4. `export_alerts_csv`
**Doel:** Exporteer security alerts naar CSV voor periodieke rapportage

**Parameters:**
- `hours` (optioneel): Terugkijk periode (default: 24)
- `severity` (optioneel): Filter op severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `threat_type` (optioneel): Filter op threat type

**Gebruik:**
```
Export all CRITICAL and HIGH alerts from the last month to CSV
```

**Output:**
- CSV data met kolommen: Timestamp, Severity, Threat Type, Source IP, Destination IP, Description, Acknowledged
- Aantal rijen
- Toegepaste filters

**Use Cases:**
- Maandelijks security rapport voor management
- Compliance documentatie
- Import in Excel/Tableau voor visualisatie
- Archivering voor audit trails

---

### 5. `export_traffic_stats_csv`
**Doel:** Exporteer verkeer statistieken naar CSV

**Parameters:**
- `hours` (optioneel): Terugkijk periode (default: 168 = 1 week)
- `interval` (optioneel): 'hourly' of 'daily' (default: daily)

**Gebruik:**
```
Export daily traffic statistics for the last 3 months
```

**Output:**
- CSV met kolommen: Time Period, Total Packets, Total Bytes, Inbound/Outbound breakdown, Averages
- Interval type
- Aantal data points

**Use Cases:**
- Capacity planning rapporten
- Trend analyse in Excel
- Vergelijking met vorige periodes
- Budget justificatie voor upgrades

---

### 6. `export_top_talkers_csv`
**Doel:** Exporteer top bandwidth consumers naar CSV

**Parameters:**
- `hours` (optioneel): Terugkijk periode (default: 24)
- `limit` (optioneel): Max resultaten (default: 50)
- `direction` (optioneel): Filter op 'inbound' of 'outbound'

**Gebruik:**
```
Export top 100 bandwidth consumers for the last week
```

**Output:**
- CSV met kolommen: IP Address, Hostname, Direction, Total Packets, Total Bytes, MB, GB, Observations, First/Last Seen
- Filters applied

**Use Cases:**
- Bandwidth abuse rapportage
- Facturering per afdeling/gebruiker
- Identificeer data exfiltration
- QoS policy planning

---

## ⚙️ Configuratie Tools

### 7. `get_config`
**Doel:** Huidige NetMonitor configuratie ophalen

**Parameters:**
- `section` (optioneel): Sectie - 'thresholds', 'alerts', 'threat_feeds', of 'all' (default: all)

**Gebruik:**
```
Show me the current threshold configuration
```

**Output:**
- Volledige of gefilterde configuratie uit config.yaml
- Alle instellingen zoals ze actief zijn

**Use Cases:**
- Inzicht in huidige detection settings
- Vergelijk config tussen omgevingen
- Documentatie van settings
- Troubleshooting (welke thresholds zijn actief?)

**Let op:** Read-only - kan **niet** gebruikt worden om config te wijzigen

---

### 8. `get_detection_rules`
**Doel:** Lijst van alle actieve detectie regels met instellingen

**Parameters:** Geen

**Gebruik:**
```
List all active detection rules
```

**Output:**
- Totaal aantal regels
- Aantal actieve regels
- Per regel:
  - Detection type (port_scan, beaconing, etc.)
  - Enabled status
  - Alle instellingen (thresholds, time windows, etc.)

**Use Cases:**
- Quick overview van wat er gemonitord wordt
- Verificatie dat regels enabled zijn
- Fine-tuning planning (welke thresholds aanpassen?)
- Documentatie voor compliance

---

## Hoe te gebruiken in Claude Desktop

Nu je de nieuwe tools hebt (na `git pull` op de server en MCP server restart), kun je vragen zoals:

### Statistiek Queries:
```
"Show me traffic trends for the last week"
"Who are the top 20 bandwidth consumers today?"
"Give me alert statistics for the last month grouped by threat type"
"What are the traffic patterns - hourly breakdown for yesterday"
```

### Export Queries:
```
"Export all CRITICAL alerts from the last 7 days to CSV"
"Generate a CSV report of daily traffic stats for the last month"
"Export the top 100 bandwidth users to CSV"
"Create a CSV of all port scan alerts this week"
```

### Configuratie Queries:
```
"Show me the current port scan detection thresholds"
"List all active detection rules"
"What are the beaconing detection settings?"
"Show me the threat feed configuration"
```

---

## Test de nieuwe tools

Op de server:
```bash
# Pull de nieuwe code
cd /opt/netmonitor
git pull

# Test de MCP server (optioneel)
cd mcp_server
source ../venv/bin/activate
python3 server.py --transport stdio
# Ctrl+C om te stoppen
```

In Claude Desktop:
- Herstart Claude Desktop
- Test een tool: "Show me traffic trends for the last 24 hours"
- Claude zou nu de nieuwe tool moeten kunnen gebruiken!

---

## Database Vereisten

✅ **Alles werkt out-of-the-box!**

De nieuwe tools gebruiken:
- Bestaande `alerts` table
- Bestaande `traffic_metrics` table
- Bestaande `top_talkers` table
- TimescaleDB `time_bucket()` voor efficiente aggregatie

Geen schema wijzigingen nodig! 🎉

---

## Volgende Stappen

**Optioneel - Nog niet geïmplementeerd:**
- [ ] `update_threshold` tool voor live config wijzigingen (vereist write permissions)
- [ ] PDF export tools (vereist extra library: reportlab)
- [ ] Grafiek generatie (vereist matplotlib)
- [ ] Ollama integratie voor AI-powered threat analysis

Laat me weten wat je prioriteit heeft!
