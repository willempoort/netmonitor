# NetMonitor - Device Classification

**ML-based apparaat classificatie met behavior learning en alert suppression**

---

## 📋 Overzicht

Device Classification is een intelligent systeem voor het automatisch herkennen en classificeren van netwerkapparaten. Het systeem leert van verkeerspatronen en kan alerts onderdrukken voor verwacht gedrag per apparaattype.

### Kernfunctionaliteit

- **Device Discovery** - Automatische detectie van apparaten via ARP/IP packets
- **Vendor Identificatie** - MAC address OUI lookup voor fabrikant herkenning
- **Behavior Learning** - Traffic patronen analyseren en leren
- **Template Matching** - Apparaten koppelen aan device templates
- **Alert Suppression** - Verwacht gedrag niet als alert tonen
- **Service Providers** - Streaming/CDN verkeer herkennen

### Machine Learning Capabilities

- **ML Device Classification** - Random Forest classifier voor automatische apparaattype herkenning
- **ML Anomaly Detection** - Isolation Forest voor gedragsafwijkingen detectie per device
- **Auto-Training** - ML modellen automatisch trainen en classificaties toepassen (24-uurs cyclus)
- **Feature Extraction** - 28 features per device voor nauwkeurige classificatie

---

## 🤖 Machine Learning Architectuur

NetMonitor bevat echte Machine Learning voor device classificatie en anomaly detectie. De ML modellen draaien **volledig op de SOC server** - geen impact op sensor RAM.

### ML Components

```
┌─────────────────────────────────────────────────────────────┐
│                    SOC Server                                │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           ML Classifier Manager                       │   │
│  │  - Coördineert training en inference                  │   │
│  │  - Auto-training elke 24 uur                          │   │
│  │  - Auto-classification na training                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│         ┌────────────────┼────────────────┐                 │
│         ▼                ▼                ▼                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Feature   │  │   Device    │  │  Anomaly    │         │
│  │  Extractor  │  │ Classifier  │  │  Detector   │         │
│  │  (28 feat)  │  │(RandomForest)│  │(IsolForest) │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           /var/lib/netmonitor/ml_models/              │   │
│  │  - device_classifier.pkl                              │   │
│  │  - anomaly_detector.pkl                               │   │
│  │  - feature_scaler.pkl                                 │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Device Types (11 klassen)

De ML classifier herkent de volgende apparaattypes:

| Type | Beschrijving | Typische Kenmerken |
|------|--------------|-------------------|
| `workstation` | Desktop/laptop computers | Diverse poorten, HTTP/HTTPS dominant |
| `server` | Servers (web, file, etc.) | Hoge inbound traffic, specifieke poorten |
| `iot_camera` | IP camera's | RTSP (554), ONVIF, constant outbound |
| `iot_sensor` | IoT sensoren | Lage bandwidth, periodiek verkeer |
| `smart_tv` | Smart TV's | Streaming poorten, Netflix/YouTube |
| `nas` | Network Attached Storage | SMB/NFS, hoge opslag traffic |
| `printer` | Netwerkprinters | IPP (631), LPD (515), SMB |
| `smart_speaker` | Smart speakers (Alexa, etc.) | Voice services, streaming |
| `mobile` | Smartphones/tablets | WiFi, diverse apps |
| `network_device` | Routers/switches | Management poorten, SNMP |
| `unknown` | Onbekend | Onvoldoende data |

### Feature Extraction (28 features)

De ML classifier analyseert de volgende features per device:

**Volume Features:**
- `total_bytes_in` - Totaal inkomende bytes
- `total_bytes_out` - Totaal uitgaande bytes
- `bytes_ratio` - Verhouding in/out
- `total_packets` - Totaal aantal packets

**Port Category Features:**
- `web_ports_ratio` - Percentage HTTP/HTTPS traffic
- `streaming_ports_ratio` - Percentage streaming poorten
- `iot_ports_ratio` - Percentage IoT-specifieke poorten
- `server_ports_ratio` - Percentage server poorten
- `other_ports_ratio` - Percentage overige poorten

**Protocol Features:**
- `tcp_ratio` - Percentage TCP traffic
- `udp_ratio` - Percentage UDP traffic
- `icmp_ratio` - Percentage ICMP traffic

**Behavioral Features:**
- `unique_dst_ports` - Aantal unieke destination poorten
- `unique_src_ports` - Aantal unieke source poorten
- `is_server` - Biedt services aan (0/1)
- `has_dns_traffic` - DNS traffic aanwezig (0/1)
- `has_streaming_traffic` - Streaming traffic (0/1)
- `has_iot_traffic` - IoT traffic aanwezig (0/1)
- `is_high_volume` - Hoge traffic volume (0/1)
- `is_low_volume` - Lage traffic volume (0/1)

**Time Features:**
- `activity_hours` - Uren actief per dag
- `burst_ratio` - Verhouding burst vs constant traffic

### ML Configuration

**config.yaml:**
```yaml
ml:
  enabled: true                    # ML inschakelen
  auto_train: true                 # Auto-training bij dashboard start
  auto_classify: true              # Auto-classificatie na training
  auto_train_interval: 86400       # Training interval (seconden)
  min_confidence: 0.7              # Minimum confidence voor auto-assign
  model_dir: /var/lib/netmonitor/ml_models
```

### Training Process

1. **Data Collection**: Verzamel learned_behavior van alle devices
2. **Feature Extraction**: Extraheer 28 features per device
3. **Bootstrap**: Gebruik vendor hints voor initial labels
4. **Model Training**: Train Random Forest classifier
5. **Validation**: Test accuracy op hold-out set
6. **Persistence**: Sla model op naar disk

**Minimum Requirements:**
- 10+ devices met learned_behavior
- 50+ packets per device voor classificatie
- scikit-learn package geïnstalleerd

### API Endpoints

**Internal (localhost only):**
```
GET  /api/internal/ml/status        - ML status en statistieken
POST /api/internal/ml/train         - Trigger training
GET  /api/internal/ml/classify/<ip> - Classificeer device
POST /api/internal/ml/classify-all  - Classificeer alle devices
```

**Authenticated:**
```
GET  /api/ml/status                 - ML status (requires login)
POST /api/ml/train                  - Trigger training (requires login)
GET  /api/ml/classify/<ip>          - Classificeer device
POST /api/ml/classify-all           - Classificeer alle devices
```

---

## 🏗️ Architectuur

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Device Discovery Module                         │
│  - ARP packet monitoring                                     │
│  - IP packet analysis                                        │
│  - MAC address extraction                                    │
│  - OUI vendor lookup                                         │
│  - DNS hostname resolution                                   │
│  - Traffic statistics collection                             │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Behavior Learning Engine                        │
│  - Port usage patterns                                       │
│  - Protocol distribution                                     │
│  - Destination analysis                                      │
│  - Traffic volume profiling                                  │
│  - Connection behavior                                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Behavior Matcher                                │
│  - Template rule matching                                    │
│  - Service provider detection                                │
│  - Alert suppression decisions                               │
│  - Never suppresses: CRITICAL, Threat Feed, C2              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Database                                  │
│  - devices                                                   │
│  - device_templates                                          │
│  - template_behaviors                                        │
│  - service_providers                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Enterprise Security Integration

Device Classification integreert naadloos met de enterprise security modules voor context-aware detectie.

### Kill Chain Correlatie

Apparaattype beïnvloedt de kill chain stage-mapping:
- **Server**: Credential access alerts krijgen hogere prioriteit
- **Workstation**: Initial access en execution alerts worden nauwer gemonitord
- **IoT**: Lateral movement naar IoT devices triggert extra alerts

### Asset Risk Scoring

Apparaatcategorie bepaalt de risk score multiplier:

| Categorie | Multiplier | Rationale |
|-----------|------------|-----------|
| server | 1.5x | Kritieke infrastructuur |
| workstation | 1.0x | Standaard |
| iot | 1.2x | Vaak kwetsbaar |
| network_device | 1.5x | Infrastructuur pivot point |
| unknown | 1.0x | Baseline |

### SOAR Integration

Device templates kunnen SOAR playbooks beïnvloeden:
- **Server templates**: Voorzichtiger met isolatie-acties
- **IoT templates**: Snellere blokkering geoorloofd
- **Kritieke assets**: Require approval altijd ingeschakeld

### Kerberos & SMB Context

Device classificatie verbetert protocol detectie:
- Alleen servers moeten SMB shares aanbieden
- Workstations die als "server" fungeren triggeren alerts
- IoT devices met Kerberos traffic zijn verdacht

---

## 📊 Database Schema

### devices
```sql
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    mac_address MACADDR,
    hostname VARCHAR(255),
    template_id INTEGER REFERENCES device_templates(id),
    sensor_id TEXT REFERENCES sensors(sensor_id),
    learned_behavior JSONB DEFAULT '{}',
    classification_confidence REAL DEFAULT 0.0,
    classification_method VARCHAR(50),  -- 'manual', 'auto', 'learned'
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    notes TEXT,
    CONSTRAINT unique_device_per_sensor UNIQUE (ip_address, sensor_id)
);
```

### device_templates
```sql
CREATE TABLE device_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    icon VARCHAR(50) DEFAULT 'device',
    category VARCHAR(50) DEFAULT 'other',  -- 'iot', 'server', 'endpoint', 'other'
    is_builtin BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(50)
);
```

### template_behaviors
```sql
CREATE TABLE template_behaviors (
    id SERIAL PRIMARY KEY,
    template_id INTEGER NOT NULL REFERENCES device_templates(id),
    behavior_type VARCHAR(50) NOT NULL,  -- allowed_ports, allowed_protocols, etc.
    parameters JSONB NOT NULL DEFAULT '{}',
    action VARCHAR(20) DEFAULT 'allow',  -- 'allow', 'alert', 'suppress'
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### service_providers
```sql
CREATE TABLE service_providers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,  -- 'streaming', 'cdn', 'cloud', etc.
    ip_ranges JSONB DEFAULT '[]',
    domains JSONB DEFAULT '[]',
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    is_builtin BOOLEAN DEFAULT FALSE
);
```

---

## 🖥️ Web Dashboard

### Device Classification Sectie

De Device Classification sectie is beschikbaar in het hoofddashboard als een collapsible panel.

#### Devices Tab

Toont alle ontdekte apparaten met:
- IP Address en Hostname
- MAC Address en Vendor (via OUI lookup)
- Toegewezen Template
- Learning Status badge:
  - `Not Started` - Geen traffic geanalyseerd
  - `Learning (N)` - N packets geanalyseerd, nog onvoldoende
  - `Ready` - Voldoende data voor template generatie

**Acties:**
- Klik op device voor details modal
- Zoeken op IP, hostname, MAC of vendor
- Filteren op template of "Unclassified"

#### Templates Tab

Grid view van alle device templates met:
- Template naam en icoon
- Categorie badge (IoT, Server, Endpoint, Other)
- Type badge (Built-in of Custom)
- Aantal gekoppelde devices

**Acties:**
- "New Template" voor handmatige template
- Klik op template voor details en behavior rules

#### Service Providers Tab

Tabel van streaming/CDN providers:
- Netflix, Spotify, YouTube, etc. (built-in)
- Custom providers toevoegen

**Gebruik:**
- Traffic naar bekende providers wordt niet als verdacht gemarkeerd
- Streaming devices kunnen hoge bandwidth hebben zonder alerts

#### Statistics Tab

Overzicht van classificatie metrics:
- Totaal aantal devices
- Geclassificeerd vs. ongeclassificeerd
- Verdeling per template
- Verdeling per vendor

---

## 🔧 Device Details Modal

Bij klikken op een device:

### Device Information
- IP Address, Hostname
- MAC Address, Vendor

### Template Assignment
- Dropdown om template te selecteren
- "Assign" knop voor handmatige toewijzing

### Behavior Learning
- Packets Analyzed counter
- Unique Ports counter
- Status indicator

### Classification Hints
Automatische suggesties gebaseerd op:
- Hostname patronen (bijv. "cam" → IP Camera)
- Server ports (bijv. port 554 → IP Camera/RTSP)
- Vendor identificatie

### Create Template from Device
Als voldoende data beschikbaar (50+ packets):
- Template naam invoeren
- Categorie selecteren
- Template wordt automatisch gegenereerd met:
  - Geleerde poorten
  - Protocollen
  - Traffic patronen

---

## 📡 API Endpoints

### Devices

```
GET    /api/devices                           - Lijst alle devices
GET    /api/devices/{ip}                      - Device details
PUT    /api/devices/{ip}/template             - Template toewijzen
DELETE /api/devices/{ip}                      - Device verwijderen
GET    /api/devices/{ip}/traffic-stats        - Traffic statistieken
GET    /api/devices/{ip}/classification-hints - Classificatie suggesties
GET    /api/devices/{ip}/learning-status      - Learning voortgang
POST   /api/devices/{ip}/save-learned-behavior - Learned behavior opslaan
```

### Templates

```
GET    /api/device-templates                  - Lijst alle templates
GET    /api/device-templates/{id}             - Template details + behaviors
POST   /api/device-templates                  - Nieuw template maken
PUT    /api/device-templates/{id}             - Template updaten
DELETE /api/device-templates/{id}             - Template verwijderen (niet builtin)
POST   /api/device-templates/{id}/behaviors   - Behavior rule toevoegen
DELETE /api/device-templates/behaviors/{id}   - Behavior rule verwijderen
POST   /api/device-templates/from-device      - Template van device maken
```

### Service Providers

```
GET    /api/service-providers                 - Lijst alle providers
GET    /api/service-providers/{id}            - Provider details
POST   /api/service-providers                 - Provider toevoegen
PUT    /api/service-providers/{id}            - Provider updaten
DELETE /api/service-providers/{id}            - Provider verwijderen
GET    /api/service-providers/check-ip?ip=x   - Check IP tegen providers
```

### Statistics

```
GET    /api/device-classification/stats       - Classificatie statistieken
GET    /api/suppression/stats                 - Alert suppression stats
POST   /api/suppression/test                  - Test of alert onderdrukt wordt
```

---

## 🤖 MCP Tools

De volgende MCP tools zijn beschikbaar voor AI integratie:

### Device Management
- `get_devices` - Lijst devices met filters
- `get_device_by_ip` - Device details ophalen
- `assign_device_template` - Template toewijzen
- `get_device_traffic_stats` - Traffic statistieken
- `get_device_classification_hints` - Classificatie suggesties

### Behavior Learning
- `get_device_learning_status` - Learning voortgang
- `get_device_learned_behavior` - Geleerd gedrag ophalen
- `save_device_learned_behavior` - Gedrag opslaan
- `create_template_from_device` - Template genereren

### Templates & Providers
- `get_device_templates` - Lijst templates
- `get_device_template_details` - Template met behaviors
- `get_service_providers` - Lijst providers
- `check_ip_service_provider` - IP check

### Alert Suppression
- `get_alert_suppression_stats` - Suppression statistieken
- `test_alert_suppression` - Test suppression voor IP/alert type

---

## ⚙️ Configuratie

In `config.yaml`:

```yaml
device_discovery:
  enabled: true
  # DNS reverse lookup voor hostnames
  dns_lookup: true
  dns_cache_ttl: 3600  # seconden
  # OUI database voor vendor lookup
  oui_lookup: true
  # Traffic statistieken verzamelen
  collect_traffic_stats: true
  # Automatisch learned behavior opslaan
  auto_save_behavior: true
  save_interval: 300  # seconden
```

---

## 🔒 Alert Suppression Regels

### Wat wordt NOOIT onderdrukt

Ongeacht template configuratie worden deze alerts altijd getoond:

1. **CRITICAL severity** - Altijd actie vereist
2. **Threat Feed matches** - Bekende malicious IPs
3. **C2 communicatie** - Command & Control detectie
4. **AbuseIPDB high confidence** - Bevestigde malicious IPs

### Bidirectional Template Checking

Alert suppression controleert nu **zowel source als destination** devices:

1. **Source device template (outbound)**: Mag dit device dit verkeer VERZENDEN?
2. **Destination device template (inbound)**: Mag dit device dit verkeer ONTVANGEN?

Dit betekent dat bijvoorbeeld:
- Een Home Assistant server geen alerts genereert voor inkomende verbindingen
- Een NAS geen alerts genereert wanneer clients verbinden voor file sharing
- Een printer geen alerts genereert bij print jobs van interne clients

### Behavior Types

Templates kunnen de volgende behavior types definiëren:

| Type | Parameters | Richting | Beschrijving |
|------|------------|----------|--------------|
| `allowed_ports` | `ports: [80, 443]`, `direction: inbound/outbound` | Beide | Toegestane poorten |
| `allowed_protocols` | `protocols: [TCP, UDP]` | Beide | Toegestane protocollen |
| `allowed_sources` | `internal: true`, `subnets: [...]` | Inbound | Toegestane bronnen (nieuw!) |
| `expected_destinations` | `destinations: [...]` | Outbound | Verwachte bestemmingen |
| `traffic_pattern` | `high_bandwidth: true` | Beide | Verwacht verkeerspatroon |
| `connection_behavior` | `accepts_connections: true`, `api_server: true` | Inbound | Server connectie gedrag |
| `bandwidth_limit` | `max_mbps: 100` | Beide | Bandwidth limiet |

### Direction Parameter

De `direction` parameter bepaalt wanneer een regel wordt toegepast:

| Direction | Wanneer toegepast | Voorbeeld |
|-----------|-------------------|-----------|
| `inbound` | Device is **destination** | Server ontvangt verbindingen |
| `outbound` | Device is **source** | Client maakt verbindingen |
| (geen) | Beide richtingen | Algemene regels |

---

## 📈 Behavior Learning Process

### Fase 1: Data Collectie

Het systeem verzamelt per device:
- Source en destination ports
- Protocol distributie (TCP/UDP/ICMP)
- Bytes in/out
- Unique destinations
- Connection rates

### Fase 2: Patroon Analyse

Na voldoende packets (default: 100):
- Typical ports (top 20 meest gebruikte)
- Server ports (inbound connections)
- Protocol mix
- Traffic pattern classificatie:
  - `streaming` - Hoge bandwidth, weinig connecties
  - `server` - Veel inbound connecties
  - `client` - Voornamelijk outbound
  - `periodic` - Regelmatige kleine bursts
  - `continuous` - Constante traffic

### Fase 3: Template Generatie

Bij "Create Template from Device":
1. Automatic port rules gebaseerd op observed traffic
2. Protocol rules van gebruikte protocollen
3. Traffic pattern rule van gedetecteerd patroon
4. Template direct toegewezen aan source device

---

## 🏷️ Built-in Templates

De volgende templates worden automatisch aangemaakt:

| Template | Categorie | Typische Behaviors |
|----------|-----------|-------------------|
| IP Camera | IoT | RTSP (554), HTTP (80/443), NTP |
| Smart TV | IoT | Streaming ports, high bandwidth |
| Smart Speaker | IoT | Voice services, streaming |
| Network Printer | IoT | IPP (631), LPD (515), SMB, **inbound print jobs** |
| Home Automation Hub | IoT | HTTP (8123), MQTT, **inbound van smart devices** |
| NAS/File Server | Server | SMB (445), NFS, AFP, **inbound file access** |
| Web Server | Server | HTTP (80), HTTPS (443), **inbound web requests** |
| Database Server | Server | MySQL, PostgreSQL, MongoDB, **inbound queries** |
| Workstation | Endpoint | Mixed traffic, web browsing |
| Mobile Device | Endpoint | App traffic, sync services |

---

## 🔄 Migration

Voor bestaande installaties:

```bash
# Run migration script
python3 migrate_device_classification.py

# Optioneel: importeer streaming filters uit config.yaml
python3 migrate_device_classification.py --import-config
```

De migration script:
- Creëert nieuwe database tabellen
- Voegt built-in templates toe
- Voegt built-in service providers toe (Netflix, Spotify, etc.)
- Importeert optioneel bestaande streaming filters

---

## 📊 Voorbeeld Workflows

### 1. Nieuwe IP Camera classificeren

```
1. Camera verschijnt in Devices tab als "Unclassified"
2. Learning status: "Learning (45)" → wacht op meer traffic
3. Status wordt "Ready" na 100+ packets
4. Klik op device → zie "Suggested Templates: IP Camera"
5. Of: Create Template from Device → "Woonkamer Camera"
6. Template automatisch toegewezen
7. RTSP/HTTP traffic genereert geen alerts meer
```

### 2. Custom streaming service toevoegen

```
1. Ga naar Service Providers tab
2. Klik "New Provider"
3. Naam: "Custom CDN"
4. Category: "cdn"
5. IP Ranges: "203.0.113.0/24"
6. Save
7. Traffic naar deze IPs wordt als bekend gemarkeerd
```

### 3. Template behavior aanpassen

```
1. Ga naar Templates tab
2. Klik op custom template
3. Bekijk huidige behaviors
4. Voeg via API nieuwe behavior toe:
   POST /api/device-templates/{id}/behaviors
   {
     "behavior_type": "allowed_ports",
     "parameters": {"ports": [8080], "direction": "inbound"},
     "action": "allow"
   }
```

---

## 🐛 Troubleshooting

### Devices worden niet ontdekt

- Check of `device_discovery.enabled: true` in config.yaml
- Verify dat netmonitor draait met root/sudo (voor packet capture)
- Check logs: `sudo journalctl -u netmonitor -f`

### Learning status blijft "Not Started"

- Device moet actief traffic genereren
- ARP packets alleen zijn niet voldoende
- Check of device IP in monitored network range zit

### Alerts worden niet onderdrukt

- Verify dat device een template heeft toegewezen
- Check of de alert type gedekt wordt door template behaviors
- CRITICAL alerts worden nooit onderdrukt (by design)
- Threat feed matches worden nooit onderdrukt

### Template from Device mislukt

- Minimaal 50 packets vereist
- Check learned_behavior in database:
  ```sql
  SELECT learned_behavior FROM devices WHERE ip_address = '192.168.1.x';
  ```

---

## 📚 Gerelateerde Documentatie

- [Detection Features](DETECTION_FEATURES.md) - Threat detection capabilities
- [MCP HTTP API](MCP_HTTP_API.md) - API documentatie
- [Config Guide](../usage/CONFIG_GUIDE.md) - Configuratie opties
- [Admin Manual](../usage/ADMIN_MANUAL.md) - Beheer en troubleshooting

---

**Last Updated:** December 2024
