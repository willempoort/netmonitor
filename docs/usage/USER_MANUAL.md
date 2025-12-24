# NetMonitor SOC - User Manual

**SOC Operator Guide for Daily Operations**

Version: 2.2
Last Updated: December 2025

---

## 📋 Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Monitoring Alerts](#monitoring-alerts)
4. [Managing Sensors](#managing-sensors)
5. [Configuration](#configuration)
6. [Whitelist Management](#whitelist-management)
7. [Device Classification](#device-classification)
8. [AI Integration (MCP Server)](#ai-integration-mcp-server)
9. [Common Tasks](#common-tasks)
10. [Best Practices](#best-practices)

---

## Getting Started

### Logging In

NetMonitor v2.0+ requires authentication to access the dashboard.

**URL:** `http://your-soc-server:8181/`

1. **Enter your credentials:**
   - Username (provided by your administrator)
   - Password (minimum 12 characters)

2. **Two-Factor Authentication** (if enabled):
   - After entering username/password, you'll be prompted for a 6-digit code
   - Open your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.)
   - Enter the 6-digit code shown for "NetMonitor SOC"
   - Or use a backup code if you've lost access to your authenticator

3. **Access granted:**
   - You'll be redirected to the main dashboard
   - Your session will remain active for 30 minutes of inactivity

**First-Time Login:**
If this is your first time logging in, consider:
- Setting up Two-Factor Authentication for enhanced security (User menu → "Two-Factor Auth")
- Changing your temporary password (User menu → "Profile Settings")

### Account Types

Your permissions depend on your role:

| Role | What You Can Do |
|------|-----------------|
| **Viewer** | View dashboard, alerts, sensors, and metrics (read-only) |
| **Operator** | Everything Viewer can do + manage sensors, acknowledge alerts, edit configurations |
| **Admin** | Everything + user management, create/delete users, system configuration |

### User Menu

In the top-right corner, you'll find your username with a dropdown menu:

- **Profile Settings** - View your account details and change password
- **Two-Factor Auth** - Enable/disable 2FA for your account
- **User Management** (admin only) - Create and manage user accounts
- **Logout** - End your session

### Accessing the Dashboard

After logging in, the dashboard opens automatically to the main monitoring view with:
- Real-time alert feed
- Traffic visualizations
- System metrics
- Top talkers

### Dashboard Layout

```
┌────────────────────────────────────────────────────────────┐
│  NetMonitor SOC Dashboard                    🔔 🔄 ⚙️  │
├────────────────────────────────────────────────────────────┤
│  [Alerts] [Sensors] [Config] [Whitelist]                  │
├──────────────────┬─────────────────────────────────────────┤
│                  │  Real-Time Alert Feed                   │
│  System Metrics  │  ┌──────────────────────────────────┐  │
│  ┌─────────────┐ │  │ HIGH - Port Scan Detected        │  │
│  │ CPU: 45%    │ │  │ 192.168.1.100 → Multiple ports   │  │
│  │ RAM: 62%    │ │  └──────────────────────────────────┘  │
│  │ Alerts: 12  │ │  ┌──────────────────────────────────┐  │
│  └─────────────┘ │  │ MEDIUM - High Traffic            │  │
│                  │  │ 10.0.0.50 → 500 Mbps             │  │
│  Traffic Graphs  │  └──────────────────────────────────┘  │
│                  │                                         │
└──────────────────┴─────────────────────────────────────────┘
```

---

## Dashboard Overview

### Main Dashboard

**What you see:**

1. **Alert Feed** (center):
   - Real-time security alerts
   - Color-coded by severity (RED/ORANGE/YELLOW)
   - Auto-scrolls with new alerts
   - Click alert for details

2. **System Metrics** (left):
   - CPU usage gauge
   - Memory usage gauge
   - Packets/second counter
   - Alerts/minute counter

3. **Traffic Visualizations**:
   - Bandwidth graph (last hour)
   - Packets/second graph
   - Protocol distribution

4. **Top Talkers**:
   - IPs with most traffic
   - Shows hostname when available
   - Inbound/outbound breakdown
   - Country flags for external IPs (GeoIP lookup)

### Navigation Tabs

**🚨 Alerts Tab**
- Main alert monitoring view
- Filter by severity
- Search alerts
- Acknowledge alerts

**🖥️ Sensors Tab**
- View all deployed sensors
- Monitor sensor health
- Manage sensor settings
- Control sensor operations

**⚙️ Configuration Tab**
- Detection rule settings
- Threshold adjustments
- Alert management
- Performance tuning

**📋 Whitelist Tab**
- Manage trusted IPs
- Add/remove whitelist entries
- Scope: global or per-sensor

---

## Monitoring Alerts

### Alert Types

**Port Scan Detection** 🔴 HIGH
```
Source IP scanning multiple ports
Indicates: Reconnaissance activity
Action: Investigate source, block if malicious
```

**Brute Force Attack** 🔴 HIGH
```
Multiple failed login attempts
Indicates: Password guessing attack
Action: Block source IP, check target system
```

**DNS Tunneling** 🟠 MEDIUM
```
Suspicious DNS query patterns
Indicates: Data exfiltration or C2 communication
Action: Analyze DNS queries, investigate client
```

**DDoS Attack** 🔴 HIGH
```
Abnormally high traffic volume
Indicates: Denial of service attempt
Action: Activate DDoS mitigation, contact ISP
```

**Protocol Anomaly** 🟡 LOW
```
Unusual protocol behavior
Indicates: Misconfiguration or evasion attempt
Action: Investigate protocol usage
```

### Alert Workflow

**1. Alert Appears:**
- Dashboard shows alert in feed
- Sound notification (if enabled)
- Counter increments

**2. Investigate:**
- Click alert for details
- Check source/destination IPs
- Review traffic patterns
- Check logs

**3. Take Action:**
- **False Positive**: Add to whitelist
- **Real Threat**: Block IP, investigate further
- **Unclear**: Monitor for pattern

**4. Acknowledge:**
- Mark alert as reviewed
- Add notes (if available)
- Track in incident log

### GeoIP Country Information

External IP addresses in alerts and top talkers display country information:

**Display Format:**
- Country flag emoji + country code (e.g., 🇺🇸 US, 🇳🇱 NL, 🇩🇪 DE)
- "Local" for internal/private IP ranges
- "Unknown" if GeoIP lookup fails

**How It Works:**
- NetMonitor looks up IP addresses in a local GeoIP database (if installed)
- Falls back to online API if no local database
- Internal IPs (10.x.x.x, 192.168.x.x, etc.) are marked as "Local"

**Using Country Information:**
- Identify attacks from specific regions
- Spot unusual traffic patterns (e.g., connections to unexpected countries)
- Correlate with threat intelligence

### Filtering Alerts

**By Severity:**
- Click severity badge to filter
- RED (High) / ORANGE (Medium) / YELLOW (Low)

**By Time:**
- Last hour / 6 hours / 24 hours / 7 days
- Custom date range

**By Source:**
- Filter by sensor
- Filter by source IP
- Filter by alert type
- Filter by country

---

## Managing Sensors

### Sensor Overview

**Sensors Tab** shows all deployed sensors with:
- 🟢 Status (Online/Offline)
- Hostname
- Location
- IP address
- Performance metrics (CPU, RAM, Bandwidth)
- Last seen timestamp
- Action buttons

### Sensor Actions

**🔄 Update** (Blue button)
```
Updates sensor software from git
- Prompts for branch (optional)
- Pulls latest code
- Restarts sensor automatically
- ~30 seconds downtime
```

**⚡ Reboot** (Yellow button)
```
Reboots the entire sensor system
- Full system restart
- ~1-5 minutes downtime
- Use for system-level issues
- Requires confirmation (type sensor name)
```

**🎚️ Settings** (Cyan button)
```
Edit sensor configuration
- Location description
- Custom parameters
- Saved to central database
- Sensor picks up within 5 minutes
```

**🗑️ Delete** (Red button)
```
Permanently removes sensor
- Deletes all metrics
- Deletes all alerts
- Cannot be undone
- Use when decommissioning
```

### Managing Sensor Settings

**Advanced Sensor Configuration:**

Each sensor can be configured with detailed settings via the dashboard. Click the Settings icon (sliders 🎚️) next to any sensor to access the sensor settings modal.

**Available Settings:**

1. **Sensor Location**
   - Physical location or network segment description
   - Examples: "Office VLAN 10", "DMZ Gateway", "Branch Office Amsterdam"
   - Helps identify which part of your network the sensor monitors
   - Shows in dashboard for quick reference

2. **Internal Networks**
   - Define your internal network CIDR ranges
   - One range per line
   - Examples:
     ```
     10.0.0.0/8
     172.16.0.0/12
     192.168.0.0/16
     ```
   - Used for detection logic (internal vs external traffic)
   - Helps identify lateral movement and internal scanning

3. **Heartbeat Interval**
   - How often the sensor sends heartbeat signals to SOC
   - Range: 10-300 seconds
   - Default: 30 seconds
   - Lower = faster offline detection, higher network overhead
   - Higher = less network traffic, slower offline detection

4. **Config Sync Interval**
   - How often sensor checks for configuration updates
   - Range: 60-3600 seconds (1 minute to 1 hour)
   - Default: 300 seconds (5 minutes)
   - Lower = faster config updates, more database queries
   - Higher = less overhead, slower config propagation

**How to Configure:**

1. Navigate to **Sensors Tab**
2. Click the **Settings** icon (🎚️) next to the sensor
3. Sensor settings modal opens
4. Edit the desired settings:
   - Update location description
   - Add/modify internal network ranges
   - Adjust heartbeat interval
   - Adjust config sync interval
5. Click **"Save Settings"**
6. Settings are saved to central database
7. Sensor automatically picks up changes within the sync interval
8. For immediate application: use the Update or Reboot button

**Important Notes:**
- All settings are stored centrally in the SOC database
- Sensors automatically synchronize settings at their configured interval
- No need to manually edit sensor.conf files
- Changes apply to the specific sensor only (not global)
- Always test settings changes on one sensor before rolling out to all

### Monitoring Sensor Health

**Green Status**: Sensor is healthy
- Sending metrics regularly
- No performance issues
- Last seen < 2 minutes ago

**Red Status**: Sensor has issues
- No communication for > 5 minutes
- High CPU/RAM usage
- Network problems

**Actions for Offline Sensor:**
1. Check sensor logs: `journalctl -u netmonitor-sensor -f`
2. Verify network connectivity
3. Check SOC server accessibility
4. Restart sensor if needed

---

## Configuration

### Centralized Configuration Management

**Modern Approach:**

NetMonitor SOC uses a centralized configuration system. All sensor settings (except basic connection parameters) are managed through the dashboard and synchronized automatically.

**Sensor-Side Configuration (sensor.conf):**

Sensors only need minimal local configuration:
```ini
INTERFACE=eth0
SOC_SERVER_URL=http://soc.example.com:8080
SSL_VERIFY=true
SENSOR_SECRET_KEY=optional-secret-key
```

**Centrally Managed Settings:**
- Sensor location and description
- Internal network ranges (CIDR)
- Detection rule thresholds
- Heartbeat and sync intervals
- Alert severity levels
- Custom detection parameters

**How It Works:**
1. Configure settings via dashboard (Sensors → Settings or Configuration tab)
2. Settings stored in SOC database
3. Sensors poll for updates at configured sync interval (default: 5 minutes)
4. Sensors automatically apply new settings
5. No manual file editing required on sensor systems

**Benefits:**
- Consistent configuration across all sensors
- Easy bulk updates
- Version control and audit trail
- No need to SSH into sensor systems
- Per-sensor customization when needed

### Detection Rules

**Configuration → Detection Rules Tab**

**Available Rules:**
1. Port Scan Detection
2. Brute Force Detection
3. DNS Tunneling Detection
4. Large File Transfer Detection
5. DDoS Detection
6. Unusual Port Activity
7. Internal Scanning
8. Protocol Anomaly Detection
9. Beacon Detection
10. Data Exfiltration Detection
11. Malware Communication Detection
12. Lateral Movement Detection
13. Suspicious DNS Detection

**For Each Rule:**
- ☑️ Enable/Disable checkbox
- 📊 Threshold values
- 📝 Description and purpose
- 🌍 Scope: Global or per-sensor

### Adjusting Thresholds

**Example: Port Scan Detection**

```
Threshold: Number of unique ports before alert
Default: 10 ports
Too many alerts: Increase to 20-30
Missing scans: Decrease to 5-10
```

**Example: Brute Force Detection**

```
Threshold: Failed attempts before alert
Default: 5 attempts
Strong security: 3 attempts
Reduce noise: 10 attempts
```

### Configuration Workflow

1. **Navigate to Configuration tab**
2. **Select category** (Detection Rules / Thresholds / etc.)
3. **Adjust values** in the form
4. **Choose scope**:
   - Global: Applies to all sensors
   - Sensor-specific: Override for one sensor
5. **Click "Save Changes"**
6. **Wait for sync** (sensors update within 5 minutes)
7. **Force immediate**: Restart sensor

### Resetting Configuration

**Reset to Defaults:**
- Click "Reset to Best Practice Defaults"
- Confirms destructive action
- Reverts all settings to recommended values
- Use when configuration is misconfigured

---

## Whitelist Management

### Why Whitelist?

Prevent false positives from:
- Internal servers
- Trusted external services
- Backup systems
- Monitoring tools
- Admin workstations

### Adding Whitelist Entries

**Whitelist Tab → Add Entry**

**Single IP:**
```
IP/CIDR: 192.168.1.50
Description: Admin workstation
Scope: Global
```

**IP Range (CIDR):**
```
IP/CIDR: 10.0.0.0/8
Description: Internal network
Scope: Global
```

**Per-Sensor Whitelist:**
```
IP/CIDR: 203.0.113.100
Description: External backup server
Scope: Sensor-specific
Sensor: office-vlan10-01
```

### Managing Whitelist

**View Entries:**
- Global whitelist (applies to all)
- Sensor-specific entries
- Shows IP, description, scope

**Remove Entry:**
- Click delete button
- Confirms action
- Sensor picks up within 5 minutes

---

## Device Classification

### Wat is Device Classification?

Device Classification is een intelligent systeem dat automatisch apparaten in uw netwerk herkent, hun gedrag leert en alerts onderdrukt voor verwacht verkeer. Dit vermindert "alert fatigue" door alleen te waarschuwen bij **afwijkend** gedrag.

**Voordelen:**
- 🔍 **Automatische herkenning** - Apparaten worden automatisch gedetecteerd via ARP/IP packets
- 📚 **Gedrag leren** - Het systeem leert welk verkeer normaal is per apparaat
- 🔇 **Alert suppressie** - Verwacht gedrag genereert geen alerts (behalve CRITICAL/C2)
- 📺 **Streaming herkenning** - Netflix, YouTube, Teams verkeer wordt als normaal gezien
- 🏷️ **Templates** - Groepeer apparaten per type (IP Camera, Smart TV, Server, etc.)

### Device Classification Openen

**Locatie:** Hoofddashboard → Sectie "Device Classification" (klik om uit te klappen)

**Header badges:**
- **Blauw getal**: Totaal aantal ontdekte apparaten
- **Groen getal**: Aantal geclassificeerde apparaten (met template)

### Tabbladen Overzicht

De Device Classification sectie bevat 4 tabbladen:

| Tab | Functie |
|-----|---------|
| **Devices** | Alle ontdekte apparaten bekijken en beheren |
| **Templates** | Apparaatprofielen maken en beheren |
| **Service Providers** | Streaming/CDN diensten configureren |
| **Statistics** | Overzicht en statistieken |

---

### Devices Tab

#### Apparatenlijst

De apparatenlijst toont alle ontdekte apparaten met:

| Kolom | Beschrijving |
|-------|--------------|
| **IP Address** | IP-adres van het apparaat (met CIDR notatie) |
| **Hostname** | Hostname indien beschikbaar via DNS |
| **MAC / Vendor** | MAC-adres en fabrikant (via OUI lookup uit 30.000+ entries) |
| **Template** | Toegewezen template of "Unclassified" |
| **Learning Status** | Voortgang van gedrag leren |
| **Last Seen** | Wanneer het apparaat laatst verkeer genereerde |
| **Actions** | Actieknoppen |

**Tip:** De MAC vendor database bevat 30.000+ fabrikanten inclusief populaire IoT merken zoals Sonos, Philips Hue, Shelly, Tuya, en meer. Administrators kunnen de database bijwerken met `python3 update_oui_database.py`.

#### Learning Status

| Status | Betekenis | Actie |
|--------|-----------|-------|
| **Not Started** | Nog geen verkeer geanalyseerd | Wacht op verkeer |
| **Learning (N)** | N packets geanalyseerd, <100 | Laat meer verkeer door |
| **Ready** | 100+ packets, profiel compleet | Template kan worden gegenereerd |

#### Zoeken en Filteren

**Zoekbalk:**
Zoek op IP-adres, hostname, MAC-adres of vendor naam.

**Template Filter:**
- **All Templates**: Toon alle apparaten
- **Unclassified**: Alleen apparaten zonder template
- **[Template naam]**: Alleen apparaten met specifieke template

#### Apparaat Details Bekijken

Klik op een rij om de apparaat details modal te openen:

**Basisinformatie:**
- IP-adres
- Hostname
- MAC-adres
- Vendor/fabrikant

**Template Toewijzen:**
- Selecteer een template uit de dropdown
- Klik "Apply Template"
- Het apparaat wordt geclassificeerd

**Learning Statistics:**
- **Packets Analyzed**: Aantal geanalyseerde packets
- **Unique Ports**: Aantal unieke poorten gezien
- **Learning Status**: Huidige status

**Classification Hints:**
Tips gebaseerd op geobserveerd gedrag, bijvoorbeeld:
- "Device uses port 554 (RTSP) - likely an IP Camera"
- "High DNS traffic detected - could be a DNS server"

**Template Genereren:**
Als Learning Status "Ready" is (100+ packets):
- Klik "Create Template from Learned Behavior"
- Vul een naam in (bijv. "Woonkamer TV")
- Het systeem genereert automatisch behavior rules

---

### Templates Tab

#### Templates Overzicht

Templates definiëren verwacht gedrag per apparaattype. Ze bevatten regels die bepalen welk verkeer normaal is.

**Template Kaarten:**

Elke template toont:
- **Icoon**: Visuele representatie van het apparaattype
- **Naam**: Template naam
- **Categorie**: IoT, Network, Server, Workstation, etc.
- **Type badge**: "Built-in" (standaard) of "Custom" (zelfgemaakt)
- **Device count**: Aantal apparaten met deze template

**Filteren op Categorie:**
Gebruik de category dropdown om templates te filteren:
- All Categories
- IoT (cameras, smart home)
- Network (routers, switches)
- Server (web servers, databases)
- Workstation (PCs, laptops)
- Mobile (telefoons, tablets)

#### Built-in Templates

NetMonitor wordt geleverd met standaard templates:

| Template | Categorie | Typisch Gedrag |
|----------|-----------|----------------|
| **IP Camera** | IoT | RTSP (554), ONVIF, beperkte bestemmingen |
| **Smart TV** | IoT | Streaming poorten, Netflix/YouTube |
| **Network Printer** | IoT | Poort 9100, IPP, SMB |
| **Router/Firewall** | Network | Alle poorten, management interfaces |
| **DNS Server** | Server | Poort 53, hoge DNS traffic |
| **Web Server** | Server | Poort 80, 443, hoge HTTP traffic |
| **Workstation** | Workstation | Brede poortrange, diverse bestemmingen |

**Let op:** Built-in templates kunnen niet worden gewijzigd of verwijderd.

#### Template Details

Klik op een template kaart om details te bekijken:

**Template Info:**
- Naam
- Categorie
- Type (Built-in/Custom)
- Beschrijving

**Behavior Rules:**
Lijst van regels die bepalen wat "normaal" gedrag is:
- Type regel
- Waarde/parameters
- Actie (Allow/Suppress/Alert)
- Beschrijving

**Apparaten met deze Template:**
Lijst van alle apparaten die deze template gebruiken.

#### Custom Template Maken

**Methode 1: Handmatig**

1. Klik "Create Template" knop
2. Vul in:
   - **Name**: Unieke naam (bijv. "VoIP Telefoon")
   - **Category**: Selecteer categorie
   - **Icon**: Kies een icoon
   - **Description**: Omschrijving van het apparaattype
3. Klik "Create"
4. Open de nieuwe template om Behavior Rules toe te voegen

**Methode 2: Vanuit Geleerd Gedrag**

1. Ga naar Devices tab
2. Klik op een apparaat met "Ready" learning status
3. Klik "Create Template from Learned Behavior"
4. Het systeem genereert automatisch rules gebaseerd op geobserveerd verkeer
5. Geef de template een naam
6. Pas rules aan indien nodig

#### Template Verwijderen

1. Open template details
2. Klik "Delete Template" (rode knop)
3. Bevestig verwijdering

**Let op:**
- Built-in templates kunnen niet worden verwijderd
- Apparaten met deze template worden "Unclassified"

---

### Behavior Rules

Behavior Rules definiëren wat "normaal" gedrag is voor een apparaattype. Verkeer dat matcht met deze regels genereert geen alerts.

#### Rule Types

| Type | Beschrijving | Voorbeeld Waarde |
|------|--------------|------------------|
| **allowed_ports** | Toegestane poorten | `443` of `5060-5090` of `80,443,8080` |
| **allowed_protocols** | Toegestane protocollen | `TCP`, `UDP`, `ICMP` |
| **bandwidth_limit** | Maximum bandbreedte | `100` (MB per uur) |
| **connection_behavior** | Connectie gedrag | `50` (max connecties) |
| **expected_destinations** | Verwachte bestemmingen | `8.8.8.8` of `*.google.com` |
| **time_restrictions** | Tijdsbeperkingen | `08:00-18:00` |
| **dns_behavior** | DNS gedrag | `*.netflix.com` |
| **traffic_pattern** | Verkeerspatroon | `bidirectional` |

#### Rule Actions

| Actie | Effect |
|-------|--------|
| **Allow** | Verkeer wordt als normaal beschouwd, alerts worden onderdrukt |
| **Suppress** | Alerts worden volledig verborgen |
| **Alert** | Altijd een alert genereren (voor monitoring) |

**Belangrijk:** CRITICAL en C2/Threat alerts worden **NOOIT** onderdrukt, ongeacht de rules.

#### Behavior Rule Toevoegen

1. Open een template (niet Built-in)
2. Klik "Add Rule" knop
3. Selecteer **Behavior Type**
4. Voer **Value** in:
   - Enkele poort: `443`
   - Poort range: `5060-5090`
   - Meerdere poorten: `80,443,8080`
   - Protocol: `TCP`
   - IP/domein: `192.168.1.0/24` of `*.example.com`
5. Selecteer **Action**
6. (Optioneel) Voeg **Description** toe
7. Klik "Add"

#### Voorbeelden

**VoIP Telefoon Template:**
```
Type: allowed_ports     Value: 5060-5090      Action: Allow    Desc: SIP signaling
Type: allowed_ports     Value: 10000-20000    Action: Allow    Desc: RTP media
Type: allowed_protocols Value: UDP            Action: Allow    Desc: VoIP protocol
```

**IP Camera Template:**
```
Type: allowed_ports     Value: 554            Action: Allow    Desc: RTSP streaming
Type: allowed_ports     Value: 80,443,8080    Action: Allow    Desc: Web interface
Type: bandwidth_limit   Value: 500            Action: Alert    Desc: Max 500MB/hour
```

**Smart TV Template:**
```
Type: allowed_ports     Value: 443,8080       Action: Allow    Desc: HTTPS streaming
Type: expected_destinations  Value: *.netflix.com,*.youtube.com  Action: Allow
```

#### Behavior Rule Verwijderen

1. Open template details
2. Klik op het prullenbak-icoon naast de regel
3. Bevestig verwijdering

---

### Service Providers Tab

Service Providers zijn bekende streaming- en CDN-diensten. Verkeer naar deze providers wordt als "normaal entertainment/zakelijk verkeer" beschouwd.

#### Waarom Service Providers?

Zonder Service Providers zou verkeer naar Netflix, YouTube of Microsoft 365 alerts kunnen genereren voor:
- Hoog bandbreedtegebruik
- Vele verbindingen
- Onbekende bestemmingen

Door providers te definiëren weet NetMonitor dat dit legitiem verkeer is.

#### Provider Lijst

De lijst toont:
- **Provider naam** (Netflix, YouTube, Microsoft 365, etc.)
- **Category** (Streaming, CDN, Cloud, Gaming, etc.)
- **IP Ranges**: Bekende IP-reeksen van de provider
- **Domains**: Bekende domeinen

**Filteren:**
Gebruik de category dropdown om te filteren op type provider.

#### Built-in Providers

NetMonitor bevat standaard providers:

| Provider | Category | Voorbeelden |
|----------|----------|-------------|
| Netflix | Streaming | *.netflix.com, Netflix CDN IPs |
| YouTube | Streaming | *.youtube.com, *.googlevideo.com |
| Spotify | Streaming | *.spotify.com, *.scdn.co |
| Microsoft 365 | Cloud | *.office365.com, *.microsoft.com |
| AWS | CDN | *.amazonaws.com |
| Cloudflare | CDN | Cloudflare IP ranges |

#### Custom Provider Toevoegen

1. Klik "Add Provider" knop
2. Vul in:
   - **Name**: Naam van de dienst
   - **Category**: Selecteer type
   - **IP Ranges**: IP-reeksen (één per regel, CIDR notatie)
   - **Domains**: Domeinen (één per regel, wildcards toegestaan)
   - **Description**: Omschrijving
3. Klik "Create"

**Voorbeeld: Zoom toevoegen**
```
Name: Zoom
Category: Cloud
IP Ranges:
  3.7.35.0/25
  3.21.137.128/25
  3.22.11.0/24
Domains:
  *.zoom.us
  *.zoomgov.com
Description: Zoom video conferencing
```

#### Provider Verwijderen

1. Klik op het prullenbak-icoon naast de provider
2. Bevestig verwijdering

**Let op:** Built-in providers kunnen niet worden verwijderd.

---

### Statistics Tab

De Statistics tab geeft een overzicht van uw device classification.

#### Overzicht Kaarten

| Metric | Beschrijving |
|--------|--------------|
| **Total Devices** | Totaal ontdekte apparaten |
| **Classified** | Apparaten met een template |
| **Unclassified** | Apparaten zonder template |

#### Devices by Template

Grafiek/lijst die toont hoeveel apparaten per template zijn gecategoriseerd.

#### Devices by Vendor

Top 10 fabrikanten in uw netwerk, gebaseerd op MAC-adres OUI lookup.

---

### Praktische Voorbeelden

#### Voorbeeld 1: Nieuwe IP Camera Toevoegen

**Situatie:** U installeert een nieuwe IP camera en wilt voorkomen dat het RTSP verkeer alerts genereert.

**Stappen:**
1. Wacht tot de camera in de Devices lijst verschijnt
2. Klik op het apparaat
3. Selecteer template "IP Camera" uit de dropdown
4. Klik "Apply Template"
5. ✅ Camera verkeer wordt nu als normaal beschouwd

#### Voorbeeld 2: Custom Template voor VoIP

**Situatie:** U heeft VoIP telefoons die SIP/RTP gebruiken op non-standard poorten.

**Stappen:**
1. Ga naar Templates tab
2. Klik "Create Template"
3. Naam: "Office VoIP Phone"
4. Category: "IoT"
5. Klik "Create"
6. Open de nieuwe template
7. Klik "Add Rule"
8. Voeg toe:
   - Type: `allowed_ports`, Value: `5060-5090`, Desc: "SIP signaling"
   - Type: `allowed_ports`, Value: `10000-20000`, Desc: "RTP media"
   - Type: `allowed_protocols`, Value: `UDP`, Desc: "Voice protocol"
9. Ga naar Devices, wijs de template toe aan uw VoIP telefoons

#### Voorbeeld 3: Streaming Dienst Toevoegen

**Situatie:** Medewerkers gebruiken een specifieke streaming dienst die niet in de standaard providers zit.

**Stappen:**
1. Ga naar Service Providers tab
2. Klik "Add Provider"
3. Vul in:
   - Name: "Internal Video Platform"
   - Category: "Streaming"
   - IP Ranges: `10.100.50.0/24`
   - Domains: `video.company.internal`
4. Klik "Create"
5. ✅ Verkeer naar deze dienst wordt als normaal beschouwd

#### Voorbeeld 4: Template Genereren uit Geleerd Gedrag

**Situatie:** U heeft een nieuw IoT apparaat waarvan u niet precies weet welke poorten het gebruikt.

**Stappen:**
1. Sluit het apparaat aan en laat het een paar uur draaien
2. Ga naar Devices tab
3. Vind het apparaat (zoek op IP of MAC)
4. Wacht tot Learning Status "Ready" is (100+ packets)
5. Klik op het apparaat
6. Klik "Create Template from Learned Behavior"
7. Geef de template een naam
8. Review de automatisch gegenereerde rules
9. Pas aan indien nodig
10. ✅ Template is klaar voor gebruik

---

### Tips en Best Practices

#### Do's ✅

- **Classificeer apparaten zo snel mogelijk** - Hoe sneller geclassificeerd, hoe minder false positives
- **Gebruik templates voor groepen** - Maak één template voor alle apparaten van hetzelfde type
- **Review geleerde gedrag** - Controleer automatisch gegenereerde rules voor je ze accepteert
- **Houd Service Providers up-to-date** - Voeg nieuwe diensten toe als ze worden gebruikt
- **Monitor de Statistics** - Houd bij hoeveel apparaten nog ongeclass zijn

#### Don'ts ❌

- **Classificeer niet te ruim** - Een template met "alle poorten allowed" is zinloos
- **Negeer unclassified apparaten niet** - Deze genereren de meeste false positives
- **Wijzig geen Built-in templates** - Maak een custom template als je andere rules nodig hebt
- **Suppress geen CRITICAL alerts** - Deze worden sowieso niet onderdrukt

---

## AI Integration (MCP Server)

### Overview

NetMonitor SOC includes an MCP (Model Context Protocol) server that enables AI assistants like Claude to monitor and interact with your SOC platform through a modern HTTP API with **37 specialized security tools**.

**What is MCP?**

MCP is a standardized protocol that allows AI assistants to access external systems securely. The NetMonitor MCP server exposes your SOC data and operations to AI tools while maintaining security and access control.

**What Can AI Do?**

- **Threat Analysis**: "Claude, analyze the last 24 hours of critical alerts and identify patterns"
- **Incident Response**: "What are the top 3 priority incidents I should handle first?"
- **Security Queries**: "Show me all port scan alerts from external sources this week"
- **TLS/HTTPS Analysis**: "Check if any devices have malicious JA3 fingerprints"
- **PCAP Forensics**: "Export the PCAP file for the latest critical alert"
- **Device Classification**: "Show me all unclassified IoT devices"
- **Whitelist Management**: "Add 10.0.0.0/8 to the whitelist as internal network"
- **Operational Insights**: "Which sensors have performance issues?"
- **Custom Reports**: "Generate a summary of all brute force attempts by source country"

**For SOC Operators:**

You typically don't need to interact with the MCP server directly - it's designed for administrators who want to integrate AI capabilities. However, if you're interested in using an AI assistant to help monitor your SOC:

1. Ask your administrator to create a **read_only** API token for you
2. Connect Claude or another AI assistant using the token
3. Ask questions in natural language about your security posture
4. Get AI-powered analysis and recommendations

**Example Workflow:**

```
You: "Claude, show me the sensors that are offline"
Claude: *queries MCP server*
        "Currently 2 sensors are offline:
        - office-vlan10-01 (last seen 15 minutes ago)
        - branch-dmz-03 (last seen 2 hours ago)"

You: "Analyze the recent DDoS alerts"
Claude: *retrieves and analyzes alerts*
        "I found 5 DDoS alerts in the past 6 hours, all targeting
        10.0.0.50. Pattern suggests volumetric attack.
        Recommendation: Enable rate limiting and contact ISP."
```

**Available Tool Categories:**

The MCP server provides 37 tools organized into categories:

| Category | Tools | Description |
|----------|-------|-------------|
| **Security Analysis** | 6 | Analyze IPs, threats, attackers, patterns |
| **Exports & Reporting** | 4 | Export alerts/traffic to CSV, generate reports |
| **Configuration** | 4 | Get/set detection rules and thresholds |
| **Sensor Management** | 4 | Monitor sensors, send commands, update settings |
| **Whitelist** | 4 | Add/remove/check whitelist entries |
| **TLS Analysis** | 4 | JA3 fingerprints, TLS metadata, certificate info |
| **PCAP Forensics** | 5 | List/export/manage packet captures |
| **Device Classification** | 6 | Manage devices, templates, behaviors |

**Security Note:**

All MCP access is authenticated and logged. Your administrator controls what permissions each token has (read-only vs full access). AI assistants can only see data you have access to.

**Learn More:**

If you want to set up AI integration, refer to the [ADMIN_MANUAL.md](ADMIN_MANUAL.md) MCP Server section or contact your administrator.

---

## Common Tasks

### Investigating a Port Scan Alert

**1. Review Alert:**
```
Alert: Port Scan Detected
Source: 192.168.1.100
Ports: 22, 23, 80, 443, 3306, 3389, 8080
```

**2. Identify Source:**
- Is it internal or external?
- Known IP? Check inventory
- Hostname available?

**3. Determine Intent:**
- **Legitimate**: Admin tool, vulnerability scanner
  → Add to whitelist
- **Malicious**: Unauthorized scanning
  → Block IP, investigate system
- **Compromised**: Internal system infected
  → Isolate system, run antivirus

**4. Take Action:**
- Whitelist if legitimate
- Block and monitor if suspicious
- Incident response if compromised

### Adding a New Sensor

**1. Prepare Sensor:**
- Linux machine with network access
- Mirror port or in-line deployment
- SSH access

**2. Deploy:**
```bash
# On sensor machine
scp -r netmonitor/ user@sensor:/tmp/
ssh user@sensor
cd /tmp/netmonitor
sudo ./setup_sensor.sh
```

**3. Verify:**
- Check Sensors tab in dashboard
- Sensor appears as Online
- Metrics updating

**4. Configure:**
- Click Settings button
- Set location
- Configure internal networks
- Adjust heartbeat/sync intervals if needed
- Adjust sensor-specific config if needed

### Tuning Detection Rules

**Too Many Alerts:**
1. Review alert patterns
2. Identify common sources
3. Options:
   - Add legitimate sources to whitelist
   - Increase detection thresholds
   - Disable overly sensitive rules

**Missing Real Threats:**
1. Review known attack scenarios
2. Check if alerts generated
3. Options:
   - Decrease thresholds
   - Enable additional rules
   - Review whitelist (too broad?)

### Investigating TLS/Malware Alerts

**MALICIOUS_JA3_FINGERPRINT Alert:**

Dit is een **CRITICAL** alert - de TLS fingerprint komt overeen met bekende malware.

**1. Identificeer het device:**
- Noteer source IP uit de alert
- Ga naar Devices tab, zoek het device
- Check of het device geclassificeerd is

**2. Analyseer TLS metadata via AI:**
```
# Vraag aan Claude via MCP:
"Analyseer de TLS metadata voor IP 192.168.1.100"
"Welke hostnames (SNI) heeft dit device recent bezocht?"
"Zijn er andere verdachte JA3 fingerprints van dit device?"
```

**3. Download PCAP voor deep analysis:**
- PCAP files worden automatisch opgeslagen bij critical alerts
- Locatie: `/var/log/netmonitor/pcap/`
- Open in Wireshark voor packet-level analyse

**4. Neem actie:**
- Isoleer het device van het netwerk
- Scan met antivirus/EDR
- Check voor lateral movement naar andere devices

### Using PCAP Forensics

**Wanneer PCAP gebruiken:**
- Bij CRITICAL/HIGH alerts voor deep packet analysis
- Bij vermoeden van data exfiltration
- Voor incident response en bewijs

**PCAP bestanden vinden:**
```bash
# Op de NetMonitor server
ls -la /var/log/netmonitor/pcap/

# Voorbeeld output:
alert_malicious_ja3_fingerprint_192_168_1_100_to_45_33_32_156_20231215_143022.pcap
alert_port_scan_10_0_0_50_20231214_091532.pcap
```

**Analyse met Wireshark:**
```bash
# Download PCAP
scp user@netmonitor:/var/log/netmonitor/pcap/alert_*.pcap ./

# Open in Wireshark
wireshark alert_malicious_ja3_fingerprint_*.pcap

# Useful Wireshark filters:
# - TLS handshakes: tls.handshake
# - JA3 fingerprints: tls.handshake.ja3
# - Specific IP: ip.addr == 192.168.1.100
# - Certificate info: tls.handshake.certificate
```

**Export specifieke flow via AI:**
```
# Vraag aan Claude via MCP:
"Export de PCAP voor verkeer tussen 192.168.1.100 en 45.33.32.156 port 443"
```

### Weekly Maintenance

**Monday Morning Checklist:**
- ✅ Review alerts from weekend
- ✅ Check sensor status (all online?)
- ✅ Review top talkers for anomalies
- ✅ Update whitelist if needed
- ✅ Check disk space on SOC server

---

## Best Practices

### Alert Management

**Do:**
- ✅ Review alerts daily
- ✅ Investigate unknowns immediately
- ✅ Keep whitelist up to date
- ✅ Document your decisions
- ✅ Track false positive patterns

**Don't:**
- ❌ Ignore low-severity alerts completely
- ❌ Disable rules without understanding
- ❌ Over-whitelist (defeats purpose)
- ❌ Forget to acknowledge reviewed alerts

### Configuration

**Do:**
- ✅ Start with defaults
- ✅ Adjust gradually based on experience
- ✅ Document changes
- ✅ Test in development first
- ✅ Use sensor-specific overrides when needed

**Don't:**
- ❌ Set thresholds too high (miss threats)
- ❌ Set thresholds too low (alert fatigue)
- ❌ Change multiple settings at once
- ❌ Disable all detection rules

### Sensor Management

**Do:**
- ✅ Deploy sensors strategically
- ✅ Monitor sensor health
- ✅ Keep sensors updated
- ✅ Use descriptive names/locations
- ✅ Document sensor placements

**Don't:**
- ❌ Deploy sensors without planning
- ❌ Ignore offline sensors
- ❌ Mix sensor versions significantly
- ❌ Overload sensors with traffic

### Sensor Configuration

**Do:**
- ✅ Use dashboard to adjust sensor settings (not manual sensor.conf editing)
- ✅ Always configure location and internal networks via dashboard
- ✅ Test configuration changes on one sensor first before rolling out to all
- ✅ Monitor sensor status after config changes
- ✅ Document why you made specific configuration choices
- ✅ Use appropriate heartbeat intervals (default 30s is good for most)
- ✅ Keep config sync interval at default (300s) unless you have specific needs

**Don't:**
- ❌ Manually edit sensor.conf files on sensor systems (except initial setup)
- ❌ Set heartbeat interval too low (< 15s causes unnecessary overhead)
- ❌ Set config sync interval too high (> 600s delays important updates)
- ❌ Copy sensor.conf between different sensors (each needs unique ID)
- ❌ Change multiple sensor settings simultaneously without testing
- ❌ Forget to define internal networks (critical for accurate detection)

### Account Security

**Do:**
- ✅ Enable Two-Factor Authentication (2FA) for your account
- ✅ Use a strong, unique password (12+ characters)
- ✅ Save your 2FA backup codes in a safe place
- ✅ Log out when you're done (User menu → Logout)
- ✅ Change your password if you suspect it's compromised
- ✅ Keep your authenticator app updated
- ✅ Report suspicious activity to your administrator

**Don't:**
- ❌ Share your password with anyone
- ❌ Use the same password for multiple accounts
- ❌ Leave your session logged in on shared computers
- ❌ Disable 2FA without admin approval
- ❌ Screenshot or write down your password
- ❌ Use simple passwords like "Password123"
- ❌ Lose your 2FA backup codes (you'll be locked out!)

**If You Lose Access:**
- Contact your administrator immediately
- They can reset your 2FA (after verifying your identity)
- You'll need to set up 2FA again with a new QR code

**Session Security:**
- Your session expires after 30 minutes of inactivity
- Always log out on shared computers
- If you see unusual activity in your account, report it immediately

---

## Keyboard Shortcuts

### Dashboard Navigation

- `Alt + 1`: Alerts tab
- `Alt + 2`: Sensors tab
- `Alt + 3`: Configuration tab
- `Alt + 4`: Whitelist tab
- `F5`: Refresh dashboard
- `Ctrl + F`: Search alerts

### Alert Actions

- `↑` `↓`: Navigate alerts
- `Enter`: View alert details
- `A`: Acknowledge alert
- `W`: Add to whitelist

*(Note: Shortcuts may vary by browser)*

---

## Troubleshooting

### Dashboard Not Updating

**Issue:** Real-time updates stopped
**Solution:**
1. Check browser console for errors
2. Refresh page (F5)
3. Check SOC server status
4. Verify WebSocket connection

### Sensor Offline

**Issue:** Sensor shows red status
**Solution:**
1. Check sensor logs
2. Verify network connectivity
3. Ping SOC server from sensor
4. Restart sensor service
5. Check firewall rules

### Too Many Alerts

**Issue:** Alert fatigue
**Solution:**
1. Review common alert sources
2. Add legitimate traffic to whitelist
3. Increase thresholds for noisy rules
4. Consider disabling rules temporarily
5. Analyze traffic patterns

### False Positives

**Issue:** Alerts on legitimate traffic
**Solution:**
1. Identify source of false positives
2. Add to whitelist (preferred)
3. Or adjust rule thresholds
4. Document why it's legitimate
5. Monitor for true pattern

---

## Getting Help

**For Technical Issues:**
- Check logs: `journalctl -u netmonitor-soc -f`
- Review [ADMIN_MANUAL.md](ADMIN_MANUAL.md)
- Contact system administrator

**For Security Questions:**
- Follow incident response procedures
- Escalate to security team
- Document findings

**For Feature Requests:**
- Discuss with admin team
- Submit via proper channels
- Provide use case details

---

## Quick Reference

### Alert Severity Levels

| Color | Severity | Action Required |
|-------|----------|----------------|
| 🔴 RED | HIGH | Immediate investigation |
| 🟠 ORANGE | MEDIUM | Review within 1 hour |
| 🟡 YELLOW | LOW | Review daily |

### Sensor Status Icons

| Icon | Meaning | Action |
|------|---------|--------|
| 🟢 Green | Online, healthy | None |
| 🔴 Red | Offline | Investigate |
| 🟡 Yellow | Degraded | Monitor |

### Common IP Ranges

| Range | Purpose |
|-------|---------|
| 10.0.0.0/8 | Private networks |
| 172.16.0.0/12 | Private networks |
| 192.168.0.0/16 | Private networks |
| 127.0.0.0/8 | Localhost |
| 0.0.0.0/8 | Invalid source |

---

## Next Steps

**Learn More:**
- [DETECTION_FEATURES.md](DETECTION_FEATURES.md) - All detection capabilities
- [DASHBOARD.md](DASHBOARD.md) - Dashboard features in detail
- [CONFIG_GUIDE.md](CONFIG_GUIDE.md) - Configuration reference

**For Administrators:**
- [ADMIN_MANUAL.md](ADMIN_MANUAL.md) - Installation and administration

---

*Last updated: December 2025*
*NetMonitor SOC v2.2 - Stay Vigilant, Stay Secure*
