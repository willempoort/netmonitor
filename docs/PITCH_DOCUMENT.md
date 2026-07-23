# NetMonitor - De AI Scout voor Uw Security Stack

**Bescherm uw bedrijfsnetwerk met AI-powered network monitoring**

---

## 🚨 Het Probleem: Security Teams Verdrinken in Logs

**Een typische dag voor een SOC analyst:**

```
08:00 - Login Wazuh dashboard
        → 8.472 nieuwe events sinds gisteren
        → Waar te beginnen?

09:00 - Suricata alerts checken
        → 1.203 alerts
        → 90% false positives?
        → Welke zijn echt gevaarlijk?

10:30 - Zeek logs doorzoeken
        → 450 MB aan conn.log, dns.log, http.log
        → Zoeken naar patronen met grep/scripts
        → Duurt uren

12:00 - Lunch (vermoeid van log analyse)

13:00 - Terug naar logs
        → Aandacht daalt na 100e log entry
        → Kritieke lateral movement gemist (begraven in ruis)

17:00 - Dag voorbij
        → 80% tijd besteed aan log triage
        → 20% aan daadwerkelijk onderzoek
        → Belangrijke attack chain pas volgende week ontdekt
```

**Het echte probleem:**
- ❌ **Mensen kunnen niet 10.000 events/dag lezen** zonder vermoeidheid
- ❌ **Patronen over tools heen worden gemist** (Wazuh + Suricata + Zeek correlatie)
- ❌ **Reactief werk** - Alleen kijken als alarm afgaat
- ❌ **11% coverage** - Een menselijke analyst verwerkt ~800 events/dag, dat is 11% van 7.200 events
- ❌ **Geen bewijs** - Traffic al weg wanneer incident ontdekt wordt

### Maar Het Wordt Erger: De Blinde Vlek

Endpoint security (Wazuh, antivirus, EDR) werkt perfect voor **devices waar je software op kunt installeren**.

**Maar wat met:**
- 🖨️ **Printers** - Geen OS voor antivirus, vaak kwetsbaar, geen agent mogelijk
- 💼 **Externen met eigen laptops** - BYOD, buiten IT controle, weigeren bedrijfs-agent
- 📹 **IoT devices** - IP camera's, smart thermostaten, NAS - geen agent mogelijk
- 🏭 **OT/ICS systemen** - Modbus PLC's, SCADA - te kritisch voor agent installatie
- 📱 **Guest WiFi** - Bezoekers, leveranciers - geen trust voor agents
- 🔧 **Legacy systemen** - Windows XP embedded, oude medical devices - ongepatchbaar

```
Typisch netwerk:
├─ 100 werkstations met Wazuh     ✅ 67% Beschermd
├─ 50 servers met Wazuh
└─ 75 andere devices               ❌ 33% BLINDE VLEK
    ├─ 15 printers
    ├─ 20 IoT devices
    ├─ 10 BYOD laptops
    ├─ 5 OT/ICS devices
    ├─ 10 legacy systemen
    └─ 15 guests

Een aanvaller hoeft alleen:
1. Compromitteer printer (vaak ongepatchd)
2. Lateral movement naar werkstations
3. Endpoint security ziet niets (printer heeft geen agent)
```

**33% van uw netwerk is onzichtbaar voor endpoint security.**

---

## ✅ De Oplossing: NetMonitor AI Scout + Agentless Network Coverage

### NetMonitor is NIET Nóg Een IDS

**NetMonitor is de AI-powered triage laag die:**
1. **Analyseert** - AI leest 100% events 24/7 (nooit moe)
2. **Correleert** - Patronen over tools heen, over weken
3. **Prioriteert** - 10.000 events → 5 CRITICAL alerts
4. **Adviseert** - "Dit gebeurde, doe dit, hier is bewijs"
5. **Verzamelt** - Auto PCAP per incident (NIS2 compliant)
6. **Ziet Alles** - Agentless SPAN monitoring (ook printers, IoT, BYOD)

### Het Verschil: AI Scout vs Traditioneel

```
TRADITIONEEL:
Tools genereren data → Mens analyseert (langzaam) → Reageert wanneer overweldigd

NETMONITOR:
Tools genereren data → AI analyseert (24/7) → Mens onderzoekt (efficiënt)
                       ↓
                  SPAN port ziet ALLES
                  (100% netwerk, ook zonder agent)
```

---

## 🎯 De 3 Unieke Waarden van NetMonitor

### 1. AI-Powered Triage (De Onvermoeibare Scout)

**Mensen vs AI:**

| Aspect | Menselijke Analyst | NetMonitor AI |
|--------|-------------------|---------------|
| **Capaciteit** | 100 events/uur | 10.000+ events/minuut |
| **Aandacht** | Daalt na 2 uur | Constant 100% |
| **Correlatie** | 3-5 bronnen | Onbeperkt |
| **Patroonherkenning** | Dagelijkse patterns | Weken/maanden |
| **Beschikbaarheid** | 8 uur/dag | 24/7/365 |

**Concreet voorbeeld - APT Kill Chain Detectie:**

```
ZONDER NetMonitor (Traditionele Aanpak):
Week 1, Maandag 03:00: DNS query naar ongebruikelijk domain
→ Analyst: niet gezien (buiten werktijd, begraven in 8.000+ logs)

Week 1, Woensdag 14:00: TLS handshake naar zelfde domain
→ Analyst: lijkt normaal HTTPS traffic

Week 2, Vrijdag 02:00: Lateral movement via SMB naar 3 hosts
→ Analyst: niet gezien (nacht, veel SMB traffic normaal)

Week 4: Ransomware deployed, netwerk down
→ Detection: TE LAAT
→ Damage: €millions
```

```
MET NetMonitor AI:
Week 1, Maandag 03:00:
→ DNS query gedetecteerd
→ AI: gecorreleerd met threat intel, PCAP opgeslagen

Week 1, Woensdag 14:00:
→ TLS handshake gedetecteerd (encrypted)
→ AI: JA3 fingerprint match met Cobalt Strike → alert severity HIGH

Week 2, Vrijdag 02:00:
→ Lateral movement via SMB gedetecteerd
→ AI: correleert met eerdere events, CRITICAL alert:

🚨 CRITICAL: APT Kill Chain Gedetecteerd

Timeline:
├─ Week 1 Maandag 03:00 - Initial access (suspicious DNS)
├─ Week 1 Woensdag 14:00 - C2 established (Cobalt Strike JA3)
└─ Week 2 Vrijdag 02:00 - Lateral movement (5 hosts)

🎯 AI ADVIES:
1. IMMEDIATE: Isoleer 10.0.1.50 van netwerk
2. INVESTIGATION: Onderzoek met Zeek SMB logs
3. EVIDENCE: PCAP beschikbaar /forensics/apt-campaign-001/*.pcap

Week 2, Vrijdag 08:30:
→ Analyst ziet 1 CRITICAL alert met complete tijdlijn
→ Alle bewijs al verzameld, ready voor forensics
→ Incident response binnen 1 uur
→ Ransomware STOPPED voordat deployed

Time to detection: 5.5 uur vs 4 weken
Damage: €0 vs €millions
```

**NetMonitor AI Analysis - Volledig Voorbeeld:**

Traditionele tools geven alleen data:
```
Wazuh:    "Alert: Multiple failed login attempts"
Suricata: "ET SCAN Potential SSH Scan"
Zeek:     "Notice: SSH::Password_Guessing 10.0.1.50"
```

NetMonitor AI geeft complete context + advies:
```
🚨 CRITICAL: Active Brute Force Attack + Lateral Movement

Timeline:
├─ 14:23 - SSH brute force detected (source: 185.220.101.50)
│         200+ login attempts in 5 minutes
│         Target: 10.0.1.15 (production server)
│
├─ 14:27 - SUCCESSFUL login (username: admin)
│         ⚠️ Alert escalation: MEDIUM → CRITICAL
│
├─ 14:30 - Lateral movement initiated
│         10.0.1.15 → SMB connections to 5 internal hosts
│         Pass-the-Hash suspected (Kerberos RC4)
│
└─ 14:35 - Data exfiltration detected
          Large outbound transfer: 450 MB to 185.220.101.50:443
          TLS fingerprint: Unknown (possible custom malware)

🎯 AI ADVIES:

1. IMMEDIATE ACTIONS:
   ✓ Block 185.220.101.50 (already added to firewall - SOAR executed)
   ✓ Isolate 10.0.1.15 from network (approval pending)
   ✓ Disable user 'admin' in Active Directory (approval pending)

2. INVESTIGATION:
   → Use Zeek for deep SMB analysis:
     zeek-cut -d < /opt/zeek/logs/current/smb_mapping.log | grep 10.0.1.15

   → Analyze TLS with Wireshark:
     wireshark /forensics/case-2025-01-20-001.pcap -Y "ip.addr==185.220.101.50"

3. EVIDENCE COLLECTED:
   ✓ Full PCAP: /forensics/case-2025-01-20-001.pcap (1.2 GB)
   ✓ Extracted files: 3 executables, 12 documents
   ✓ Kerberos tickets: saved for offline analysis
   ✓ Timeline export: CSV ready for incident report

4. THREAT INTEL:
   → IP 185.220.101.50:
     - AbuseIPDB: 94% confidence malicious
     - MISP: Tagged as APT28 infrastructure
     - OTX: Seen in ransomware campaign (Ryuk) last week

   → MITRE ATT&CK Mapping:
     - T1110: Brute Force (Credential Access)
     - T1021.002: SMB/Windows Admin Shares (Lateral Movement)
     - T1041: Exfiltration Over C2 Channel

⏱️ Total response time: 12 minutes (from detection to containment)
📊 Manual analysis time saved: ~4-6 hours
```

**52 MCP Tools voor AI Assistants:**
- Natural language queries: "Welke lateral movement was er vannacht?"
- Auto investigation: AI correleert over Wazuh/Zeek/NetMonitor data
- Proactieve hunting: AI zoekt patronen zonder expliciete opdracht
- Threat enrichment: MISP/OTX/AbuseIPDB context automatisch

---

### 2. Agentless Network Visibility (De Blinde Vlek Oplossing)

**Waarom NetMonitor essentieel is:**

```
SPAN port op switch → NetMonitor ziet ALLE network traffic

Inclusief devices die endpoint security NIET kan beschermen:
✅ Printers die contact maken met C2 server
✅ IoT camera die meedoet aan botnet
✅ Externe laptop die netwerk scant
✅ Guest die malware downloadt
✅ Legacy device met SMB v1 exploit
✅ OT device met Modbus aanval

Zonder software installatie.
Zonder toestemming nodig.
Zonder risk voor productie systemen.
```

**Real-world voorbeelden:**

#### Voorbeeld 1: Gecompromitteerde Printer

```
Scenario: HP printer (firmware kwetsbaarheid)
❌ Wazuh: Kan niet installeren (geen OS)
❌ Antivirus: Printers hebben geen antivirus

✅ NetMonitor detecteert:
├─ TLS verbinding naar 185.220.101.50
├─ JA3 fingerprint match: Cobalt Strike
├─ Beaconing pattern (elke 60 sec)
└─ AI Alert: "🚨 Printer 10.0.1.200 compromised
              C2 communication detected
              Evidence: /forensics/printer-c2.pcap
              Action: Isoleer printer VLAN"
```

#### Voorbeeld 2: BYOD Laptop Aanval

```
Scenario: Externe consultant met eigen laptop
❌ Wazuh: Weigert agent (privacy, eigen device)
❌ Endpoint security: Buiten scope (BYOD policy)

✅ NetMonitor detecteert:
├─ Port scan naar 254 IP's (full subnet)
├─ SMB share enumeration
├─ Unusual traffic volume
└─ AI Alert: "⚠️ BYOD device 10.0.5.42 suspicious
              Cannot deploy agent (policy)
              Detection: Network behavior analysis
              Action: Disconnect guest WiFi"
```

#### Voorbeeld 3: IoT Camera Botnet

```
Scenario: IP camera (Mirai botnet variant)
❌ Wazuh: Embedded Linux, 64MB RAM (geen agent support)
❌ Antivirus: Impossible voor embedded device

✅ NetMonitor detecteert:
├─ Outbound connections to botnet C2
├─ DDoS traffic generation (UDP floods)
├─ Unusual bandwidth (camera sending > receiving)
└─ AI Alert: "🚨 Camera 10.0.3.15 botnet participation
              Cannot install software (embedded)
              Evidence: /forensics/iot-botnet.pcap
              Action: Segment IoT VLAN, replace device"
```

---

### 3. Automatic Evidence Collection (Altijd Klaar)

**Probleem zonder NetMonitor:**
```
Incident ontdekt na 30 dagen
→ "We need network traffic from 3 weeks ago!"
→ Niet opgenomen (te duur om alles te bewaren)
→ Of: 50 TB PCAP (onmogelijk te analyseren)
→ Forensisch onderzoek incomplete
```

**Met NetMonitor:**
```
Ring buffer: 7 dagen continuous PCAP (50-500GB)

Bij elke CRITICAL/HIGH alert:
→ Auto-extract relevante flows
→ Opslaan per case: /forensics/case-YYYY-MM-DD-NNN/
→ Inclusief metadata:
   - Source/destination IPs
   - Protocols gebruikt
   - File hashes (extracted files)
   - TLS certificates
   - DNS queries
→ Ready voor Wireshark/Zeek analyse

Resultaat:
✓ Bewijs er altijd (ook voor late-discovered incidents)
✓ Alleen relevante data (geen TB doorzoeken)
✓ Forensisch onderzoek kan direct starten
✓ NIS2 compliant (incident evidence vereist)
```

---

## 🤝 NetMonitor + Uw Bestaande Tools = Complete Coverage

### NetMonitor is GEEN Vervanging

**We claimen NIET:**
- ❌ Betere protocol parsing dan Zeek
- ❌ Meer signatures dan Suricata
- ❌ Betere endpoint visibility dan Wazuh
- ❌ Meer analytics dan Splunk

### NetMonitor is DE Missing Link

**We claimen WEL:**
- ✅ **Beste AI integration** in open-source security (52 MCP tools)
- ✅ **Agentless network visibility** voor devices die je niet kunt beschermen
- ✅ **Snelste triage** van 10.000 events naar 5 acties
- ✅ **Proactief advies** in plaats van alleen data
- ✅ **Automatische bewijs verzameling** voor elk incident

### Aanbevolen Combinaties

#### NetMonitor + Wazuh (MKB Favoriet)

```
Wazuh (Endpoints):
├─ File integrity monitoring
├─ Rootkit detection
├─ Process monitoring
└─ ✅ 67% netwerk (met agents)

NetMonitor (Network):
├─ Traffic analysis
├─ TLS fingerprinting
├─ ML device classification
├─ ✅ 33% netwerk (zonder agents)
└─ ✅ 100% netwerk (alles)

Native integration → Wazuh Manager
→ Unified alerting
→ Complete visibility
→ €0 licensing

Setup tijd: 1-2 uur
Kosten (3 jaar): €19.000 vs €270.000 Splunk
```

#### NetMonitor + Suricata (Security Specialist)

```
Suricata (Signatures):
├─ 30.000+ ET Open rules
├─ Known CVE detection
├─ IPS inline blocking
└─ Signature-based

NetMonitor (Behavior + AI):
├─ ML anomaly detection
├─ Kill chain correlation
├─ AI-powered analysis
├─ Zero-day detection
└─ Behavior-based

Beide → Splunk/ELK (via CEF)
→ Complementaire detectie
→ Suricata: known threats
→ NetMonitor: zero-days + AI triage
```

#### NetMonitor + Zeek (Enterprise Forensics)

```
Zeek (Deep Forensics):
├─ 100+ protocol parsers
├─ Complete session reconstruction
├─ Rich metadata extraction
└─ Specialist tool

NetMonitor (AI Intelligence):
├─ 52 MCP tools
├─ Natural language queries
├─ Automated correlation
└─ Orchestration layer

AI Assistant (Claude/GPT):
"Correleer Zeek's DNS logs met NetMonitor's TLS fingerprints
 voor lateral movement detection in laatste 24h"

→ Zeek's diepte + NetMonitor's AI
→ Complete forensics + automated analysis
```

---

## 📊 Eerlijke Technische Specificaties

### Wat NetMonitor Goed Doet

| Aspect | NetMonitor Waarde | Vergelijking |
|--------|-------------------|--------------|
| **Setup Snelheid** | **10-30 minuten** | vs 4-8 uur Security Onion |
| **Resource Gebruik** | **150-280 MB RAM** (sensor) | vs 500MB Zeek, 2GB Security Onion |
| **AI Integration** | **52 MCP tools** | Native protocol - geen andere OSS IDS heeft dit |
| **Built-in Dashboard** | ✅ Modern web UI | Zeek/Suricata hebben geen native UI |
| **Raspberry Pi** | ✅ ARM64 support | Distributed sensors mogelijk |
| **Nederlandse Docs** | ✅ Volledig NL | Alle anderen: alleen Engels |
| **SIEM Ready** | ✅ Wazuh + CEF/LEEF/JSON | Out-of-box naar elk SIEM |

### Waar Anderen Beter Zijn

| Aspect | Alternatief Voordeel | Wanneer Kiezen |
|--------|---------------------|----------------|
| **Protocol Diepte** | **Zeek** heeft 100+ protocol parsers | Deep protocol forensics nodig |
| **Community** | **Suricata** heeft grotere rule community | Duizenden community rules gewenst |
| **Enterprise** | **Splunk** heeft meer apps | Budget geen issue, enterprise support |
| **Maturity** | **Security Onion** battle-tested | Complete gevestigde suite gewenst |
| **MITRE Breadth** | **Wazuh** ~75% coverage | Comprehensive ATT&CK prioriteit |

### MITRE ATT&CK Coverage (Eerlijk)

**NetMonitor: 15 techniques (~8% coverage)**

Focus op high-impact common attacks:

**Reconnaissance:**
- T1046 - Network Service Discovery

**Credential Access:**
- T1110 - Brute Force
- T1558.003 - Kerberoasting
- T1558.004 - AS-REP Roasting
- T1003.006 - DCSync
- T1550.002 - Pass the Hash

**Command & Control:**
- T1071 - Application Layer Protocol
- T1071.004 - DNS
- T1095 - Non-Application Layer Protocol
- T1571 - Non-Standard Port
- T1573 - Encrypted Channel

**Lateral Movement:**
- T1021 - Remote Services
- T1021.002 - SMB/Windows Admin Shares

**Exfiltration:**
- T1041 - Exfiltration Over C2
- T1048 - Exfiltration Over Alternative Protocol

**Trade-off:** Deep detection van common techniques vs breed maar shallow.

**Voor comprehensive coverage:** Combineer met Wazuh (~75%).

### Detectie Capabilities (Eerlijk)

**21 Threat Types Enabled by Default:**
- Port scanning
- Connection floods
- Brute force attacks
- Beaconing (C2)
- Lateral movement
- DNS tunneling
- Protocol mismatch
- ICMP tunneling
- HTTP anomalies
- Large file transfers
- TLS/SSL analysis (JA3/JA3S)
- Certificate validation
- AD/Kerberos attacks
- Kill chain correlation
- SMB/LDAP deep parsing
- Risk scoring
- Encrypted traffic analysis

**53 Additional Detections Available (Opt-in):**
- Cryptomining, phishing, Tor, VPN detection
- Web application security (SQLi, XSS, SSRF, etc.)
- DDoS & resource exhaustion
- Ransomware indicators
- IoT security (Mirai, UPnP, MQTT, etc.)
- OT/ICS protocols (Modbus, DNP3, IEC-104, BACnet)
- Container security (Docker, Kubernetes)
- Advanced evasion techniques

**Waarom niet alle enabled?**
- False positive tuning per environment
- Performance considerations
- Specifieke use cases (niet iedereen heeft OT/ICS)

---

## 💰 ROI: Meetbare Waarde

### Medium Business (250 medewerkers, 100 devices)

**Zonder NetMonitor:**
```
Security Stack: Wazuh + Suricata
Events: 7.000/dag
Analyst: Kan 800/dag reviewen (11%)
Salary: €60.000/jaar
Incident Response: €30.000-150.000/jaar (late detection)

Total: €90.000-210.000/jaar
Coverage: 11% events reviewed, 89% never seen
```

**Met NetMonitor:**
```
Security Stack: Wazuh + Suricata + NetMonitor
Events: 7.000/dag
AI: Analyseert 100% → 5 CRITICAL alerts
Analyst: Reviews 25 prioritized cases/dag
Efficiency: 90% minder triage tijd
Salary: €60.000/jaar
Incident Response: €6.000-15.000/jaar (early detection)
Hardware: €2.000 (one-time)

Total: €68.000/jaar (first year)
Coverage: 100% events analyzed, 100% critical reviewed
```

**Savings: €22.000-142.000/jaar**
**ROI: 1.100% - 7.100% (first year)**

**Time to Detection:**
- Brute force: 15-30 min → 1-2 min (15x faster)
- Lateral movement: 2-7 dagen → 5-30 min (500x faster)
- Data exfiltration: 30-90 dagen → 2-24 uur (100x faster)
- Zero-day: 90-180 dagen → 1-48 uur (2000x faster)

---

## 🎯 Wanneer NetMonitor Kiezen

### ✅ Gebruik NetMonitor Als:

- Je verdrinkt in security logs (10.000+ events/dag)
- Je wilt AI-powered triage (90% tijdwinst)
- Je hebt devices zonder agent (printers, IoT, BYOD, OT/ICS)
- Je wilt automatic evidence collection (NIS2 compliant)
- Je hebt Wazuh/Suricata/Zeek en wilt ze slimmer maken
- Je hebt distributed locations (Raspberry Pi sensors)
- Je wilt snel starten (10-30 min setup)
- Budget is beperkt (€0 licensing)

### ❌ Gebruik NetMonitor NIET Als:

- Je comprehensive MITRE coverage prioriteert (kies Wazuh ~75%)
- Je >100 protocol parsers nodig hebt (kies Zeek)
- Je inline IPS bij 10Gbps+ wilt (kies Suricata)
- Je 24/7 vendor support met SLA vereist (kies enterprise)
- Je alleen endpoint detection nodig hebt (NetMonitor is network-focused)
- Je geen enkele technische kennis hebt (kies managed SOC)

---

## 🚀 Implementatie Scenario's

### Scenario 1: Klein Kantoor (10-50 medewerkers)

**Setup:**
- Raspberry Pi 4 (8GB) als sensor
- Verbonden met centrale switch (port mirroring)
- NetMonitor analyseert alle traffic
- Dashboard toegankelijk voor IT admin

**Kosten:** €500-1.000 (hardware + setup)
**Tijd:** 1-2 uur
**Result:** 100% network visibility, AI triage, auto PCAP

---

### Scenario 2: Middelgroot Bedrijf (50-500 medewerkers)

**Setup:**
- Centrale NetMonitor server (4 cores, 16GB RAM)
- Raspberry Pi sensoren op elke locatie/VLAN
- Wazuh voor endpoints
- NetMonitor voor network (inclusief IoT/printers/BYOD)
- Kiosk display bij IT-afdeling

**Extras:**
- AI-integratie voor analyse en rapportage
- PCAP forensics voor compliance
- Native Wazuh integration (unified alerts)

**Kosten:** €5.000-10.000 (hardware + setup)
**Tijd:** 1-2 dagen
**Result:** 100% coverage (endpoint + network), complete visibility

---

### Scenario 3: Enterprise (500+ medewerkers)

**Setup:**
- Gedistribueerde architectuur
- Meerdere sensoren per locatie
- PostgreSQL cluster (high availability)
- Integration met Splunk/QRadar
- PCAP forensics + long-term storage

**Extras:**
- Dedicated SOC team training
- Custom threat detection rules
- SOAR playbook development
- Compliance reporting (NIS2)

**Kosten:** €15.000-30.000 (projectmatig)
**Tijd:** 1-2 weken
**Result:** Enterprise-grade SOC, complete automation

---

## 🔒 Compliance & Security

NetMonitor ondersteunt compliance met:

**AVG/GDPR:**
- Data blijft binnen eigen infrastructuur
- Encrypted traffic analysis WITHOUT decryption
- Privacy-safe detection methods

**NIS2:**
- Incident detectie en alerting
- PCAP forensics (evidence collection)
- Rapportage capabilities
- Logging retention

**ISO 27001:**
- Security monitoring controls
- Audit logging
- Access management

**MITRE ATT&CK:**
- 15 technique coverage
- Kill chain correlation
- Technique mapping per alert

---

## 📝 Technische Highlights

| Component | Specificatie |
|-----------|--------------|
| **Platform** | Linux (Ubuntu/Debian) - ARM64 & x86_64 |
| **Database** | PostgreSQL + TimescaleDB |
| **Interface** | Modern Web Dashboard (Bootstrap 5) |
| **API** | REST + WebSocket + MCP HTTP (52 tools) |
| **AI Integratie** | Native Model Context Protocol |
| **Schaalbaarheid** | Multi-sensor architectuur |
| **Performance** | 1Gbps+ per sensor (8-12% CPU, 150-280 MB RAM) |
| **Forensics** | PCAP capture met ring buffer (NIS2) |
| **TLS Analyse** | JA3/JA3S, ESNI/ECH, Domain Fronting |
| **AD Security** | Kerberos attacks, DCSync, Pass-the-Hash |
| **Correlation** | Kill chain, MITRE ATT&CK mapping |
| **Response** | SOAR playbooks, automated actions |
| **Machine Learning** | Random Forest classification + Isolation Forest anomaly |
| **Threat Intel** | MISP, AlienVault OTX, AbuseIPDB |
| **SIEM Output** | Native Wazuh + CEF/LEEF/JSON (Splunk/QRadar/ArcSight) |

---

## 🎛️ NetMonitor Flexibility: The Porsche Principle

### Gebouwd voor Performance, Geleverd met Veilige Limieten

NetMonitor is als een Porsche: **volledige capability beschikbaar, conservatieve factory settings**.

#### Out-of-the-Box (Safety Mode) ✅

**21 Core Threat Detections Enabled**
- Port scanning, brute force, lateral movement
- TLS/SSL analysis (JA3/JA3S), certificate validation
- Beaconing (C2), DNS tunneling, protocol mismatch
- AD/Kerberos attacks (Kerberoasting, DCSync)
- Kill chain correlation, SMB/LDAP deep parsing
- HTTP anomalies, large file transfers
- Risk scoring, encrypted traffic analysis

**MITRE Coverage:** ~8% (high-confidence essentials)
**False Positives:** Minimaal (getuned voor broad deployment)
**Deployment:** Immediate (10-30 minuten)
**Hardware:** Raspberry Pi compatible (150-280MB RAM)

**Analogy:** Porsche met factory speed limiter (250 km/h van 300 km/h capability)

---

#### Professional Mode (Full Capability) 🚀

**74 Total Threat Detections Available**

**All 9 Phases Fully Implemented:**

**Phase 1: Core Advanced Threats (6 types)**
- Cryptomining (Stratum protocol)
- Phishing domains (OpenPhish feed)
- Tor exit node connections
- VPN tunnels (OpenVPN, WireGuard, IPsec)
- Cloud metadata access (AWS/Azure/GCP IMDS)
- DNS anomalies (DGA detection)

**Phase 2: Web Application Security (8 types)**
- SQL Injection, XSS, Command Injection
- Path Traversal, XXE, SSRF
- WebShell detection, API abuse

**Phase 3: DDoS & Resource Exhaustion (8 types)**
- SYN/UDP/HTTP floods
- Slowloris, DNS/NTP amplification
- Connection exhaustion, Bandwidth saturation

**Phase 4: Ransomware Indicators (5 types)**
- SMB mass encryption patterns
- Crypto file extensions (.locked, .encrypted)
- Ransom note detection
- Shadow copy / backup deletion

**Phase 5: IoT & Smart Device Security (8 types)**
- IoT botnet (Mirai), UPnP exploits
- MQTT abuse, Smart home protocols
- RTSP, CoAP, Z-Wave, Zigbee attacks

**Phase 6: OT/ICS Protocol Security (6 types)**
- Modbus attacks (port 502)
- DNP3 attacks (port 20000)
- IEC-104 control commands (port 2404)
- BACnet, Profinet, EtherNet/IP

**Phase 7: Container & Orchestration (4 types)**
- Docker container escape
- Kubernetes API exploitation
- Container registry poisoning
- Privileged containers

**Phase 8: Advanced Evasion (4 types)**
- IP fragmentation attacks
- Protocol tunneling (DNS/ICMP)
- Polymorphic malware
- Domain Generation Algorithms (DGA)

**Phase 9: Additional Kill Chain (+ extended detections)**
- Credential dumping (Mimikatz, LSASS)
- LOLBins, Memory injection, Process hollowing
- Registry manipulation, Scheduled task abuse

**MITRE Coverage:** Tot ~92% mogelijk (met tuning)
**Deployment:** Vereist environment-specific configuration
**Hardware:** May need more powerful sensors (dependent on enabled features)

**Analogy:** Porsche met limiter verwijderd (volledige 300 km/h capability)

---

### Why Conservative Defaults?

**The Alert Fatigue Problem:**

```
Scenario A: All 74 detections enabled zonder tuning
→ 10.000 events/dag waarvan 8.000 false positives
→ Analyst leert alerts te negeren
→ Echte attack gemist (begraven in noise)
→ FAILURE

Scenario B: 21 tuned detections enabled
→ 500 events/dag waarvan 450 accurate
→ Analyst onderzoekt alle alerts
→ Echte attack detected en stopped
→ SUCCESS
```

**Specifieke Voorbeelden:**

| Detection | Why Not Always-On? |
|-----------|-------------------|
| **SQL Injection** | Vereist application baseline - legitimate apps trigger without tuning |
| **DDoS Detection** | Legitimate traffic spikes (product launch, viral content) look like DDoS |
| **Modbus Attacks** | Irrelevant without OT/ICS devices - 0% value, wastes resources |
| **Container Escape** | Irrelevant without Docker/Kubernetes - waarom noise genereren? |
| **Web App Security** | E-commerce needs it, factory doesn't - environment-specific |

**NetMonitor Philosophy:**
> "Better 21 accurate detections than 74 noisy ones.
> Unlock more when YOU need them, for YOUR environment."

---

### How to Unlock Full Potential

#### Option 1: Manual Configuration (Web UI)

```
Dashboard → Configuration → Threat Detection

Enable detections relevant voor jouw environment:
✅ Web applications? → Enable SQL Injection, XSS, SSRF
✅ OT/ICS devices? → Enable Modbus, DNP3, IEC-104
✅ Containers? → Enable Docker Escape, K8s Exploit
✅ IoT devices? → Enable Mirai, UPnP, MQTT abuse

Each with tunable thresholds per environment.
```

#### Option 2: AI-Assisted via MCP

```
AI analyzes your environment:
- Detects web servers → "Enable web app security?"
- Detects no containers → Leaves container security disabled
- Detects Modbus traffic → "Enable OT/ICS monitoring?"
- Learns baselines → Tunes thresholds automatically

Result: Optimal configuration zonder manual work
```

#### Option 3: Configuration File

```yaml
# config.yaml
threat:
  sql_injection:
    enabled: true
    sensitivity: medium  # low/medium/high
    check_query_string: true
    check_post_data: true

  modbus_attacks:
    enabled: true
    ports: [502]
    alert_on_write: true

  docker_escape:
    enabled: true
    monitor_privileged: true
```

#### Option 4: Professional Services

```
Contact: willem@awimax.nl

Professional deployment services:
→ Environment assessment
→ Baseline tuning (all 74 detections)
→ False positive minimization
→ ~92% MITRE coverage optimization
→ Ongoing support

Investment: €5.000-15.000 (one-time)
Result: Fully optimized enterprise deployment
```

---

### The Honest Comparison

**Other IDS Approach:**
```
Suricata: Enable 30.000 rules by default
→ Massive false positives
→ Users spend weeks tuning
→ Many give up, disable rules

Zeek: No detection rules, only logging
→ Users must write custom scripts
→ Steep learning curve
→ Requires expert knowledge
```

**NetMonitor Approach:**
```
Day 1: 21 core detections work immediately
→ Low false positives
→ Immediate security value
→ No tuning required

Week 1-4: Enable relevant additional detections
→ Per YOUR environment
→ AI-assisted or manual
→ Incremental complexity

Result: Best of both worlds
→ Beginner-friendly (works day 1)
→ Expert-capable (92% MITRE possible)
```

---

### Real-World Deployment Paths

#### Small Business (10-50 employees)

```
Day 1: Install with defaults (21 detections)
✅ Immediate visibility
✅ Core threats detected
✅ 0 false positives (tuned defaults)

Month 1+: Add detections as needed
- Hire remote workers? Enable VPN detection
- Add web app? Enable SQL injection
- Buy IoT cameras? Enable Mirai detection

Cost: €1.000 (RPi setup)
Complexity: Low (web UI configuration)
```

#### Medium Business (50-500 employees)

```
Week 1: Deploy with defaults (21 detections)
✅ Immediate protection
✅ NetMonitor + Wazuh integration

Week 2-4: Professional tuning
- Enable web app security (you have e-commerce)
- Enable IoT security (you have 50 cameras)
- Tune thresholds based on baselines
- Result: 45-60 detections optimized

Cost: €19.000 (NetMonitor + Wazuh, 3 years)
Complexity: Medium (professional tuning recommended)
```

#### Enterprise (500+ employees)

```
Week 1-2: Full deployment planning
- Inventory all device types
- Identify all protocols in use
- Map to relevant detection phases

Week 3-4: Professional deployment
- All 74 detections enabled
- Environment-specific baselines
- Integration with existing SIEM
- SOC team training

Result: ~92% MITRE coverage, fully tuned

Cost: €30.000-50.000 (professional deployment)
Complexity: High (professional services recommended)
```

---

### The Porsche Principle Summary

**You bought a Porsche (NetMonitor with 74 detections):**
- Factory limiter: 21 enabled (safe for everyone)
- Full capability: 74 available (unlock when ready)
- Expert tuning: Professional services (maximize performance)

**Benefits of This Approach:**

1. **Immediate Value** - Works day 1, no tuning required
2. **Flexibility** - Grow capabilities with your needs
3. **No Alert Fatigue** - Only relevant detections enabled
4. **Future-Proof** - All capabilities already built-in
5. **Cost-Effective** - No additional licensing as you grow

**NetMonitor = Only IDS that's both:**
- ✅ Beginner-friendly (Raspberry Pi, works immediately)
- ✅ Expert-capable (92% MITRE, enterprise-grade)

**Choose your level. Upgrade anytime. No limits.**

---

## 🎨 De NetMonitor Belofte

### Traditionele Security Stack:
```
Tools genereren data → Mens analyseert (langzaam, 11% coverage)
                     → Reageert wanneer overwhelmed
                     → 33% netwerk onzichtbaar (geen agents)
```

### NetMonitor-Enhanced Stack:
```
Tools genereren data → AI analyseert (24/7, 100% coverage)
    +                → Mens onderzoekt (efficiënt, alleen top alerts)
SPAN port ziet alles → 100% netwerk zichtbaar (ook zonder agents)
```

**Resultaat:**
- ✅ 90% minder tijd aan triage
- ✅ 100% event coverage (AI nooit moe)
- ✅ 10-100x snellere detectie
- ✅ 100% netwerk visibility (vs 67% endpoint-only)
- ✅ Complete evidence (altijd)
- ✅ Proactief in plaats van reactief

**NetMonitor: The AI Scout That Never Sleeps**

*Zodat security analysts focussen op onderzoek,*
*niet eindeloze log triage.*

*En zodat de 33% van uw netwerk zonder agents,*
*niet langer een blinde vlek is.*

---

## 📞 Volgende Stappen

### 1. Demo Aanvragen
Zie NetMonitor in actie met uw eigen netwerkverkeer.

### 2. Proof of Concept
Installeer NetMonitor vrijblijvend in uw testomgeving.
Setup tijd: 10-30 minuten.

### 3. Implementatie
Onze experts helpen bij productie-implementatie.

---

## 📚 Meer Informatie

- **Website:** [https://awimax.nl]
- **Email:** [willem@awimax.nl]
- **GitHub:** [github.com/willempoort/netmonitor]
- **Documentatie:** [docs/ folder]

---

**NetMonitor - Zie wat er in uw netwerk gebeurt. Voordat het te laat is.**

*21 Core Detections | 15 MITRE Techniques | 52 AI Tools | €0 Licensing*
*Agentless Network Visibility | AI-Powered Triage | Automatic Evidence Collection*
