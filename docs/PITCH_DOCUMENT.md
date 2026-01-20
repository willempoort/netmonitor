# NetMonitor - De AI Scout voor Uw Security Stack

**Bescherm uw bedrijfsnetwerk met AI-powered network monitoring**

---

## 🚨 Het Probleem: Security Teams Verdrinken in Logs

Uw security tools werken perfect. Ze genereren data:
- Wazuh: 5.000 endpoint events/dag
- Suricata: 2.000 network alerts/dag
- Zeek: 200 MB protocol logs/dag

**Maar wie leest dit allemaal?**

Een menselijke analyst kan ~800 events/dag verwerken (8 uur × 100/uur).
Dat is **11% coverage** - 89% wordt nooit bekeken.

### De Gevolgen

- ❌ **Kritieke threats gemist** - Lateral movement begraven in 6.812 normale events
- ❌ **Trage detectie** - APT aanvallen ontdekt na 6 maanden in plaats van 6 uur
- ❌ **Analyst burn-out** - 80% tijd aan log triage, 20% aan écht onderzoek
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

**Concreet voorbeeld:**

```
Traditioneel (zonder NetMonitor):
Day 1-7: Attacker spreidt door netwerk
→ 50.000+ events (normaal + aanval gemixed)
→ Analyst: Geen tijd om alles te reviewen (11% coverage)
→ Detection: Week 3 (TE LAAT)
→ Evidence: Niet verzameld
→ Damage: Ransomware deployed (€millions)

Met NetMonitor AI:
Day 1, 03:24: Suspicious DNS query
→ AI: Threat score 40 (MEDIUM), start PCAP recording

Day 3, 14:15: TLS fingerprint = Cobalt Strike
→ AI: Correleert met Day 1, escalates HIGH

Day 7, 02:30: SMB lateral movement (5 hosts)
→ AI: Kill chain detected, escalates CRITICAL
→ Alert: "🚨 APT kill chain: Initial access → C2 → Lateral movement
          Advies: Isoleer 10.0.1.50
          Evidence: 7 dagen PCAP ready at /forensics/apt-001/"

Day 7, 08:00: Analyst arrives
→ Dashboard: 1 CRITICAL met complete timeline
→ Action: Isolated binnen 30 min
→ Result: Stopped BEFORE ransomware

Time to detection: 5.5 uur vs 21 dagen
Damage: €0 vs €millions
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
- **Actuele Status:** [docs/STATUS_VERIFICATIE.md]

---

**NetMonitor - Zie wat er in uw netwerk gebeurt. Voordat het te laat is.**

*21 Core Detections | 15 MITRE Techniques | 52 AI Tools | €0 Licensing*
*Agentless Network Visibility | AI-Powered Triage | Automatic Evidence Collection*
