# NetMonitor - Uw Digitale Bewaker

**Bescherm uw bedrijfsnetwerk tegen cyberdreigingen met een professionele Security Operations Center oplossing**

---

## Het Probleem

Elke dag worden bedrijven slachtoffer van cyberaanvallen. Ransomware, datadiefstal en gehackte systemen kosten bedrijven gemiddeld **€250.000 per incident** - exclusief reputatieschade en omzetverlies.

De meeste aanvallen worden pas **maanden later** ontdekt, wanneer de schade al is aangericht. Waarom?

- Traditionele antivirussoftware detecteert alleen **bekende** dreigingen
- Firewalls beschermen de buitenkant, maar niet wat er **binnen** uw netwerk gebeurt
- IT-afdelingen missen vaak de tools om verdacht gedrag **in real-time** te zien

**NetMonitor biedt de oplossing.**

---

## Wat is NetMonitor?

NetMonitor is een **Security Operations Center (SOC)** voor uw bedrijfsnetwerk. Het bewaakt continu al het netwerkverkeer en waarschuwt onmiddellijk bij verdachte activiteiten.

Vergelijk het met een beveiligingscamera voor uw digitale omgeving: 24/7 wakend, direct alarmerend bij inbrekers.

![Screenshot van het NetMonitor dashboard met live alerts, grafieken en systeem metrics - toon het overzichtelijke dark-theme interface](./images/netmonitor-afb1.png)

## Unieke Voordelen

### 1. Real-Time Dreigingsdetectie

NetMonitor detecteert aanvallen **op het moment dat ze plaatsvinden**, niet maanden later.

| Traditionele Beveiliging | NetMonitor |
|--------------------------|------------|
| Detectie na weken/maanden | Detectie binnen seconden |
| Alleen bekende virussen | Verdacht gedrag herkennen |
| Passieve logbestanden | Live dashboard met alerts |
| Handmatige analyse nodig | Automatische classificatie |

**Wat we detecteren:**
- Ransomware die probeert te verspreiden
- Datadiefstal naar het internet
- Gehackte computers die contact maken met criminele servers
- Ongeautoriseerde toegangspogingen
- Verdachte poortscans en netwerkverkenning

### 2. Slimme Apparaatherkenning met Machine Learning

NetMonitor **leert** welke apparaten in uw netwerk horen en wat normaal gedrag is — met echte **Machine Learning**.

![Screenshot: van Device Classification scherm met apparatenlijst, vendors en templates](./images/netmonitor-afb3.png)

**Hoe het werkt:**
- **ML Device Classification**: Random Forest classifier herkent automatisch 11 apparaattypes (servers, werkstations, IoT-camera's, smart TV's, NAS, printers, etc.)
- **ML Anomaly Detection**: Isolation Forest detecteert afwijkend gedrag per apparaat
- **Auto-Training**: Modellen worden elke 24 uur automatisch getraind en toegepast
- Automatische herkenning van printers, camera's, servers en werkstations
- Leert het normale verkeerspatroon per apparaat (28 features per device)
- Waarschuwt alleen bij **afwijkend** gedrag
- Voorkomt vals alarm door streaming-diensten (Netflix, Teams) te herkennen

**Technisch:** De ML modellen draaien volledig op de SOC server — geen impact op sensor RAM (belangrijk voor Raspberry Pi deployments).

**Resultaat:** Minder ruis, automatische classificatie, en alleen relevante waarschuwingen die actie vereisen.

### 3. Centraal Beheer

Meerdere kantoorlocaties? NetMonitor beheert alles vanuit **één dashboard**.

**Voordelen:**
- Eén overzicht voor alle locaties
- Centrale configuratie, lokale uitvoering
- Real-time status van elke sensor
- Uniforme beveiligingsregels

### 4. Kiosk Mode voor NOC/SOC Display

Perfect voor een dedicated beveiligingsscherm in uw serverruimte of bij de IT-afdeling.

![Screenshot: van Kiosk mode - volledig scherm met grote metrics en traffic grafiek](./images/netmonitor-afb4.png)

- Automatisch verversen
- Duidelijke visuele waarschuwingen
- Geschikt voor wandmontage

### 5. TLS/HTTPS Analyse

NetMonitor analyseert versleuteld verkeer **zonder decryptie** - privacy-vriendelijk maar effectief.

**Wat we detecteren:**
- **JA3/JA3S fingerprints**: Identificeert malware aan TLS handshake patronen
- **SNI analyse**: Ziet welke domeinen bezocht worden, ook via HTTPS
- **Certificate monitoring**: Detecteert verdachte of verlopen certificaten
- **Bekende malware signatures**: JA3 hashes van Emotet, Cobalt Strike, etc.

### 6. PCAP Forensics (NIS2 Compliant)

Volledige netwerkopname voor incident response en compliance.

**Mogelijkheden:**
- Ring buffer voor continue opname (configureerbare retentie)
- Export specifieke flows voor forensisch onderzoek
- Per-alert PCAP bestanden voor bewijsvoering
- Voldoet aan NIS2 logging vereisten

### 7. Enterprise Security Suite

NetMonitor bevat een complete enterprise security suite voor geavanceerde dreigingsdetectie:

#### AD/Kerberos Aanvalsdetectie
- **Kerberoasting**: Detecteert mass TGS-REQ aanvragen voor offline password cracking
- **AS-REP Roasting**: Identificeert aanvallen op accounts zonder pre-authenticatie
- **DCSync**: Detecteert Domain Controller replicatie misbruik
- **Pass-the-Hash**: Herkent ticket hergebruik aanvallen
- **Golden Ticket**: Detecteert vervalste TGT tickets
- **Zwakke encryptie**: Waarschuwt bij RC4/DES gebruik

#### Kill Chain Correlatie (MITRE ATT&CK)
Automatische correlatie van alerts naar aanvalsketens:
- 10-fasen kill chain model
- MITRE ATT&CK technique mapping
- Multi-host lateral movement tracking
- APT campaign detectie

#### SMB/LDAP Deep Parsing
- Admin share access detectie (C$, ADMIN$, IPC$)
- Gevoelige bestandstoegang monitoring
- LDAP enumeratie detectie
- DCSync query herkenning

#### SOAR (Automated Response)
- Playbook-based automatisering
- Goedkeuringsworkflows
- Dry-run modus voor veilig testen
- Integratie met firewall, NAC, AD

#### Asset Risk Scoring
- Dynamische risicoscores (0-100)
- Tijdsgewogen alerthistorie
- Trend analyse per asset
- Prioritering voor SOC teams

### 8. GeoIP Intelligence

Geografische context voor elke IP-verbinding.

- Land-identificatie voor alle externe IP's
- Onderscheid tussen Local (uw netwerk) en Private (andere RFC1918)
- MaxMind database of online API fallback
- Detecteer onverwachte verbindingen naar high-risk landen

---

## 🤖 AI-Powered Security met MCP Integratie

NetMonitor is een van de eerste security monitoring tools met native **Model Context Protocol (MCP)** integratie voor AI-assistenten zoals Claude.

### Wat Maakt Dit Uniek?

De MCP HTTP API biedt **49 gespecialiseerde security tools** die AI-assistenten direct kunnen aanroepen:

| Categorie | Tools | Mogelijkheden |
|-----------|-------|---------------|
| **Analyse** | 5 | IP analyse, threat lookup, sensor status |
| **Device Classification** | 13 | Apparaat herkenning, behavior learning, templates |
| **TLS Analysis** | 3 | JA3 checks, TLS statistieken, blacklist beheer |
| **PCAP Forensics** | 5 | Capture listing, flow export, buffer status |
| **Sensor Beheer** | 2 | Remote commands, command history |
| **Whitelist** | 3 | Entries toevoegen, bekijken, verwijderen |
| **Export** | 1 | CSV export voor SIEM integratie |
| **Configuratie** | 5 | Parameters lezen en schrijven |
| **AD/Kerberos** | 3 | Attack stats, ticket analysis, encryption checks |
| **Kill Chain** | 2 | Attack chains, MITRE ATT&CK mapping |
| **Risk Scoring** | 3 | Asset scores, trends, prioritering |
| **SOAR** | 4 | Playbooks, approvals, action history |

### Concrete AI Use Cases

**1. Natuurlijke Taal Security Queries**

In plaats van complexe SQL queries of dashboard navigatie:

```
Gebruiker: "Welke verdachte activiteiten waren er vannacht?"

AI analyseert via MCP:
→ get_recent_threats (hours=8, severity=HIGH)
→ analyze_ip (voor top verdachte IPs)
→ check_ja3_fingerprint (voor TLS anomalies)

Resultaat: Samenvatting in begrijpelijke taal met actie-advies
```

**2. Geautomatiseerde Incident Response**

```
AI detecteert via MCP: Nieuwe CRITICAL alert voor IP 185.220.101.50

AI onderzoekt automatisch:
→ analyze_ip: Threat score 92, 47 alerts in 24 uur
→ get_country_for_ip: Russia (RU)
→ check_ip_service_provider: Geen bekende provider

AI actie (met goedkeuring):
→ add_whitelist_entry (action=block): IP geblokkeerd
→ send_sensor_command: Alle sensoren geüpdatet
```

**3. Proactieve Threat Hunting**

```
AI periodieke scan via MCP:
→ get_devices: 127 apparaten bekend
→ get_device_classification_hints: 3 nieuwe apparaten
→ get_tls_metadata: Onbekende JA3 hash gedetecteerd

Rapportage: "3 nieuwe apparaten ontdekt, 1 met verdachte TLS fingerprint"
```

### Technische Voordelen van MCP

| Aspect | Voordeel |
|--------|----------|
| **Token-based Auth** | Veilige Bearer tokens per AI client |
| **Permission Scopes** | read_only, read_write, admin granulariteit |
| **Rate Limiting** | Bescherming tegen misbruik |
| **Audit Trail** | Volledige logging van alle AI acties |
| **Multi-Client** | Meerdere AI's tegelijk ondersteunen |

### Waarom AI + NetMonitor Effectief Is

1. **Contextuele Analyse**: AI kan meerdere databronnen combineren (alerts, device info, GeoIP, TLS) voor betere conclusies

2. **Patroonherkenning**: AI herkent subtiele patronen in grote datasets die mensen missen

3. **24/7 Beschikbaarheid**: AI kan continu monitoren en reageren, ook buiten kantooruren

4. **Kennisverrijking**: AI koppelt NetMonitor data aan externe threat intelligence kennis

5. **Natuurlijke Rapportage**: Technische data vertaald naar begrijpelijke taal voor management

---

## Waarom NetMonitor Kiezen?

### Open Source & Transparant

- Geen verborgen kosten of vendor lock-in
- Volledige controle over uw data
- Draait op uw eigen hardware

### Kosteneffectief

| Oplossing | Jaarlijkse Kosten |
|-----------|-------------------|
| Enterprise SIEM | €50.000 - €500.000+ |
| Managed SOC Service | €30.000 - €100.000+ |
| **NetMonitor** | **Eenmalige implementatie** |

### Bewezen Technologie

- Gebaseerd op industriestandaard threat intelligence feeds
- Integratie met AbuseIPDB, FeodoTracker, URLhaus
- Continue updates van bekende dreigingen

### Eenvoudige Implementatie

1. Installeer op een Linux server
2. Verbind met uw netwerkswitch (mirror port)
3. Open het dashboard en start met bewaken

**Geen weken aan consulting nodig** - binnen een dag operationeel.

---

## Technische Highlights (voor uw IT-afdeling)

| Component | Specificatie |
|-----------|--------------|
| Platform | Linux (Ubuntu/Debian) |
| Database | PostgreSQL + TimescaleDB |
| Interface | Modern Web Dashboard |
| API | REST + WebSocket + MCP HTTP API |
| AI Integratie | 49 MCP tools met token auth |
| Schaalbaarheid | Multi-sensor architectuur |
| Performance | 1Gbps+ netwerkverkeer |
| Forensics | PCAP capture met ring buffer |
| TLS Analyse | JA3/JA3S, ESNI/ECH, Domain Fronting |
| AD Security | Kerberos attacks, DCSync, Pass-the-Hash |
| Correlation | Kill chain, MITRE ATT&CK mapping |
| Response | SOAR playbooks, automated actions |

---

## Detectie Capabilities Overzicht

### Threat Intelligence
- Command & Control server detectie
- Malware download herkenning
- Bekende kwaadaardige IP-adressen
- Real-time reputation checks
- JA3 malware fingerprint database

### AD/Kerberos Attack Detection
- Kerberoasting (mass TGS-REQ)
- AS-REP Roasting (pre-auth bypass)
- DCSync (replication abuse)
- Pass-the-Hash/Ticket
- Golden/Silver Ticket forgery
- Weak encryption (RC4/DES)

### Kill Chain Correlatie
- 10-stage attack tracking
- MITRE ATT&CK technique mapping
- Cross-host lateral movement
- APT campaign identification
- Automated severity escalation

### Gedragsanalyse met ML
- Data exfiltratie (grote uploads)
- Beaconing (regelmatige "check-ins" naar hackers)
- Lateral movement (verspreiding binnen netwerk)
- Ongebruikelijke verkeerspatronen
- **ML Device Classification**: Random Forest classifier (11 apparaattypes)
- **ML Anomaly Detection**: Isolation Forest per-device baseline
- Device behavior learning (28 features per apparaat)

### Protocol Analyse
- DNS tunneling (data verstopt in DNS)
- Verdachte HTTP/HTTPS patronen
- TLS/SSL anomalies (certificate issues, unusual ciphers)
- Brute force aanvallen (wachtwoord raden)
- Poortscanning

### SMB/LDAP Deep Parsing
- Admin share access (C$, ADMIN$, IPC$)
- Sensitive file access (password.txt, .kdbx, id_rsa)
- Share enumeration detectie
- LDAP user/group enumeration
- DCSync query detection
- Credential harvesting attempts

### Automated Response (SOAR)
- Playbook-based automation
- IP blocking, host isolation
- Account disabling
- PCAP capture on alert
- Multi-channel notifications

### Netwerk Context
- GeoIP locatie per verbinding
- Service provider identificatie
- Internal vs External traffic classificatie
- Automatische device discovery

![Screenshot: Infographic met de verschillende detectie-types in een visueel aantrekkelijke layout - iconen voor elke categorie](./images/netmonitor-afb2.png)

---

## Implementatie Scenario's

### Scenario 1: Klein Kantoor (10-50 medewerkers)

- Eén NetMonitor server
- Verbonden met centrale switch
- Dashboard toegankelijk via intranet
- **Investering:** Enkele uren implementatie

### Scenario 2: Middelgroot Bedrijf (50-500 medewerkers)

- Centrale NetMonitor server
- Sensoren op elke locatie/VLAN
- Kiosk display bij IT-afdeling
- AI-integratie voor analyse en rapportage
- **Investering:** 1-2 dagen implementatie

### Scenario 3: Enterprise (500+ medewerkers)

- Gedistribueerde architectuur
- Meerdere sensoren per locatie
- PostgreSQL cluster voor high availability
- Integratie met bestaande SIEM
- PCAP forensics voor compliance
- **Investering:** Projectmatige aanpak

---

## Volgende Stappen

### 1. Demo Aanvragen
Zie NetMonitor in actie met uw eigen netwerkverkeer.

### 2. Proof of Concept
Installeer NetMonitor vrijblijvend in uw testomgeving.

### 3. Implementatie
Onze experts helpen bij de productie-implementatie.

---

## Contact

**NetMonitor - Professional Network Security Monitoring**

- Website: [https://awimax.nl]
- Email: [willem@awimax.nl]
- GitHub: [github.com/willempoort/netmonitor]

---

## Bijlagen

### A. Feature Overzicht

| Categorie | Features |
|-----------|----------|
| **Monitoring** | Real-time packet analyse, Traffic visualisatie, Top talkers, System metrics |
| **Detectie** | 40+ detectie types, Threat feeds, IP reputation, Behavior analysis, JA3 fingerprinting |
| **TLS/HTTPS** | JA3/JA3S analyse, SNI monitoring, Certificate checks, Malware fingerprints, ESNI/ECH, Domain Fronting |
| **AD/Kerberos** | Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash, Golden Ticket, Weak encryption |
| **Kill Chain** | MITRE ATT&CK mapping, 10-stage correlation, Multi-host tracking, APT campaign detection |
| **SMB/LDAP** | Admin share access, Sensitive file detection, LDAP enumeration, DCSync queries |
| **Forensics** | PCAP capture, Ring buffer, Flow export, Per-alert opname (NIS2 compliant) |
| **Classificatie** | Device discovery, **ML Classification** (Random Forest), Behavior learning, **ML Anomaly Detection** (Isolation Forest), Template matching, Alert suppression |
| **Risk Scoring** | Dynamic 0-100 scores, Time decay, Asset categorization, Trend analysis |
| **SOAR** | Automated playbooks, Approval workflows, Dry-run mode, Multi-integration |
| **GeoIP** | Land identificatie, Local/Private onderscheid, MaxMind database |
| **Beheer** | Central dashboard, Multi-sensor, Remote config, Whitelist management |
| **AI Integratie** | 45+ MCP tools, Token auth, Permission scopes, Audit logging |

### B. Compliance & Security

NetMonitor ondersteunt compliance met:
- **AVG/GDPR**: Data blijft binnen uw eigen infrastructuur
- **NIS2**: Incident detectie, PCAP forensics en rapportage capabilities
- **ISO 27001**: Onderdeel van security monitoring controls

### C. ROI Berekening

| Factor | Waarde |
|--------|--------|
| Gemiddelde kosten datalek | €250.000 |
| Kans op datalek zonder monitoring | 30%/jaar |
| Kans op datalek met NetMonitor | 5%/jaar |
| **Risicoreductie** | **€62.500/jaar** |

*Exclusief reputatieschade, omzetverlies en herstelkosten.*

### D. MCP API Tool Categorieën

| Categorie | Aantal | Scope |
|-----------|--------|-------|
| Core Analysis | 5 | read_only |
| Device Classification | 13 | mixed |
| TLS Analysis | 3 | mixed |
| PCAP Forensics | 5 | mixed |
| Sensor Commands | 2 | mixed |
| Whitelist Management | 3 | mixed |
| Export Tools | 1 | read_only |
| Config Management | 5 | mixed |
| AD/Kerberos | 3 | read_only |
| Kill Chain | 2 | read_only |
| Risk Scoring | 3 | read_only |
| SOAR | 4 | mixed |
| **Totaal** | **49** | - |

---

**NetMonitor - Zie wat er in uw netwerk gebeurt. Voordat het te laat is.**
