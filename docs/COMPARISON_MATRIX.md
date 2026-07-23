# NetMonitor Comparison Matrix - Eerlijke Vergelijking

**Updated:** 20 januari 2026
**Perspectief:** Objectieve analyse van NetMonitor vs alternatieven

---

## 🎯 Belangrijke Disclaimer

**Dit is GEEN "NetMonitor is beter dan alles" document.**

Dit is een eerlijke analyse van:
- ✅ Wat NetMonitor goed doet
- ⚠️ Waar anderen beter zijn
- 🤝 Aanbevolen combinaties

**NetMonitor is ontworpen als complementaire AI-laag, niet als vervanging.**

---

## 📊 Quick Decision Guide

### Gebruik NetMonitor Als Je:

✅ **Verdrinkt in logs** (10.000+ events/dag, kan slechts 11% reviewen)
✅ **Devices zonder agents hebt** (printers, IoT, BYOD, OT/ICS = 33% blind spot)
✅ **AI-powered triage wilt** (90% tijdwinst, 100% coverage)
✅ **Automatic evidence collection nodig hebt** (NIS2 compliant PCAP)
✅ **Bestaande tools slimmer wilt maken** (Wazuh/Suricata/Zeek + AI)
✅ **Snel wilt starten** (10-30 min setup vs uren/dagen)
✅ **Budget beperkt is** (€0 licensing, RPi compatible)

### Gebruik NetMonitor NIET Als Je:

❌ **Comprehensive MITRE coverage prioriteert zonder tuning** (kies Wazuh ~75% out-of-box vs NetMonitor ~8% default, ~92% expert mode)
❌ **>100 protocol parsers nodig hebt** (kies Zeek - specialist tool)
❌ **Inline IPS bij 10Gbps+ wilt** (kies Suricata - superieure multi-threading)
❌ **24/7 vendor support met SLA vereist** (kies enterprise: Splunk, CrowdStrike)
❌ **Alleen endpoint detection nodig hebt** (NetMonitor = network-focused)
❌ **Geen enkele technische kennis hebt** (kies managed SOC service)

---

## 🎯 Feature Comparison Matrix (Eerlijk)

| Feature | NetMonitor<br/>(Out-of-Box) | NetMonitor<br/>(Expert Mode) | Wazuh | Suricata | Zeek | Security Onion | Splunk |
|---------|-----------|-----------|-------|----------|------|----------------|--------|
| **Easy Setup** | ✅✅✅ | ✅✅ | ✅✅ | ⚠️ | ⚠️⚠️ | ⚠️⚠️ | ⚠️ |
| **Built-in Dashboard** | ✅✅✅ | ✅✅✅ | ✅✅ | ❌ | ❌ | ✅✅✅ | ✅✅✅ |
| **AI Integration (MCP)** | ✅✅✅ | ✅✅✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ |
| **Agentless Network** | ✅✅✅ | ✅✅✅ | ❌ | ✅✅✅ | ✅✅✅ | ✅✅✅ | ⚠️ |
| **Endpoint Visibility** | ❌ | ❌ | ✅✅✅ | ❌ | ❌ | ✅✅ | ✅✅✅ |
| **Protocol Depth** | ⚠️ | ✅✅ | ⚠️ | ✅✅ | ✅✅✅ | ✅✅✅ | ✅✅ |
| **Signature Rules** | ❌ | ❌ | ⚠️ | ✅✅✅ | ❌ | ✅✅✅ | ⚠️ |
| **ML Anomaly Detection** | ✅✅ | ✅✅✅ | ❌ | ❌ | ⚠️ | ❌ | ✅✅✅ |
| **PCAP Forensics** | ✅✅✅ | ✅✅✅ | ❌ | ⚠️ | ✅✅ | ✅✅✅ | ⚠️ |
| **Resource (Low)** | ✅✅✅ | ✅✅ | ✅✅ | ✅✅ | ⚠️ | ❌ | ❌ |
| **Raspberry Pi** | ✅✅✅ | ✅ | ⚠️ | ⚠️ | ❌ | ❌ | ❌ |
| **Multi-Sensor** | ✅✅✅ | ✅✅✅ | ✅✅✅ | ⚠️ | ⚠️ | ✅✅ | ✅✅✅ |
| **SIEM Export** | ✅✅✅ | ✅✅✅ | ✅✅✅ | ⚠️ | ⚠️ | ✅✅✅ | N/A |
| **SOAR/Automation** | ✅✅ | ✅✅✅ | ✅✅✅ | ❌ | ❌ | ⚠️ | ✅✅✅ |
| **MITRE Coverage** | ⚠️ **8%** | ✅✅✅ **~92%** | ✅✅✅ 75% | ⚠️ 40% | ✅✅ 70% | ✅✅✅ 80% | ✅✅✅ 85% |
| **Threat Detection Types** | **21** | **74** | ~100 | ~40 | ~80 | ~120 | ~150 |
| **Community Size** | ⚠️ Small | ⚠️ Small | ✅✅ Large | ✅✅✅ Huge | ✅✅ Large | ✅✅ Large | ✅✅✅ Huge |
| **Cost (3yr, 500emp)** | **€11k** | **€15k** | **€26k** | **€23k** | **€41k** | **€51k** | **€270k** |

**Legend:**
- ✅✅✅ = Excellent
- ✅✅ = Good
- ✅ = Basic
- ⚠️ = Limited
- ❌ = Not Available

**NetMonitor Modes Explained:**

| Mode | Description | MITRE Coverage | Detections | Use Case |
|------|-------------|----------------|------------|----------|
| **Out-of-Box** | Conservative defaults, minimal false positives | ~8% (21 enabled) | High-confidence essentials | Immediate deployment, broad environments |
| **Expert Mode** | All capabilities enabled, environment-tuned | ~92% (74 enabled) | All 9 phases active | Professional tuning, specific use cases |

*Zie PITCH_DOCUMENT.md § "The Porsche Principle" voor details over unlock methodes.*

---

## 💰 Total Cost of Ownership (3 jaar, 500 werknemers)

### Open Source Options (Zelf Beheren)

| Oplossing | Hardware | Setup | Training | Support (opt) | **Total** |
|-----------|----------|-------|----------|---------------|-----------|
| **NetMonitor (out-of-box)** | €2k | €5k | €1k | €3k | **€11k** |
| **NetMonitor (expert mode)** | €2.5k | €7k | €2k | €3.5k | **€15k** |
| **NetMonitor + Wazuh** | €3k | €8k | €3k | €5k | **€19k** |
| **NetMonitor + Suricata** | €3.5k | €10k | €4k | €4k | **€21.5k** |
| **Suricata + Zeek** | €5k | €20k | €10k | €0 | **€35k** |
| **Wazuh (zelf)** | €3k | €12k | €5k | €6k | **€26k** |
| **Security Onion** | €6k | €30k | €15k | €0 | **€51k** |

**Note:** Expert mode TCO includes extra tuning effort (+€2k setup, +€1k training) en mogelijk krachtigere hardware (+€0.5k).

### Enterprise/Managed Options

| Oplossing | License | Hardware | Setup | Training | Support | **Total** |
|-----------|---------|----------|-------|----------|---------|-----------|
| **Splunk Enterprise** | €150k | €5k | €50k | €20k | €45k | **€270k** |
| **Microsoft Sentinel** | €80k | €0 | €30k | €15k | €25k | **€150k** |
| **Managed SOC** | €0 | €0 | €10k | €0 | €210k | **€220k** |
| **CrowdStrike Falcon** | €120k | €0 | €20k | €10k | €40k | **€190k** |

---

## 🚀 Aanbevolen Combinaties

### Voor MKB (50-500 werknemers): NetMonitor + Wazuh

```
Wazuh (Endpoints):
├─ Agents op werkstations/servers (67% netwerk)
├─ File integrity, process monitoring
├─ Rootkit detection
└─ Covers devices MET agents

NetMonitor (Network):
├─ SPAN port monitoring (100% netwerk)
├─ AI-powered triage van alle events
├─ IoT/printers/BYOD/guests
└─ Covers devices ZONDER agents (33% blind spot)

Native Integration → Wazuh Manager
→ Unified alerting
→ Complete visibility
→ €19.000 (3 jaar) vs €270.000 Splunk
```

### Voor Security Specialists: NetMonitor + Suricata

```
Suricata (Signatures):
├─ 30.000+ ET Open rules
├─ Known CVE detection
├─ Inline IPS blocking
└─ Signature-based

NetMonitor (Behavior + AI):
├─ ML anomaly detection
├─ Zero-day detection
├─ AI-powered triage
└─ Behavior-based

Both → Splunk/ELK (via CEF)
→ Complementary detection
→ €21.500 (3 jaar)
```

### Voor Enterprise Forensics: NetMonitor + Zeek

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

AI: "Correleer Zeek's DNS met NetMonitor's TLS voor lateral movement"
→ Zeek's diepte + NetMonitor's AI
```

---

## 📈 Performance Benchmark (Gemeten)

**Test Setup:** Raspberry Pi 4 (8GB) sensors, Intel NUC i5 servers, 100 Mbps traffic, 50 devices, 24h monitoring

### Resource Usage

| Tool | RAM (Light) | RAM (Heavy) | CPU (Baseline) | CPU (Peak) |
|------|-------------|-------------|----------------|------------|
| **NetMonitor** | 150 MB | 280 MB | 8-12% | 60% (ML) |
| Wazuh Agent | 100 MB | 150 MB | 5-8% | 20% |
| Suricata | 300 MB | 450 MB | 15-20% | 40% |
| Zeek | 500 MB | 700 MB | 10-15% | 30% |
| Security Onion | 2 GB | 4 GB | 30-50% | 80% |

---

## 🎯 Decision Matrix

```
Je prioriteit:                    Beste keuze:
───────────────────────────────   ─────────────────────────────────
AI-powered analysis          →    NetMonitor ✅
Agentless coverage           →    NetMonitor ✅
Quick deployment (1h)        →    NetMonitor (out-of-box) ✅
Cost-effective (<€15k)       →    NetMonitor ✅
Flexible growth path         →    NetMonitor (8% → 92%) ✅

Comprehensive MITRE (75%+)   →    Wazuh / NetMonitor Expert Mode ✅
Endpoint visibility          →    Wazuh ✅
Community size               →    Suricata/Snort ✅
Protocol forensics (100+)    →    Zeek ✅
High-speed IPS (10Gbps+)     →    Suricata ✅
Enterprise support           →    Splunk ✅
Complete suite               →    Security Onion ✅

Complete coverage            →    NetMonitor + Wazuh ✅✅
Best of both worlds          →    NetMonitor Expert + Suricata/Zeek ✅✅
Grow at your pace            →    NetMonitor (21→74 detections) ✅✅
```

---

**Remember: NetMonitor is the AI Scout that makes your existing tools smarter.**
**Not a replacement. A force multiplier.**

*Voor details: willem@awimax.nl*
