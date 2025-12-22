# Integrations - SIEM & Threat Intelligence

## Overview

NetMonitor ondersteunt optionele integraties voor:
- **SIEM Output** - Stuur alerts naar Wazuh, Splunk, Elastic of andere SIEM systemen
- **Threat Intelligence** - Verrijk alerts met IOC data van MISP, AlienVault OTX en AbuseIPDB

Alle integraties zijn **standaard uitgeschakeld** zodat NetMonitor ook in een eenvoudige setup kan worden gebruikt.

---

## Quick Start

### Minimale Setup (alleen SIEM)

```yaml
# config.yaml
integrations:
  enabled: true

  siem:
    enabled: true
    syslog:
      enabled: true
      host: "10.0.0.50"
      port: 514
      format: "cef"
```

### Volledige Setup (SIEM + Threat Intel)

```yaml
# config.yaml
integrations:
  enabled: true

  siem:
    enabled: true
    wazuh:
      enabled: true
      api_url: "https://wazuh.example.com:55000"
      api_user: "netmonitor"
      api_password: "${WAZUH_API_PASSWORD}"

  threat_intel:
    enabled: true
    misp:
      enabled: true
      url: "https://misp.example.com"
      api_key: "${MISP_API_KEY}"
```

---

## SIEM Integrations

### Syslog Output (CEF/LEEF/JSON)

Universele syslog output voor elk SIEM systeem.

```yaml
integrations:
  enabled: true
  siem:
    enabled: true
    syslog:
      enabled: true
      host: "siem.example.com"
      port: 514
      protocol: "udp"        # udp, tcp, of tls
      format: "cef"          # cef, leef, of json
      facility: 1            # LOCAL0

      # Voor TLS (optioneel)
      tls:
        enabled: false
        ca_cert: "/etc/ssl/certs/ca.pem"
        verify: true
```

#### Ondersteunde Formaten

**CEF (Common Event Format)** - Voor ArcSight, Wazuh, QRadar:
```
CEF:0|NetMonitor|IDS|1.0|PORT_SCAN|Port Scan Detected|7|src=192.168.1.100 dst=10.0.0.1 dpt=22 cs1=detected 50 ports in 60 seconds
```

**LEEF (Log Event Extended Format)** - Voor IBM QRadar:
```
LEEF:2.0|NetMonitor|IDS|1.0|PORT_SCAN|src=192.168.1.100	dst=10.0.0.1	dstPort=22
```

**JSON** - Voor Elastic, Splunk, Graylog:
```json
{"timestamp":"2025-01-15T10:30:00Z","severity":"HIGH","threat_type":"PORT_SCAN","source_ip":"192.168.1.100"}
```

### Wazuh Native Integration

Directe integratie met Wazuh API + custom decoder/rules.

```yaml
integrations:
  enabled: true
  siem:
    enabled: true
    wazuh:
      enabled: true

      # Wazuh Manager API
      api_url: "https://wazuh-manager:55000"
      api_user: "netmonitor"
      api_password: "${WAZUH_API_PASSWORD}"  # Gebruik environment variable!

      # Fallback naar syslog als API faalt
      syslog_fallback: true
      syslog_host: "wazuh-manager"
      syslog_port: 1514

      # Verify SSL (zet false voor self-signed certs)
      verify_ssl: true
```

Voor Wazuh setup instructies, zie [WAZUH_SETUP.md](./WAZUH_SETUP.md).

---

## Threat Intelligence Integrations

Threat intelligence verrijkt alerts met IOC data:
- Bekende malafide IP's worden gemarkeerd met confidence score
- MITRE ATT&CK technieken worden toegevoegd
- Alert severity kan worden verhoogd op basis van threat intel

### MISP (Malware Information Sharing Platform)

```yaml
integrations:
  enabled: true
  threat_intel:
    enabled: true
    cache_ttl_hours: 24    # Cache lookups voor 24 uur

    misp:
      enabled: true
      url: "https://misp.example.com"
      api_key: "${MISP_API_KEY}"
      verify_ssl: true
      timeout: 30
```

Voor MISP setup instructies, zie [MISP_SETUP.md](./MISP_SETUP.md).

### AlienVault OTX (Open Threat Exchange)

Gratis community threat intelligence.

```yaml
integrations:
  enabled: true
  threat_intel:
    enabled: true

    otx:
      enabled: true
      api_key: "${OTX_API_KEY}"  # Gratis op https://otx.alienvault.com
      timeout: 30
```

### AbuseIPDB

IP reputatie database met abuse reports.

```yaml
integrations:
  enabled: true
  threat_intel:
    enabled: true

    abuseipdb:
      enabled: true
      api_key: "${ABUSEIPDB_API_KEY}"

      # Filtering
      max_age_days: 90           # Alleen reports van laatste 90 dagen
      min_confidence: 50         # Minimum confidence score (0-100)

      timeout: 30
```

---

## Volledige Configuratie Voorbeeld

```yaml
# /etc/netmonitor/config.yaml

# === SIEM & Threat Intel Integrations ===
integrations:
  enabled: true

  # --- SIEM Output ---
  siem:
    enabled: true

    # Generic Syslog (voor elk SIEM)
    syslog:
      enabled: false
      host: "siem.example.com"
      port: 514
      protocol: "udp"
      format: "cef"
      facility: 1

    # Wazuh specifieke integratie
    wazuh:
      enabled: true
      api_url: "https://wazuh-manager:55000"
      api_user: "netmonitor"
      api_password: "${WAZUH_API_PASSWORD}"
      syslog_fallback: true
      syslog_host: "wazuh-manager"
      syslog_port: 1514
      verify_ssl: false  # Voor self-signed certs

  # --- Threat Intelligence ---
  threat_intel:
    enabled: true
    cache_ttl_hours: 24

    # MISP (self-hosted)
    misp:
      enabled: true
      url: "https://misp.example.com"
      api_key: "${MISP_API_KEY}"
      verify_ssl: true
      timeout: 30

    # AlienVault OTX (gratis)
    otx:
      enabled: true
      api_key: "${OTX_API_KEY}"
      timeout: 30

    # AbuseIPDB
    abuseipdb:
      enabled: true
      api_key: "${ABUSEIPDB_API_KEY}"
      max_age_days: 90
      min_confidence: 50
      timeout: 30
```

---

## Environment Variables

Gebruik environment variables voor gevoelige data:

```bash
# /etc/netmonitor/netmonitor.env
WAZUH_API_PASSWORD=your-secure-password
MISP_API_KEY=your-misp-key
OTX_API_KEY=your-otx-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

Environment variables worden automatisch geladen via de systemd service.

---

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │        NetMonitor SOC Server         │
                    │                                       │
  Network Traffic   │  ┌─────────┐    ┌──────────────────┐ │
  ───────────────> │  │ Detector │───>│ Alert Pipeline   │ │
                    │  └─────────┘    │                  │ │
                    │                  │  1. Enrichment   │ │
                    │                  │  2. Database     │ │
                    │                  │  3. SIEM Output  │ │
                    │                  │  4. Dashboard    │ │
                    │                  └────────┬─────────┘ │
                    └──────────────────────────┼───────────┘
                                               │
                    ┌──────────────────────────┼───────────┐
                    │          Integrations    │           │
                    │                          ▼           │
                    │  ┌─────────────────────────────────┐ │
                    │  │      Threat Intel Manager       │ │
                    │  │  ┌─────┐  ┌─────┐  ┌──────────┐ │ │
                    │  │  │MISP │  │ OTX │  │AbuseIPDB │ │ │
                    │  │  └─────┘  └─────┘  └──────────┘ │ │
                    │  └─────────────────────────────────┘ │
                    │                                       │
                    │  ┌─────────────────────────────────┐ │
                    │  │       SIEM Output Manager       │ │
                    │  │  ┌────────┐    ┌─────────────┐  │ │
                    │  │  │ Syslog │    │   Wazuh     │  │ │
                    │  │  │CEF/LEEF│    │  Native API │  │ │
                    │  │  └────────┘    └─────────────┘  │ │
                    │  └─────────────────────────────────┘ │
                    └──────────────────────────────────────┘
```

### Alert Flow

1. **Detection** - ThreatDetector analyseert packets
2. **Enrichment** - ThreatIntelManager verrijkt alert met IOC data
3. **Storage** - Alert wordt opgeslagen in database
4. **SIEM Output** - Alert wordt naar SIEM systemen gestuurd
5. **Dashboard** - Alert wordt gebroadcast naar web dashboard

### Caching

Threat intel lookups worden gecached om:
- API rate limits te respecteren
- Latency te minimaliseren
- Bandbreedte te besparen

Default cache TTL: 24 uur (configureerbaar via `cache_ttl_hours`).

---

## Troubleshooting

### Integration Status Bekijken

```bash
# Via API
curl http://localhost:8080/api/integrations/status

# Logs
journalctl -u netmonitor -f | grep -i integration
```

### Health Checks

```bash
# Test SIEM connectie
curl http://localhost:8080/api/integrations/siem/test

# Test Threat Intel bronnen
curl http://localhost:8080/api/integrations/threat-intel/test
```

### Veelvoorkomende Problemen

**SIEM ontvangt geen alerts:**
- Check firewall (port 514 UDP/TCP)
- Verify syslog format (CEF vs JSON)
- Check logs: `journalctl -u netmonitor | grep siem`

**Threat intel lookups falen:**
- Verify API keys
- Check network connectivity
- Check rate limits (vooral AbuseIPDB)

**High latency:**
- Verhoog `cache_ttl_hours`
- Verlaag aantal enabled sources
- Check network latency naar externe APIs

---

## Related Documentation

- [WAZUH_SETUP.md](./WAZUH_SETUP.md) - Wazuh SIEM installatie en configuratie
- [MISP_SETUP.md](./MISP_SETUP.md) - MISP Threat Intelligence Platform setup
- [CONFIG_GUIDE.md](../usage/CONFIG_GUIDE.md) - Algemene configuratie handleiding
