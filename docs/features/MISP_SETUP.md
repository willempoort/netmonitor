# MISP Threat Intelligence Setup voor NetMonitor

## Overview

MISP (Malware Information Sharing Platform) is een open-source threat intelligence platform voor het delen en opslaan van Indicators of Compromise (IOCs). NetMonitor kan MISP gebruiken om alerts te verrijken met threat intelligence data.

---

## Quick Start met Docker

De snelste manier om MISP te installeren is via Docker.

### 1. Clone MISP Docker

```bash
# Clone MISP Docker repository
git clone https://github.com/MISP/misp-docker.git
cd misp-docker

# Kopieer template configuratie
cp template.env .env
```

### 2. Configureer Environment

```bash
# Bewerk .env file
nano .env
```

Belangrijke instellingen:
```bash
# Basis URL (aanpassen aan je server)
BASE_URL=https://misp.example.com

# Admin email en organisatie
MISP_ADMIN_EMAIL=admin@example.com
MISP_ADMIN_ORG=MyOrganization

# Database wachtwoord (wijzig dit!)
MYSQL_PASSWORD=SecureMysqlPassword123!

# Redis
REDIS_HOST=redis
```

### 3. Start MISP

```bash
# Start MISP stack
docker-compose up -d

# Wacht tot initialisatie compleet is (~5-10 minuten)
docker-compose logs -f misp
```

### 4. Eerste Login

1. Open: https://misp.example.com
2. Default credentials:
   - Email: admin@admin.test
   - Password: admin
3. **Wijzig direct je wachtwoord!**

---

## MISP Configureren voor NetMonitor

### 1. Maak API Gebruiker Aan

1. Ga naar Administration > Add User
2. Vul in:
   - Email: netmonitor@example.com
   - Role: User (of Sync user voor meer rechten)
   - Organisation: Je organisatie
3. Klik Save

### 2. Genereer API Key

1. Ga naar Administration > List Users
2. Klik op de netmonitor gebruiker
3. Klik "Auth Keys" in het menu
4. Klik "Add authentication key"
5. Noteer de API key (wordt maar 1x getoond!)

### 3. Configureer Feed Synchronisatie

MISP kan automatisch feeds importeren van externe bronnen:

1. Ga naar Sync Actions > List Feeds
2. Enable nuttige feeds:
   - CIRCL OSINT Feed
   - Abuse.ch URLhaus
   - Abuse.ch Feodo Tracker
   - MISP Default Feeds

3. Klik "Fetch and store all feed data"

---

## NetMonitor Configuratie

### Basic Setup

```yaml
# /etc/netmonitor/config.yaml
integrations:
  enabled: true

  threat_intel:
    enabled: true
    cache_ttl_hours: 24

    misp:
      enabled: true
      url: "https://misp.example.com"
      api_key: "${MISP_API_KEY}"
      verify_ssl: true
      timeout: 30
```

### Environment Variable

```bash
# /etc/netmonitor/netmonitor.env
MISP_API_KEY=your-misp-api-key-here
```

### Advanced Options

```yaml
integrations:
  threat_intel:
    misp:
      enabled: true
      url: "https://misp.example.com"
      api_key: "${MISP_API_KEY}"

      # SSL verificatie (false voor self-signed certs)
      verify_ssl: false

      # Request timeout
      timeout: 30

      # Cache TTL (in uren)
      cache_ttl_hours: 24
```

---

## Verifieer Integratie

### 1. Test API Connectie

```bash
# Test vanuit NetMonitor
curl http://localhost:8080/api/integrations/threat-intel/test

# Of direct naar MISP
curl -k -H "Authorization: YOUR_API_KEY" \
  https://misp.example.com/servers/getVersion
```

### 2. Test IOC Lookup

```bash
# Zoek een bekende malafide IP
curl -X POST http://localhost:8080/api/threat-intel/lookup \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "185.234.218.228"}'
```

### 3. Check Logs

```bash
# NetMonitor logs
journalctl -u netmonitor -f | grep -i misp

# MISP logs
docker-compose logs -f misp
```

---

## MISP Data Bronnen Toevoegen

### Feeds Configureren

1. Ga naar Sync Actions > List Feeds
2. Klik "Add Feed" voor custom feeds

**Aanbevolen Feeds:**

| Feed | Type | URL |
|------|------|-----|
| Abuse.ch Feodo | C2 IPs | https://feodotracker.abuse.ch/... |
| Abuse.ch URLhaus | Malware URLs | https://urlhaus.abuse.ch/... |
| CIRCL OSINT | Mixed | Ingebouwd |
| EmergingThreats | IPs/Domains | https://rules.emergingthreats.net/... |

### Synchronisatie met andere MISP instances

1. Ga naar Sync Actions > List Servers
2. Klik "New Server"
3. Vul in:
   - Base URL: https://other-misp.example.com
   - Authkey: API key van andere MISP
   - Organisation: Sharing organisatie
4. Configureer sync settings

---

## MISP Events Maken

### Handmatig Event Aanmaken

1. Ga naar Event Actions > Add Event
2. Vul in:
   - Date: Datum van incident
   - Distribution: Your organisation only (of breder)
   - Threat Level: High/Medium/Low
   - Analysis: Initial/Ongoing/Completed
   - Info: Beschrijving van de threat
3. Klik Submit

### Attributen Toevoegen

1. Open het event
2. Klik "Add Attribute"
3. Selecteer type:
   - ip-src / ip-dst: IP adressen
   - domain: Domeinnamen
   - md5/sha1/sha256: File hashes
   - url: Malicious URLs
4. Voeg waarde en context toe

### Automatisch Importeren

MISP kan automatisch IOCs importeren uit:
- CSV bestanden
- STIX/TAXII feeds
- OpenIOC
- NetMonitor (via API integratie)

---

## Geavanceerde Configuratie

### Correlation Engine

MISP heeft een ingebouwde correlation engine die:
- Automatisch gerelateerde events vindt
- IOC duplicaten detecteert
- Cross-organisatie correlaties toont

Configureer onder Administration > Server Settings > Correlation.

### Tagging en Taxonomies

Tags helpen bij categorisatie:

1. Ga naar Event Actions > List Taxonomies
2. Enable nuttige taxonomies:
   - TLP (Traffic Light Protocol)
   - MITRE ATT&CK
   - Admiralty Code
   - OSINT

### Sighting Reporting

NetMonitor kan sightings rapporteren naar MISP:

```yaml
# config.yaml (toekomstige feature)
integrations:
  threat_intel:
    misp:
      enabled: true
      report_sightings: true  # Rapporteer IOC matches terug naar MISP
```

---

## Productie Overwegingen

### Performance

```bash
# Vergroot PHP memory limit
docker exec -it misp-docker-misp-1 bash
sed -i 's/memory_limit = 128M/memory_limit = 2048M/' /etc/php/7.4/apache2/php.ini
```

### SSL Certificaten

Voor productie, gebruik echte certificaten:

```yaml
# docker-compose.override.yml
services:
  misp:
    volumes:
      - ./ssl/cert.pem:/etc/ssl/private/misp.local.crt
      - ./ssl/key.pem:/etc/ssl/private/misp.local.key
```

### Backup

```bash
# Backup MISP database
docker exec misp-docker-db-1 mysqldump -u misp -p misp > misp_backup.sql

# Backup files
docker cp misp-docker-misp-1:/var/www/MISP/app/files ./misp_files_backup
```

### High Availability

Voor HA setup, gebruik:
- MySQL replication
- Redis Sentinel
- Load balancer voor MISP web
- Shared storage voor files

---

## Troubleshooting

### API Connection Failed

1. Check API key geldig is:
   ```bash
   curl -k -H "Authorization: YOUR_API_KEY" \
     https://misp.example.com/servers/getVersion
   ```

2. Check MISP draait:
   ```bash
   docker-compose ps
   docker-compose logs misp
   ```

3. Check firewall:
   ```bash
   curl -k https://misp.example.com
   ```

### Geen Resultaten bij Lookup

1. Check of er data in MISP zit:
   - Ga naar Administration > Jobs
   - Bekijk feed import status

2. Check of feeds enabled zijn:
   - Sync Actions > List Feeds
   - Klik "Fetch all" op een feed

3. Zoek handmatig in MISP:
   - Klik op Search
   - Voer IP/domain in
   - Check of er events zijn

### Slow Lookups

1. Verhoog cache TTL:
   ```yaml
   misp:
     cache_ttl_hours: 48  # 2 dagen cache
   ```

2. Enable Redis caching in MISP:
   - Administration > Server Settings > Redis

3. Optimaliseer database:
   ```bash
   docker exec misp-docker-db-1 mysqlcheck -o misp -u root -p
   ```

### SSL Certificate Errors

```yaml
# Voor self-signed certs
misp:
  verify_ssl: false
```

Of voeg CA cert toe:
```yaml
misp:
  verify_ssl: true
  ca_cert: "/etc/ssl/certs/misp-ca.pem"
```

---

## Integratie met Andere Tools

### Wazuh

Wazuh kan ook IOCs uit MISP halen:
1. Configureer MISP in Wazuh
2. Enable CDB list updates
3. Alerts worden automatisch verrijkt

### TheHive

MISP integreert naadloos met TheHive incident response:
1. Configureer TheHive als MISP sync server
2. Importeer events als cases
3. Exporteer findings terug naar MISP

### Cortex

Cortex analyzers kunnen MISP queryen:
1. Install MISP analyzer in Cortex
2. Configureer API credentials
3. Gebruik in TheHive analyses

---

## Related Documentation

- [INTEGRATIONS.md](./INTEGRATIONS.md) - Algemene integratie configuratie
- [WAZUH_SETUP.md](./WAZUH_SETUP.md) - Wazuh SIEM setup
- [MISP Official Docs](https://www.misp-project.org/documentation/)
- [MISP Training](https://www.misp-project.org/training/)
