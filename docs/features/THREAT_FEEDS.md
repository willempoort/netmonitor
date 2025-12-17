# Threat Intelligence Feeds Integratie

Dit document beschrijft de threat intelligence feeds die geïntegreerd zijn in de Network Monitor.

## Overzicht

De Network Monitor gebruikt gratis threat intelligence feeds van **abuse.ch** en (optioneel) **AbuseIPDB** voor real-time IP reputation lookups.

## Beschikbare Feeds

### 1. FeodoTracker (Botnet C&C Servers) ⭐

**Source**: https://feodotracker.abuse.ch/

**Wat**: IP adressen van bekende Botnet Command & Control servers
- Emotet
- TrickBot
- QakBot
- BazarLoader
- En meer...

**Update frequentie**: Meerdere keren per dag

**Use case**: Detecteert wanneer een interne machine communiceert met een C&C server (geïnfecteerde machine!)

### 2. URLhaus (Malware Distribution URLs)

**Source**: https://urlhaus.abuse.ch/

**Wat**: URLs en IPs die gebruikt worden voor malware distributie

**Update frequentie**: Real-time, wij gebruiken "recent" feed

**Use case**: Detecteert wanneer een machine malware download

### 3. ThreatFox (Recent IOCs)

**Source**: https://threatfox.abuse.ch/

**Wat**: Recent Indicators of Compromise (IOCs)
- IP adressen
- Domains
- URLs
- File hashes

**Update frequentie**: Real-time

**Use case**: Detecteert recent aktieve threats

### 4. SSL Blacklist

**Source**: https://sslbl.abuse.ch/

**Wat**: IPs die malicious SSL/TLS certificaten gebruiken

**Update frequentie**: Dagelijks

**Use case**: Detecteert HTTPS malware communicatie

## AbuseIPDB API (Optioneel)

**Source**: https://www.abuseipdb.com/

**Type**: Real-time API lookups

**Gratis tier**: 1000 queries/dag

**Wat**: Community-driven IP reputation database met abuse confidence scores (0-100)

**Use case**: Real-time lookup van verdachte IPs die niet in feeds staan

## Configuratie

### Basis Configuratie (config.yaml)

```yaml
# Threat Intelligence Feeds
threat_feeds:
  enabled: true

  feeds:
    - feodotracker    # C&C servers (aanbevolen!)
    - urlhaus         # Malware URLs
    - threatfox       # Recent IOCs
    - sslblacklist    # SSL threats

  update_interval: 3600  # 1 uur
  cache_dir: /var/cache/netmonitor/feeds
```

### AbuseIPDB Configuratie (Optioneel)

1. **Maak gratis account**: https://www.abuseipdb.com/register

2. **Verkrijg API key**: https://www.abuseipdb.com/account/api

3. **Configureer in config.yaml**:

```yaml
abuseipdb:
  enabled: true
  api_key: "YOUR_API_KEY_HERE"
  rate_limit: 1000
  threshold: 50  # Alert alleen bij score >= 50
  query_suspicious_only: true  # Beperkt API calls
```

## Feed Updates

### Automatische Updates (Aanbevolen)

De feeds worden automatisch geüpdatet via systemd timer:

```bash
# Installeer timer (in install.sh)
sudo cp netmonitor-feed-update.service /etc/systemd/system/
sudo cp netmonitor-feed-update.timer /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable netmonitor-feed-update.timer
sudo systemctl start netmonitor-feed-update.timer

# Check status
sudo systemctl status netmonitor-feed-update.timer
sudo systemctl list-timers netmonitor-feed-update.timer
```

**Update frequentie**: Elk uur

### Handmatige Updates

```bash
# Update alle feeds
sudo python3 update_feeds.py

# Check logs
sudo tail -f /var/log/netmonitor/feed_updates.log
```

### Via Cron (Alternatief voor systemd)

```bash
# Edit crontab
sudo crontab -e

# Voeg toe: update elk uur
0 * * * * cd /opt/netmonitor && /usr/bin/python3 update_feeds.py >> /var/log/netmonitor/feed_updates.log 2>&1
```

## Feed Cache

Feeds worden gecached in: `/var/cache/netmonitor/feeds/`

```bash
# Check cached feeds
ls -lh /var/cache/netmonitor/feeds/

# Output:
feodotracker.csv
urlhaus.csv
threatfox.csv
sslblacklist.csv
```

**Cache TTL**: Feeds worden hergebruikt als ze < 1 uur oud zijn

## Threat Detection met Feeds

### C&C Communicatie (CRITICAL)

Als een **interne machine** (bijv. 192.168.1.50) verbindt met een IP uit FeodoTracker:

```
[2025-11-06 15:30:45] [CRITICAL] [C2_COMMUNICATION] Internal machine verbindt met C&C server: Emotet | Source: 192.168.1.50 | Destination: 203.0.113.50
```

**Actie**: Machine is zeer waarschijnlijk geïnfecteerd! Isoleer direct.

### Threat Feed Match (HIGH)

Als een **externe IP** uit een feed wordt gezien:

```
[2025-11-06 15:31:20] [HIGH] [THREAT_FEED_MATCH] IP gevonden in threat feed: urlhaus - malicious | Source: 198.51.100.100
```

**Actie**: Mogelijk attack attempt van buiten

## Performance Overwegingen

### Feed Sizes

- **FeodoTracker**: ~500-1000 IPs (~50 KB)
- **URLhaus**: ~1000-2000 URLs (~200 KB)
- **ThreatFox**: ~5000-10000 IOCs (~500 KB)
- **SSL Blacklist**: ~100-200 IPs (~20 KB)

**Total memory**: < 5 MB

**Lookup performance**: O(1) via Python sets

### Network Usage

- **Initial download**: ~1 MB
- **Hourly updates**: ~1 MB/uur
- **Daily bandwidth**: < 30 MB

### AbuseIPDB Rate Limiting

- Gratis tier: 1000 queries/dag
- **Strategie**: Query alleen verdachte IPs (`query_suspicious_only: true`)
- **Cache**: Lookups worden 1 uur gecached

## Troubleshooting

### Feeds downloaden niet

```bash
# Check network connectivity
curl https://feodotracker.abuse.ch/downloads/ipblocklist.csv

# Check permissions
ls -la /var/cache/netmonitor/feeds/

# Check logs
sudo tail -f /var/log/netmonitor/feed_updates.log
```

### AbuseIPDB rate limit bereikt

```
AbuseIPDB rate limit bereikt, query geskipped
```

**Oplossing**:
- Verhoog `query_suspicious_only: true` in config
- Wacht tot dagelijkse reset (24 uur)
- Upgrade naar betaald AbuseIPDB plan (optioneel)

### Feeds zijn oud

```bash
# Forceer update
sudo python3 update_feeds.py

# Check timer
sudo systemctl status netmonitor-feed-update.timer
```

## Best Practices

### Minimale Configuratie (Intern Netwerk)

Voor monitoring van intern verkeer:

```yaml
threat_feeds:
  enabled: true
  feeds:
    - feodotracker  # C&C detection (MOET!)
    - urlhaus       # Malware downloads
```

### Volledige Configuratie

Voor maximum detectie:

```yaml
threat_feeds:
  enabled: true
  feeds:
    - feodotracker
    - urlhaus
    - threatfox
    - sslblacklist

abuseipdb:
  enabled: true
  api_key: "YOUR_KEY"
  query_suspicious_only: true
```

### Alleen Basis Detectie (Geen External Feeds)

Als je geen feeds wilt gebruiken:

```yaml
threat_feeds:
  enabled: false

abuseipdb:
  enabled: false
```

De tool werkt nog steeds met:
- Port scan detectie
- Connection flooding
- Beaconing detection
- Lateral movement
- Etc.

## Feed URLs

Voor referentie, de volledige URLs:

- **FeodoTracker**: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
- **URLhaus**: https://urlhaus.abuse.ch/downloads/csv_recent/
- **ThreatFox**: https://threatfox.abuse.ch/export/csv/recent/
- **SSL Blacklist**: https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
- **AbuseIPDB API**: https://api.abuseipdb.com/api/v2/

## Support

Alle feeds zijn **gratis** en geen registratie vereist (behalve AbuseIPDB voor API).

Voor vragen over de feeds, zie:
- abuse.ch: https://abuse.ch/
- AbuseIPDB: https://www.abuseipdb.com/
