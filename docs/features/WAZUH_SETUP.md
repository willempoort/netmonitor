# Wazuh SIEM Setup voor NetMonitor

## Overview

Wazuh is een open-source SIEM en XDR platform. Deze handleiding beschrijft hoe je Wazuh installeert en configureert voor integratie met NetMonitor.

---

## Quick Start met Docker

De snelste manier om Wazuh te installeren is via Docker Compose.

### 1. Download Wazuh Docker

```bash
# Clone Wazuh Docker repository
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node

# Genereer certificaten
docker-compose -f generate-indexer-certs.yml run --rm generator
```

### 2. Start Wazuh Stack

```bash
# Start Wazuh (Manager + Indexer + Dashboard)
docker-compose up -d

# Wacht tot alle services up zijn (~2-3 minuten)
docker-compose logs -f
```

### 3. Toegang tot Dashboard

- URL: https://localhost:443
- Username: admin
- Password: SecretPassword (wijzig dit!)

---

## NetMonitor Integratie Configureren

### 1. Maak API Gebruiker aan

```bash
# Open Wazuh manager container
docker exec -it single-node-wazuh.manager-1 bash

# Methode 1: Via Wazuh API (aanbevolen)
# Eerst authenticeren met admin credentials
TOKEN=$(curl -s -u wazuh:wazuh -k -X POST "https://localhost:55000/security/user/authenticate" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# Maak nieuwe gebruiker aan
curl -s -k -X POST "https://localhost:55000/security/users" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"username":"netmonitor","password":"SecureApiPassword123!"}'

# Methode 2: Via wazuh-user tool (oudere versies)
# /var/ossec/framework/python/bin/python3 /var/ossec/api/scripts/wazuh-apid.py

# Verlaat container
exit
```

> **Note:** De default admin credentials zijn `wazuh:wazuh` of `wazuh-wui:wazuh-wui`.
> Wijzig deze direct na installatie!

### 2. Custom Decoder Toevoegen

Maak een custom decoder voor NetMonitor alerts:

```bash
# In Wazuh manager container
docker exec -it single-node-wazuh.manager-1 bash

cat >> /var/ossec/etc/decoders/local_decoder.xml << 'EOF'
<!-- NetMonitor IDS Decoder -->
<decoder name="netmonitor">
  <prematch>^CEF:0\|NetMonitor\|</prematch>
</decoder>

<decoder name="netmonitor-cef">
  <parent>netmonitor</parent>
  <regex type="pcre2">CEF:0\|NetMonitor\|IDS\|[\d.]+\|(\w+)\|([^|]+)\|(\d+)\|(.+)</regex>
  <order>action,name,severity,extra_data</order>
</decoder>

<decoder name="netmonitor-fields">
  <parent>netmonitor-cef</parent>
  <regex type="pcre2">src=([\d.]+)</regex>
  <order>srcip</order>
</decoder>

<decoder name="netmonitor-fields-dst">
  <parent>netmonitor-cef</parent>
  <regex type="pcre2">dst=([\d.]+)</regex>
  <order>dstip</order>
</decoder>

<decoder name="netmonitor-fields-port">
  <parent>netmonitor-cef</parent>
  <regex type="pcre2">dpt=(\d+)</regex>
  <order>dstport</order>
</decoder>
EOF

# Verlaat container
exit
```

### 3. Custom Rules Toevoegen

```bash
docker exec -it single-node-wazuh.manager-1 bash

cat >> /var/ossec/etc/rules/local_rules.xml << 'EOF'
<!-- NetMonitor IDS Rules -->
<group name="netmonitor,ids,">

  <!-- Base rule for all NetMonitor alerts -->
  <rule id="100100" level="3">
    <decoded_as>netmonitor</decoded_as>
    <description>NetMonitor IDS Alert</description>
  </rule>

  <!-- Port Scan Detection -->
  <rule id="100101" level="7">
    <if_sid>100100</if_sid>
    <field name="action">PORT_SCAN</field>
    <description>NetMonitor: Port scan detected from $(srcip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <!-- SSH Brute Force -->
  <rule id="100102" level="10">
    <if_sid>100100</if_sid>
    <field name="action">SSH_BRUTE_FORCE</field>
    <description>NetMonitor: SSH brute force from $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- DNS Tunneling -->
  <rule id="100103" level="10">
    <if_sid>100100</if_sid>
    <field name="action">DNS_TUNNEL</field>
    <description>NetMonitor: DNS tunneling detected from $(srcip)</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
  </rule>

  <!-- Malware C2 Communication -->
  <rule id="100104" level="14">
    <if_sid>100100</if_sid>
    <field name="action">MALWARE_C2</field>
    <description>NetMonitor: Malware C2 communication from $(srcip) to $(dstip)</description>
    <mitre>
      <id>T1071</id>
      <id>T1573</id>
    </mitre>
  </rule>

  <!-- Known Malicious IP -->
  <rule id="100105" level="12">
    <if_sid>100100</if_sid>
    <field name="action">KNOWN_MALICIOUS_IP</field>
    <description>NetMonitor: Communication with known malicious IP $(dstip)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
  </rule>

  <!-- DDoS Attack -->
  <rule id="100106" level="12">
    <if_sid>100100</if_sid>
    <field name="action">DDOS_ATTACK</field>
    <description>NetMonitor: DDoS attack pattern detected from $(srcip)</description>
    <mitre>
      <id>T1498</id>
    </mitre>
  </rule>

  <!-- Suspicious Outbound Traffic -->
  <rule id="100107" level="8">
    <if_sid>100100</if_sid>
    <field name="action">SUSPICIOUS_OUTBOUND</field>
    <description>NetMonitor: Suspicious outbound traffic from $(srcip)</description>
  </rule>

  <!-- Beaconing Behavior -->
  <rule id="100108" level="10">
    <if_sid>100100</if_sid>
    <field name="action">BEACONING</field>
    <description>NetMonitor: C2 beaconing behavior detected from $(srcip)</description>
    <mitre>
      <id>T1071</id>
      <id>T1573</id>
    </mitre>
  </rule>

  <!-- Critical severity override -->
  <rule id="100150" level="15">
    <if_sid>100100</if_sid>
    <field name="severity">^(9|10)$</field>
    <description>NetMonitor: CRITICAL severity alert - $(name)</description>
  </rule>

</group>
EOF

# Test configuration
/var/ossec/bin/wazuh-analysisd -t

# Restart Wazuh manager
/var/ossec/bin/wazuh-control restart

exit
```

### 4. Configureer Syslog Input

```bash
docker exec -it single-node-wazuh.manager-1 bash

# Voeg syslog input toe aan ossec.conf
cat >> /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>1514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>
</ossec_config>
EOF

# Restart Wazuh
/var/ossec/bin/wazuh-control restart

exit
```

### 5. Expose Syslog Port

Update je docker-compose.yml om port 1514 te exposen:

```yaml
# In wazuh-docker/single-node/docker-compose.yml
services:
  wazuh.manager:
    ports:
      - "1514:1514/udp"   # Syslog
      - "55000:55000"     # API
```

```bash
# Restart met nieuwe ports
docker-compose down
docker-compose up -d
```

---

## NetMonitor Configuratie

### Via Wazuh API (Aanbevolen)

```yaml
# /etc/netmonitor/config.yaml
integrations:
  enabled: true
  siem:
    enabled: true
    wazuh:
      enabled: true
      api_url: "https://wazuh-server:55000"
      api_user: "netmonitor"
      api_password: "${WAZUH_API_PASSWORD}"
      verify_ssl: false  # Voor self-signed certs
      syslog_fallback: true
      syslog_host: "wazuh-server"
      syslog_port: 1514
```

### Via Syslog Only

```yaml
# /etc/netmonitor/config.yaml
integrations:
  enabled: true
  siem:
    enabled: true
    syslog:
      enabled: true
      host: "wazuh-server"
      port: 1514
      protocol: "udp"
      format: "cef"
```

### Environment Variable

```bash
# /etc/netmonitor/netmonitor.env
WAZUH_API_PASSWORD=SecureApiPassword123!
```

---

## Verifieer Integratie

### 1. Genereer Test Alert

```bash
# Op NetMonitor server
curl -X POST http://localhost:8080/api/alerts/test

# Of trigger echte alert via nmap scan
nmap -sS 192.168.1.1
```

### 2. Check Wazuh Logs

```bash
docker exec -it single-node-wazuh.manager-1 bash

# Bekijk alerts
tail -f /var/ossec/logs/alerts/alerts.log

# Filter op NetMonitor
grep "netmonitor" /var/ossec/logs/alerts/alerts.log
```

### 3. Bekijk in Dashboard

1. Open Wazuh Dashboard: https://wazuh-server
2. Ga naar Security Events
3. Filter op `rule.groups: netmonitor`

---

## Wazuh Dashboard Customization

### NetMonitor Dashboard Maken

1. Ga naar Dashboards > Create new dashboard
2. Voeg visualisaties toe:

**Top Source IPs (Pie Chart)**
```json
{
  "aggs": {
    "srcip": {
      "terms": {"field": "data.srcip", "size": 10}
    }
  },
  "query": {"match": {"rule.groups": "netmonitor"}}
}
```

**Alerts Over Time (Line Chart)**
```json
{
  "aggs": {
    "timeline": {
      "date_histogram": {"field": "@timestamp", "interval": "hour"}
    }
  },
  "query": {"match": {"rule.groups": "netmonitor"}}
}
```

**Alert Types Distribution**
```json
{
  "aggs": {
    "types": {
      "terms": {"field": "data.action", "size": 10}
    }
  },
  "query": {"match": {"rule.groups": "netmonitor"}}
}
```

---

## Productie Overwegingen

### High Availability

Voor productie, gebruik de multi-node Wazuh setup:

```bash
cd wazuh-docker/multi-node
docker-compose up -d
```

### SSL Certificaten

Gebruik echte SSL certificaten voor de API:

```yaml
# NetMonitor config
wazuh:
  verify_ssl: true
  ca_cert: "/etc/ssl/certs/wazuh-ca.pem"
```

### Log Rotation

Configureer log rotation in Wazuh:

```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>
</ossec_config>
```

### Alerting

Configureer email/Slack alerts in Wazuh:

```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>security@example.com</email_to>
    <smtp_server>smtp.example.com</smtp_server>
    <email_from>wazuh@example.com</email_from>
  </global>

  <email_alerts>
    <email_to>security@example.com</email_to>
    <level>10</level>
    <group>netmonitor</group>
  </email_alerts>
</ossec_config>
```

---

## Troubleshooting

### Alerts Komen Niet Binnen

1. Check firewall:
   ```bash
   sudo ufw allow 1514/udp
   ```

2. Check Wazuh luistert:
   ```bash
   docker exec single-node-wazuh.manager-1 netstat -tulpn | grep 1514
   ```

3. Test syslog verbinding:
   ```bash
   echo "<134>NetMonitor test message" | nc -u wazuh-server 1514
   ```

### Decoder Werkt Niet

1. Test decoder:
   ```bash
   docker exec -it single-node-wazuh.manager-1 bash
   echo 'CEF:0|NetMonitor|IDS|1.0|PORT_SCAN|Port Scan|7|src=192.168.1.100 dst=10.0.0.1' | \
     /var/ossec/bin/wazuh-logtest
   ```

2. Check syntax:
   ```bash
   /var/ossec/bin/wazuh-analysisd -t
   ```

### API Connection Fails

1. Check API status:
   ```bash
   curl -k -u netmonitor:password -X POST https://wazuh-server:55000/security/user/authenticate
   ```

2. List users via API:
   ```bash
   # Authenticeer eerst
   TOKEN=$(curl -s -u wazuh:wazuh -k -X POST "https://wazuh-server:55000/security/user/authenticate" | \
       python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

   # List users
   curl -s -k -X GET "https://wazuh-server:55000/security/users" \
       -H "Authorization: Bearer $TOKEN"
   ```

---

## Related Documentation

- [INTEGRATIONS.md](./INTEGRATIONS.md) - Algemene integratie configuratie
- [MISP_SETUP.md](./MISP_SETUP.md) - MISP Threat Intelligence setup
- [Wazuh Official Docs](https://documentation.wazuh.com/)
