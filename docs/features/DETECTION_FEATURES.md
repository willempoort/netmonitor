# NetMonitor - Advanced Detection Features

Complete overview van alle geïmplementeerde detectie capabilities.

## 📊 Overview

NetMonitor ondersteunt nu **volledige protocol-analyse** met **content inspection**, **entropy analysis**, en **DLP capabilities**.

## ✅ Configuration Management Status

### Database Integration
- ✅ **sensor_configs** tabel ondersteunt ALLE parameters
- ✅ JSONB storage voor flexibele nested configuratie
- ✅ Global en sensor-specific configs beide ondersteund
- ✅ Automatische schema migratie bij eerste run

### API Integration
- ✅ **GET /api/config** - Haal huidige configuratie op
- ✅ **PUT /api/config/parameter** - Update individuele parameter
- ✅ **GET /api/config/defaults** - Haal best-practice defaults op
- ✅ **POST /api/config/reset** - Reset naar defaults
- ✅ Real-time synchronisatie naar sensors

### Web UI Integration
- ✅ **Dynamisch configuration management** - automatische rendering van alle parameters
- ✅ **Categorie grouping** - Detection Rules, Thresholds, Alert Management, Performance
- ✅ **Parameter descriptions** - tooltips voor elke configuratie
- ✅ **Input type detection** - boolean toggles, number inputs, text fields
- ✅ **Live preview** - default waarden zichtbaar tijdens editing
- ✅ **Sensor-specific overrides** - global of per-sensor configuratie

**Alle nieuwe detection features (HTTP, SMTP/FTP, DNS Enhanced) zijn volledig geïntegreerd en configureerbaar via zowel Web UI als API!**

---

## ✅ Geïmplementeerde Detectie Capabilities

### 1. 🌐 **DNS Anomaly Detection** (ENHANCED)

#### Basis Features:
- ✅ Lange DNS queries (>50 chars)
- ✅ Hoge query frequentie (>150 queries/min)

#### Nieuwe Advanced Features:
- ✅ **DGA Detection** (Domain Generation Algorithm)
  - Entropie-analyse van subdomeinen
  - Patroonherkenning voor random strings
  - Vowel ratio analysis (low vowels = suspicious)
  - DGA score berekening (0-1)

- ✅ **Encoding Detection**
  - Base64 gecodeerde queries
  - Hexadecimale strings
  - URL encoding detection

- ✅ **Entropy Analysis**
  - Shannon entropy berekening
  - Alert bij entropy >4.5 (suggestief voor encrypted/random data)

**Alert Types:**
- `DNS_DGA_DETECTED` (HIGH) - Domain Generation Algorithm gedetecteerd
- `DNS_ENCODED_QUERY` (MEDIUM) - Gecodeerde query (Base64/Hex)
- `DNS_HIGH_ENTROPY` (MEDIUM) - Query met hoge entropie (>4.5)
- `DNS_TUNNEL_SUSPICIOUS_LENGTH` (MEDIUM) - Legacy: lange query
- `DNS_TUNNEL_HIGH_RATE` (MEDIUM) - Legacy: hoge query rate

---

### 2. 🔔 **ICMP Tunneling Detection** (NEW)

Detecteert ICMP-tunneling voor data exfiltration.

#### Features:
- ✅ **Large Payload Detection**
  - Alert bij ICMP payloads >500 bytes (configureerbaar)
  - Payload entropy analysis (encrypted data detection)
  - Encoding detection in payloads

- ✅ **Rate-Based Detection**
  - Alert bij >10 large ICMP packets per minuut
  - Gemiddelde payload size tracking

**Alert Types:**
- `ICMP_LARGE_PAYLOAD` (MEDIUM) - Grote ICMP payload gedetecteerd
- `ICMP_TUNNEL_HIGH_RATE` (HIGH) - Veel grote ICMP packets

**Configuratie:**
```yaml
thresholds:
  icmp_tunnel:
    enabled: true
    size_threshold: 500      # bytes
    rate_threshold: 10       # packets/min
```

---

### 3. 🌐 **HTTP/HTTPS Anomaly Detection** (NEW)

Detecteert verdacht HTTP verkeer en data exfiltration.

#### Features:
- ✅ **POST Request Monitoring**
  - Alert bij >50 POST requests in 5 minuten
  - Mogelijke data exfiltration

- ✅ **User-Agent Analysis**
  - Detectie van suspicious tools: python, curl, wget, scanner, sqlmap, nikto
  - Alert bij automated scanning tools

- ✅ **Payload Analysis** (>1KB payloads)
  - **DLP Scanning**: Detecteert gevoelige data
    - Credit card nummers
    - Email adressen
    - SSN (Social Security Numbers)
    - API keys
    - Private keys (RSA/EC)
    - AWS keys
    - JWT tokens

- ✅ **Entropy Analysis**
  - Alert bij hoge entropy (>6.5) in plaintext HTTP
  - Suggestief voor encrypted data in onversleuteld verkeer

**Alert Types:**
- `HTTP_EXCESSIVE_POSTS` (MEDIUM) - Verdacht veel POST requests
- `HTTP_SUSPICIOUS_USER_AGENT` (LOW) - Scanning tool gedetecteerd
- `HTTP_SENSITIVE_DATA` (CRITICAL) - Gevoelige data in HTTP verkeer
- `HTTP_HIGH_ENTROPY_PAYLOAD` (MEDIUM) - Encrypted data in plain HTTP

---

### 4. 📧 **SMTP/FTP Large Transfer Detection** (NEW)

Detecteert grote bestandsoverdrachten via email en FTP.

#### Features:
- ✅ **SMTP Large Attachments**
  - Alert bij >50 MB overdracht in 5 minuten
  - Monitort poorten: 25, 465, 587

- ✅ **FTP Large Transfers**
  - Alert bij >50 MB overdracht in 5 minuten
  - Monitort poorten: 20, 21, 989, 990

**Alert Types:**
- `SMTP_LARGE_ATTACHMENT` (MEDIUM) - Grote email attachment
- `FTP_LARGE_TRANSFER` (MEDIUM) - Grote FTP bestandsoverdracht

---

### 5. 🔍 **Protocol Mismatch Detection** (ENHANCED)

Detecteert protocol verkeer op ongebruikelijke poorten (tunneling, stealth exfil).

#### Features:
- ✅ **SSH Detection**
  - Detecteert SSH banner (`SSH-`) op niet-standaard poorten
  - **Fixed (v2.8):** Checkt nu ZOWEL source ALS destination port
  - Voorkomt false positives bij ephemeral client ports (bijv. 51906)
  - Alert alleen als BEIDE poorten != 22

- ✅ **HTTP Detection**
  - Detecteert HTTP requests op niet-standaard poorten
  - Standaard: 80, 443, 8080, 8443

- ✅ **DNS Detection**
  - Detecteert DNS verkeer op niet-standaard poorten (HIGH severity)
  - Mogelijke DNS tunneling indicator

- ✅ **FTP Detection**
  - Detecteert FTP commands op niet-standaard poorten
  - Controleert: USER, PASS, 220, 331 commands

**Alert Types:**
- `SSH_NON_STANDARD_PORT` (MEDIUM) - SSH verkeer op ongebruikelijke poort
- `HTTP_NON_STANDARD_PORT` (MEDIUM) - HTTP verkeer op ongebruikelijke poort
- `DNS_NON_STANDARD_PORT` (HIGH) - DNS tunneling indicator
- `FTP_NON_STANDARD_PORT` (MEDIUM) - FTP verkeer op ongebruikelijke poort

**Bug Fix (v2.8 - 2026-01-03):**
```python
# VOOR (bug): Triggerde op client ephemeral ports
if dst_port != 22:  # ❌ False positive bij SSH responses

# NA (fix): Checkt beide kanten van de verbinding
if dst_port != 22 and src_port != 22:  # ✅ Alleen echte non-standard SSH
```

**Voorbeeld False Positive (Opgelost):**
```
SSH verbinding: 10.100.0.92:51906 → 10.100.0.70:22
Response packet: 10.100.0.70:22 → 10.100.0.92:51906
  ❌ Oude logica: "SSH op poort 51906!" (ephemeral port)
  ✅ Nieuwe logica: src_port=22, geen alert
```

---

### 6. 🔒 **Content Analysis Module** (NEW)

Standalone module voor payload analysis.

#### Shannon Entropy Calculation
```python
from content_analysis import calculate_entropy

entropy = calculate_entropy("example.com")  # Returns: ~2.5
entropy = calculate_entropy("aGVsbG8gd29ybGQ=")  # Returns: ~3.8 (Base64)
```

**Interpretation:**
- 0-2: Low entropy (repetitive data)
- 2-4: Medium entropy (normal text)
- 4-6: High entropy (compressed/encrypted)
- 6-8: Very high entropy (random/encrypted)

#### Encoding Detection
```python
from content_analysis import ContentAnalyzer

analyzer = ContentAnalyzer()
result = analyzer.detect_encoding("aGVsbG8gd29ybGQ=")

# Returns:
{
    'encoded': True,
    'type': 'base64',
    'confidence': 0.9,
    'decoded_sample': 'hello world'
}
```

Supported encodings:
- Base64
- Hexadecimal
- URL encoding

#### DLP Scanning
```python
findings = analyzer.scan_for_sensitive_data(payload)

# Detects:
# - Credit cards (with masking)
# - Emails (with masking)
# - SSNs (with masking)
# - API keys (generic pattern)
# - Private keys (PEM format)
# - AWS keys (AKIA...)
# - JWT tokens
```

---

### 7. 🔐 **TLS/HTTPS Analysis** (NEW)

Analyseert TLS handshakes **zonder decryptie** voor threat detection.

#### JA3 Fingerprinting
JA3 is een MD5 hash van TLS Client Hello parameters die uniek is per applicatie/malware.

```
JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
```

**Waarom nuttig?**
- Malware heeft vaak unieke JA3 fingerprints
- Zelfs bij encrypted traffic kun je de client identificeren
- Cobalt Strike, Metasploit, etc. hebben bekende signatures

**Ingebouwde Blacklist:**
```python
KNOWN_MALICIOUS_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "6734f37431670b3ab4292b8f60f29984": "Metasploit Meterpreter",
    "e7d705a3286e19ea42f587b344ee6865": "Empire",
    "51c64c77e60f3980eea90869b68c58a8": "TrickBot",
    "4d7a28d6f2263ed61de88ca66eb2e04b": "Emotet",
}
```

#### Features:
- ✅ **JA3/JA3S Fingerprinting** - Client en server identificatie
- ✅ **SNI Extraction** - Server Name Indication (welke hostname)
- ✅ **Certificate Metadata** - Subject, issuer, validity, chain
- ✅ **TLS Version Detection** - Detecteert verouderde SSL 3.0, TLS 1.0/1.1
- ✅ **Weak Cipher Detection** - Alert bij NULL, RC4, 3DES ciphers
- ✅ **Certificate Validation** - Expired/invalid certificates

**Alert Types:**
- `MALICIOUS_JA3_FINGERPRINT` (CRITICAL) - Bekende malware fingerprint
- `TLS_WEAK_CIPHER_OFFERED` (MEDIUM) - Client biedt zwakke cipher aan
- `TLS_WEAK_CIPHER_SELECTED` (HIGH) - Server selecteert zwakke cipher
- `TLS_DEPRECATED_TLS_VERSION` (MEDIUM) - Verouderde TLS versie
- `TLS_EXPIRED_CERTIFICATE` (HIGH) - Verlopen certificaat
- `TLS_MISSING_SNI` (LOW) - Geen SNI (mogelijk C2)

**Configuratie:**
```yaml
thresholds:
  tls_analysis:
    enabled: true
    ja3_detection: true           # Extract JA3 fingerprints
    ja3s_detection: true          # Extract JA3S fingerprints
    sni_extraction: true          # Extract Server Name Indication
    certificate_validation: true   # Validate certificate chains
    detect_weak_ciphers: true     # Alert on weak cipher suites
    detect_deprecated_tls: true   # Alert on TLS 1.0/1.1
    detect_expired_certs: true    # Alert on expired certificates
    detect_missing_sni: false     # Alert on missing SNI (noisy)
    ja3_blacklist: {}             # Custom JA3 fingerprints to block
```

**MCP Tools:**
```bash
# Check TLS metadata voor recent verkeer
get_tls_metadata --limit 100 --sni_filter "suspicious.com"

# Check of een JA3 hash bekend malicious is
check_ja3_fingerprint --ja3_hash "72a589da586844d7f0818ce684948eea"

# Voeg custom JA3 toe aan blacklist
add_ja3_blacklist --ja3_hash "abc123..." --malware_family "CustomMalware"
```

---

### 8. 📦 **PCAP Forensics** (ENHANCED)

Selectieve packet capture voor forensische analyse.

#### Features:
- ✅ **Ring Buffer** - Houdt laatste 10.000 packets in memory
- ✅ **Alert-Triggered Capture** - Automatisch packets opslaan rond alerts
- ✅ **Flow Export** - Export specifieke netwerk flows on-demand
- ✅ **Automatic Cleanup** - Verwijdert oude captures na 24 uur

#### Alert-Triggered Capture
Bij elke CRITICAL/HIGH alert worden automatisch packets opgeslagen:
- 100 packets **vóór** de alert (context)
- 50 packets **na** de alert (follow-up)

```
Timeline:
... [100 packets] [ALERT] [50 packets] ...
         ↓           ↓         ↓
    pre-alert    trigger  post-alert
         └─────────┬─────────┘
              PCAP file
```

**Output locatie:** `/var/log/netmonitor/pcap/`

**Bestandsnaam formaat:**
```
alert_malicious_ja3_fingerprint_192_168_1_100_to_45_33_32_156_20231215_143022.pcap
```

**Configuratie:**
```yaml
thresholds:
  pcap_export:
    enabled: true
    output_dir: "/var/log/netmonitor/pcap"
    buffer_size: 10000            # Ring buffer size (packets)
    alert_capture_enabled: true   # Save packets around alerts
    pre_alert_packets: 100        # Packets before alert
    post_alert_packets: 50        # Packets after alert
    flow_buffer_size: 500         # Per-flow buffer size
    max_captures: 100             # Max saved PCAP files
    max_age_hours: 24             # Delete captures after 24 hours
    ram_flush_threshold: 80       # Flush buffer at RAM % (NEW v2.8)
```

#### RAM-Based PCAP Flush (NEW v2.8)

Voor resource-constrained sensors (Raspberry Pi, NanoPi) met beperkt RAM.

**Problem (Fixed):**
- Sensors met 1-2GB RAM liepen vast door volle PCAP buffers
- `PCAP_RAM_FLUSH_THRESHOLD` environment variable werd niet ingelezen
- Detector tracking buffers groeiden onbeperkt (memory leak)
- RAM usage 95-99%, sensors crashed

**Solution:**
```bash
# sensor.conf
PCAP_RAM_FLUSH_THRESHOLD=75    # Flush bij 75% RAM (was: 80% hardcoded)
```

**Werking:**
1. **Monitoring:** Elke metrics cycle (30s) wordt RAM % gecheckt
2. **Emergency Flush bij threshold:**
   - PCAP buffer naar disk schrijven en uploaden
   - PCAP packet buffer wissen
   - Detector tracking buffers clearen (port_scan, dns, brute_force, etc.)
   - Garbage collection forceren
3. **Periodieke Cleanup:**
   - `detector.cleanup_old_data()` elke 30s
   - Oude entries (>5-10 min) worden verwijderd

**Impact:**
```
VOOR fix:  RAM 97-99% → sensor crash
NA fix:    RAM 70-80% → stabiel
```

**Logs:**
```
⚠️ RAM usage 76.2% exceeds threshold 75%, flushing PCAP buffer...
Cleared PCAP buffer (1247 packets)
Cleared 342 detector tracking entries
✓ Emergency flush complete, RAM now at 68.4%
```

**MCP Tools:**
```bash
# Lijst alle opgeslagen PCAP captures
get_pcap_captures

# Export specifieke flow naar PCAP
export_flow_pcap --src_ip "192.168.1.100" --dst_ip "45.33.32.156" --dst_port 443

# Bekijk ring buffer status
get_packet_buffer_summary

# Verwijder oude capture
delete_pcap_capture --filename "alert_port_scan_192_168_1_50_20231215.pcap"
```

**Wireshark analyse:**
```bash
# Download PCAP via dashboard of kopieer direct
scp user@netmonitor:/var/log/netmonitor/pcap/alert_*.pcap ./

# Open in Wireshark
wireshark alert_malicious_ja3_fingerprint_*.pcap
```

---

## 🔐 **Sensor Authentication** (NEW)

Token-based authenticatie voor remote sensors.

### Features:
- ✅ **Token Generation**
  - SHA-256 hashed tokens (256-bit entropy)
  - Optional expiration
  - Granular permissions (alerts, metrics, commands)

- ✅ **Token Management**
  - List all tokens
  - Revoke tokens
  - Auto-cleanup expired tokens
  - Last used tracking

### Setup:

**1. Generate Token:**
```bash
sudo python3 setup_sensor_auth.py
```

**2. Configure Sensor:**
```bash
# Environment variable
export SENSOR_TOKEN="your-generated-token"

# Or in systemd service
Environment="SENSOR_TOKEN=your-generated-token"
```

**3. Sensor Usage:**
```python
# Sensor sends token in Authorization header
headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}
```

### Database Schema:
```sql
CREATE TABLE sensor_tokens (
    id SERIAL PRIMARY KEY,
    sensor_id TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    token_name TEXT,
    created_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN,
    permissions JSONB
);
```

---

## 🔒 **MFA voor Web Dashboard** (NGINX)

Multi-Factor Authentication voor dashboard toegang via Nginx reverse proxy.

### Architectuur:
```
Browser → Nginx (SSL + MFA) → Flask Dashboard
Sensor  → Nginx (SSL only) → Flask API (Token Auth)
```

### Features:
- ✅ SSL/TLS encryption (Let's Encrypt)
- ✅ MFA voor web interface (Authelia compatible)
- ✅ Token auth voor sensors (geen MFA overhead)
- ✅ CORS headers configured
- ✅ Security headers (HSTS, X-Frame-Options, etc.)

### Setup:

**1. Install Nginx:**
```bash
sudo apt install nginx certbot python3-certbot-nginx
```

**2. Install Authelia (MFA provider):**
```bash
# Via Docker
docker run -d \
  --name authelia \
  -p 9091:9091 \
  -v /path/to/authelia-config:/config \
  authelia/authelia
```

**3. Configure Nginx:**
```bash
sudo cp nginx-netmonitor.conf /etc/nginx/sites-available/netmonitor
sudo ln -s /etc/nginx/sites-available/netmonitor /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

**4. Get SSL Certificate:**
```bash
sudo certbot --nginx -d soc.example.com
```

### Endpoint Routing:

| Endpoint | MFA Required | Authentication |
|----------|--------------|----------------|
| `/` (Dashboard) | ✅ Yes | Authelia |
| `/api/alerts` | ✅ Yes | Authelia |
| `/api/sensors/*` | ❌ No | Token (Bearer) |
| `/socket.io/` | ✅ Yes | Authelia |

---

## 🚀 **Performance Impact**

### Content Analysis Overhead:
- **Entropy calculation**: ~0.1ms per 1KB
- **Encoding detection**: ~0.2ms per check
- **DLP scanning**: ~1-5ms per 10KB (depends on payload size)

### Mitigations:
- Payloads >50KB skipped for performance
- DLP only scans HTTP payloads >1KB
- Entropy calculated only on suspicious queries
- Efficient regex patterns

### Resource Usage:
- **Additional Memory**: ~50-100 MB (content analyzer + trackers)
- **CPU**: +5-10% during active scanning
- **Database**: 3 new tables (sensor_tokens, etc.)

---

## 📈 **Alert Statistics**

**Nieuwe Alert Types:**
Total: **13 nieuwe alert types**

| Category | Count |
|----------|-------|
| DNS Enhanced | 3 new |
| ICMP | 2 new |
| HTTP/HTTPS | 4 new |
| SMTP/FTP | 2 new |
| Auth | 2 new |

---

## 🔧 **Configuration Examples**

### Complete config.yaml (All Detection Features):
```yaml
thresholds:
  # DNS tunneling detection (enhanced)
  dns_tunnel:
    enabled: true
    query_length_threshold: 50
    queries_per_minute: 150

  # Enhanced DNS detection parameters
  dns_enhanced:
    dga_threshold: 0.6       # DGA score threshold (0-1)
    entropy_threshold: 4.5   # Shannon entropy threshold
    encoding_detection: true # Detect Base64/Hex encoding

  # ICMP tunneling detection
  icmp_tunnel:
    enabled: true
    size_threshold: 500      # ICMP payload >500 bytes
    rate_threshold: 10       # >10 large packets per minute

  # HTTP/HTTPS anomaly detection
  http_anomaly:
    enabled: true
    post_threshold: 50       # Alert at >50 POST requests
    post_time_window: 300    # Within 5 minutes
    dlp_min_payload_size: 1024  # Minimum payload size for DLP (bytes)
    entropy_threshold: 6.5   # Entropy threshold for plaintext HTTP

  # SMTP/FTP large transfer detection
  smtp_ftp_transfer:
    enabled: true
    size_threshold_mb: 50    # Alert at >50 MB transfer
    time_window: 300         # Within 5 minutes

  # Port scan detection
  port_scan:
    enabled: true
    unique_ports: 20
    time_window: 60

  # Beaconing detection
  beaconing:
    enabled: true
    min_connections: 5
    max_jitter_percent: 20

dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8080
  # Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
  secret_key: "your-secret-key-here"
```

### Web UI Configuration:

**All parameters zijn configureerbaar via de Web UI:**

1. Ga naar het **Configuration** tabblad in het dashboard
2. Selecteer **Detection Rules** categorie
3. Parameters worden automatisch geladen en kunnen worden aangepast:
   - **Port Scan** (enabled, unique_ports, time_window)
   - **DNS Tunnel** (enabled, query_length_threshold, queries_per_minute)
   - **DNS Enhanced** (dga_threshold, entropy_threshold, encoding_detection)
   - **ICMP Tunnel** (enabled, size_threshold, rate_threshold)
   - **HTTP Anomaly** (enabled, post_threshold, post_time_window, dlp_min_payload_size, entropy_threshold)
   - **SMTP/FTP Transfer** (enabled, size_threshold_mb, time_window)
   - **Beaconing** (enabled, min_connections, max_jitter_percent)

4. Wijzigingen worden real-time opgeslagen in de database
5. Sensors synchroniseren automatisch de nieuwe configuratie

### API Configuration:

**Via REST API parameters wijzigen:**

```bash
# Get current config
curl -X GET https://soc.example.com/api/config

# Update specific parameter
curl -X PUT https://soc.example.com/api/config/parameter \
  -H "Content-Type: application/json" \
  -d '{
    "parameter_path": "thresholds.http_anomaly.post_threshold",
    "value": 75,
    "scope": "global",
    "updated_by": "admin"
  }'

# Get defaults
curl -X GET https://soc.example.com/api/config/defaults

# Reset to defaults
curl -X POST https://soc.example.com/api/config/reset \
  -H "Content-Type: application/json" \
  -d '{"confirm": true}'
```

---

## 📚 **API Reference**

### Content Analysis API:
```python
from content_analysis import ContentAnalyzer

analyzer = ContentAnalyzer()

# DNS Analysis
dns_result = analyzer.analyze_dns_query("subdomain.example.com")
# Returns: {'entropy', 'encoding', 'dga_score', 'suspicious', 'reasons'}

# HTTP Payload Analysis
http_result = analyzer.analyze_http_payload(payload_bytes)
# Returns: {'size', 'entropy', 'encoding', 'dlp_findings', 'suspicious'}

# Entropy Calculation
entropy = analyzer.calculate_entropy(data_string)
# Returns: float (0-8)

# Encoding Detection
encoding = analyzer.detect_encoding(data_string)
# Returns: {'encoded', 'type', 'confidence', 'decoded_sample'}

# DLP Scan
findings = analyzer.scan_for_sensitive_data(text)
# Returns: [{'type', 'count', 'samples'}]
```

### Sensor Auth API:
```python
from sensor_auth import SensorAuthManager

auth = SensorAuthManager(db)

# Generate token
token = auth.generate_token(
    sensor_id="nano-01",
    token_name="Production Token",
    expires_days=365,
    permissions={'alerts': True, 'metrics': True, 'commands': False}
)

# Validate token
details = auth.validate_token(token, required_permission='alerts')
# Returns: {'sensor_id', 'hostname', 'permissions', ...} or None

# List tokens
tokens = auth.list_tokens(sensor_id="nano-01", include_inactive=False)

# Revoke token
auth.revoke_token(token_id=123)
```

---

## 🐛 **Troubleshooting**

### ICMP Detection Niet Actief:
```bash
# Check config
grep -A 3 "icmp_tunnel" config.yaml

# Check logs
tail -f /var/log/netmonitor/alerts.log | grep ICMP
```

### HTTP Detection Geen Alerts:
HTTP layer detectie werkt alleen voor **onversleuteld HTTP (port 80)**.
Voor HTTPS (port 443) is payload encrypted, dus alleen metadata analysis.

### DLP False Positives:
DLP patterns zijn basic - fine-tune regex in `content_analysis.py`:
```python
PATTERNS = {
    'credit_card': re.compile(r'your-pattern'),
    ...
}
```

### Sensor Token Auth Fails:
```bash
# Check token validity
psql -U netmonitor -d netmonitor -c "SELECT * FROM sensor_tokens WHERE is_active = TRUE;"

# Check logs
tail -f /var/log/netmonitor/sensor.log | grep -i auth
```

---

## 📝 **Migration Guide**

### Existing Installations:

**1. Update Database Schema:**
Database migration is automatic - new tables created on first run.

**2. Generate Sensor Tokens:**
```bash
# For each existing sensor
sudo python3 setup_sensor_auth.py
```

**3. Update Sensor Config:**
```bash
# Add token to sensor environment
sudo nano /etc/systemd/system/netmonitor-sensor.service

# Add line:
Environment="SENSOR_TOKEN=your-token-here"

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart netmonitor-sensor
```

**4. Update Web Dashboard:**
No changes needed - authentication is backward compatible.
Old sensors without tokens will get 401 errors (add tokens to fix).

---

## 🎯 **What's Next?**

Future enhancements:
- [ ] Machine Learning voor anomaly detection
- [ ] GeoIP blocking rules
- [ ] Automated threat response (auto-block)
- [ ] SIEM integration (Splunk, ELK)
- [ ] Custom alert rules via GUI
- [ ] Multi-tenant support

---

**Versie:** 2.0.0
**Datum:** 2025-11-28
**Auteur:** NetMonitor Development Team
