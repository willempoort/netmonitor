# Switch Port Mirroring Configuration Guide

Praktische configuratiegids voor het opzetten van port mirroring/SPAN op verschillende switch merken.

---

## 📋 Overzicht

Port mirroring (ook wel SPAN - Switched Port Analyzer) kopieert al het verkeer van één of meerdere poorten naar een monitoring poort waar de NetMonitor sensor op aangesloten is.

**Belangrijke terminologie:**
- **Source Port**: De poort(en) waarvan verkeer wordt gekopieerd
- **Destination Port**: De poort waar de sensor op zit
- **Direction**: RX (inbound), TX (outbound), of Both

---

## 🎯 Algemene Aanbevelingen

### Wat te Mirroren?

**⚠️ CRUCIAAL: Mirror WAN Traffic (vóór NAT)!**

**Beste Keuze: WAN Uplink naar Firewall**
```
Internet ─► [Switch Port 1: WAN] ─► Firewall ─► [Switch Port 2: LAN]
                   ▲                                    │
                   │                                    └──► Internal Network
              SPAN/Mirror
                   │
                   └──────────────────────► [Port 24: Sensor]

✅ Mirror Port 1 (WAN side) - Ziet originele externe IP's!
❌ Mirror Port 2 (LAN side) - Ziet alleen NAT'd IP's!
```

**Waarom WAN-side monitoren:**
✅ Ziet originele externe IP adressen (vóór NAT)
✅ Accurate threat detection voor reverse proxy setups
✅ Geen false positives door firewall IP
✅ Correcte brute force detection per client
✅ Juiste threat intelligence lookups

**Wat gebeurt er met LAN-side (VERKEERD):**
❌ Alle externe verkeer lijkt van 1 IP te komen (firewall)
❌ Brute force alerts op verkeerd IP
❌ Geen onderscheid tussen verschillende externe clients

**Alternatieve Monitoring Punten:**

1. **WAN uplink** (aanbevolen) - Alle internet traffic
2. **DMZ VLAN** - Alleen publieke servers (web, mail, etc.)
3. **Server farm uplink** - Intern datacentre verkeer
4. **Specifieke kritieke servers** - Database, domain controllers

**Netwerk Topologie Voorbeelden:**

**Type A: Firewall tussen twee switches**
```
Internet ──► WAN Switch ──Port X──► [Firewall WAN] ──► [Firewall LAN] ──Port Y──► LAN Switch
                  │
             SPAN Port X (✅ CORRECT - ziet externe IPs)
```

**Type B: Firewall op één switch (meest voorkomend)**
```
         ┌──Port 1 (WAN)──► Firewall ──► Port 2 (LAN)──┐
Internet─┤                                              ├──► Internal Network
         └──────────────── Switch ────────────────────┘
                            │
                       SPAN Port 1 (✅ CORRECT)
                    of SPAN Port 2 (❌ VERKEERD)
```

**Type C: Router/modem rechtstreeks**
```
Internet ──► Modem ──► [Switch Port 1] ──► Firewall/Router ──► [Port 2] ──► LAN
                            │
                       SPAN Port 1 (✅ CORRECT - als modem in bridge mode)
```

### Destination Port Setup

De sensor monitoring port (meestal eth0 op Nano Pi):

❌ **NIET configureren:**
- IP adres
- VLAN membership
- STP (Spanning Tree)
- LLDP/CDP

✅ **WEL configureren:**
- Access mode (geen trunk)
- Geen VLAN tagging
- Promiscuous mode op sensor

---

## 🔧 Cisco Catalyst Switches

### IOS Command Line

**Basis SPAN configuratie:**
```cisco
! Enable privileged mode
enable
configure terminal

! Create SPAN session
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24

! Configure destination port
interface GigabitEthernet0/24
 description NetMonitor Sensor - eth0
 switchport mode access
 no cdp enable
 no lldp transmit
 no lldp receive
 spanning-tree portfast
 spanning-tree bpduguard disable

! Save config
end
write memory
```

**Meerdere source poorten:**
```cisco
monitor session 1 source interface Gi0/1 - 4 both
monitor session 1 destination interface Gi0/24
```

**Specifieke VLAN mirroren:**
```cisco
monitor session 1 source vlan 10 both
monitor session 1 destination interface Gi0/24
```

**Verificatie:**
```cisco
show monitor session 1
show interface Gi0/24
```

### Verwachte Output

```
Session 1
---------
Type                   : Local Session
Source Ports           :
    Both               : Gi0/1
Destination Ports      : Gi0/24
    Encapsulation      : Native
          Ingress      : Disabled
```

---

## 🔧 HPE/Aruba Switches

### Aruba CX (AOS-CX)

**Web UI:**
1. Navigate to **Monitoring** → **Port Mirroring**
2. Click **Add Session**
3. Source: Select port(s) or VLAN
4. Destination: Select sensor port
5. Direction: Both
6. Apply

**CLI:**
```
configure
mirror session monitor_traffic
 source interface 1/1/1 both
 destination interface 1/1/24
 no shutdown
exit
write memory
```

### Aruba Legacy (ProCurve)

```
configure
mirror-port 24
interface 1
 mirror
exit
write memory
```

**Verificatie:**
```
show monitor
```

---

## 🔧 Ubiquiti EdgeSwitch

### Via Web UI (Aanbevolen)

1. Log in op EdgeSwitch web interface
2. **Monitoring** → **Port Mirroring**
3. Click **Add Session**
4. **Session ID:** 1
5. **Source Ports:** Select uplink port (bijv. 1)
6. **Destination Port:** Select sensor port (bijv. 24)
7. **Direction:** Both
8. **Status:** Enable
9. Click **Apply**

### Via CLI

```
configure
monitor session 1 source interface 0/1
monitor session 1 destination interface 0/24
monitor session 1 mode
exit
write memory
```

**Verificatie:**
```
show monitor session 1
```

---

## 🔧 Mikrotik RouterBOARD/Switch

### Via CLI

```
/interface ethernet switch
set switch1 mirror-source=ether1 mirror-target=ether24
```

### Via WebFig/WinBox

1. **Bridge** → **Settings**
2. **Mirror Source:** Selecteer bron interface
3. **Mirror Target:** Selecteer sensor interface
4. **Apply**

**Notitie:** Mikrotik heeft beperkte SPAN functionaliteit. Voor betere resultaten, gebruik sniffer:

```
/tool sniffer
set filter-interface=ether1 streaming-enabled=yes streaming-server=<sensor-ip>:37008
```

Sensor moet dan TZSP packets ontvangen.

---

## 🔧 Dell PowerConnect/Networking

### CLI Configuratie

```
console# configure
console(config)# monitor session 1 source interface ethernet g1/0/1 both
console(config)# monitor session 1 destination interface ethernet g1/0/24
console(config)# exit
console# copy running-config startup-config
```

**Verificatie:**
```
show monitor session 1
```

---

## 🔧 Netgear Smart/Managed Switches

### Via Web Interface

1. **Monitoring** → **Mirroring**
2. **Session:** 1
3. **Source Port:** Port waar firewall op zit
4. **Destination Port:** Sensor port
5. **Mode:** TX and RX
6. **Status:** Enabled
7. **Apply**

**Notitie:** Goedkope Netgear switches hebben vaak slechts 1 mirror sessie. Check documentatie.

---

## 🔧 Juniper EX Series

```
configure
set ethernet-switching-options analyzer monitor-traffic input ingress interface ge-0/0/1.0
set ethernet-switching-options analyzer monitor-traffic input egress interface ge-0/0/1.0
set ethernet-switching-options analyzer monitor-traffic output interface ge-0/0/24.0
commit
```

**Verificatie:**
```
show ethernet-switching-options analyzer
```

---

## 🔧 TP-Link Managed Switches

### Web Interface

1. **Monitoring** → **Port Mirroring**
2. **Mirroring Status:** Enable
3. **Source Port:** Select uplink
4. **Target Port:** Select sensor port
5. **Direction:** Both
6. **Apply**

---

## ⚠️ Common Issues & Troubleshooting

### Issue: Sensor ziet geen verkeer

**Check 1: Is SPAN actief?**
```bash
# Op sensor
sudo tcpdump -i eth0 -c 10
```
Als je niets ziet:

**Check 2: Switch config**
```
# Cisco
show monitor session 1
show interface gi0/24 status
```

**Check 3: Sensor interface**
```bash
# Op sensor
ip link show eth0  # Moet UP zijn
ethtool eth0       # Check link speed
```

### Issue: Gemixte/corrupte packets

**Oorzaak:** Destination port heeft IP/VLAN config

**Oplossing:**
```cisco
interface Gi0/24
 no switchport access vlan
 no ip address
 no cdp enable
```

### Issue: Hoge packet drops

**Oorzaak:** SPAN port bottleneck (te veel verkeer)

**Oplossing:**
1. Mirror alleen RX of TX in plaats van Both
2. Mirror specifieke VLAN i.p.v. alle traffic
3. Gebruik dedicated monitoring switch
4. Upgrade naar snellere sensor hardware

**Check drops:**
```bash
# Op sensor
ifconfig eth0 | grep "RX packets"
# Kijk naar "dropped" counter
```

### Issue: Switch performance degraded

**Oorzaak:** Te veel mirrors of CPU-intensive filtering

**Oplossing:**
- Max 1-2 SPAN sessions op kleine switches
- Gebruik hardware-based mirrors (niet software filters)
- Check switch CPU usage

---

## 🎯 Sensor Interface Setup

Na het configureren van switch mirroring, setup de sensor:

### Ubuntu/Debian (Nano Pi)

```bash
# Edit /etc/network/interfaces
auto eth0
iface eth0 inet manual
    up ip link set eth0 up
    up ip link set eth0 promisc on
    down ip link set eth0 down

auto eth1
iface eth1 inet dhcp
    # Of static:
    # address 192.168.100.10
    # netmask 255.255.255.0
    # gateway 192.168.100.1

# Restart networking
sudo systemctl restart networking
```

### Check Promiscuous Mode

```bash
# Moet "PROMISC" bevatten
ip link show eth0

# Output:
# 2: eth0: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 ...
```

### Test Capture

```bash
# Capture 100 packets
sudo tcpdump -i eth0 -c 100 -n

# Je zou nu verkeer moeten zien van verschillende IP's
```

---

## 📊 Validation Checklist

Na SPAN configuratie:

- [ ] Switch SPAN session actief (show monitor)
- [ ] Source port = firewall/uplink
- [ ] Destination port = sensor poort
- [ ] Direction = Both (of RX voor inbound only)
- [ ] Destination port geen IP/VLAN config
- [ ] Sensor eth0 in promiscuous mode
- [ ] tcpdump toont verkeer op eth0
- [ ] NetMonitor sensor ziet packets (dashboard)
- [ ] Geen packet drops op switch
- [ ] Switch performance normaal

---

## 💡 Pro Tips

**Tip 1: Label je kabels**
```
Port 24 ─► "MONITOR - DO NOT DISCONNECT"
```

**Tip 2: Documenteer je config**
```cisco
interface Gi0/24
 description NetMonitor Sensor - Location:ServerRoom Rack:3 U:42
```

**Tip 3: Monitor de monitor**
```bash
# Cron job om packet rate te checken
*/5 * * * * /usr/local/bin/check_monitor_health.sh
```

**Tip 4: Bandwidth estimation**
- Gemiddeld kantoor: ~10-50 Mbps
- Drukke server: ~100-500 Mbps
- Gigabit uplink: Plan voor burst traffic

**Tip 5: Test eerst met tcpdump**

Voordat je NetMonitor start:
```bash
# Capture 1 minuut en tel packets
sudo tcpdump -i eth0 -w /tmp/test.pcap &
sleep 60
killall tcpdump
capinfos /tmp/test.pcap

# Check of je verkeer ziet met verschillende IP's
tcpdump -r /tmp/test.pcap -n | head -50
```

---

## 🔍 Reference: Switch SPAN Capabilities

| Merk | Model Range | Max Sessions | Remote SPAN | VLAN Filter |
|------|-------------|--------------|-------------|-------------|
| Cisco Catalyst | 2960/3560/3750 | 2 | ✅ (RSPAN) | ✅ |
| HPE/Aruba | 2530/2930/3810 | 1-4 | ✅ | ✅ |
| Ubiquiti | EdgeSwitch | 1 | ❌ | ❌ |
| Mikrotik | CRS series | 1 | ⚠️ (TZSP) | ⚠️ |
| Netgear | M4300/M4500 | 1-2 | ❌ | ✅ |
| Dell | PowerConnect | 2 | ✅ | ✅ |
| Juniper | EX series | 4+ | ✅ | ✅ |

---

**Gerelateerd:**
- [ARCHITECTURE_BEST_PRACTICES.md](../ARCHITECTURE_BEST_PRACTICES.md) - Netwerk architectuur
- [SENSOR_DEPLOYMENT.md](../SENSOR_DEPLOYMENT.md) - Sensor installatie
- [README.md](../README.md) - Hoofddocumentatie

**Versie:** 1.0
**Datum:** 2024-12-15
