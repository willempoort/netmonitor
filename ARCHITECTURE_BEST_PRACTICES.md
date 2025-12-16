# NetMonitor SOC - Architecture Best Practices

## 🏗️ Production Architecture Overview

Deze gids beschrijft de aanbevolen productie architectuur voor NetMonitor SOC met dedicated monitoring hardware en gescheiden netwerk segmentatie.

---

## 📐 Netwerk Topologie

```
                    Internet
                       │
                       ▼
                  ┌─────────┐
                  │ Firewall│
                  │ Router  │
                  └────┬────┘
                       │
              ┌────────┴────────┐
              │                 │
         SPAN/Mirror        Normal
           Port              Traffic
              │                 │
              │            ┌────┴─────┐
              │            │  Core    │
              │            │  Switch  │
              │            └────┬─────┘
              │                 │
              │            ┌────┴──────────────────┐
              │            │                       │
              │         VLAN 10              VLAN 100
              │      (Production)         (Management)
              │            │                       │
              │       ┌────┴────┐            ┌─────┴─────┐
              │       │ Users   │            │ SOC       │
              │       │ Servers │            │ Infra     │
              │       └─────────┘            └─────┬─────┘
              │                                     │
              │                              ┌──────┴──────┐
              │                              │             │
              │                         SOC Server    Sensors
              │                         (Dashboard)   (Nano Pi)
              │                              │             │
              │                         ┌────┴─────┐  ┌───┴────┐
              └────────────────────────►│ Monitor  │  │Monitor │
                                        │Interface │  │  eth0  │
                                        │   lo/    │  │        │
                                        │  eth1    │  │  eth1  │
                                        └──────────┘  │(Mgmt)  │
                                                      └────────┘
```

---

## 🎯 Design Principles

### 1. **Separated Traffic Planes**

**Data Plane (Monitor Traffic)**
- Sensoren ontvangen gespiegeld verkeer via SPAN/mirror ports
- Dit verkeer bevat originele source/destination IP's
- Eenrichtingsverkeer (read-only)
- Geen routing nodig

**Management Plane (SOC Communication)**
- Dedicated VLAN voor sensor ↔ SOC server communicatie
- HTTPS API calls met token authenticatie
- Heartbeats, alerts, config sync
- Beveiligde tweerichtingscommunicatie

### 2. **Firewall-Agnostic Design**

✅ Werkt met **elke** firewall:
- OPNsense / pfSense
- Cisco ASA / Firepower
- Fortinet FortiGate
- Palo Alto
- MikroTik
- Ubiquiti EdgeRouter

Vereiste: Switch met port mirroring/SPAN capability

### 3. **Consistent Sensor Deployment**

Alle sensoren gebruiken:
- **Hardware**: Nano Pi R2S/R4S (of vergelijkbaar)
- **Software**: `sensor_client.py` met `sensor.conf`
- **Config**: Centraal beheer via SOC dashboard
- **Deployment**: Identiek proces voor alle locaties

---

## 🔌 Hardware Setup: Sensor Deployment

### Aanbevolen Hardware: Nano Pi R2S

**Specificaties:**
- 2x Gigabit Ethernet poorten
- Quad-core ARM processor
- 1GB RAM (voldoende voor meeste scenarios)
- ~€35-45 per unit
- Laag stroomverbruik (~5W)

### Netwerk Aansluiting

```
┌─────────────────────────────────────┐
│         Nano Pi R2S Sensor          │
│                                     │
│  ┌───────┐              ┌────────┐ │
│  │ eth0  │              │  eth1  │ │
│  │Monitor│              │  Mgmt  │ │
│  └───┬───┘              └───┬────┘ │
└──────┼──────────────────────┼──────┘
       │                      │
       │                      └─────► Management VLAN 100
       │                              (API, heartbeat, alerts)
       │
       └─────────────────────────────► SPAN/Mirror Port
                                       (Monitored traffic)
```

**Interface Configuratie:**

**eth0 (Monitor Interface)**
- Aangesloten op SPAN/mirror port
- **Geen IP adres** (promiscuous mode)
- Alleen packet capture
- Read-only verkeer

**eth1 (Management Interface)**
- Aangesloten op Management VLAN
- Heeft IP adres (DHCP of static)
- HTTPS naar SOC server
- API communicatie

---

## 🌐 VLAN Design

### Aanbevolen VLAN Structuur

| VLAN ID | Naam | Doel | Devices |
|---------|------|------|---------|
| 10 | Production | Gebruikers, servers, IoT | Workstations, servers |
| 20 | DMZ | Publieke services | Web servers |
| 30 | Guest | Gast netwerk | Guest WiFi |
| **100** | **SOC-Management** | **Sensor ↔ SOC communicatie** | **SOC Server, Sensors (eth1)** |

### Waarom Dedicated Management VLAN?

**Security:**
✅ Scheiding van monitoring data en management verkeer
✅ Firewall rules voor sensor authenticatie
✅ Geen risico dat sensoren productie verkeer verstoren

**Performance:**
✅ Sensoren zien elkaars verkeer niet
✅ Geen dubbele analyse van hetzelfde verkeer
✅ Gecontroleerde bandwidth voor API calls

**Operationeel:**
✅ Centraal beheer van sensor netwerk
✅ Makkelijk troubleshooting
✅ Consistente configuratie

---

## 🔄 Port Mirroring / SPAN Configuration

### Cisco Switch

```cisco
! Mirror alle verkeer van interface naar sensor
interface GigabitEthernet0/1
 description Uplink to Firewall

monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24

interface GigabitEthernet0/24
 description NetMonitor Sensor - Monitor Port
 switchport mode access
 no cdp enable
 no spanning-tree portfast
```

### HPE/Aruba Switch

```
# Mirror verkeer van port 1 naar port 24
mirror-port 24
interface 1
 mirror
```

### Ubiquiti EdgeSwitch

Via Web UI:
1. **System** → **Mirror Session**
2. Source: Port 1 (uplink)
3. Destination: Port 24 (sensor eth0)
4. Direction: Both (TX + RX)

### OPNsense/pfSense (via Switch)

OPNsense zelf heeft geen port mirroring, maar je kunt:

**Optie A: Mirror op switch**
- Mirror de switch port waar OPNsense op zit
- Sensor ziet al het verkeer dat via firewall gaat

**Optie B: Transparent bridge mode**
- Plaats Nano Pi inline tussen firewall en switch
- Nano Pi bridge mode + packet capture

---

## 🖧 SOC Server Network Configuration

### Scenario 1: SOC Server met Monitor Interface

**Hardware:** Server met 2 NIC's

```yaml
# config.yaml
self_monitor:
  enabled: true
  sensor_id: soc-server
  interface: eth1  # Monitor interface (connected to SPAN port)

# eth0 = Management (dashboard access, API)
# eth1 = Monitor (SPAN port, no IP needed)
```

### Scenario 2: SOC Server zonder Monitor Interface

**Hardware:** Server met 1 NIC (alleen management)

```yaml
# config.yaml
self_monitor:
  enabled: false  # SOC server ontvangt alleen alerts van remote sensors
```

SOC server fungeert als:
- Dashboard & Web UI
- Database (PostgreSQL + TimescaleDB)
- API endpoint voor sensors
- Centraal configuratiebeheer

---

## 🔐 Security Best Practices

### 1. Management VLAN Firewall Rules

```
# Allow sensor → SOC server (HTTPS API)
VLAN 100 → SOC Server IP : TCP 8443 (HTTPS) : ALLOW

# Allow SOC dashboard access from admin network
VLAN 100 → SOC Server IP : TCP 8080 (Dashboard) : ALLOW (source: admin IPs only)

# Block sensor → sensor communication
VLAN 100 → VLAN 100 : ANY : DENY

# Block sensor → production networks
VLAN 100 → VLAN 10,20,30 : ANY : DENY

# Allow sensor → Internet (threat feed updates)
VLAN 100 → Internet : TCP 443 : ALLOW

# Default deny
VLAN 100 → ANY : DENY
```

### 2. Token-Based Authentication

Elke sensor heeft unieke token:
```bash
# Op SOC server: genereer token per sensor
cd /opt/netmonitor
python3 mcp_server/manage_tokens.py create \
  --name "sensor-vlan10-01" \
  --scope read_write \
  --description "Production VLAN 10 sensor"
```

Token in sensor config:
```bash
# sensor.conf
SENSOR_TOKEN=<generated-token>
```

### 3. TLS/SSL Encryption

**Vereis HTTPS** voor alle sensor communicatie:
```yaml
# config.yaml
database:
  require_ssl: true

api:
  ssl_cert: /etc/ssl/certs/soc.crt
  ssl_key: /etc/ssl/private/soc.key
```

---

## 📊 Deployment Checklist

### Core Infrastructure

- [ ] Core switch met SPAN/mirror capability
- [ ] Management VLAN 100 geconfigureerd
- [ ] Firewall rules voor management VLAN
- [ ] SOC server met PostgreSQL + NetMonitor
- [ ] SSL certificaten voor HTTPS API

### Per Sensor Deployment

- [ ] Nano Pi R2S hardware
- [ ] SD card met Ubuntu/Armbian
- [ ] NetMonitor sensor software geïnstalleerd
- [ ] SPAN/mirror port geconfigureerd op switch
- [ ] eth0 → SPAN port (geen IP)
- [ ] eth1 → Management VLAN (met IP)
- [ ] Sensor token gegenereerd
- [ ] `sensor.conf` configuratie
- [ ] Sensor geregistreerd in SOC dashboard
- [ ] Heartbeat zichtbaar (< 60 seconden)

### Testing

- [ ] Sensor ziet verkeer (packets > 0)
- [ ] Alerts komen aan op SOC server
- [ ] Dashboard toont sensor status
- [ ] Sensor ontvangt config updates
- [ ] Threat feeds werken

---

## 🚀 Scaling: Multi-Location Setup

Voor organisaties met meerdere locaties:

```
Location A (HQ)                Location B (Branch)
┌─────────────┐               ┌─────────────┐
│ SOC Server  │◄─────HTTPS────┤ Sensors     │
│ (Central)   │               │ (Remote)    │
└─────────────┘               └─────────────┘
     │                              │
     └────────HTTPS────────────────►│
                              Location C
                              ┌─────────────┐
                              │ Sensors     │
                              │ (Remote)    │
                              └─────────────┘
```

**Requirements:**
- SOC server publiek bereikbaar (of VPN)
- Port 8443 open voor sensor API
- Per-location VLAN 100 voor management
- Site-to-site VPN of public HTTPS endpoint

---

## 💡 Cost Breakdown

### Small Deployment (1 locatie)

| Item | Qty | Cost | Total |
|------|-----|------|-------|
| Managed Switch (24p Gigabit) | 1 | €150 | €150 |
| Nano Pi R2S | 3 | €40 | €120 |
| SOC Server (gebruikt hardware) | 1 | €200 | €200 |
| Cabling, PSU, etc. | - | €50 | €50 |
| **Total** | | | **€520** |

### Medium Deployment (3 locaties)

| Item | Qty | Cost | Total |
|------|-----|------|-------|
| Managed Switch per locatie | 3 | €150 | €450 |
| Nano Pi R2S sensors | 10 | €40 | €400 |
| SOC Server (dedicated) | 1 | €500 | €500 |
| Site-to-site VPN setup | - | €100 | €100 |
| **Total** | | | **€1,450** |

---

## 📚 Gerelateerde Documentatie

- **[SENSOR_DEPLOYMENT.md](SENSOR_DEPLOYMENT.md)** - Sensor installatie stap-voor-stap
- **[CONFIG_GUIDE.md](CONFIG_GUIDE.md)** - Configuratie opties
- **[ADMIN_MANUAL.md](ADMIN_MANUAL.md)** - SOC server beheer
- **[README.md](README.md)** - Algemene documentatie

---

## ❓ FAQ

**Q: Kan ik meerdere switches monitoren met 1 sensor?**
A: Nee, elke sensor monitort 1 SPAN port. Voor meerdere switches heb je meerdere sensors nodig, OF je configure een uplink mirror (mirror het verkeer tussen switches).

**Q: Moet ik het gehele netwerk mirroren?**
A: Nee, je kunt selectief mirroren:
- Alleen uplink naar firewall
- Alleen specifieke VLANs
- Alleen specifieke servers

**Q: Wat als mijn switch geen SPAN ondersteunt?**
A: Opties:
- Upgrade naar managed switch met SPAN (~€150)
- Gebruik inline TAP device (€200-500)
- Plaats sensor inline in transparent bridge mode

**Q: Hoe veel bandwidth gebruikt de management VLAN?**
A: Minimaal:
- Heartbeat: ~1 KB per 30 seconden
- Config sync: ~5 KB per 5 minuten
- Alerts: ~1-2 KB per alert
- Totaal: < 10 KB/s gemiddeld per sensor

**Q: Kan ik sensoren extern (WAN) bereiken?**
A: Ja, via:
- VPN (aanbevolen): Site-to-site of sensor VPN client
- Public API endpoint: Port forward + SSL + strong tokens
- Cloud relay: Tunnel via intermediate cloud server

---

## 🎓 Best Practice Summary

✅ **DO's:**
- Gebruik dedicated hardware voor sensoren (Nano Pi)
- Configureer management VLAN voor SOC verkeer
- Mirror strategisch (firewall uplink vaak ideaal)
- Gebruik unieke tokens per sensor
- Enable SSL/TLS voor API communicatie
- Monitor sensor health (heartbeats)
- Test regelmatig met test traffic

❌ **DON'Ts:**
- Sensor software op productie servers draaien
- Management verkeer over productie netwerk
- Sensoren elkaars verkeer laten zien
- Dezelfde token voor meerdere sensoren
- Plain HTTP voor sensor API
- SPAN hele netwerk zonder filtering (overload)

---

**Versie:** 1.0
**Laatst gewijzigd:** 2024-12-15
**Auteur:** NetMonitor SOC Team
