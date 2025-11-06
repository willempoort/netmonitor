# Network Monitor - Verdacht Netwerkverkeer Detectie

Een krachtig netwerk monitoring programma voor Linux dat verdacht netwerkverkeer kan detecteren. Speciaal geschikt voor gebruik op een monitoring/span port van een switch.

## Features

### Detectie Mogelijkheden

- **Port Scanning Detectie**: Detecteert wanneer een host systematisch meerdere poorten scant
- **Connection Flooding**: Detecteert abnormaal hoge aantallen connecties in korte tijd
- **DNS Tunneling**: Detecteert verdachte DNS queries (lange queries, hoge query rates)
- **Ongewone Packet Sizes**: Detecteert abnormaal grote packets (mogelijk data exfiltration)
- **IP Blacklist**: Alert bij verkeer van bekende malicious IPs
- **IP Whitelist**: Voorkomt false positives van vertrouwde systemen

### Algemene Features

- Real-time packet capture en analyse
- Configureerbare detection thresholds
- Gekleurde console output
- Gestructureerde logging naar file
- Rate limiting om alert flooding te voorkomen
- Graceful shutdown bij SIGINT/SIGTERM

## Vereisten

- Linux systeem met root/sudo privileges
- Python 3.7 of hoger
- libpcap (meestal standaard geïnstalleerd)

## Installatie

### 1. Clone de repository

```bash
git clone <repository-url>
cd netmonitor
```

### 2. Installeer Python dependencies

```bash
pip install -r requirements.txt
```

Of met sudo voor system-wide installatie:

```bash
sudo pip install -r requirements.txt
```

### 3. Maak log directory aan

```bash
sudo mkdir -p /var/log/netmonitor
sudo chmod 755 /var/log/netmonitor
```

## Configuratie

Pas `config.yaml` aan naar je wensen:

### Network Interface

```yaml
interface: eth0  # Vervang met je monitoring interface (eth0, ens33, etc.)
```

Om alle interfaces te monitoren, gebruik:
```yaml
interface: any
```

### Detection Thresholds Aanpassen

Je kunt de gevoeligheid van elke detector aanpassen:

```yaml
thresholds:
  port_scan:
    enabled: true
    unique_ports: 20    # Aantal poorten voor alert
    time_window: 60     # Binnen X seconden

  connection_flood:
    enabled: true
    connections_per_second: 100
    time_window: 10
```

### Whitelist/Blacklist

Voeg vertrouwde netwerken toe aan whitelist:

```yaml
whitelist:
  - 192.168.1.0/24      # Je eigen netwerk
  - 10.0.0.0/8          # Intern netwerk
```

Voeg bekende malicious IPs toe aan blacklist:

```yaml
blacklist:
  - 203.0.113.0/24      # Bekend malicious netwerk
  - 198.51.100.50       # Specifiek IP
```

## Gebruik

### Basis Gebruik

Run als root (vereist voor packet capture):

```bash
sudo python3 netmonitor.py
```

### Met Specifieke Interface

```bash
sudo python3 netmonitor.py -i eth0
```

### Met Custom Config File

```bash
sudo python3 netmonitor.py -c /path/to/custom/config.yaml
```

### Verbose Mode (Debug)

```bash
sudo python3 netmonitor.py -v
```

### Stoppen

Druk op `Ctrl+C` voor graceful shutdown.

## Command Line Opties

```
usage: netmonitor.py [-h] [-c CONFIG] [-i INTERFACE] [-v]

options:
  -h, --help            Toon help bericht
  -c CONFIG, --config CONFIG
                        Pad naar configuratie file (default: config.yaml)
  -i INTERFACE, --interface INTERFACE
                        Network interface om te monitoren (overschrijft config file)
  -v, --verbose         Verbose output (DEBUG level)
```

## Output en Logging

### Console Output

Alerts worden real-time getoond in de console met kleuren:
- **ROOD**: HIGH severity (bijv. port scans, blacklisted IPs)
- **GEEL**: MEDIUM severity (bijv. connection flooding, DNS tunneling)
- **CYAAN**: LOW severity (bijv. grote packets)

Voorbeeld:
```
[2025-11-06 15:30:45] [HIGH] [PORT_SCAN] Mogelijk port scan gedetecteerd: 25 unieke poorten binnen 60s | Source: 192.168.1.100 | Destination: 10.0.0.50
```

### Log Files

Twee log files worden aangemaakt:

1. **Algemene logs**: `/var/log/netmonitor/alerts.log`
   - Alle system events en errors

2. **Security alerts**: `/var/log/netmonitor/security_alerts.log`
   - Alleen security threats

## Monitoring Port Setup

### Switch Configuratie

Voor gebruik op een monitoring/span port, configureer je switch om verkeer te mirroren:

#### Cisco IOS Voorbeeld

```
configure terminal
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24
end
```

#### Linux Bridge Voorbeeld

```bash
# Stel port mirroring in met tc
tc qdisc add dev eth0 ingress
tc filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev eth1
```

### Interface in Promiscuous Mode

De tool zet de interface automatisch in promiscuous mode, maar je kunt dit ook manueel doen:

```bash
sudo ip link set eth0 promisc on
```

## Troubleshooting

### "Permission Denied" Error

De tool vereist root privileges voor packet capture:

```bash
sudo python3 netmonitor.py
```

### Interface Niet Gevonden

Controleer beschikbare interfaces:

```bash
ip link show
# of
ifconfig
```

Pas `interface` in `config.yaml` aan naar een bestaande interface.

### Geen Packets Ontvangen

1. Check of interface UP is:
   ```bash
   sudo ip link set eth0 up
   ```

2. Check of er daadwerkelijk verkeer is:
   ```bash
   sudo tcpdump -i eth0 -c 10
   ```

3. Bij monitoring port: check switch configuratie

### Te Veel False Positives

Pas detection thresholds aan in `config.yaml`:
- Verhoog `unique_ports` voor port scan detectie
- Verhoog `connections_per_second` voor flood detectie
- Voeg interne netwerken toe aan whitelist

## Performance Consideraties

- De tool gebruikt `store=0` bij packet capture om memory gebruik laag te houden
- Voor high-traffic netwerken (>1Gbps): overweeg specifieke BPF filters
- Monitor CPU en memory gebruik met `top` of `htop`

## Systemd Service (Optioneel)

Om de monitor automatisch te starten bij boot:

1. Maak service file `/etc/systemd/system/netmonitor.service`:

```ini
[Unit]
Description=Network Monitor - Threat Detection
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/netmonitor
ExecStart=/usr/bin/python3 /path/to/netmonitor/netmonitor.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. Enable en start service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable netmonitor
sudo systemctl start netmonitor
```

3. Check status:

```bash
sudo systemctl status netmonitor
sudo journalctl -u netmonitor -f  # Live logs
```

## Security Overwegingen

- **Run als root**: Vereist voor raw packet access, maar wees voorzichtig
- **Log file permissions**: Zorg dat alleen root toegang heeft tot logs (kunnen gevoelige info bevatten)
- **Whitelist configuratie**: Voeg vertrouwde systemen toe om false positives te reduceren
- **Monitor de monitor**: Check periodiek of de tool nog draait en correct functioneert

## Architectuur

```
netmonitor.py       - Main entry point, packet capture loop
├── config_loader.py - YAML configuratie laden
├── detector.py      - Threat detection algoritmes
└── alerts.py        - Alert management en logging
```

## Licentie

[Specificeer licentie]

## Contributing

[Specificeer contribution guidelines]

## Contact

[Contact informatie]
