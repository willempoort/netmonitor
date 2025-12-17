"""
Device Discovery Module
Automatically discovers and tracks network devices based on observed traffic.

Features:
- MAC address extraction from Ethernet frames
- ARP monitoring for IP-MAC mapping
- DNS reverse lookup for hostnames
- Automatic device registration in database
- Periodic device activity tracking
- OUI (Organizationally Unique Identifier) lookup for vendor detection
"""

import logging
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import ipaddress

try:
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class DeviceDiscovery:
    """
    Discovers and tracks network devices based on observed traffic.

    Tracks devices by:
    - IP address (primary identifier)
    - MAC address (when available from Ethernet frames)
    - Hostname (via DNS reverse lookup)
    - First/last seen timestamps
    - Traffic patterns for classification hints
    """

    def __init__(self, db_manager=None, sensor_id: str = None, config: dict = None):
        """
        Initialize DeviceDiscovery.

        Args:
            db_manager: DatabaseManager instance for persisting devices
            sensor_id: Sensor identifier for multi-sensor deployments
            config: Configuration dictionary
        """
        self.logger = logging.getLogger('NetMonitor.DeviceDiscovery')
        self.db = db_manager
        self.sensor_id = sensor_id
        self.config = config or {}

        # In-memory device cache to reduce database writes
        # Key: (ip_address, sensor_id) -> device_info dict
        self.device_cache: Dict[Tuple[str, str], Dict] = {}
        self.cache_lock = threading.Lock()

        # Track when devices were last updated in DB to avoid excessive writes
        # Key: (ip_address, sensor_id) -> last_db_update timestamp
        self.last_db_update: Dict[Tuple[str, str], datetime] = {}

        # Minimum interval between DB updates for the same device (seconds)
        self.db_update_interval = self.config.get('device_discovery', {}).get(
            'db_update_interval', 300  # 5 minutes default
        )

        # DNS cache for hostname lookups
        self.dns_cache: Dict[str, Tuple[str, datetime]] = {}
        self.dns_cache_ttl = 3600  # 1 hour

        # ARP table: MAC -> IP mapping
        self.arp_table: Dict[str, str] = {}

        # Traffic statistics per device for classification hints
        # Key: ip_address -> stats dict
        self.traffic_stats: Dict[str, Dict] = defaultdict(lambda: {
            'ports_seen': set(),
            'protocols_seen': set(),
            'total_bytes': 0,
            'total_packets': 0,
            'first_seen': None,
            'last_seen': None,
            'outbound_ips': set(),
            'inbound_ips': set()
        })

        # OUI database for vendor lookup (first 3 bytes of MAC)
        self.oui_database = self._load_oui_database()

        # Internal networks for classification
        internal_networks = self.config.get('internal_networks', [
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
        ])
        self.internal_networks = self._parse_networks(internal_networks)

        # Start background thread for periodic tasks
        self._start_background_tasks()

        self.logger.info(f"Device Discovery initialized (sensor_id: {sensor_id})")

    def _parse_networks(self, network_list: List[str]) -> List:
        """Parse list of CIDR strings to network objects"""
        networks = []
        for net_str in network_list:
            try:
                networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError as e:
                self.logger.warning(f"Invalid network CIDR: {net_str}: {e}")
        return networks

    def _load_oui_database(self) -> Dict[str, str]:
        """
        Load OUI database for vendor identification.
        Returns dict mapping MAC prefix to vendor name.

        Common vendors included by default, can be extended with full OUI file.
        """
        # Common OUI prefixes (first 6 hex chars, no separators)
        oui_db = {
            # Apple
            '000A95': 'Apple', '000D93': 'Apple', '001451': 'Apple',
            '0016CB': 'Apple', '0017F2': 'Apple', '001B63': 'Apple',
            '001EC2': 'Apple', '002312': 'Apple', '002436': 'Apple',
            '002500': 'Apple', '0026BB': 'Apple', '00264A': 'Apple',
            # Google/Nest
            '54604A': 'Google', 'F47730': 'Google', '94EB2C': 'Google',
            '18B430': 'Nest', '64167F': 'Nest',
            # Amazon
            '0C47C9': 'Amazon', '40B4CD': 'Amazon', '84D6D0': 'Amazon',
            'A002DC': 'Amazon', 'FCA667': 'Amazon',
            # Samsung
            '002119': 'Samsung', '002339': 'Samsung', '00265D': 'Samsung',
            '08373D': 'Samsung', '10D38A': 'Samsung',
            # Microsoft/Xbox
            '001DD8': 'Microsoft', '002481': 'Microsoft',
            '7CB27D': 'Microsoft', '28186C': 'Microsoft',
            # Sony/PlayStation
            '001A80': 'Sony', '0019C5': 'Sony', '001D0D': 'Sony',
            '00041F': 'Sony', '0015C1': 'Sony',
            # Intel
            '001111': 'Intel', '001320': 'Intel', '00166F': 'Intel',
            '001E64': 'Intel', '001E67': 'Intel',
            # Raspberry Pi
            'B827EB': 'Raspberry Pi', 'DC26D7': 'Raspberry Pi',
            'E45F01': 'Raspberry Pi',
            # TP-Link
            '50C7BF': 'TP-Link', '6466B3': 'TP-Link', '983B8F': 'TP-Link',
            'C025E9': 'TP-Link', 'D8074A': 'TP-Link',
            # Netgear
            '00095B': 'Netgear', '001E2A': 'Netgear', '002636': 'Netgear',
            '20E52A': 'Netgear', 'C43DC7': 'Netgear',
            # Cisco
            '000E38': 'Cisco', '001011': 'Cisco', '0016C8': 'Cisco',
            '001A2F': 'Cisco', '001C58': 'Cisco',
            # HP
            '00110A': 'HP', '001321': 'HP', '0017A4': 'HP',
            '001871': 'HP', '001A4B': 'HP',
            # Dell
            '001422': 'Dell', '00188B': 'Dell', '001C23': 'Dell',
            '002219': 'Dell', '00248C': 'Dell',
            # Synology
            '0011324': 'Synology', '001132': 'Synology',
            # QNAP
            '00089B': 'QNAP', '002265': 'QNAP',
            # Ubiquiti
            '0027EE': 'Ubiquiti', '0418D6': 'Ubiquiti', '245A4C': 'Ubiquiti',
            '687251': 'Ubiquiti', '802AA8': 'Ubiquiti',
            # Hikvision (cameras)
            'C0562D': 'Hikvision', '54C4BF': 'Hikvision', 'E0CA94': 'Hikvision',
            # Dahua (cameras)
            '3C9BD6': 'Dahua', '4C11BF': 'Dahua', 'E0500A': 'Dahua',
            # Axis (cameras)
            '00408C': 'Axis', 'ACCC8E': 'Axis',
            # Ring
            '34DF20': 'Ring', 'F48CEB': 'Ring',
            # Roku
            'DC3A5E': 'Roku', 'B0A737': 'Roku', 'CC6DA0': 'Roku',
            # Sonos
            '5CDAD4': 'Sonos', '7405A5': 'Sonos', '949452': 'Sonos',
            'B8E937': 'Sonos',
            # Philips Hue
            '001788': 'Philips Hue', 'ECB5FA': 'Philips Hue',
        }
        return oui_db

    def _start_background_tasks(self):
        """Start background thread for periodic tasks"""
        self._running = True
        self._bg_thread = threading.Thread(target=self._background_worker, daemon=True)
        self._bg_thread.start()

    def _background_worker(self):
        """Background worker for periodic tasks"""
        while self._running:
            try:
                # Flush stale DNS cache entries
                self._cleanup_dns_cache()

                # Persist cached devices to database periodically
                self._flush_device_cache()

            except Exception as e:
                self.logger.error(f"Error in background worker: {e}")

            time.sleep(60)  # Run every minute

    def _cleanup_dns_cache(self):
        """Remove expired entries from DNS cache"""
        now = datetime.now()
        expired = [
            ip for ip, (hostname, cached_at) in self.dns_cache.items()
            if (now - cached_at).total_seconds() > self.dns_cache_ttl
        ]
        for ip in expired:
            del self.dns_cache[ip]

    def _flush_device_cache(self):
        """Persist cached device updates to database"""
        if not self.db:
            return

        with self.cache_lock:
            now = datetime.now()
            for (ip, sensor_id), device_info in list(self.device_cache.items()):
                # Check if we should update this device in DB
                last_update = self.last_db_update.get((ip, sensor_id))
                if last_update and (now - last_update).total_seconds() < self.db_update_interval:
                    continue

                try:
                    self._persist_device(device_info)
                    self.last_db_update[(ip, sensor_id)] = now
                except Exception as e:
                    self.logger.error(f"Error persisting device {ip}: {e}")

    def _persist_device(self, device_info: Dict):
        """Persist a device to the database"""
        if not self.db:
            return

        try:
            self.db.register_device(
                ip_address=device_info['ip_address'],
                sensor_id=device_info.get('sensor_id'),
                mac_address=device_info.get('mac_address'),
                hostname=device_info.get('hostname'),
                created_by='device_discovery'
            )
        except Exception as e:
            self.logger.error(f"Error registering device: {e}")

    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP is in internal networks"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.internal_networks:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    def get_vendor_from_mac(self, mac_address: str) -> Optional[str]:
        """
        Get vendor name from MAC address using OUI lookup.

        Args:
            mac_address: MAC address in any common format

        Returns:
            Vendor name or None if not found
        """
        if not mac_address:
            return None

        # Normalize MAC to uppercase hex without separators
        mac_clean = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')

        if len(mac_clean) < 6:
            return None

        # Get OUI (first 6 characters = 3 bytes)
        oui = mac_clean[:6]

        return self.oui_database.get(oui)

    def resolve_hostname(self, ip_address: str) -> Optional[str]:
        """
        Resolve IP address to hostname via DNS reverse lookup.
        Uses caching to reduce DNS queries.

        Args:
            ip_address: IP address to resolve

        Returns:
            Hostname or None if resolution fails
        """
        # Check cache first
        if ip_address in self.dns_cache:
            hostname, cached_at = self.dns_cache[ip_address]
            if (datetime.now() - cached_at).total_seconds() < self.dns_cache_ttl:
                return hostname

        # Perform DNS lookup
        hostname = None
        try:
            result = socket.gethostbyaddr(ip_address)
            hostname = result[0]
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        except Exception as e:
            self.logger.debug(f"DNS lookup failed for {ip_address}: {e}")

        # Cache result (even None to avoid repeated failed lookups)
        self.dns_cache[ip_address] = (hostname, datetime.now())

        return hostname

    def process_packet(self, packet) -> Optional[Dict]:
        """
        Process a packet for device discovery.
        Extracts device information from packet headers.

        Args:
            packet: Scapy packet object

        Returns:
            Device info dict if a device was discovered/updated, None otherwise
        """
        if not SCAPY_AVAILABLE:
            return None

        device_info = None

        # Extract MAC address from Ethernet layer if available
        mac_address = None
        if packet.haslayer(Ether):
            ether = packet[Ether]
            # Use source MAC (the device sending the packet)
            mac_address = ether.src

        # Process ARP packets for IP-MAC mapping
        if packet.haslayer(ARP):
            device_info = self._process_arp_packet(packet)

        # Process IP packets
        elif packet.haslayer(IP):
            device_info = self._process_ip_packet(packet, mac_address)

        return device_info

    def _process_arp_packet(self, packet) -> Optional[Dict]:
        """
        Process ARP packet for device discovery.
        ARP packets contain both IP and MAC addresses.
        """
        arp = packet[ARP]

        # ARP op codes: 1 = request, 2 = reply
        # For device discovery, we're interested in:
        # - ARP replies (op=2): sender is announcing their IP/MAC
        # - ARP requests (op=1): sender is looking for someone

        sender_ip = arp.psrc
        sender_mac = arp.hwsrc

        # Skip invalid or broadcast addresses
        if not sender_ip or sender_ip == '0.0.0.0':
            return None
        if not sender_mac or sender_mac == '00:00:00:00:00:00':
            return None
        if sender_mac.lower() == 'ff:ff:ff:ff:ff:ff':
            return None

        # Skip if not internal IP
        if not self._is_internal_ip(sender_ip):
            return None

        # Update ARP table
        self.arp_table[sender_mac.lower()] = sender_ip

        # Create/update device
        return self._register_device(sender_ip, sender_mac)

    def _process_ip_packet(self, packet, mac_address: str = None) -> Optional[Dict]:
        """
        Process IP packet for device discovery.
        """
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        device_info = None

        # Track source device (if internal)
        if self._is_internal_ip(src_ip):
            device_info = self._register_device(src_ip, mac_address)
            self._update_traffic_stats(src_ip, packet, direction='outbound', dst_ip=dst_ip)

        # Track destination device (if internal and we see return traffic)
        if self._is_internal_ip(dst_ip):
            # We might not have MAC for destination, but track the IP
            self._update_traffic_stats(dst_ip, packet, direction='inbound', src_ip=src_ip)

        return device_info

    def _register_device(self, ip_address: str, mac_address: str = None) -> Dict:
        """
        Register or update a device in the cache.

        Args:
            ip_address: Device IP address
            mac_address: Device MAC address (optional)

        Returns:
            Device info dictionary
        """
        cache_key = (ip_address, self.sensor_id)
        now = datetime.now()

        with self.cache_lock:
            if cache_key in self.device_cache:
                # Update existing device
                device = self.device_cache[cache_key]
                device['last_seen'] = now

                # Update MAC if we didn't have it before
                if mac_address and not device.get('mac_address'):
                    device['mac_address'] = mac_address
                    device['vendor'] = self.get_vendor_from_mac(mac_address)

                # Try hostname resolution if we don't have it
                if not device.get('hostname'):
                    device['hostname'] = self.resolve_hostname(ip_address)

            else:
                # New device
                hostname = self.resolve_hostname(ip_address)
                vendor = self.get_vendor_from_mac(mac_address) if mac_address else None

                device = {
                    'ip_address': ip_address,
                    'mac_address': mac_address,
                    'hostname': hostname,
                    'vendor': vendor,
                    'sensor_id': self.sensor_id,
                    'first_seen': now,
                    'last_seen': now,
                    'is_new': True
                }

                self.device_cache[cache_key] = device
                self.logger.info(f"New device discovered: {ip_address} (MAC: {mac_address}, Vendor: {vendor}, Hostname: {hostname})")

                # Immediately persist new devices
                self._persist_device(device)
                self.last_db_update[cache_key] = now
                device['is_new'] = False

        return device

    def _update_traffic_stats(self, ip_address: str, packet, direction: str,
                              src_ip: str = None, dst_ip: str = None):
        """
        Update traffic statistics for a device.
        These stats can be used for device classification hints.
        """
        stats = self.traffic_stats[ip_address]
        now = datetime.now()

        if not stats['first_seen']:
            stats['first_seen'] = now
        stats['last_seen'] = now

        # Track packet count and size
        stats['total_packets'] += 1
        if hasattr(packet, 'len'):
            stats['total_bytes'] += packet.len

        # Track ports if TCP/UDP
        if packet.haslayer(IP):
            ip_layer = packet[IP]

            # Track protocol
            stats['protocols_seen'].add(ip_layer.proto)

            # Track TCP/UDP ports
            from scapy.layers.inet import TCP, UDP
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                if direction == 'outbound':
                    stats['ports_seen'].add(('TCP', tcp.dport, 'dst'))
                else:
                    stats['ports_seen'].add(('TCP', tcp.sport, 'src'))
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                if direction == 'outbound':
                    stats['ports_seen'].add(('UDP', udp.dport, 'dst'))
                else:
                    stats['ports_seen'].add(('UDP', udp.sport, 'src'))

        # Track communication partners
        if direction == 'outbound' and dst_ip:
            stats['outbound_ips'].add(dst_ip)
        elif direction == 'inbound' and src_ip:
            stats['inbound_ips'].add(src_ip)

    def get_device_stats(self, ip_address: str) -> Optional[Dict]:
        """
        Get traffic statistics for a device.

        Args:
            ip_address: Device IP address

        Returns:
            Statistics dictionary or None if device not tracked
        """
        if ip_address not in self.traffic_stats:
            return None

        stats = self.traffic_stats[ip_address]

        # Convert sets to lists for JSON serialization
        return {
            'ip_address': ip_address,
            'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else None,
            'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else None,
            'total_packets': stats['total_packets'],
            'total_bytes': stats['total_bytes'],
            'ports_seen': list(stats['ports_seen']),
            'protocols_seen': list(stats['protocols_seen']),
            'unique_outbound_destinations': len(stats['outbound_ips']),
            'unique_inbound_sources': len(stats['inbound_ips'])
        }

    def get_all_devices(self) -> List[Dict]:
        """
        Get all discovered devices from cache.

        Returns:
            List of device dictionaries
        """
        with self.cache_lock:
            devices = []
            for (ip, sensor_id), device in self.device_cache.items():
                device_copy = device.copy()
                # Add traffic stats
                if ip in self.traffic_stats:
                    stats = self.traffic_stats[ip]
                    device_copy['total_packets'] = stats['total_packets']
                    device_copy['total_bytes'] = stats['total_bytes']
                devices.append(device_copy)
            return devices

    def get_classification_hints(self, ip_address: str) -> Dict:
        """
        Get classification hints for a device based on observed behavior.
        These hints can help with automatic or suggested device classification.

        Args:
            ip_address: Device IP address

        Returns:
            Dictionary with classification hints
        """
        hints = {
            'suggested_templates': [],
            'confidence': 0.0,
            'reasoning': []
        }

        stats = self.traffic_stats.get(ip_address)
        if not stats:
            return hints

        # Get device info
        cache_key = (ip_address, self.sensor_id)
        device = self.device_cache.get(cache_key, {})
        vendor = device.get('vendor', '')

        # Analyze ports
        ports_seen = stats['ports_seen']
        dst_ports = {port for proto, port, direction in ports_seen if direction == 'dst'}
        src_ports = {port for proto, port, direction in ports_seen if direction == 'src'}

        # Classification rules
        suggestions = []

        # Camera detection
        if 554 in dst_ports or 8554 in dst_ports:  # RTSP
            suggestions.append(('IP Camera', 0.8, 'Uses RTSP streaming port'))
        if vendor and 'hikvision' in vendor.lower():
            suggestions.append(('IP Camera', 0.9, 'Hikvision vendor'))
        if vendor and 'dahua' in vendor.lower():
            suggestions.append(('IP Camera', 0.9, 'Dahua vendor'))
        if vendor and 'axis' in vendor.lower():
            suggestions.append(('IP Camera', 0.9, 'Axis vendor'))

        # Smart speaker detection
        if vendor and any(v in vendor.lower() for v in ['sonos', 'amazon', 'google']):
            if stats['total_bytes'] > 1000000:  # Some traffic
                suggestions.append(('Smart Speaker', 0.7, f'{vendor} device with significant traffic'))

        # Smart TV detection
        if vendor and any(v in vendor.lower() for v in ['samsung', 'sony', 'roku']):
            # High bandwidth, streaming ports
            if stats['total_bytes'] > 10000000:
                suggestions.append(('Smart TV', 0.7, f'{vendor} device with high bandwidth'))

        # Server detection (listening on common server ports)
        server_ports = {22, 80, 443, 3306, 5432, 8080}
        if src_ports & server_ports:
            suggestions.append(('Web Server', 0.6, 'Responds on web server ports'))

        # NAS detection
        nas_ports = {139, 445, 548, 2049}  # SMB, AFP, NFS
        if src_ports & nas_ports:
            suggestions.append(('File Server (NAS)', 0.7, 'Serves file sharing protocols'))
        if vendor and any(v in vendor.lower() for v in ['synology', 'qnap']):
            suggestions.append(('File Server (NAS)', 0.9, f'{vendor} NAS device'))

        # Printer detection
        printer_ports = {515, 631, 9100}  # LPR, IPP, RAW
        if src_ports & printer_ports:
            suggestions.append(('Printer', 0.8, 'Serves printer ports'))

        # Raspberry Pi likely an IoT sensor or server
        if vendor and 'raspberry' in vendor.lower():
            suggestions.append(('IoT Sensor', 0.5, 'Raspberry Pi device'))

        # Sort by confidence and return top suggestions
        suggestions.sort(key=lambda x: x[1], reverse=True)

        if suggestions:
            hints['suggested_templates'] = [
                {'name': name, 'confidence': conf, 'reason': reason}
                for name, conf, reason in suggestions[:3]
            ]
            hints['confidence'] = suggestions[0][1]
            hints['reasoning'] = [reason for _, _, reason in suggestions[:3]]

        return hints

    def shutdown(self):
        """Shutdown the device discovery module"""
        self._running = False

        # Final flush of device cache
        self._flush_device_cache()

        self.logger.info("Device Discovery shutdown complete")
