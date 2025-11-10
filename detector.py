"""
Threat Detection Module
Implementeert verschillende detectie algoritmes voor verdacht netwerkverkeer
"""

import time
import logging
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR


class ThreatDetector:
    """Detecteert verschillende soorten verdacht netwerkverkeer"""

    def __init__(self, config, threat_feed_manager=None, behavior_detector=None, abuseipdb_client=None):
        self.config = config
        self.logger = logging.getLogger('NetMonitor.Detector')

        # External components
        self.threat_feeds = threat_feed_manager
        self.behavior_detector = behavior_detector
        self.abuseipdb = abuseipdb_client

        # Tracking data structures
        self.port_scan_tracker = defaultdict(lambda: {
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })

        self.connection_tracker = defaultdict(lambda: deque(maxlen=1000))
        self.dns_tracker = defaultdict(lambda: deque(maxlen=100))

        # Parsed whitelist/blacklist
        self.whitelist = self._parse_ip_list(config.get('whitelist', []))
        self.blacklist = self._parse_ip_list(config.get('blacklist', []))

        self.logger.info("Threat Detector geïnitialiseerd")

    def _parse_ip_list(self, ip_list):
        """Parse lijst van IPs/CIDRs naar ipaddress objecten"""
        parsed = []
        # Protect against None
        if ip_list is None:
            return parsed

        for ip_str in ip_list:
            try:
                parsed.append(ipaddress.ip_network(ip_str, strict=False))
            except ValueError as e:
                self.logger.warning(f"Ongeldig IP/CIDR: {ip_str}: {e}")
        return parsed

    def _is_in_list(self, ip_str, ip_list):
        """Check of IP in de lijst zit"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in ip_list:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    def analyze_packet(self, packet):
        """
        Analyseer een packet en detecteer threats
        Returns: lijst van threat dicts
        """
        threats = []

        if not packet.haslayer(IP):
            return threats

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Skip whitelisted IPs
        if self._is_in_list(src_ip, self.whitelist):
            return threats

        # Check blacklist (static config)
        if self._is_in_list(src_ip, self.blacklist):
            threats.append({
                'type': 'BLACKLISTED_IP',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Packet van blacklisted IP: {src_ip}'
            })

        # Check threat feeds (C&C servers, malware IPs)
        if self.threat_feeds:
            # Check source IP tegen feeds
            is_malicious, metadata = self.threat_feeds.is_malicious_ip(src_ip)
            if is_malicious:
                threats.append({
                    'type': 'THREAT_FEED_MATCH',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'IP gevonden in threat feed: {metadata.get("feed", "unknown")} - {metadata.get("type", "malicious")}',
                    'feed': metadata.get('feed'),
                    'malware': metadata.get('malware', 'Unknown')
                })

            # Check destination IP (voor outbound connections naar C&C)
            is_malicious_dst, metadata_dst = self.threat_feeds.is_malicious_ip(dst_ip)
            if is_malicious_dst:
                threats.append({
                    'type': 'C2_COMMUNICATION',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'Internal machine verbindt met C&C server: {metadata_dst.get("malware", "Unknown")}',
                    'feed': metadata_dst.get('feed'),
                    'malware': metadata_dst.get('malware', 'Unknown')
                })

        # Port scan detection
        if self.config['thresholds']['port_scan']['enabled']:
            threat = self._detect_port_scan(packet)
            if threat:
                threats.append(threat)

        # Connection flood detection
        if self.config['thresholds']['connection_flood']['enabled']:
            threat = self._detect_connection_flood(packet)
            if threat:
                threats.append(threat)

        # Unusual packet size detection
        if self.config['thresholds']['packet_size']['enabled']:
            threat = self._detect_unusual_packet_size(packet)
            if threat:
                threats.append(threat)

        # DNS tunneling detection
        if self.config['thresholds']['dns_tunnel']['enabled']:
            threat = self._detect_dns_tunnel(packet)
            if threat:
                threats.append(threat)

        # Behavior-based detection (beaconing, lateral movement, etc.)
        if self.behavior_detector:
            behavior_threats = self.behavior_detector.analyze_packet(packet)
            threats.extend(behavior_threats)

        return threats

    def _detect_port_scan(self, packet):
        """Detecteer port scanning activiteit"""
        if not packet.haslayer(TCP):
            return None

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_port = tcp_layer.dport

        # Track poorten per source IP
        tracker = self.port_scan_tracker[src_ip]
        current_time = time.time()

        # Reset tracking als time window is verlopen
        if tracker['first_seen'] and \
           (current_time - tracker['first_seen']) > self.config['thresholds']['port_scan']['time_window']:
            tracker['ports'].clear()
            tracker['first_seen'] = current_time

        if not tracker['first_seen']:
            tracker['first_seen'] = current_time

        tracker['ports'].add(dst_port)
        tracker['last_seen'] = current_time

        # Check threshold
        threshold = self.config['thresholds']['port_scan']['unique_ports']
        if len(tracker['ports']) >= threshold:
            # Bewaar de gescande poorten voordat we resetten
            ports_found = len(tracker['ports'])
            scanned_ports = sorted(list(tracker['ports']))  # Sla de lijst op

            # Reset om duplicate alerts te voorkomen
            tracker['ports'].clear()
            tracker['first_seen'] = current_time

            # Include metadata with the actual ports scanned
            return {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': ip_layer.dst,
                'description': f'Mogelijk port scan gedetecteerd: {ports_found} unieke poorten binnen {self.config["thresholds"]["port_scan"]["time_window"]}s',
                'ports_scanned': ports_found,
                'metadata': json.dumps({
                    'ports': scanned_ports,
                    'port_count': ports_found,
                    'time_window': self.config["thresholds"]["port_scan"]["time_window"]
                })
            }

        return None

    def _detect_connection_flood(self, packet):
        """Detecteer connection flooding (veel connecties in korte tijd)"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        # Check voor SYN packets (nieuwe connecties)
        if not (tcp_layer.flags & 0x02):  # SYN flag
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        current_time = time.time()

        # Track connection timestamps
        connections = self.connection_tracker[src_ip]
        connections.append(current_time)

        # Verwijder oude entries buiten time window
        time_window = self.config['thresholds']['connection_flood']['time_window']
        cutoff_time = current_time - time_window

        # Count recente connecties
        recent_connections = sum(1 for ts in connections if ts > cutoff_time)

        threshold = self.config['thresholds']['connection_flood']['connections_per_second'] * time_window

        if recent_connections > threshold:
            return {
                'type': 'CONNECTION_FLOOD',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': ip_layer.dst,
                'description': f'Mogelijk connection flood: {recent_connections} connecties binnen {time_window}s',
                'connection_count': recent_connections
            }

        return None

    def _detect_unusual_packet_size(self, packet):
        """Detecteer ongewoon grote packets (mogelijk data exfiltration)"""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        packet_size = len(packet)
        threshold = self.config['thresholds']['packet_size']['min_suspicious_size']

        if packet_size > threshold:
            return {
                'type': 'UNUSUAL_PACKET_SIZE',
                'severity': 'LOW',
                'source_ip': ip_layer.src,
                'destination_ip': ip_layer.dst,
                'description': f'Ongewoon groot packet gedetecteerd: {packet_size} bytes',
                'packet_size': packet_size
            }

        return None

    def _detect_dns_tunnel(self, packet):
        """Detecteer mogelijke DNS tunneling"""
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        dns_layer = packet[DNS]
        if dns_layer.qr != 0:  # Alleen queries, niet responses
            return None

        query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
        ip_layer = packet[IP]
        src_ip = ip_layer.src

        # Check query length
        query_length_threshold = self.config['thresholds']['dns_tunnel']['query_length_threshold']
        if len(query) > query_length_threshold:
            return {
                'type': 'DNS_TUNNEL_SUSPICIOUS_LENGTH',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': ip_layer.dst,
                'description': f'Verdacht lange DNS query: {len(query)} karakters',
                'query': query[:100]  # Limiteer voor logging
            }

        # Track query rate
        current_time = time.time()
        queries = self.dns_tracker[src_ip]
        queries.append(current_time)

        # Count queries in laatste minuut
        cutoff_time = current_time - 60
        recent_queries = sum(1 for ts in queries if ts > cutoff_time)

        queries_threshold = self.config['thresholds']['dns_tunnel']['queries_per_minute']
        if recent_queries > queries_threshold:
            return {
                'type': 'DNS_TUNNEL_HIGH_RATE',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': ip_layer.dst,
                'description': f'Hoog aantal DNS queries: {recent_queries} per minuut',
                'query_count': recent_queries
            }

        return None

    def cleanup_old_data(self):
        """Cleanup oude tracking data (call periodiek)"""
        current_time = time.time()

        # Cleanup port scan tracker
        for ip in list(self.port_scan_tracker.keys()):
            tracker = self.port_scan_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 300:  # 5 minuten
                del self.port_scan_tracker[ip]

        self.logger.debug("Oude tracking data opgeschoond")
