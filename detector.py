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
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.packet import Raw

# Import content analysis module
try:
    from content_analysis import ContentAnalyzer, analyze_dns
except ImportError:
    ContentAnalyzer = None
    analyze_dns = None


class ThreatDetector:
    """Detecteert verschillende soorten verdacht netwerkverkeer"""

    def __init__(self, config, threat_feed_manager=None, behavior_detector=None, abuseipdb_client=None, db_manager=None, sensor_id=None):
        self.config = config
        self.logger = logging.getLogger('NetMonitor.Detector')

        # External components
        self.threat_feeds = threat_feed_manager
        self.behavior_detector = behavior_detector
        self.abuseipdb = abuseipdb_client
        self.db_manager = db_manager  # Optional: for database whitelist checks
        self.sensor_id = sensor_id     # Optional: for sensor-specific whitelists

        # Tracking data structures
        self.port_scan_tracker = defaultdict(lambda: {
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })

        self.connection_tracker = defaultdict(lambda: deque(maxlen=1000))
        self.dns_tracker = defaultdict(lambda: deque(maxlen=100))

        # New trackers for protocol-specific detection
        self.icmp_tracker = defaultdict(lambda: deque(maxlen=100))  # ICMP packets
        self.http_tracker = defaultdict(lambda: deque(maxlen=50))   # HTTP requests
        self.smtp_ftp_tracker = defaultdict(lambda: {
            'total_bytes': 0,
            'first_seen': None,
            'last_seen': None
        })

        # Brute force detection tracker
        # Track: (src_ip, dst_ip, dst_port) -> [(timestamp), ...]
        self.brute_force_tracker = defaultdict(lambda: deque(maxlen=100))

        # Protocol mismatch detection tracker
        # Track suspicious protocols on non-standard ports
        self.protocol_mismatch_tracker = defaultdict(lambda: deque(maxlen=50))

        # Parsed whitelist/blacklist from config
        self.config_whitelist = self._parse_ip_list(config.get('whitelist', []))
        self.blacklist = self._parse_ip_list(config.get('blacklist', []))

        # Initialize content analyzer if available
        self.content_analyzer = ContentAnalyzer() if ContentAnalyzer else None

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

    def _is_whitelisted(self, ip_str):
        """Check if IP is whitelisted (config OR database)"""
        # First check config whitelist (fast, in-memory)
        if self._is_in_list(ip_str, self.config_whitelist):
            self.logger.debug(f"IP {ip_str} whitelisted via config")
            return True

        # Then check database whitelist (if available)
        if self.db_manager:
            try:
                if self.db_manager.check_ip_whitelisted(ip_str, sensor_id=self.sensor_id):
                    self.logger.debug(f"IP {ip_str} whitelisted via database (sensor_id={self.sensor_id})")
                    return True
            except Exception as e:
                self.logger.warning(f"Error checking database whitelist for {ip_str}: {e}")

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

        # Skip whitelisted IPs (both source AND destination)
        # This allows whitelisting multicast destinations like 224.0.0.0/4
        if self._is_whitelisted(src_ip) or self._is_whitelisted(dst_ip):
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

        # DNS tunneling detection (enhanced with content analysis)
        if self.config['thresholds']['dns_tunnel']['enabled']:
            threat = self._detect_dns_tunnel(packet)
            if threat:
                threats.append(threat)

        # ICMP tunneling detection
        if self.config['thresholds'].get('icmp_tunnel', {}).get('enabled', False):
            threat = self._detect_icmp_tunnel(packet)
            if threat:
                threats.append(threat)

        # HTTP/HTTPS anomaly detection
        if self.config['thresholds'].get('http_anomaly', {}).get('enabled', False):
            http_threats = self._detect_http_anomalies(packet)
            threats.extend(http_threats)

        # SMTP/FTP large transfer detection
        if self.config['thresholds'].get('smtp_ftp_transfer', {}).get('enabled', False):
            threat = self._detect_smtp_ftp_transfer(packet)
            if threat:
                threats.append(threat)

        # Brute force detection
        if self.config['thresholds'].get('brute_force', {}).get('enabled', True):
            threat = self._detect_brute_force(packet)
            if threat:
                threats.append(threat)

        # Protocol mismatch detection
        if self.config['thresholds'].get('protocol_mismatch', {}).get('enabled', True):
            protocol_threats = self._detect_protocol_mismatch(packet)
            threats.extend(protocol_threats)

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
        """Detecteer mogelijke DNS tunneling (enhanced met content analysis)"""
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        dns_layer = packet[DNS]
        if dns_layer.qr != 0:  # Alleen queries, niet responses
            return None

        query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
        ip_layer = packet[IP]
        src_ip = ip_layer.src

        # Enhanced analysis with content analyzer
        if self.content_analyzer:
            analysis = self.content_analyzer.analyze_dns_query(query)

            # Get enhanced DNS thresholds from config
            dns_enhanced_config = self.config['thresholds'].get('dns_enhanced', {})
            dga_threshold = dns_enhanced_config.get('dga_threshold', 0.6)
            entropy_threshold = dns_enhanced_config.get('entropy_threshold', 4.5)
            encoding_detection = dns_enhanced_config.get('encoding_detection', True)

            # Check for DGA (Domain Generation Algorithm)
            if analysis['dga_score'] > dga_threshold:
                return {
                    'type': 'DNS_DGA_DETECTED',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': ip_layer.dst,
                    'description': f'Mogelijk DGA gedetecteerd: {", ".join(analysis["reasons"])}',
                    'query': query[:100],
                    'dga_score': analysis['dga_score'],
                    'entropy': analysis['entropy']
                }

            # Check for encoding in DNS query
            if encoding_detection and analysis['encoding']['encoded']:
                return {
                    'type': 'DNS_ENCODED_QUERY',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': ip_layer.dst,
                    'description': f'Gecodeerde DNS query gedetecteerd: {analysis["encoding"]["type"]}',
                    'query': query[:100],
                    'encoding_type': analysis['encoding']['type'],
                    'entropy': analysis['entropy']
                }

            # High entropy check
            if analysis['entropy'] > entropy_threshold:
                return {
                    'type': 'DNS_HIGH_ENTROPY',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': ip_layer.dst,
                    'description': f'DNS query met hoge entropie: {analysis["entropy"]:.2f}',
                    'query': query[:100],
                    'entropy': analysis['entropy']
                }

        # Check query length (legacy detection)
        query_length_threshold = self.config['thresholds']['dns_tunnel']['query_length_threshold']
        if len(query) > query_length_threshold:
            return {
                'type': 'DNS_TUNNEL_SUSPICIOUS_LENGTH',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': ip_layer.dst,
                'description': f'Verdacht lange DNS query: {len(query)} karakters',
                'query': query[:100]
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

    def _detect_icmp_tunnel(self, packet):
        """Detecteer ICMP tunneling (grote payloads of hoge rate)"""
        if not packet.haslayer(ICMP):
            return None

        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]
        src_ip = ip_layer.src

        # Check if ICMP Echo Request or Echo Reply
        if icmp_layer.type not in [8, 0]:  # 8 = Echo Request, 0 = Echo Reply
            return None

        # Get ICMP payload size
        payload_size = 0
        if packet.haslayer(Raw):
            payload_size = len(packet[Raw].load)

        # Check for large ICMP payloads
        size_threshold = self.config['thresholds'].get('icmp_tunnel', {}).get('size_threshold', 500)
        if payload_size > size_threshold:
            # Analyze payload for encoded data if content analyzer available
            metadata = {'payload_size': payload_size}

            if self.content_analyzer and packet.haslayer(Raw):
                try:
                    payload_text = packet[Raw].load.decode('utf-8', errors='ignore')
                    entropy = self.content_analyzer.calculate_entropy(payload_text)
                    encoding = self.content_analyzer.detect_encoding(payload_text[:500])

                    metadata['entropy'] = entropy
                    if encoding['encoded']:
                        metadata['encoding'] = encoding['type']

                except Exception:
                    pass

            return {
                'type': 'ICMP_LARGE_PAYLOAD',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': ip_layer.dst,
                'description': f'Grote ICMP payload gedetecteerd: {payload_size} bytes',
                'payload_size': payload_size,
                'metadata': json.dumps(metadata)
            }

        # Track ICMP packet rate
        if payload_size > size_threshold / 2:  # Track packets > half threshold
            current_time = time.time()
            packets = self.icmp_tracker[src_ip]
            packets.append({'time': current_time, 'size': payload_size})

            # Count large ICMP packets in last minute
            cutoff_time = current_time - 60
            recent_large_packets = sum(1 for p in packets if p['time'] > cutoff_time)

            rate_threshold = self.config['thresholds'].get('icmp_tunnel', {}).get('rate_threshold', 10)
            if recent_large_packets > rate_threshold:
                return {
                    'type': 'ICMP_TUNNEL_HIGH_RATE',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': ip_layer.dst,
                    'description': f'Hoog aantal grote ICMP packets: {recent_large_packets} per minuut',
                    'packet_count': recent_large_packets,
                    'avg_size': sum(p['size'] for p in packets if p['time'] > cutoff_time) / recent_large_packets
                }

        return None

    def _detect_http_anomalies(self, packet):
        """Detecteer HTTP/HTTPS anomalieën"""
        threats = []

        if not packet.haslayer(TCP):
            return threats

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_port = tcp_layer.dport

        # Check for HTTP/HTTPS ports
        if dst_port not in [80, 443, 8080, 8443]:
            return threats

        # Get HTTP anomaly config
        http_config = self.config['thresholds'].get('http_anomaly', {})
        post_threshold = http_config.get('post_threshold', 50)
        post_time_window = http_config.get('post_time_window', 300)
        dlp_min_size = http_config.get('dlp_min_payload_size', 1024)
        entropy_threshold = http_config.get('entropy_threshold', 6.5)

        # HTTP layer detection (only works for unencrypted HTTP)
        if packet.haslayer(HTTPRequest):
            try:
                http_layer = packet[HTTPRequest]
                method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else 'UNKNOWN'
                path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else '/'
                host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else 'unknown'

                # Track HTTP request rate
                current_time = time.time()
                requests = self.http_tracker[src_ip]
                requests.append({'time': current_time, 'method': method, 'path': path})

                # Detect excessive POST requests (possible data exfiltration)
                cutoff_time = current_time - post_time_window
                recent_posts = sum(1 for r in requests if r['time'] > cutoff_time and r['method'] == b'POST')

                if recent_posts > post_threshold:
                    threats.append({
                        'type': 'HTTP_EXCESSIVE_POSTS',
                        'severity': 'MEDIUM',
                        'source_ip': src_ip,
                        'destination_ip': ip_layer.dst,
                        'description': f'Verdacht veel POST requests: {recent_posts} in {post_time_window//60} minuten',
                        'post_count': recent_posts,
                        'host': host
                    })

                # Check for suspicious user agents
                user_agent = None
                if hasattr(http_layer, 'User_Agent') and http_layer.User_Agent:
                    user_agent = http_layer.User_Agent.decode('utf-8', errors='ignore')

                    # Detect suspicious patterns in User-Agent
                    suspicious_ua_patterns = ['python', 'curl', 'wget', 'scanner', 'bot', 'sqlmap', 'nikto']
                    for pattern in suspicious_ua_patterns:
                        if pattern.lower() in user_agent.lower():
                            threats.append({
                                'type': 'HTTP_SUSPICIOUS_USER_AGENT',
                                'severity': 'LOW',
                                'source_ip': src_ip,
                                'destination_ip': ip_layer.dst,
                                'description': f'Verdachte User-Agent gedetecteerd: {pattern}',
                                'user_agent': user_agent[:100],
                                'pattern': pattern
                            })
                            break

            except Exception as e:
                self.logger.debug(f"Error parsing HTTP request: {e}")

        # Analyze HTTP payload (POST data, etc.)
        if packet.haslayer(Raw) and self.content_analyzer:
            try:
                payload = packet[Raw].load

                # Only analyze payloads above configured minimum size
                if len(payload) > dlp_min_size:
                    analysis = self.content_analyzer.analyze_http_payload(payload)

                    # Check for sensitive data in HTTP
                    if analysis['dlp_findings']:
                        threats.append({
                            'type': 'HTTP_SENSITIVE_DATA',
                            'severity': 'CRITICAL',
                            'source_ip': src_ip,
                            'destination_ip': ip_layer.dst,
                            'description': f'Gevoelige data in HTTP verkeer: {", ".join([f["type"] for f in analysis["dlp_findings"]])}',
                            'findings': [f['type'] for f in analysis['dlp_findings']],
                            'payload_size': len(payload)
                        })

                    # Check for high entropy (encrypted/compressed data in plaintext HTTP)
                    if dst_port == 80 and analysis['entropy'] > entropy_threshold:  # Only for plain HTTP
                        threats.append({
                            'type': 'HTTP_HIGH_ENTROPY_PAYLOAD',
                            'severity': 'MEDIUM',
                            'source_ip': src_ip,
                            'destination_ip': ip_layer.dst,
                            'description': f'Mogelijk versleutelde data in onversleuteld HTTP: entropie {analysis["entropy"]:.2f}',
                            'entropy': analysis['entropy'],
                            'payload_size': len(payload)
                        })

            except Exception as e:
                self.logger.debug(f"Error analyzing HTTP payload: {e}")

        return threats

    def _detect_smtp_ftp_transfer(self, packet):
        """Detecteer grote bestandsoverdrachten via SMTP/FTP"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_port = tcp_layer.dport

        # Check for SMTP/FTP ports
        # SMTP: 25 (plain), 587 (submission), 465 (SMTPS)
        # FTP: 21 (control), 20 (data), 989/990 (FTPS)
        monitored_ports = [20, 21, 25, 465, 587, 989, 990]

        if dst_port not in monitored_ports:
            return None

        # Get SMTP/FTP transfer config
        smtp_ftp_config = self.config['thresholds'].get('smtp_ftp_transfer', {})
        time_window = smtp_ftp_config.get('time_window', 300)
        threshold_mb = smtp_ftp_config.get('size_threshold_mb', 50)
        threshold_bytes = threshold_mb * 1024 * 1024

        # Track total bytes transferred
        if packet.haslayer(Raw):
            payload_size = len(packet[Raw].load)

            tracker = self.smtp_ftp_tracker[f"{src_ip}:{dst_port}"]
            current_time = time.time()

            if not tracker['first_seen']:
                tracker['first_seen'] = current_time

            tracker['total_bytes'] += payload_size
            tracker['last_seen'] = current_time

            # Check if large transfer over a time window
            if (current_time - tracker['first_seen']) < time_window:
                # Still within window, check threshold

                if tracker['total_bytes'] > threshold_bytes:
                    total_mb = tracker['total_bytes'] / (1024 * 1024)
                    duration = current_time - tracker['first_seen']

                    # Determine protocol
                    if dst_port in [25, 465, 587]:
                        protocol = 'SMTP'
                        alert_type = 'SMTP_LARGE_ATTACHMENT'
                    else:
                        protocol = 'FTP'
                        alert_type = 'FTP_LARGE_TRANSFER'

                    # Reset tracker to avoid duplicate alerts
                    tracker['total_bytes'] = 0
                    tracker['first_seen'] = current_time

                    return {
                        'type': alert_type,
                        'severity': 'MEDIUM',
                        'source_ip': src_ip,
                        'destination_ip': ip_layer.dst,
                        'description': f'Grote {protocol} overdracht gedetecteerd: {total_mb:.2f} MB in {duration:.0f}s',
                        'total_mb': total_mb,
                        'duration_seconds': duration,
                        'protocol': protocol,
                        'port': dst_port
                    }
            else:
                # Window expired, reset
                tracker['total_bytes'] = payload_size
                tracker['first_seen'] = current_time

        return None

    def _detect_brute_force(self, packet):
        """
        Detecteer brute force aanvallen op authenticatie services

        Detecteert herhaalde connection attempts naar:
        - SSH (22), Telnet (23), FTP (21), RDP (3389)
        - HTTP Auth (80, 443, 8080), SMB (445), MySQL (3306), PostgreSQL (5432)
        """
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport

        # Authentication service ports
        auth_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt'
        }

        if dst_port not in auth_ports:
            return None

        # Only track SYN packets (connection attempts)
        if not (tcp_layer.flags & 0x02):  # SYN flag
            return None

        brute_force_config = self.config['thresholds'].get('brute_force', {})
        if not brute_force_config.get('enabled', True):
            return None

        attempts_threshold = brute_force_config.get('attempts_threshold', 5)
        time_window = brute_force_config.get('time_window', 300)

        # Track connection attempts
        current_time = time.time()
        tracker_key = (src_ip, dst_ip, dst_port)
        attempts = self.brute_force_tracker[tracker_key]
        attempts.append(current_time)

        # Count attempts in time window
        cutoff_time = current_time - time_window
        recent_attempts = sum(1 for ts in attempts if ts > cutoff_time)

        if recent_attempts >= attempts_threshold:
            protocol = auth_ports[dst_port]

            return {
                'type': 'BRUTE_FORCE_ATTEMPT',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'description': f'Mogelijke brute force aanval op {protocol}: {recent_attempts} pogingen in {time_window//60} minuten',
                'attempts': recent_attempts,
                'protocol': protocol,
                'time_window': time_window,
                'metadata': json.dumps({
                    'attempts': recent_attempts,
                    'protocol': protocol,
                    'port': dst_port
                })
            }

        return None

    def _detect_protocol_mismatch(self, packet):
        """
        Detecteer protocol verkeer op ongebruikelijke poorten

        Voorbeelden:
        - HTTP verkeer op niet-standaard poorten
        - SSH verkeer op andere poorten dan 22
        - DNS verkeer op andere poorten dan 53
        """
        threats = []

        if not packet.haslayer(TCP):
            return threats

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport
        src_port = tcp_layer.sport

        # HTTP/HTTPS detection on non-standard ports
        if packet.haslayer(HTTPRequest):
            standard_http_ports = {80, 443, 8080, 8443}
            if dst_port not in standard_http_ports:
                threats.append({
                    'type': 'HTTP_NON_STANDARD_PORT',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'description': f'HTTP verkeer gedetecteerd op ongebruikelijke poort: {dst_port}',
                    'expected_ports': list(standard_http_ports),
                    'actual_port': dst_port
                })

        # SSH pattern detection (based on packet characteristics)
        # SSH typically has specific patterns in initial handshake
        if packet.haslayer(Raw) and dst_port != 22:
            try:
                payload = packet[Raw].load
                # SSH banner starts with "SSH-"
                if payload.startswith(b'SSH-'):
                    threats.append({
                        'type': 'SSH_NON_STANDARD_PORT',
                        'severity': 'MEDIUM',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'destination_port': dst_port,
                        'description': f'SSH verkeer gedetecteerd op ongebruikelijke poort: {dst_port}',
                        'expected_port': 22,
                        'actual_port': dst_port
                    })
            except Exception:
                pass

        # Check for DNS traffic on non-standard ports
        if packet.haslayer(DNS):
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                if udp_layer.dport != 53 and udp_layer.sport != 53:
                    threats.append({
                        'type': 'DNS_NON_STANDARD_PORT',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'destination_port': udp_layer.dport,
                        'description': f'DNS verkeer gedetecteerd op ongebruikelijke poort: {udp_layer.dport} (mogelijk DNS tunneling)',
                        'expected_port': 53,
                        'actual_port': udp_layer.dport
                    })

        # Check for FTP on non-standard ports
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                # FTP commands (USER, PASS, etc.)
                if any(payload.startswith(cmd) for cmd in [b'USER ', b'PASS ', b'220 ', b'331 ']):
                    if dst_port not in {20, 21} and src_port not in {20, 21}:
                        threats.append({
                            'type': 'FTP_NON_STANDARD_PORT',
                            'severity': 'MEDIUM',
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'destination_port': dst_port,
                            'description': f'FTP verkeer gedetecteerd op ongebruikelijke poort: {dst_port}',
                            'expected_ports': [20, 21],
                            'actual_port': dst_port
                        })
            except Exception:
                pass

        return threats

    def cleanup_old_data(self):
        """Cleanup oude tracking data (call periodiek)"""
        current_time = time.time()

        # Cleanup port scan tracker
        for ip in list(self.port_scan_tracker.keys()):
            tracker = self.port_scan_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 300:  # 5 minuten
                del self.port_scan_tracker[ip]

        # Cleanup SMTP/FTP tracker
        for key in list(self.smtp_ftp_tracker.keys()):
            tracker = self.smtp_ftp_tracker[key]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 600:  # 10 minuten
                del self.smtp_ftp_tracker[key]

        # Cleanup brute force tracker (keep last 10 minutes of attempts)
        for key in list(self.brute_force_tracker.keys()):
            attempts = self.brute_force_tracker[key]
            cutoff_time = current_time - 600  # 10 minutes
            # Remove old attempts
            while attempts and attempts[0] < cutoff_time:
                attempts.popleft()
            # Remove empty trackers
            if not attempts:
                del self.brute_force_tracker[key]

        self.logger.debug("Oude tracking data opgeschoond")
