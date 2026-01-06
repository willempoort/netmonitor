# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
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

# Import behavior matcher for template-based alert suppression
try:
    from behavior_matcher import BehaviorMatcher
except ImportError:
    BehaviorMatcher = None

# Import TLS analyzer for JA3 fingerprinting and metadata extraction
try:
    from tls_analyzer import TLSAnalyzer, detect_tls_anomalies
except ImportError:
    TLSAnalyzer = None
    detect_tls_anomalies = None

# Import Kerberos analyzer for AD attack detection
try:
    from kerberos_analyzer import KerberosAnalyzer
except ImportError:
    KerberosAnalyzer = None

# Import Kill Chain detector for multi-stage attack correlation
try:
    from kill_chain_detector import KillChainDetector
except ImportError:
    KillChainDetector = None

# Import Protocol Parser for SMB/LDAP deep inspection
try:
    from protocol_parser import ProtocolParser
except ImportError:
    ProtocolParser = None

# Import Enhanced Encrypted Traffic Analyzer
try:
    from encrypted_traffic_analyzer import EncryptedTrafficAnalyzer
except ImportError:
    EncryptedTrafficAnalyzer = None


class ThreatDetector:
    """Detecteert verschillende soorten verdacht netwerkverkeer"""

    def __init__(self, config, threat_feed_manager=None, behavior_detector=None, abuseipdb_client=None, db_manager=None, sensor_id=None, behavior_matcher=None):
        self.config = config
        self.logger = logging.getLogger('NetMonitor.Detector')

        # External components
        self.threat_feeds = threat_feed_manager
        self.behavior_detector = behavior_detector
        self.abuseipdb = abuseipdb_client
        self.db_manager = db_manager  # Optional: for database whitelist checks
        self.sensor_id = sensor_id     # Optional: for sensor-specific whitelists

        # Initialize behavior matcher for template-based alert suppression
        self.behavior_matcher = behavior_matcher
        if not self.behavior_matcher and BehaviorMatcher and db_manager:
            try:
                self.behavior_matcher = BehaviorMatcher(db_manager=db_manager, config=config)
                self.logger.info("BehaviorMatcher initialized for template-based alert suppression")
            except Exception as e:
                self.logger.warning(f"Could not initialize BehaviorMatcher: {e}")

        # Initialize TLS analyzer for JA3 fingerprinting
        self.tls_analyzer = None
        if TLSAnalyzer and config.get('thresholds', {}).get('tls_analysis', {}).get('enabled', True):
            try:
                self.tls_analyzer = TLSAnalyzer(config)
                self.logger.info("TLSAnalyzer initialized for JA3 fingerprinting and metadata extraction")
            except Exception as e:
                self.logger.warning(f"Could not initialize TLSAnalyzer: {e}")

        # Initialize Kerberos analyzer for AD attack detection
        self.kerberos_analyzer = None
        if KerberosAnalyzer and config.get('thresholds', {}).get('kerberos', {}).get('enabled', True):
            try:
                self.kerberos_analyzer = KerberosAnalyzer(config, db_manager=db_manager)
                self.logger.info("KerberosAnalyzer initialized for AD attack detection")
            except Exception as e:
                self.logger.warning(f"Could not initialize KerberosAnalyzer: {e}")

        # Initialize Kill Chain detector for multi-stage attack correlation
        self.kill_chain_detector = None
        if KillChainDetector and config.get('thresholds', {}).get('kill_chain', {}).get('enabled', True):
            try:
                self.kill_chain_detector = KillChainDetector(config, db_manager=db_manager)
                self.logger.info("KillChainDetector initialized for multi-stage attack correlation")
            except Exception as e:
                self.logger.warning(f"Could not initialize KillChainDetector: {e}")

        # Initialize Protocol Parser for SMB/LDAP deep inspection
        self.protocol_parser = None
        if ProtocolParser and config.get('thresholds', {}).get('protocol_parsing', {}).get('enabled', True):
            try:
                self.protocol_parser = ProtocolParser(config, db_manager=db_manager)
                self.logger.info("ProtocolParser initialized for SMB/LDAP deep inspection")
            except Exception as e:
                self.logger.warning(f"Could not initialize ProtocolParser: {e}")

        # Initialize Enhanced Encrypted Traffic Analyzer
        self.encrypted_traffic_analyzer = None
        if EncryptedTrafficAnalyzer and config.get('thresholds', {}).get('encrypted_traffic', {}).get('enabled', True):
            try:
                self.encrypted_traffic_analyzer = EncryptedTrafficAnalyzer(config, db_manager=db_manager)
                self.logger.info("EncryptedTrafficAnalyzer initialized for advanced TLS analysis")
            except Exception as e:
                self.logger.warning(f"Could not initialize EncryptedTrafficAnalyzer: {e}")

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

        # TLS metadata tracker - stores recent TLS handshake data
        # Key: (src_ip, dst_ip, dst_port), Value: TLS metadata dict
        self.tls_metadata_cache = defaultdict(dict)
        self.tls_metadata_history = deque(maxlen=1000)  # Recent TLS connections

        # Advanced threat detection trackers
        self.cryptomining_tracker = defaultdict(lambda: {
            'connections': set(),  # Set of (dst_ip, dst_port)
            'first_seen': None,
            'last_seen': None
        })
        self.dns_query_tracker = defaultdict(lambda: {
            'queries': deque(maxlen=200),  # Recent queries
            'unique_domains': set(),
            'window_start': None
        })

        # Phase 2: Web Application Security trackers
        self.sqli_tracker = defaultdict(lambda: {
            'attempts': deque(maxlen=100),  # Recent SQLi attempts with timestamps
            'first_seen': None,
            'last_seen': None,
            'payloads': set()  # Unique payloads seen
        })
        self.xss_tracker = defaultdict(lambda: {
            'attempts': deque(maxlen=100),
            'first_seen': None,
            'last_seen': None,
            'payloads': set()
        })
        self.command_injection_tracker = defaultdict(lambda: {
            'attempts': deque(maxlen=100),
            'first_seen': None,
            'last_seen': None,
            'payloads': set()
        })
        self.path_traversal_tracker = defaultdict(lambda: {
            'attempts': deque(maxlen=100),
            'first_seen': None,
            'last_seen': None,
            'paths': set()
        })
        self.api_abuse_tracker = defaultdict(lambda: {
            'requests': deque(maxlen=500),  # Track API calls per IP
            'endpoints': defaultdict(int),  # Count per endpoint
            'window_start': None
        })

        # Phase 3: DDoS & Resource Exhaustion trackers
        self.syn_flood_tracker = defaultdict(lambda: {
            'syn_count': 0,
            'ack_count': 0,
            'window_start': None,
            'ports': set()
        })
        self.udp_flood_tracker = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'window_start': None,
            'ports': set()
        })
        self.http_flood_tracker = defaultdict(lambda: {
            'request_count': 0,
            'window_start': None,
            'paths': set()
        })
        self.slowloris_tracker = defaultdict(lambda: {
            'connections': defaultdict(int),  # dst_ip -> count
            'incomplete_requests': 0,
            'last_seen': None
        })
        self.amplification_tracker = defaultdict(lambda: {
            'queries_sent': 0,
            'responses_received': 0,
            'amplification_factor': 0,
            'window_start': None
        })
        self.connection_exhaustion_tracker = defaultdict(lambda: {
            'connections': set(),  # Set of (src_ip, dst_ip, dst_port)
            'count': 0,
            'window_start': None
        })
        self.bandwidth_saturation_tracker = defaultdict(lambda: {
            'bytes_sent': 0,
            'packets_sent': 0,
            'window_start': None
        })

        # Phase 4: Ransomware Indicators trackers
        self.smb_encryption_tracker = defaultdict(lambda: {
            'file_operations': deque(maxlen=100),
            'unique_files': set(),
            'window_start': None
        })
        self.crypto_extension_tracker = defaultdict(lambda: {
            'suspicious_extensions': set(),
            'file_count': 0,
            'first_seen': None
        })
        self.ransom_note_tracker = defaultdict(lambda: {
            'txt_files_created': 0,
            'html_files_created': 0,
            'window_start': None
        })
        self.shadow_copy_tracker = defaultdict(lambda: {
            'deletion_attempts': 0,
            'first_seen': None
        })

        # Phase 5: IoT & Smart Device trackers
        self.iot_botnet_tracker = defaultdict(lambda: {
            'mirai_signatures': 0,
            'telnet_attempts': 0,
            'default_creds': 0,
            'first_seen': None
        })
        self.upnp_exploit_tracker = defaultdict(lambda: {
            'ssdp_requests': 0,
            'suspicious_commands': set(),
            'window_start': None
        })
        self.mqtt_abuse_tracker = defaultdict(lambda: {
            'publish_count': 0,
            'subscribe_count': 0,
            'topics': set(),
            'window_start': None
        })
        self.smart_home_tracker = defaultdict(lambda: {
            'zigbee_packets': 0,
            'zwave_packets': 0,
            'suspicious_commands': set(),
            'window_start': None
        })

        # Phase 6: OT/ICS Protocol trackers
        self.modbus_tracker = defaultdict(lambda: {
            'function_codes': defaultdict(int),
            'write_operations': 0,
            'window_start': None
        })
        self.dnp3_tracker = defaultdict(lambda: {
            'commands': defaultdict(int),
            'suspicious_operations': 0,
            'window_start': None
        })
        self.iec104_tracker = defaultdict(lambda: {
            'control_commands': 0,
            'setpoint_changes': 0,
            'window_start': None
        })

        # Phase 7: Container & Orchestration trackers
        self.docker_escape_tracker = defaultdict(lambda: {
            'privileged_operations': 0,
            'mount_attempts': 0,
            'first_seen': None
        })
        self.k8s_exploit_tracker = defaultdict(lambda: {
            'api_calls': defaultdict(int),
            'suspicious_endpoints': set(),
            'window_start': None
        })

        # Phase 8: Advanced Evasion trackers
        self.fragmentation_tracker = defaultdict(lambda: {
            'fragments': deque(maxlen=100),
            'overlapping_count': 0,
            'window_start': None
        })
        self.tunneling_tracker = defaultdict(lambda: {
            'protocols': set(),  # DNS, ICMP, etc.
            'payload_size': 0,
            'packet_count': 0,
            'window_start': None
        })
        self.polymorphic_tracker = defaultdict(lambda: {
            'pattern_changes': 0,
            'signatures': set(),
            'first_seen': None
        })

        # Phase 9: Completion Boost trackers
        self.lateral_movement_tracker = defaultdict(lambda: {
            'smb_connections': set(),
            'rdp_attempts': 0,
            'psexec_patterns': 0,
            'window_start': None
        })
        self.data_exfil_tracker = defaultdict(lambda: {
            'outbound_bytes': 0,
            'destinations': set(),
            'protocols': set(),
            'window_start': None
        })
        self.privilege_escalation_tracker = defaultdict(lambda: {
            'sudo_attempts': 0,
            'uac_bypass': 0,
            'kernel_exploits': 0,
            'first_seen': None
        })
        self.persistence_tracker = defaultdict(lambda: {
            'registry_modifications': 0,
            'scheduled_tasks': 0,
            'startup_items': 0,
            'first_seen': None
        })
        self.credential_dumping_tracker = defaultdict(lambda: {
            'lsass_access': 0,
            'sam_access': 0,
            'mimikatz_patterns': 0,
            'first_seen': None
        })

        # Parsed whitelist/blacklist from config
        # Defensive check: ensure they are lists
        whitelist_raw = config.get('whitelist', [])
        blacklist_raw = config.get('blacklist', [])

        if not isinstance(whitelist_raw, list):
            self.logger.warning(f"whitelist is not a list (got {type(whitelist_raw).__name__}), using empty list")
            whitelist_raw = []

        if not isinstance(blacklist_raw, list):
            self.logger.warning(f"blacklist is not a list (got {type(blacklist_raw).__name__}), using empty list")
            blacklist_raw = []

        self.config_whitelist = self._parse_ip_list(whitelist_raw)
        self.blacklist = self._parse_ip_list(blacklist_raw)

        # Parse modern protocol ranges (streaming services, CDN providers)
        modern_protocols = config.get('thresholds', {}).get('modern_protocols', {})

        # Defensieve check: zorg dat het lijsten zijn
        streaming_list = modern_protocols.get('streaming_services', [])
        cdn_list = modern_protocols.get('cdn_providers', [])

        if not isinstance(streaming_list, list):
            self.logger.warning(f"streaming_services is not a list (got {type(streaming_list).__name__}), using empty list")
            streaming_list = []

        if not isinstance(cdn_list, list):
            self.logger.warning(f"cdn_providers is not a list (got {type(cdn_list).__name__}), using empty list")
            cdn_list = []

        self.streaming_services = self._parse_ip_list(streaming_list)
        self.cdn_providers = self._parse_ip_list(cdn_list)

        # Initialize content analyzer if available
        self.content_analyzer = ContentAnalyzer() if ContentAnalyzer else None

        self.logger.info("Threat Detector geïnitialiseerd")
        self.logger.info(f"Streaming services whitelist: {len(self.streaming_services)} ranges")
        self.logger.info(f"CDN providers whitelist: {len(self.cdn_providers)} ranges")

    def _get_threshold(self, *keys, default=None):
        """
        Safely get a threshold value from config with fallback to default.
        Usage: self._get_threshold('dns_tunnel', 'query_length_threshold', default=50)
        """
        try:
            value = self.config['thresholds']
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            if default is not None:
                return default
            # Log warning if no default provided
            key_path = '.'.join(keys)
            self.logger.warning(f"Config key 'thresholds.{key_path}' not found and no default provided")
            return None

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

    def _is_whitelisted(self, ip_str, direction: str = None):
        """Check if IP is whitelisted (config OR database)

        Args:
            ip_str: IP address to check
            direction: 'source', 'destination', or None for legacy/both

        Direction semantics:
            - 'source': Whitelist when this IP is the SOURCE of traffic
            - 'destination': Whitelist when this IP is the DESTINATION of traffic
            - 'both': Whitelist in either direction
        """
        # First check config whitelist (fast, in-memory, no direction support)
        if self._is_in_list(ip_str, self.config_whitelist):
            self.logger.debug(f"IP {ip_str} whitelisted via config")
            return True

        # Then check database whitelist (if available) with direction support
        if self.db_manager:
            try:
                if self.db_manager.check_ip_whitelisted(ip_str, sensor_id=self.sensor_id, direction=direction):
                    self.logger.debug(f"IP {ip_str} whitelisted via database (sensor_id={self.sensor_id}, direction={direction})")
                    return True
            except Exception as e:
                self.logger.warning(f"Error checking database whitelist for {ip_str}: {e}")

        return False

    def _is_src_whitelisted(self, src_ip: str) -> bool:
        """Check if source IP is whitelisted (traffic FROM this IP)"""
        return self._is_whitelisted(src_ip, direction='source')

    def _is_dst_whitelisted(self, dst_ip: str) -> bool:
        """Check if destination IP is whitelisted (traffic TO this IP)"""
        return self._is_whitelisted(dst_ip, direction='destination')

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

        # Skip whitelisted IPs based on direction setting
        # Source whitelist: Skip if source IP is whitelisted with direction='source' or 'both'
        # Destination whitelist: Skip if destination IP is whitelisted with direction='destination' or 'both'
        # This enables whitelisting multicast addresses (224.0.0.0/4), trusted servers, etc.
        if self._is_src_whitelisted(src_ip):
            return threats
        if self._is_dst_whitelisted(dst_ip):
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
        if self._get_threshold('port_scan', 'enabled', default=True):
            threat = self._detect_port_scan(packet)
            if threat:
                threats.append(threat)

        # Connection flood detection
        if self._get_threshold('connection_flood', 'enabled', default=True):
            threat = self._detect_connection_flood(packet)
            if threat:
                threats.append(threat)

        # Unusual packet size detection
        if self._get_threshold('packet_size', 'enabled', default=True):
            threat = self._detect_unusual_packet_size(packet)
            if threat:
                threats.append(threat)

        # DNS tunneling detection (enhanced with content analysis)
        if self._get_threshold('dns_tunnel', 'enabled', default=True):
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

        # QUIC/HTTP3 detection (informational, not a threat)
        modern_protocols_config = self.config['thresholds'].get('modern_protocols', {})
        if modern_protocols_config.get('quic_detection', True):
            self._detect_quic(packet)  # Logs but doesn't alert

        # Protocol mismatch detection
        if self.config['thresholds'].get('protocol_mismatch', {}).get('enabled', True):
            protocol_threats = self._detect_protocol_mismatch(packet)
            threats.extend(protocol_threats)

        # TLS analysis (JA3 fingerprinting, certificate validation, anomaly detection)
        if self.tls_analyzer:
            tls_threats = self._detect_tls_threats(packet)
            threats.extend(tls_threats)

        # Behavior-based detection (beaconing, lateral movement, etc.)
        if self.behavior_detector:
            behavior_threats = self.behavior_detector.analyze_packet(packet)
            threats.extend(behavior_threats)

        # Kerberos/AD attack detection
        if self.kerberos_analyzer:
            kerberos_threats = self.kerberos_analyzer.analyze_packet(packet)
            threats.extend(kerberos_threats)

        # SMB/LDAP deep protocol parsing
        if self.protocol_parser:
            protocol_threats = self.protocol_parser.analyze_packet(packet)
            threats.extend(protocol_threats)

        # Enhanced encrypted traffic analysis (ESNI/ECH, domain fronting, cert analysis)
        if self.encrypted_traffic_analyzer:
            encrypted_threats = self.encrypted_traffic_analyzer.analyze_packet(packet)
            threats.extend(encrypted_threats)

        # Advanced threat detection (cryptomining, phishing, Tor, cloud metadata, DNS anomaly)
        advanced_threats = self._detect_advanced_threats(packet)
        threats.extend(advanced_threats)

        # Apply template-based alert suppression
        # This filters out alerts for expected device behavior
        if threats and self.behavior_matcher:
            threats = self.behavior_matcher.filter_threats(threats, packet)
            # Return only non-suppressed threats (suppressed ones are logged)
            threats = self.behavior_matcher.get_active_threats(threats)

        # Kill chain / multi-stage attack correlation
        # Process each threat through the kill chain detector
        if self.kill_chain_detector and threats:
            chain_alerts = []
            for threat in threats:
                chain_result = self.kill_chain_detector.process_alert(threat)
                chain_alerts.extend(chain_result)
            # Add chain-level alerts to the threat list
            threats.extend(chain_alerts)

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
        time_window = self._get_threshold('port_scan', 'time_window', default=60)
        if tracker['first_seen'] and \
           (current_time - tracker['first_seen']) > time_window:
            tracker['ports'].clear()
            tracker['first_seen'] = current_time

        if not tracker['first_seen']:
            tracker['first_seen'] = current_time

        tracker['ports'].add(dst_port)
        tracker['last_seen'] = current_time

        # Check threshold
        threshold = self._get_threshold('port_scan', 'unique_ports', default=20)
        if threshold and len(tracker['ports']) >= threshold:
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
                'description': f'Mogelijk port scan gedetecteerd: {ports_found} unieke poorten binnen {time_window}s',
                'ports_scanned': ports_found,
                'metadata': json.dumps({
                    'ports': scanned_ports,
                    'port_count': ports_found,
                    'time_window': time_window
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
        time_window = self._get_threshold('connection_flood', 'time_window', default=10)
        cutoff_time = current_time - time_window

        # Count recente connecties
        recent_connections = sum(1 for ts in connections if ts > cutoff_time)

        connections_per_second = self._get_threshold('connection_flood', 'connections_per_second', default=100)
        threshold = connections_per_second * time_window if connections_per_second else None

        if threshold and recent_connections > threshold:
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
        threshold = self._get_threshold('packet_size', 'min_suspicious_size', default=1400)

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
        query_length_threshold = self._get_threshold('dns_tunnel', 'query_length_threshold', default=50)
        if query_length_threshold and len(query) > query_length_threshold:
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

        queries_threshold = self._get_threshold('dns_tunnel', 'queries_per_minute', default=150)
        if queries_threshold and recent_queries > queries_threshold:
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

    def _detect_quic(self, packet):
        """
        Detect QUIC (HTTP/3) protocol traffic

        QUIC uses UDP on ports 443 (most common) and 80.
        This is modern HTTP/3 traffic from browsers and apps.
        Does not generate alerts - only logs for visibility.

        QUIC characteristics:
        - UDP protocol
        - Typically port 443 (sometimes 80)
        - Initial packet has specific QUIC version negotiation bits
        """
        if not packet.haslayer(UDP):
            return None

        udp_layer = packet[UDP]
        dst_port = udp_layer.dport
        src_port = udp_layer.sport

        # QUIC commonly uses UDP port 443, sometimes 80
        if dst_port not in [443, 80] and src_port not in [443, 80]:
            return None

        # Check if packet has payload (QUIC packets have data)
        if not hasattr(packet, 'load') or len(packet.load) < 5:
            return None

        # QUIC initial packets start with specific flags
        # Long header: bit 0x80 set, version field follows
        try:
            first_byte = packet.load[0]
            # Long header (0x80 bit set) indicates QUIC
            if first_byte & 0x80:
                # This looks like QUIC traffic
                self.logger.debug(f"QUIC/HTTP3 traffic detected: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}")
                return True
        except:
            pass

        return None

    def _is_streaming_or_cdn(self, ip_address):
        """
        Check if IP belongs to known streaming service or CDN provider

        Args:
            ip_address: IP address to check

        Returns:
            tuple: (is_match, service_type) where service_type is 'streaming', 'cdn', or None
        """
        # Check streaming services
        for ip_network in self.streaming_services:
            try:
                if ipaddress.ip_address(ip_address) in ip_network:
                    return (True, 'streaming')
            except:
                pass

        # Check CDN providers
        for ip_network in self.cdn_providers:
            try:
                if ipaddress.ip_address(ip_address) in ip_network:
                    return (True, 'cdn')
            except:
                pass

        return (False, None)

    def _detect_brute_force(self, packet):
        """
        Detecteer brute force aanvallen op authenticatie services

        Detecteert herhaalde connection attempts naar:
        - SSH (22), Telnet (23), FTP (21), RDP (3389)
        - HTTP Auth (80, 443, 8080), SMB (445), MySQL (3306), PostgreSQL (5432)

        Excludes false positives from:
        - Known streaming services (Netflix, YouTube, Prime Video)
        - CDN providers (Cloudflare, Akamai)
        - QUIC/HTTP3 traffic (many parallel connections are normal)
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

        # Check if we should exclude streaming services and CDN providers
        exclude_streaming = brute_force_config.get('exclude_streaming', True)
        exclude_cdn = brute_force_config.get('exclude_cdn', True)

        # Skip detection for HTTP/HTTPS if destination is streaming service or CDN
        if dst_port in [80, 443, 8080]:
            is_match, service_type = self._is_streaming_or_cdn(dst_ip)
            if is_match:
                if (service_type == 'streaming' and exclude_streaming) or \
                   (service_type == 'cdn' and exclude_cdn):
                    self.logger.debug(f"Brute force detection skipped for {dst_ip} ({service_type} service)")
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
        # Only alert if SSH traffic is on non-standard ports (both src and dst must not be 22)
        # If either port is 22, it's normal SSH (even if the other port is ephemeral)
        if packet.haslayer(Raw) and dst_port != 22 and src_port != 22:
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

    def _detect_tls_threats(self, packet):
        """
        Analyze TLS handshakes for security threats.

        Detects:
        - Known malicious JA3 fingerprints (malware, C2 frameworks)
        - Weak cipher suites
        - Deprecated TLS versions
        - Expired certificates
        - Missing SNI (potential C2)
        """
        threats = []

        if not self.tls_analyzer:
            return threats

        # Analyze TLS handshake
        tls_metadata = self.tls_analyzer.analyze_packet(packet)
        if not tls_metadata:
            return threats

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Store metadata for MCP access
        conn_key = (src_ip, dst_ip, tls_metadata.get('dst_port'))
        self.tls_metadata_cache[conn_key].update(tls_metadata)
        self.tls_metadata_history.append(tls_metadata)

        # Check for known malicious JA3 fingerprint
        if tls_metadata.get('malicious'):
            threats.append({
                'type': 'MALICIOUS_JA3_FINGERPRINT',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': tls_metadata.get('dst_port'),
                'description': f'Bekende malware TLS fingerprint gedetecteerd: {tls_metadata.get("malware_family", "Unknown")}',
                'ja3': tls_metadata.get('ja3'),
                'malware_family': tls_metadata.get('malware_family'),
                'sni': tls_metadata.get('sni'),
                'metadata': json.dumps({
                    'ja3': tls_metadata.get('ja3'),
                    'ja3_string': tls_metadata.get('ja3_string'),
                    'malware_family': tls_metadata.get('malware_family'),
                    'sni': tls_metadata.get('sni'),
                    'tls_version': tls_metadata.get('tls_version'),
                })
            })

        # Run anomaly detection if available
        if detect_tls_anomalies:
            anomalies = detect_tls_anomalies(tls_metadata)
            for anomaly in anomalies:
                threats.append({
                    'type': f'TLS_{anomaly["type"]}',
                    'severity': anomaly['severity'],
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': tls_metadata.get('dst_port'),
                    'description': anomaly['description'],
                    'sni': tls_metadata.get('sni'),
                    'metadata': json.dumps({
                        'anomaly_type': anomaly['type'],
                        'tls_version': tls_metadata.get('tls_version'),
                        'ja3': tls_metadata.get('ja3'),
                        'sni': tls_metadata.get('sni'),
                        **{k: v for k, v in anomaly.items() if k not in ['type', 'severity', 'description']}
                    })
                })

        return threats

    def get_tls_metadata(self, limit: int = 100) -> list:
        """
        Get recent TLS metadata for MCP access.

        Returns list of TLS handshake metadata dicts.
        """
        return list(self.tls_metadata_history)[-limit:]

    def get_tls_stats(self) -> dict:
        """Get TLS analyzer statistics."""
        if self.tls_analyzer:
            return self.tls_analyzer.get_stats()
        return {}

    def _detect_advanced_threats(self, packet):
        """
        Detect advanced threats using database-backed threat feeds
        Includes: cryptomining, phishing, Tor, VPN, cloud metadata, DNS anomaly
        """
        threats = []

        if not packet.haslayer(IP):
            return threats

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Get configuration from database (cached during init or periodically synced)
        # For now, use self.config as fallback until sensor config sync is implemented
        advanced_config = self.config.get('thresholds', {}).get('advanced_threats', {})
        master_enabled = advanced_config.get('enabled', False)

        if not master_enabled or not self.db_manager:
            return threats

        # Cryptomining detection (Stratum protocol on specific ports)
        threat = self._detect_cryptomining(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Phishing domain detection (DNS queries + connections)
        phishing_threats = self._detect_phishing(packet, src_ip, dst_ip)
        threats.extend(phishing_threats)

        # Tor exit node detection
        threat = self._detect_tor_connection(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Cloud metadata access (AWS/Azure/GCP IMDS)
        threat = self._detect_cloud_metadata_access(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # DNS anomaly detection (high query rate)
        threat = self._detect_dns_anomaly(packet, src_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 2: Web Application Security =====

        # SQL Injection detection
        threat = self._detect_sql_injection(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # XSS detection
        threat = self._detect_xss(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Command Injection detection
        threat = self._detect_command_injection(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Path Traversal detection
        threat = self._detect_path_traversal(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # XXE detection
        threat = self._detect_xxe(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # SSRF detection (extended)
        ssrf_threats = self._detect_ssrf_extended(packet, src_ip, dst_ip)
        threats.extend(ssrf_threats)

        # WebShell detection
        threat = self._detect_webshell(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # API Abuse detection
        threat = self._detect_api_abuse(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 3: DDoS & Resource Exhaustion =====

        # SYN flood detection
        threat = self._detect_syn_flood(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # UDP flood detection
        threat = self._detect_udp_flood(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # HTTP flood detection
        threat = self._detect_http_flood(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Slowloris detection
        threat = self._detect_slowloris(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # DNS amplification detection
        threat = self._detect_dns_amplification(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Connection exhaustion detection
        threat = self._detect_connection_exhaustion(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Bandwidth saturation detection
        threat = self._detect_bandwidth_saturation(packet, src_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 4: Ransomware Indicators =====

        # SMB mass encryption detection
        threat = self._detect_smb_mass_encryption(packet, src_ip)
        if threat:
            threats.append(threat)

        # Crypto extension detection
        threat = self._detect_crypto_extension(packet, src_ip)
        if threat:
            threats.append(threat)

        # Ransom note detection
        threat = self._detect_ransom_note(packet, src_ip)
        if threat:
            threats.append(threat)

        # Shadow copy deletion detection
        threat = self._detect_shadow_copy_deletion(packet, src_ip)
        if threat:
            threats.append(threat)

        # Backup deletion detection
        threat = self._detect_backup_deletion(packet, src_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 5: IoT & Smart Device Security =====

        # IoT botnet detection
        threat = self._detect_iot_botnet(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # UPnP exploit detection
        threat = self._detect_upnp_exploit(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # MQTT abuse detection
        threat = self._detect_mqtt_abuse(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 6: OT/ICS Protocol Security =====

        # Modbus attack detection
        threat = self._detect_modbus_attack(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # DNP3 attack detection
        threat = self._detect_dnp3_attack(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # IEC-104 attack detection
        threat = self._detect_iec104_attack(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 7: Container & Orchestration =====

        # Docker escape detection
        threat = self._detect_docker_escape(packet, src_ip)
        if threat:
            threats.append(threat)

        # Kubernetes API exploit detection
        threat = self._detect_k8s_exploit(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 8: Advanced Evasion =====

        # IP fragmentation attack detection
        threat = self._detect_fragmentation_attack(packet, src_ip)
        if threat:
            threats.append(threat)

        # Protocol tunneling detection
        threat = self._detect_tunneling(packet, src_ip)
        if threat:
            threats.append(threat)

        # Polymorphic malware detection
        threat = self._detect_polymorphic_malware(packet, src_ip)
        if threat:
            threats.append(threat)

        # DGA detection
        threat = self._detect_dga(packet, src_ip)
        if threat:
            threats.append(threat)

        # ===== Phase 9: Completion Boost =====

        # Lateral movement detection
        threat = self._detect_lateral_movement(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Data exfiltration detection
        threat = self._detect_data_exfiltration(packet, src_ip, dst_ip)
        if threat:
            threats.append(threat)

        # Privilege escalation detection
        threat = self._detect_privilege_escalation(packet, src_ip)
        if threat:
            threats.append(threat)

        # Persistence mechanism detection
        threat = self._detect_persistence(packet, src_ip)
        if threat:
            threats.append(threat)

        # Credential dumping detection
        threat = self._detect_credential_dumping(packet, src_ip)
        if threat:
            threats.append(threat)

        return threats

    def _detect_cryptomining(self, packet, src_ip, dst_ip):
        """Detect cryptomining via Stratum protocol on common mining ports"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        dst_port = tcp_layer.dport

        # Common mining pool ports (from database config, fallback to defaults)
        stratum_ports = [3333, 4444, 8333, 9999, 14444, 45560]

        if dst_port not in stratum_ports:
            return None

        # Track connections per source IP
        tracker = self.cryptomining_tracker[src_ip]
        current_time = time.time()

        if tracker['first_seen'] is None:
            tracker['first_seen'] = current_time

        tracker['last_seen'] = current_time
        tracker['connections'].add((dst_ip, dst_port))

        # Alert if multiple connections to mining ports (min_connections threshold)
        min_connections = 3
        if len(tracker['connections']) >= min_connections:
            return {
                'type': 'CRYPTOMINING_DETECTED',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Mogelijk cryptomining: {len(tracker["connections"])} verbindingen naar Stratum poorten',
                'metadata': {
                    'dst_port': dst_port,
                    'connection_count': len(tracker['connections']),
                    'protocol': 'Stratum'
                }
            }

        return None

    def _detect_phishing(self, packet, src_ip, dst_ip):
        """Detect phishing domains via DNS queries and direct connections"""
        threats = []

        # Check DNS queries for phishing domains
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Query
            dnsqr = packet[DNS].qd
            if dnsqr:
                domain = dnsqr.qname.decode('utf-8', errors='ignore').rstrip('.')

                # Check against threat feed database
                match = self.db_manager.check_threat_indicator(
                    indicator=domain,
                    feed_types=['phishing']
                )

                if match:
                    threats.append({
                        'type': 'PHISHING_DOMAIN_QUERY',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'DNS query naar bekende phishing domain: {domain}',
                        'metadata': {
                            'domain': domain,
                            'feed_source': match.get('source'),
                            'confidence': match.get('confidence_score')
                        }
                    })

        return threats

    def _detect_tor_connection(self, packet, src_ip, dst_ip):
        """Detect connections to Tor exit nodes"""
        if not packet.haslayer(TCP):
            return None

        # Check destination IP against Tor exit node feed
        match = self.db_manager.check_ip_in_threat_feeds(
            ip_address=dst_ip,
            feed_types=['tor_exit']
        )

        if match:
            return {
                'type': 'TOR_EXIT_NODE_CONNECTION',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Verbinding naar Tor exit node: {dst_ip}',
                'metadata': {
                    'feed_source': match.get('source'),
                    'confidence': match.get('confidence_score')
                }
            }

        return None

    def _detect_cloud_metadata_access(self, packet, src_ip, dst_ip):
        """Detect access to cloud metadata endpoints (AWS/Azure/GCP IMDS/SSRF)"""
        # AWS/Azure metadata IP
        if dst_ip == '169.254.169.254':
            if packet.haslayer(TCP) or packet.haslayer(HTTP):
                return {
                    'type': 'CLOUD_METADATA_ACCESS',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'Toegang tot cloud metadata endpoint (AWS/Azure IMDS): {src_ip} -> {dst_ip}',
                    'metadata': {
                        'service': 'AWS/Azure',
                        'endpoint': '169.254.169.254',
                        'risk': 'Mogelijk SSRF of credential theft'
                    }
                }

        # GCP metadata (via DNS check)
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            dnsqr = packet[DNS].qd
            if dnsqr:
                domain = dnsqr.qname.decode('utf-8', errors='ignore').rstrip('.')
                if domain == 'metadata.google.internal':
                    return {
                        'type': 'CLOUD_METADATA_ACCESS',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'DNS query naar GCP metadata endpoint: {domain}',
                        'metadata': {
                            'service': 'GCP',
                            'endpoint': domain,
                            'risk': 'Mogelijk SSRF of credential theft'
                        }
                    }

        return None

    def _detect_dns_anomaly(self, packet, src_ip):
        """Detect suspicious DNS query rates (possible DNS tunneling or DGA)"""
        if not packet.haslayer(DNS) or packet[DNS].qr != 0:  # Only queries
            return None

        dnsqr = packet[DNS].qd
        if not dnsqr:
            return None

        domain = dnsqr.qname.decode('utf-8', errors='ignore').rstrip('.')
        tracker = self.dns_query_tracker[src_ip]
        current_time = time.time()

        # Initialize window
        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Add query
        tracker['queries'].append(current_time)
        tracker['unique_domains'].add(domain)

        # Check thresholds (60 second window)
        time_window = 60
        window_start = tracker['window_start']

        if (current_time - window_start) >= time_window:
            # Count queries in window
            queries_in_window = sum(1 for t in tracker['queries'] if t >= (current_time - time_window))
            unique_count = len(tracker['unique_domains'])

            # Thresholds (from database config, with fallbacks)
            queries_threshold = 100  # queries per minute
            unique_threshold = 50    # unique domains per minute

            if queries_in_window > queries_threshold or unique_count > unique_threshold:
                threat = {
                    'type': 'DNS_ANOMALY',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'description': f'Abnormale DNS query rate: {queries_in_window} queries, {unique_count} unieke domains in {time_window}s',
                    'metadata': {
                        'queries_per_minute': queries_in_window,
                        'unique_domains': unique_count,
                        'window_seconds': time_window
                    }
                }

                # Reset tracker for next window
                tracker['unique_domains'].clear()
                tracker['window_start'] = current_time

                return threat

        return None

    # ==================== Phase 2: Web Application Security ====================

    def _detect_sql_injection(self, packet, src_ip, dst_ip):
        """Detect SQL injection attempts in HTTP traffic"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            http_layer = packet[HTTPRequest]

            # Extract HTTP components
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''

            # Get POST data if available
            payload_data = ''
            if packet.haslayer(Raw):
                payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            # Combine all searchable content
            full_request = f"{method} {path} {payload_data}".lower()

            # SQL injection patterns (common signatures)
            sqli_patterns = [
                # UNION-based
                r'union\s+(all\s+)?select',
                # Boolean-based
                r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
                r"or\s+['\"]?[a-z]\s*['\"]?\s*=\s*['\"]?[a-z]",
                r"'\s*or\s*'1'\s*=\s*'1",
                # Comment sequences
                r'--\s*$',
                r'/\*.*?\*/',
                r'#.*$',
                # SQL keywords in suspicious context
                r';\s*(select|insert|update|delete|drop|create|alter)\s+',
                r'(exec|execute)\s*\(',
                # SQL functions
                r'(concat|char|load_file|into\s+outfile)\s*\(',
                # Encoded variations
                r'%27\s*or\s*%27',  # URL-encoded '
                r'0x[0-9a-f]+',      # Hex encoding
                # Time-based blind SQLi
                r'(sleep|benchmark|waitfor\s+delay)\s*\(',
            ]

            import re
            matched_patterns = []
            for pattern in sqli_patterns:
                if re.search(pattern, full_request, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                tracker = self.sqli_tracker[src_ip]
                current_time = time.time()

                if tracker['first_seen'] is None:
                    tracker['first_seen'] = current_time

                tracker['last_seen'] = current_time
                tracker['attempts'].append(current_time)
                tracker['payloads'].add(path[:100])  # Store truncated path

                return {
                    'type': 'SQL_INJECTION_ATTEMPT',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'SQL injection poging gedetecteerd: {len(matched_patterns)} verdachte patronen in HTTP request',
                    'metadata': {
                        'method': method,
                        'path': path[:200],  # Truncate for logging
                        'host': host,
                        'patterns_matched': len(matched_patterns),
                        'attempt_count': len(tracker['attempts']),
                        'unique_payloads': len(tracker['payloads'])
                    }
                }

        except Exception as e:
            self.logger.debug(f"Error in SQL injection detection: {e}")

        return None

    def _detect_xss(self, packet, src_ip, dst_ip):
        """Detect Cross-Site Scripting (XSS) attempts in HTTP traffic"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            http_layer = packet[HTTPRequest]

            # Extract HTTP components
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''

            # Get POST data if available
            payload_data = ''
            if packet.haslayer(Raw):
                payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            # Combine all searchable content
            full_request = f"{path} {payload_data}".lower()

            # XSS patterns
            xss_patterns = [
                # Script tags
                r'<script[^>]*>',
                r'</script>',
                # Event handlers
                r'on(load|error|click|mouse|focus|blur|change|submit)\s*=',
                # JavaScript protocol
                r'javascript\s*:',
                # Iframe injection
                r'<iframe[^>]*>',
                # Object/embed tags
                r'<(object|embed|applet)[^>]*>',
                # IMG with event handlers
                r'<img[^>]*on',
                # Data URIs
                r'data:text/html',
                # Encoded variations
                r'%3cscript',  # URL-encoded <script
                r'&#x?[0-9a-f]+;',  # HTML entities
                # SVG-based XSS
                r'<svg[^>]*onload',
            ]

            import re
            matched_patterns = []
            for pattern in xss_patterns:
                if re.search(pattern, full_request, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                tracker = self.xss_tracker[src_ip]
                current_time = time.time()

                if tracker['first_seen'] is None:
                    tracker['first_seen'] = current_time

                tracker['last_seen'] = current_time
                tracker['attempts'].append(current_time)
                tracker['payloads'].add(path[:100])

                return {
                    'type': 'XSS_ATTEMPT',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'Cross-Site Scripting (XSS) poging: {len(matched_patterns)} verdachte patronen',
                    'metadata': {
                        'method': method,
                        'path': path[:200],
                        'host': host,
                        'patterns_matched': len(matched_patterns),
                        'attempt_count': len(tracker['attempts']),
                        'unique_payloads': len(tracker['payloads'])
                    }
                }

        except Exception as e:
            self.logger.debug(f"Error in XSS detection: {e}")

        return None

    def _detect_command_injection(self, packet, src_ip, dst_ip):
        """Detect command injection attempts in HTTP traffic"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            http_layer = packet[HTTPRequest]

            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''

            payload_data = ''
            if packet.haslayer(Raw):
                payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            full_request = f"{path} {payload_data}".lower()

            # Command injection patterns
            cmd_patterns = [
                # Shell metacharacters
                r'[;&|`$]',
                # Command chaining
                r'&&|\|\|',
                # Command substitution
                r'\$\(',
                r'`[^`]+`',
                # Common commands
                r'\b(cat|ls|wget|curl|nc|netcat|bash|sh|chmod|chown)\b',
                r'\b(ping|nslookup|whoami|id|uname|ifconfig)\b',
                # Encoded variations
                r'%0a',  # URL-encoded newline
                r'%0d',  # URL-encoded carriage return
                # Base64 encoded commands (common pattern)
                r'\|\s*base64\s*-d',
            ]

            import re
            matched_patterns = []
            for pattern in cmd_patterns:
                if re.search(pattern, full_request, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                tracker = self.command_injection_tracker[src_ip]
                current_time = time.time()

                if tracker['first_seen'] is None:
                    tracker['first_seen'] = current_time

                tracker['last_seen'] = current_time
                tracker['attempts'].append(current_time)
                tracker['payloads'].add(path[:100])

                return {
                    'type': 'COMMAND_INJECTION_ATTEMPT',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'Command injection poging: {len(matched_patterns)} verdachte shell metacharacters',
                    'metadata': {
                        'method': method,
                        'path': path[:200],
                        'host': host,
                        'patterns_matched': len(matched_patterns),
                        'attempt_count': len(tracker['attempts']),
                        'unique_payloads': len(tracker['payloads'])
                    }
                }

        except Exception as e:
            self.logger.debug(f"Error in command injection detection: {e}")

        return None

    def _detect_path_traversal(self, packet, src_ip, dst_ip):
        """Detect path traversal attempts in HTTP traffic"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            http_layer = packet[HTTPRequest]

            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''

            payload_data = ''
            if packet.haslayer(Raw):
                payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            full_request = f"{path} {payload_data}"

            # Path traversal patterns
            traversal_patterns = [
                # Directory traversal
                r'\.\./|\.\.\%2[fF]',
                r'\.\.\x5c',  # Windows backslash
                # Absolute paths
                r'/etc/passwd',
                r'/etc/shadow',
                r'c:\\windows',
                r'c:\\boot\.ini',
                # Encoded variations
                r'%2e%2e/',
                r'\.\./',
                # Null byte injection
                r'%00',
                r'\x00',
            ]

            import re
            matched_patterns = []
            for pattern in traversal_patterns:
                if re.search(pattern, full_request, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                tracker = self.path_traversal_tracker[src_ip]
                current_time = time.time()

                if tracker['first_seen'] is None:
                    tracker['first_seen'] = current_time

                tracker['last_seen'] = current_time
                tracker['attempts'].append(current_time)
                tracker['paths'].add(path[:100])

                return {
                    'type': 'PATH_TRAVERSAL_ATTEMPT',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'Path traversal poging: {len(matched_patterns)} verdachte patronen',
                    'metadata': {
                        'method': method,
                        'path': path[:200],
                        'host': host,
                        'patterns_matched': len(matched_patterns),
                        'attempt_count': len(tracker['attempts']),
                        'unique_paths': len(tracker['paths'])
                    }
                }

        except Exception as e:
            self.logger.debug(f"Error in path traversal detection: {e}")

        return None

    def _detect_xxe(self, packet, src_ip, dst_ip):
        """Detect XML External Entity (XXE) attacks"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            # Only check POST/PUT requests with XML content
            http_layer = packet[HTTPRequest]
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''

            if method not in ['POST', 'PUT']:
                return None

            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''

            # Get POST data
            if not packet.haslayer(Raw):
                return None

            payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            # XXE patterns
            xxe_patterns = [
                # DOCTYPE with ENTITY
                r'<!DOCTYPE[^>]*<!ENTITY',
                r'<!ENTITY[^>]*SYSTEM',
                # File protocol
                r'file://',
                # SYSTEM keyword in XML
                r'SYSTEM\s+["\']',
                # Data exfiltration patterns
                r'<!ENTITY[^>]*%',  # Parameter entities
                # XXE exploitation indicators
                r'expect://',
                r'php://',
            ]

            import re
            matched_patterns = []
            for pattern in xxe_patterns:
                if re.search(pattern, payload_data, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                return {
                    'type': 'XXE_ATTEMPT',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'XML External Entity (XXE) attack poging: {len(matched_patterns)} verdachte XML patronen',
                    'metadata': {
                        'method': method,
                        'path': path[:200],
                        'host': host,
                        'patterns_matched': len(matched_patterns),
                        'payload_preview': payload_data[:200]
                    }
                }

        except Exception as e:
            self.logger.debug(f"Error in XXE detection: {e}")

        return None

    def _detect_ssrf_extended(self, packet, src_ip, dst_ip):
        """Detect Server-Side Request Forgery (SSRF) - extended beyond cloud metadata"""
        threats = []

        # Check HTTP requests for internal IP targeting
        if packet.haslayer(HTTPRequest):
            try:
                http_layer = packet[HTTPRequest]
                path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
                host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''
                method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''

                payload_data = ''
                if packet.haslayer(Raw):
                    payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

                full_request = f"{path} {payload_data}".lower()

                # SSRF patterns (looking for internal IPs in parameters)
                ssrf_patterns = [
                    # Internal IP ranges
                    r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                    r'(192\.168\.\d{1,3}\.\d{1,3})',
                    r'(172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})',
                    # Localhost variations
                    r'127\.0\.0\.1',
                    r'localhost',
                    r'\[::1\]',
                    r'0\.0\.0\.0',
                    # Cloud metadata (already covered but included for completeness)
                    r'169\.254\.169\.254',
                    r'metadata\.google\.internal',
                ]

                import re
                matched_ips = []
                for pattern in ssrf_patterns:
                    matches = re.findall(pattern, full_request, re.IGNORECASE)
                    matched_ips.extend(matches)

                if matched_ips:
                    threats.append({
                        'type': 'SSRF_ATTEMPT',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'SSRF poging: interne IP adressen in HTTP request parameters',
                        'metadata': {
                            'method': method,
                            'path': path[:200],
                            'host': host,
                            'internal_ips_found': matched_ips[:5]  # Limit to first 5
                        }
                    })

            except Exception as e:
                self.logger.debug(f"Error in SSRF detection: {e}")

        return threats

    def _detect_webshell(self, packet, src_ip, dst_ip):
        """Detect webshell activity (uploads and suspicious POST requests)"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            http_layer = packet[HTTPRequest]
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''

            # Get POST data if available
            payload_data = ''
            if packet.haslayer(Raw):
                payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            # Webshell indicators
            webshell_patterns = [
                # Known webshell names
                r'(c99|r57|b374k|wso|shell|cmd|backdoor)\.(php|jsp|asp|aspx)',
                # Suspicious file uploads
                r'\.php\d*$',
                r'\.(phtml|php3|php4|php5|phar)$',
                # POST to recently uploaded files (pattern in path)
                r'upload.*\.(php|jsp|asp)',
                # Common webshell functions
                r'(eval|system|exec|shell_exec|passthru|base64_decode)\s*\(',
                # Obfuscated PHP
                r'\$_[A-Z]+\[',  # $_POST, $_GET, $_REQUEST
            ]

            import re
            matched_patterns = []

            # Check both path and payload
            combined = f"{path} {payload_data}".lower()

            for pattern in webshell_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                return {
                    'type': 'WEBSHELL_DETECTED',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'Webshell activiteit gedetecteerd: {len(matched_patterns)} verdachte patronen',
                    'metadata': {
                        'method': method,
                        'path': path[:200],
                        'host': host,
                        'patterns_matched': len(matched_patterns)
                    }
                }

        except Exception as e:
            self.logger.debug(f"Error in webshell detection: {e}")

        return None

    def _detect_api_abuse(self, packet, src_ip, dst_ip):
        """Detect API abuse (excessive requests, rate limit violations)"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            http_layer = packet[HTTPRequest]
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ''

            # Track API requests per source IP
            tracker = self.api_abuse_tracker[src_ip]
            current_time = time.time()

            if tracker['window_start'] is None:
                tracker['window_start'] = current_time

            # Add request to tracker
            tracker['requests'].append(current_time)

            # Track endpoint-specific requests (normalize path)
            endpoint = path.split('?')[0]  # Remove query string
            tracker['endpoints'][endpoint] += 1

            # Check thresholds (60 second window)
            time_window = 60
            window_start = tracker['window_start']

            if (current_time - window_start) >= time_window:
                # Count requests in window
                requests_in_window = sum(1 for t in tracker['requests'] if t >= (current_time - time_window))

                # Thresholds
                rate_limit = 100  # requests per minute (configurable)
                endpoint_limit = 50  # requests to same endpoint per minute

                # Check overall rate
                if requests_in_window > rate_limit:
                    # Reset tracker
                    tracker['window_start'] = current_time

                    return {
                        'type': 'API_ABUSE_RATE_LIMIT',
                        'severity': 'MEDIUM',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'API rate limit overschreden: {requests_in_window} requests in {time_window}s',
                        'metadata': {
                            'requests_per_minute': requests_in_window,
                            'threshold': rate_limit,
                            'unique_endpoints': len(tracker['endpoints'])
                        }
                    }

                # Check per-endpoint rate
                for ep, count in tracker['endpoints'].items():
                    if count > endpoint_limit:
                        # Reset tracker
                        tracker['endpoints'].clear()
                        tracker['window_start'] = current_time

                        return {
                            'type': 'API_ABUSE_ENDPOINT',
                            'severity': 'MEDIUM',
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'description': f'Excessive requests naar API endpoint: {count} requests in {time_window}s',
                            'metadata': {
                                'endpoint': ep[:200],
                                'requests': count,
                                'threshold': endpoint_limit
                            }
                        }

        except Exception as e:
            self.logger.debug(f"Error in API abuse detection: {e}")

        return None

    # ==================== Phase 3: DDoS & Resource Exhaustion ====================

    def _detect_syn_flood(self, packet, src_ip, dst_ip):
        """Detect SYN flood attacks"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        flags = tcp_layer.flags

        tracker = self.syn_flood_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Count SYN packets (without ACK)
        if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
            tracker['syn_count'] += 1
            tracker['ports'].add(tcp_layer.dport)

        # Check threshold (100 SYN/sec default)
        time_window = 1  # 1 second
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['syn_count'] > 100:
                threat = {
                    'type': 'SYN_FLOOD_ATTACK',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'SYN flood attack: {tracker["syn_count"]} SYN packets in {time_window}s',
                    'metadata': {
                        'syn_count': tracker['syn_count'],
                        'unique_ports': len(tracker['ports']),
                        'window_seconds': time_window
                    }
                }
                # Reset
                tracker['syn_count'] = 0
                tracker['ports'].clear()
                tracker['window_start'] = current_time
                return threat

        return None

    def _detect_udp_flood(self, packet, src_ip, dst_ip):
        """Detect UDP flood attacks"""
        if not packet.haslayer(UDP):
            return None

        udp_layer = packet[UDP]
        tracker = self.udp_flood_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        tracker['packet_count'] += 1
        tracker['byte_count'] += len(packet)
        tracker['ports'].add(udp_layer.dport)

        # Check threshold (500 UDP packets/sec default)
        time_window = 1
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['packet_count'] > 500:
                threat = {
                    'type': 'UDP_FLOOD_ATTACK',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'UDP flood: {tracker["packet_count"]} packets in {time_window}s',
                    'metadata': {
                        'packet_count': tracker['packet_count'],
                        'bytes': tracker['byte_count'],
                        'unique_ports': len(tracker['ports']),
                        'pps': tracker['packet_count'] / time_window
                    }
                }
                # Reset
                tracker['packet_count'] = 0
                tracker['byte_count'] = 0
                tracker['ports'].clear()
                tracker['window_start'] = current_time
                return threat

        return None

    def _detect_http_flood(self, packet, src_ip, dst_ip):
        """Detect HTTP flood (Layer 7 DDoS)"""
        if not packet.haslayer(HTTPRequest):
            return None

        tracker = self.http_flood_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        tracker['request_count'] += 1

        try:
            http_layer = packet[HTTPRequest]
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else '/'
            tracker['paths'].add(path[:100])
        except:
            pass

        # Check threshold (200 HTTP requests/sec default)
        time_window = 1
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['request_count'] > 200:
                threat = {
                    'type': 'HTTP_FLOOD_ATTACK',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'HTTP flood: {tracker["request_count"]} requests in {time_window}s',
                    'metadata': {
                        'request_count': tracker['request_count'],
                        'unique_paths': len(tracker['paths']),
                        'rps': tracker['request_count'] / time_window
                    }
                }
                # Reset
                tracker['request_count'] = 0
                tracker['paths'].clear()
                tracker['window_start'] = current_time
                return threat

        return None

    def _detect_slowloris(self, packet, src_ip, dst_ip):
        """Detect Slowloris attacks (slow HTTP)"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None

        tcp_layer = packet[TCP]
        if tcp_layer.dport not in [80, 443, 8080]:
            return None

        tracker = self.slowloris_tracker[src_ip]
        current_time = time.time()

        # Track incomplete HTTP requests (very slow sends)
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'HTTP/' in payload and not payload.endswith('\r\n\r\n'):
                tracker['incomplete_requests'] += 1
                tracker['connections'][dst_ip] += 1
                tracker['last_seen'] = current_time
        except:
            pass

        # Alert if many incomplete requests
        if tracker['incomplete_requests'] > 50:
            return {
                'type': 'SLOWLORIS_ATTACK',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Slowloris attack: {tracker["incomplete_requests"]} incomplete HTTP requests',
                'metadata': {
                    'incomplete_requests': tracker['incomplete_requests'],
                    'target_servers': len(tracker['connections'])
                }
            }

        return None

    def _detect_dns_amplification(self, packet, src_ip, dst_ip):
        """Detect DNS amplification attacks"""
        if not packet.haslayer(DNS):
            return None

        dns_layer = packet[DNS]
        tracker = self.amplification_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Track query vs response size
        if dns_layer.qr == 0:  # Query
            tracker['queries_sent'] += 1
        else:  # Response
            tracker['responses_received'] += 1
            # Calculate amplification factor
            if len(packet) > 512:  # Large response
                query_size = 60  # Typical query size
                response_size = len(packet)
                tracker['amplification_factor'] = max(tracker['amplification_factor'],
                                                      response_size / query_size)

        # Check for amplification pattern
        time_window = 10
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['amplification_factor'] > 10:  # 10x amplification
                threat = {
                    'type': 'DNS_AMPLIFICATION_ATTACK',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'DNS amplification: {tracker["amplification_factor"]:.1f}x factor',
                    'metadata': {
                        'amplification_factor': tracker['amplification_factor'],
                        'queries': tracker['queries_sent'],
                        'responses': tracker['responses_received']
                    }
                }
                # Reset
                tracker['amplification_factor'] = 0
                tracker['queries_sent'] = 0
                tracker['responses_received'] = 0
                tracker['window_start'] = current_time
                return threat

        return None

    def _detect_connection_exhaustion(self, packet, src_ip, dst_ip):
        """Detect connection exhaustion attacks"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        tracker = self.connection_exhaustion_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Track unique connections
        conn_tuple = (src_ip, dst_ip, tcp_layer.dport)
        tracker['connections'].add(conn_tuple)
        tracker['count'] = len(tracker['connections'])

        # Alert if too many connections (1000 concurrent default)
        if tracker['count'] > 1000:
            return {
                'type': 'CONNECTION_EXHAUSTION',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'description': f'Connection exhaustion: {tracker["count"]} concurrent connections',
                'metadata': {
                    'connection_count': tracker['count'],
                    'unique_destinations': len(set(c[1] for c in tracker['connections']))
                }
            }

        return None

    def _detect_bandwidth_saturation(self, packet, src_ip):
        """Detect bandwidth saturation attacks"""
        tracker = self.bandwidth_saturation_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        tracker['bytes_sent'] += len(packet)
        tracker['packets_sent'] += 1

        # Check bandwidth usage (100 Mbps threshold default)
        time_window = 1  # 1 second
        if (current_time - tracker['window_start']) >= time_window:
            mbps = (tracker['bytes_sent'] * 8) / (1000000 * time_window)
            if mbps > 100:  # 100 Mbps
                threat = {
                    'type': 'BANDWIDTH_SATURATION',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Bandwidth saturation: {mbps:.1f} Mbps',
                    'metadata': {
                        'mbps': mbps,
                        'bytes': tracker['bytes_sent'],
                        'packets': tracker['packets_sent'],
                        'pps': tracker['packets_sent'] / time_window
                    }
                }
                # Reset
                tracker['bytes_sent'] = 0
                tracker['packets_sent'] = 0
                tracker['window_start'] = current_time
                return threat

        return None

    # ==================== Phase 4: Ransomware Indicators ====================

    def _detect_smb_mass_encryption(self, packet, src_ip):
        """Detect mass file encryption via SMB"""
        # This is a simplified version - full implementation would parse SMB protocol
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        if tcp_layer.dport not in [445, 139]:  # SMB ports
            return None

        tracker = self.smb_encryption_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Track file operations (simplified - would need SMB parser)
        tracker['file_operations'].append(current_time)

        # Alert if many file operations in short time
        time_window = 60  # 1 minute
        if (current_time - tracker['window_start']) >= time_window:
            ops_count = len(tracker['file_operations'])
            if ops_count > 100:  # 100 file ops/minute
                return {
                    'type': 'RANSOMWARE_MASS_ENCRYPTION',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'description': f'Mogelijk ransomware: {ops_count} SMB file operations in {time_window}s',
                    'metadata': {
                        'file_operations': ops_count,
                        'operations_per_minute': ops_count / (time_window / 60)
                    }
                }

        return None

    def _detect_crypto_extension(self, packet, src_ip):
        """Detect files with ransomware extensions"""
        # Simplified - would need DNS/HTTP/SMB parsing for full detection
        if not packet.haslayer(Raw):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Known ransomware extensions
            crypto_extensions = [
                '.encrypted', '.locked', '.crypto', '.crypt',
                '.cerber', '.locky', '.zepto', '.odin',
                '.shit', '.fuck', '.wcry', '.wncry',
                '.zzzzz', '.aaa', '.abc', '.xyz',
                '.encrypted', '.locked', '.crypted'
            ]

            import re
            for ext in crypto_extensions:
                if re.search(rf'\w+{re.escape(ext)}\b', payload, re.IGNORECASE):
                    tracker = self.crypto_extension_tracker[src_ip]
                    current_time = time.time()

                    if tracker['first_seen'] is None:
                        tracker['first_seen'] = current_time

                    tracker['suspicious_extensions'].add(ext)
                    tracker['file_count'] += 1

                    if tracker['file_count'] > 5:
                        return {
                            'type': 'RANSOMWARE_CRYPTO_EXTENSION',
                            'severity': 'CRITICAL',
                            'source_ip': src_ip,
                            'description': f'Ransomware extensions gedetecteerd: {list(tracker["suspicious_extensions"])}',
                            'metadata': {
                                'extensions': list(tracker['suspicious_extensions']),
                                'file_count': tracker['file_count']
                            }
                        }

        except:
            pass

        return None

    def _detect_ransom_note(self, packet, src_ip):
        """Detect ransom note creation patterns"""
        if not packet.haslayer(Raw):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

            # Ransom note indicators
            ransom_keywords = [
                'decrypt', 'bitcoin', 'btc', 'ransom',
                'encrypted', 'files have been', 'pay',
                'restore', 'recovery', 'instructions'
            ]

            matches = sum(1 for keyword in ransom_keywords if keyword in payload)

            if matches >= 3:  # At least 3 keywords
                tracker = self.ransom_note_tracker[src_ip]
                current_time = time.time()

                if tracker['window_start'] is None:
                    tracker['window_start'] = current_time

                # Check for README or DECRYPT files
                if 'readme' in payload or 'decrypt' in payload:
                    tracker['txt_files_created'] += 1
                if '<html>' in payload or '<body>' in payload:
                    tracker['html_files_created'] += 1

                if tracker['txt_files_created'] + tracker['html_files_created'] > 2:
                    return {
                        'type': 'RANSOMWARE_RANSOM_NOTE',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'description': 'Ransom note detected in network traffic',
                        'metadata': {
                            'txt_files': tracker['txt_files_created'],
                            'html_files': tracker['html_files_created'],
                            'keyword_matches': matches
                        }
                    }

        except:
            pass

        return None

    def _detect_shadow_copy_deletion(self, packet, src_ip):
        """Detect shadow copy deletion (vssadmin delete shadows)"""
        if not packet.haslayer(Raw):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

            # Shadow copy deletion patterns
            shadow_patterns = [
                'vssadmin delete shadows',
                'vssadmin.exe delete shadows',
                'wmic shadowcopy delete',
                'bcdedit /set {default} bootstatuspolicy ignoreallfailures',
                'bcdedit /set {default} recoveryenabled no'
            ]

            for pattern in shadow_patterns:
                if pattern in payload:
                    tracker = self.shadow_copy_tracker[src_ip]
                    current_time = time.time()

                    if tracker['first_seen'] is None:
                        tracker['first_seen'] = current_time

                    tracker['deletion_attempts'] += 1

                    return {
                        'type': 'RANSOMWARE_SHADOW_COPY_DELETION',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'description': 'Shadow copy deletion detected (ransomware indicator)',
                        'metadata': {
                            'command': pattern,
                            'attempts': tracker['deletion_attempts']
                        }
                    }

        except:
            pass

        return None

    def _detect_backup_deletion(self, packet, src_ip):
        """Detect backup deletion attempts"""
        if not packet.haslayer(Raw):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

            # Backup deletion patterns
            if 'wbadmin delete' in payload or 'del /s /f /q' in payload and ('backup' in payload or '.bak' in payload):
                return {
                    'type': 'RANSOMWARE_BACKUP_DELETION',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'description': 'Backup deletion detected (ransomware behavior)',
                    'metadata': {
                        'pattern': 'backup_deletion'
                    }
                }

        except:
            pass

        return None

    # ==================== Phase 5: IoT & Smart Device Security ====================

    def _detect_iot_botnet(self, packet, src_ip, dst_ip):
        """Detect IoT botnet activity (Mirai-like patterns)"""
        tracker = self.iot_botnet_tracker[src_ip]
        current_time = time.time()

        if tracker['first_seen'] is None:
            tracker['first_seen'] = current_time

        # Check for Telnet brute force (typical Mirai behavior)
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.dport == 23:  # Telnet
                tracker['telnet_attempts'] += 1

                # Check for default credentials in payload
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                    default_creds = ['admin', 'root', '12345', 'default', 'support']
                    if any(cred in payload for cred in default_creds):
                        tracker['default_creds'] += 1

        # Alert on patterns
        if tracker['telnet_attempts'] > 10 or tracker['default_creds'] > 3:
            return {
                'type': 'IOT_BOTNET_ACTIVITY',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'IoT botnet activity (Mirai-like): {tracker["telnet_attempts"]} telnet attempts',
                'metadata': {
                    'telnet_attempts': tracker['telnet_attempts'],
                    'default_cred_attempts': tracker['default_creds']
                }
            }

        return None

    def _detect_upnp_exploit(self, packet, src_ip, dst_ip):
        """Detect UPnP exploitation attempts"""
        if not packet.haslayer(UDP):
            return None

        udp_layer = packet[UDP]
        if udp_layer.dport != 1900:  # SSDP port
            return None

        tracker = self.upnp_exploit_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        tracker['ssdp_requests'] += 1

        # Check for malicious SSDP payloads
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'M-SEARCH' in payload or 'SUBSCRIBE' in payload:
                suspicious_patterns = ['../../../', 'exec', 'system', '<script>']
                for pattern in suspicious_patterns:
                    if pattern in payload:
                        tracker['suspicious_commands'].add(pattern)

        # Alert on excessive SSDP or suspicious patterns
        if tracker['ssdp_requests'] > 100 or len(tracker['suspicious_commands']) > 0:
            return {
                'type': 'UPNP_EXPLOIT_ATTEMPT',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': 'UPnP exploitation attempt detected',
                'metadata': {
                    'ssdp_requests': tracker['ssdp_requests'],
                    'suspicious_patterns': list(tracker['suspicious_commands'])
                }
            }

        return None

    def _detect_mqtt_abuse(self, packet, src_ip, dst_ip):
        """Detect MQTT protocol abuse"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        if tcp_layer.dport != 1883:  # MQTT port
            return None

        tracker = self.mqtt_abuse_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Simplified MQTT detection (would need full MQTT parser)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # MQTT PUBLISH = 0x30, SUBSCRIBE = 0x82
            if len(payload) > 0:
                packet_type = payload[0] & 0xF0
                if packet_type == 0x30:  # PUBLISH
                    tracker['publish_count'] += 1
                elif packet_type == 0x80:  # SUBSCRIBE
                    tracker['subscribe_count'] += 1

        # Alert on excessive publishes (potential data exfil or spam)
        time_window = 60
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['publish_count'] > 1000:
                return {
                    'type': 'MQTT_ABUSE',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'MQTT abuse: {tracker["publish_count"]} publishes in {time_window}s',
                    'metadata': {
                        'publish_count': tracker['publish_count'],
                        'subscribe_count': tracker['subscribe_count']
                    }
                }

        return None

    # ==================== Phase 6: OT/ICS Protocol Security ====================

    def _detect_modbus_attack(self, packet, src_ip, dst_ip):
        """Detect Modbus protocol attacks"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        if tcp_layer.dport != 502:  # Modbus port
            return None

        tracker = self.modbus_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Simplified Modbus detection (would need full Modbus parser)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if len(payload) >= 8:
                # Modbus function codes (simplified)
                function_code = payload[7] if len(payload) > 7 else 0
                tracker['function_codes'][function_code] += 1

                # Write operations (function codes 5, 6, 15, 16)
                if function_code in [5, 6, 15, 16]:
                    tracker['write_operations'] += 1

        # Alert on excessive write operations
        time_window = 60
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['write_operations'] > 50:
                return {
                    'type': 'MODBUS_ATTACK',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'Modbus write attack: {tracker["write_operations"]} write operations',
                    'metadata': {
                        'write_operations': tracker['write_operations'],
                        'function_codes': dict(tracker['function_codes'])
                    }
                }

        return None

    def _detect_dnp3_attack(self, packet, src_ip, dst_ip):
        """Detect DNP3 protocol attacks (SCADA)"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        if tcp_layer.dport != 20000:  # DNP3 port
            return None

        tracker = self.dnp3_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Simplified DNP3 detection
        if packet.haslayer(Raw):
            tracker['suspicious_operations'] += 1

        # Alert on excessive DNP3 traffic
        time_window = 60
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['suspicious_operations'] > 100:
                return {
                    'type': 'DNP3_ATTACK',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'DNP3 SCADA attack: {tracker["suspicious_operations"]} operations',
                    'metadata': {
                        'operations': tracker['suspicious_operations']
                    }
                }

        return None

    def _detect_iec104_attack(self, packet, src_ip, dst_ip):
        """Detect IEC-104 protocol attacks"""
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet[TCP]
        if tcp_layer.dport != 2404:  # IEC-104 port
            return None

        tracker = self.iec104_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        tracker['control_commands'] += 1

        # Alert on control commands
        time_window = 60
        if (current_time - tracker['window_start']) >= time_window:
            if tracker['control_commands'] > 50:
                return {
                    'type': 'IEC104_ATTACK',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'IEC-104 control attack: {tracker["control_commands"]} commands',
                    'metadata': {
                        'commands': tracker['control_commands']
                    }
                }

        return None

    # ==================== Phase 7: Container & Orchestration ====================

    def _detect_docker_escape(self, packet, src_ip):
        """Detect Docker container escape attempts"""
        if not packet.haslayer(Raw):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

            # Docker escape indicators
            escape_patterns = [
                '/var/run/docker.sock',  # Docker socket access
                '--privileged',  # Privileged flag
                'cap-add=sys_admin',  # Dangerous capabilities
                '/proc/self/exe',  # Process namespace escape
                'nsenter',  # Namespace manipulation
                'unshare',  # Namespace unsharing
            ]

            for pattern in escape_patterns:
                if pattern in payload:
                    tracker = self.docker_escape_tracker[src_ip]
                    current_time = time.time()

                    if tracker['first_seen'] is None:
                        tracker['first_seen'] = current_time

                    tracker['privileged_operations'] += 1

                    if tracker['privileged_operations'] > 3:
                        return {
                            'type': 'DOCKER_ESCAPE_ATTEMPT',
                            'severity': 'CRITICAL',
                            'source_ip': src_ip,
                            'description': f'Docker container escape attempt: {pattern}',
                            'metadata': {
                                'pattern': pattern,
                                'attempts': tracker['privileged_operations']
                            }
                        }

        except:
            pass

        return None

    def _detect_k8s_exploit(self, packet, src_ip, dst_ip):
        """Detect Kubernetes API exploitation"""
        if not packet.haslayer(HTTPRequest):
            return None

        try:
            http_layer = packet[HTTPRequest]
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ''

            # Kubernetes API patterns
            k8s_patterns = [
                '/api/v1/namespaces',
                '/api/v1/pods',
                '/api/v1/secrets',
                '/api/v1/serviceaccounts',
                '/apis/rbac.authorization.k8s.io',
            ]

            for pattern in k8s_patterns:
                if pattern in path:
                    tracker = self.k8s_exploit_tracker[src_ip]
                    current_time = time.time()

                    if tracker['window_start'] is None:
                        tracker['window_start'] = current_time

                    tracker['api_calls'][pattern] += 1
                    tracker['suspicious_endpoints'].add(path[:100])

                    # Alert on excessive API calls
                    total_calls = sum(tracker['api_calls'].values())
                    if total_calls > 100:
                        return {
                            'type': 'K8S_API_EXPLOIT',
                            'severity': 'HIGH',
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'description': f'Kubernetes API exploitation: {total_calls} API calls',
                            'metadata': {
                                'total_calls': total_calls,
                                'endpoints': list(tracker['suspicious_endpoints'])[:5]
                            }
                        }

        except:
            pass

        return None

    # ==================== Phase 8: Advanced Evasion ====================

    def _detect_fragmentation_attack(self, packet, src_ip):
        """Detect IP fragmentation attacks"""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        tracker = self.fragmentation_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Check for fragmentation
        if ip_layer.flags & 0x1 or ip_layer.frag > 0:  # More fragments or fragment offset
            tracker['fragments'].append(current_time)

            # Check for overlapping fragments (evasion technique)
            if ip_layer.frag > 0 and len(tracker['fragments']) > 1:
                tracker['overlapping_count'] += 1

        # Alert on excessive fragmentation
        time_window = 60
        if (current_time - tracker['window_start']) >= time_window:
            frag_count = len(tracker['fragments'])
            if frag_count > 100 or tracker['overlapping_count'] > 10:
                return {
                    'type': 'FRAGMENTATION_ATTACK',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'IP fragmentation evasion: {frag_count} fragments',
                    'metadata': {
                        'fragment_count': frag_count,
                        'overlapping': tracker['overlapping_count']
                    }
                }

        return None

    def _detect_tunneling(self, packet, src_ip):
        """Detect protocol tunneling (DNS, ICMP, etc.)"""
        tracker = self.tunneling_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # DNS tunneling detection
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0 and dns_layer.qd:  # Query
                domain = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                # Long subdomains indicate tunneling
                if len(domain) > 50 or domain.count('.') > 5:
                    tracker['protocols'].add('DNS')
                    tracker['payload_size'] += len(domain)
                    tracker['packet_count'] += 1

        # ICMP tunneling detection
        if packet.haslayer(ICMP):
            if packet.haslayer(Raw):
                payload_size = len(packet[Raw].load)
                if payload_size > 64:  # Unusually large ICMP payload
                    tracker['protocols'].add('ICMP')
                    tracker['payload_size'] += payload_size
                    tracker['packet_count'] += 1

        # Alert on tunneling patterns
        time_window = 60
        if (current_time - tracker['window_start']) >= time_window:
            if len(tracker['protocols']) > 0 and tracker['packet_count'] > 50:
                return {
                    'type': 'PROTOCOL_TUNNELING',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Protocol tunneling detected via {list(tracker["protocols"])}',
                    'metadata': {
                        'protocols': list(tracker['protocols']),
                        'packets': tracker['packet_count'],
                        'total_payload': tracker['payload_size']
                    }
                }

        return None

    def _detect_polymorphic_malware(self, packet, src_ip):
        """Detect polymorphic malware patterns"""
        if not packet.haslayer(Raw):
            return None

        tracker = self.polymorphic_tracker[src_ip]
        current_time = time.time()

        if tracker['first_seen'] is None:
            tracker['first_seen'] = current_time

        try:
            payload = packet[Raw].load

            # Simple signature based on payload hash (simplified)
            import hashlib
            payload_hash = hashlib.md5(payload[:32]).hexdigest()[:8] if len(payload) >= 32 else None

            if payload_hash:
                tracker['signatures'].add(payload_hash)
                tracker['pattern_changes'] = len(tracker['signatures'])

                # Alert if many different signatures from same source
                if tracker['pattern_changes'] > 20:
                    return {
                        'type': 'POLYMORPHIC_MALWARE',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'description': f'Polymorphic malware: {tracker["pattern_changes"]} signature variations',
                        'metadata': {
                            'signature_count': tracker['pattern_changes']
                        }
                    }

        except:
            pass

        return None

    def _detect_dga(self, packet, src_ip):
        """Detect Domain Generation Algorithm (DGA) patterns"""
        if not packet.haslayer(DNS):
            return None

        dns_layer = packet[DNS]
        if dns_layer.qr != 0 or not dns_layer.qd:  # Only queries
            return None

        try:
            domain = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            domain_parts = domain.split('.')

            if len(domain_parts) < 2:
                return None

            subdomain = domain_parts[0]

            # DGA characteristics
            is_suspicious = (
                len(subdomain) > 12 and  # Long subdomain
                sum(c.isdigit() for c in subdomain) > len(subdomain) * 0.3 and  # Many digits
                not any(word in subdomain for word in ['www', 'mail', 'smtp', 'ftp', 'api'])  # Not common
            )

            if is_suspicious:
                return {
                    'type': 'DGA_DETECTED',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Domain Generation Algorithm detected: {domain}',
                    'metadata': {
                        'domain': domain,
                        'subdomain_length': len(subdomain)
                    }
                }

        except:
            pass

        return None

    # ==================== Phase 9: Completion Boost ====================

    def _detect_lateral_movement(self, packet, src_ip, dst_ip):
        """Detect lateral movement (SMB, RDP, PSExec)"""
        tracker = self.lateral_movement_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            dst_port = tcp_layer.dport

            # SMB connections (port 445)
            if dst_port == 445:
                tracker['smb_connections'].add(dst_ip)

            # RDP connections (port 3389)
            if dst_port == 3389:
                tracker['rdp_attempts'] += 1

            # Check for PSExec patterns in payload
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                if 'psexec' in payload or 'paexec' in payload or '\\\\pipe\\' in payload:
                    tracker['psexec_patterns'] += 1

        # Alert on lateral movement patterns
        time_window = 300  # 5 minutes
        if (current_time - tracker['window_start']) >= time_window:
            smb_count = len(tracker['smb_connections'])
            if smb_count > 5 or tracker['rdp_attempts'] > 3 or tracker['psexec_patterns'] > 0:
                return {
                    'type': 'LATERAL_MOVEMENT',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'description': f'Lateral movement: {smb_count} SMB targets, {tracker["rdp_attempts"]} RDP attempts',
                    'metadata': {
                        'smb_targets': smb_count,
                        'rdp_attempts': tracker['rdp_attempts'],
                        'psexec_detected': tracker['psexec_patterns'] > 0
                    }
                }

        return None

    def _detect_data_exfiltration(self, packet, src_ip, dst_ip):
        """Detect data exfiltration patterns"""
        tracker = self.data_exfil_tracker[src_ip]
        current_time = time.time()

        if tracker['window_start'] is None:
            tracker['window_start'] = current_time

        # Track outbound traffic
        if packet.haslayer(IP):
            # Check if destination is external (not RFC1918)
            try:
                import ipaddress
                dst_addr = ipaddress.ip_address(dst_ip)
                if not dst_addr.is_private:
                    tracker['outbound_bytes'] += len(packet)
                    tracker['destinations'].add(dst_ip)

                    # Track protocol
                    if packet.haslayer(TCP):
                        tracker['protocols'].add('TCP')
                    elif packet.haslayer(UDP):
                        tracker['protocols'].add('UDP')

            except:
                pass

        # Alert on excessive outbound traffic
        time_window = 60
        if (current_time - tracker['window_start']) >= time_window:
            mbytes = tracker['outbound_bytes'] / (1024 * 1024)
            if mbytes > 100 or len(tracker['destinations']) > 20:  # 100 MB or 20+ destinations
                return {
                    'type': 'DATA_EXFILTRATION',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'description': f'Data exfiltration: {mbytes:.1f} MB to {len(tracker["destinations"])} destinations',
                    'metadata': {
                        'megabytes': mbytes,
                        'destination_count': len(tracker['destinations']),
                        'protocols': list(tracker['protocols'])
                    }
                }

        return None

    def _detect_privilege_escalation(self, packet, src_ip):
        """Detect privilege escalation attempts"""
        if not packet.haslayer(Raw):
            return None

        tracker = self.privilege_escalation_tracker[src_ip]
        current_time = time.time()

        if tracker['first_seen'] is None:
            tracker['first_seen'] = current_time

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

            # Privilege escalation indicators
            if 'sudo ' in payload or 'su -' in payload or 'runas' in payload:
                tracker['sudo_attempts'] += 1

            if 'uac' in payload or 'bypassuac' in payload:
                tracker['uac_bypass'] += 1

            if 'exploit' in payload or 'cve-' in payload or 'kernel' in payload:
                tracker['kernel_exploits'] += 1

            total_attempts = tracker['sudo_attempts'] + tracker['uac_bypass'] + tracker['kernel_exploits']
            if total_attempts > 5:
                return {
                    'type': 'PRIVILEGE_ESCALATION',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'description': f'Privilege escalation attempts: {total_attempts} indicators',
                    'metadata': {
                        'sudo_attempts': tracker['sudo_attempts'],
                        'uac_bypass': tracker['uac_bypass'],
                        'kernel_exploits': tracker['kernel_exploits']
                    }
                }

        except:
            pass

        return None

    def _detect_persistence(self, packet, src_ip):
        """Detect persistence mechanism creation"""
        if not packet.haslayer(Raw):
            return None

        tracker = self.persistence_tracker[src_ip]
        current_time = time.time()

        if tracker['first_seen'] is None:
            tracker['first_seen'] = current_time

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

            # Persistence indicators
            if 'hkey' in payload or 'currentversion\\run' in payload:
                tracker['registry_modifications'] += 1

            if 'schtasks' in payload or 'at.exe' in payload or 'cron' in payload:
                tracker['scheduled_tasks'] += 1

            if 'startup' in payload or 'appdata\\roaming' in payload:
                tracker['startup_items'] += 1

            total = tracker['registry_modifications'] + tracker['scheduled_tasks'] + tracker['startup_items']
            if total > 3:
                return {
                    'type': 'PERSISTENCE_MECHANISM',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Persistence creation: {total} mechanisms detected',
                    'metadata': {
                        'registry': tracker['registry_modifications'],
                        'scheduled_tasks': tracker['scheduled_tasks'],
                        'startup_items': tracker['startup_items']
                    }
                }

        except:
            pass

        return None

    def _detect_credential_dumping(self, packet, src_ip):
        """Detect credential dumping attempts"""
        if not packet.haslayer(Raw):
            return None

        tracker = self.credential_dumping_tracker[src_ip]
        current_time = time.time()

        if tracker['first_seen'] is None:
            tracker['first_seen'] = current_time

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()

            # Credential dumping indicators
            if 'lsass' in payload or 'procdump' in payload:
                tracker['lsass_access'] += 1

            if 'sam' in payload or 'system32\\config\\sam' in payload:
                tracker['sam_access'] += 1

            if 'mimikatz' in payload or 'sekurlsa' in payload or 'kerberos::' in payload:
                tracker['mimikatz_patterns'] += 1

            total = tracker['lsass_access'] + tracker['sam_access'] + tracker['mimikatz_patterns']
            if total > 2:
                return {
                    'type': 'CREDENTIAL_DUMPING',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'description': f'Credential dumping: {total} indicators detected',
                    'metadata': {
                        'lsass_access': tracker['lsass_access'],
                        'sam_access': tracker['sam_access'],
                        'mimikatz': tracker['mimikatz_patterns']
                    }
                }

        except:
            pass

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

        # Cleanup cryptomining tracker
        for ip in list(self.cryptomining_tracker.keys()):
            tracker = self.cryptomining_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 300:  # 5 minuten
                del self.cryptomining_tracker[ip]

        # Cleanup DNS query tracker
        for ip in list(self.dns_query_tracker.keys()):
            tracker = self.dns_query_tracker[ip]
            # Reset window if older than time_window
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 120:  # 2 minuten
                tracker['unique_domains'].clear()
                tracker['window_start'] = None

        # Cleanup Phase 2: Web Application Security trackers
        for ip in list(self.sqli_tracker.keys()):
            tracker = self.sqli_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 600:  # 10 minuten
                del self.sqli_tracker[ip]

        for ip in list(self.xss_tracker.keys()):
            tracker = self.xss_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 600:
                del self.xss_tracker[ip]

        for ip in list(self.command_injection_tracker.keys()):
            tracker = self.command_injection_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 600:
                del self.command_injection_tracker[ip]

        for ip in list(self.path_traversal_tracker.keys()):
            tracker = self.path_traversal_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 600:
                del self.path_traversal_tracker[ip]

        for ip in list(self.api_abuse_tracker.keys()):
            tracker = self.api_abuse_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 120:  # 2 minuten
                tracker['endpoints'].clear()
                tracker['window_start'] = None

        # Cleanup Phase 3: DDoS & Resource Exhaustion trackers
        for ip in list(self.syn_flood_tracker.keys()):
            tracker = self.syn_flood_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 60:
                del self.syn_flood_tracker[ip]

        for ip in list(self.udp_flood_tracker.keys()):
            tracker = self.udp_flood_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 60:
                del self.udp_flood_tracker[ip]

        for ip in list(self.http_flood_tracker.keys()):
            tracker = self.http_flood_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 60:
                del self.http_flood_tracker[ip]

        for ip in list(self.slowloris_tracker.keys()):
            tracker = self.slowloris_tracker[ip]
            if tracker['last_seen'] and \
               (current_time - tracker['last_seen']) > 300:  # 5 min
                del self.slowloris_tracker[ip]

        for ip in list(self.amplification_tracker.keys()):
            tracker = self.amplification_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 60:
                del self.amplification_tracker[ip]

        for ip in list(self.connection_exhaustion_tracker.keys()):
            tracker = self.connection_exhaustion_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:  # 5 min
                del self.connection_exhaustion_tracker[ip]

        for ip in list(self.bandwidth_saturation_tracker.keys()):
            tracker = self.bandwidth_saturation_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 60:
                del self.bandwidth_saturation_tracker[ip]

        # Cleanup Phase 4: Ransomware Indicators trackers
        for ip in list(self.smb_encryption_tracker.keys()):
            tracker = self.smb_encryption_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 600:  # 10 min
                del self.smb_encryption_tracker[ip]

        for ip in list(self.crypto_extension_tracker.keys()):
            tracker = self.crypto_extension_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 1800:  # 30 min
                del self.crypto_extension_tracker[ip]

        for ip in list(self.ransom_note_tracker.keys()):
            tracker = self.ransom_note_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 600:
                del self.ransom_note_tracker[ip]

        for ip in list(self.shadow_copy_tracker.keys()):
            tracker = self.shadow_copy_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 1800:
                del self.shadow_copy_tracker[ip]

        # Cleanup Phase 5: IoT & Smart Device Security trackers
        for ip in list(self.iot_botnet_tracker.keys()):
            tracker = self.iot_botnet_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 600:
                del self.iot_botnet_tracker[ip]

        for ip in list(self.upnp_exploit_tracker.keys()):
            tracker = self.upnp_exploit_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.upnp_exploit_tracker[ip]

        for ip in list(self.mqtt_abuse_tracker.keys()):
            tracker = self.mqtt_abuse_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.mqtt_abuse_tracker[ip]

        # Cleanup Phase 6: OT/ICS Protocol trackers
        for ip in list(self.modbus_tracker.keys()):
            tracker = self.modbus_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.modbus_tracker[ip]

        for ip in list(self.dnp3_tracker.keys()):
            tracker = self.dnp3_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.dnp3_tracker[ip]

        for ip in list(self.iec104_tracker.keys()):
            tracker = self.iec104_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.iec104_tracker[ip]

        # Cleanup Phase 7: Container & Orchestration trackers
        for ip in list(self.docker_escape_tracker.keys()):
            tracker = self.docker_escape_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 600:
                del self.docker_escape_tracker[ip]

        for ip in list(self.k8s_exploit_tracker.keys()):
            tracker = self.k8s_exploit_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.k8s_exploit_tracker[ip]

        # Cleanup Phase 8: Advanced Evasion trackers
        for ip in list(self.fragmentation_tracker.keys()):
            tracker = self.fragmentation_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.fragmentation_tracker[ip]

        for ip in list(self.tunneling_tracker.keys()):
            tracker = self.tunneling_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.tunneling_tracker[ip]

        for ip in list(self.polymorphic_tracker.keys()):
            tracker = self.polymorphic_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 1800:  # 30 min
                del self.polymorphic_tracker[ip]

        # Cleanup Phase 9: Completion Boost trackers
        for ip in list(self.lateral_movement_tracker.keys()):
            tracker = self.lateral_movement_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 600:  # 10 min
                del self.lateral_movement_tracker[ip]

        for ip in list(self.data_exfil_tracker.keys()):
            tracker = self.data_exfil_tracker[ip]
            if tracker['window_start'] and \
               (current_time - tracker['window_start']) > 300:
                del self.data_exfil_tracker[ip]

        for ip in list(self.privilege_escalation_tracker.keys()):
            tracker = self.privilege_escalation_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 1800:
                del self.privilege_escalation_tracker[ip]

        for ip in list(self.persistence_tracker.keys()):
            tracker = self.persistence_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 1800:
                del self.persistence_tracker[ip]

        for ip in list(self.credential_dumping_tracker.keys()):
            tracker = self.credential_dumping_tracker[ip]
            if tracker['first_seen'] and \
               (current_time - tracker['first_seen']) > 1800:
                del self.credential_dumping_tracker[ip]

        self.logger.debug("Oude tracking data opgeschoond")
