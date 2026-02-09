# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Behavior Matcher Module
Matches observed network behavior against device templates to determine
if alerts should be suppressed based on expected device behavior.

This enables intelligent alert filtering where:
- A Smart TV connecting to Netflix doesn't trigger false positives
- An IP Camera streaming RTSP is expected behavior
- A NAS serving SMB shares is normal operation
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
import ipaddress


class BehaviorMatcher:
    """
    Matches network behavior against device templates to suppress
    expected alerts while still flagging anomalous behavior.
    """

    def __init__(self, db_manager=None, config: dict = None):
        """
        Initialize BehaviorMatcher.

        Args:
            db_manager: DatabaseManager instance for device/template lookups
            config: Configuration dictionary
        """
        self.logger = logging.getLogger('NetMonitor.BehaviorMatcher')
        self.db = db_manager
        self.config = config or {}

        # Cache for device templates (ip -> template_data)
        self._device_cache: Dict[str, Dict] = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = 300  # 5 minutes

        # Track when cache entries were last updated
        self._cache_timestamps: Dict[str, datetime] = {}
        self._last_cache_cleanup = time.time()
        self._max_cache_size = 1000

        # Service provider IP ranges cache
        self._service_provider_ranges: List[Tuple] = []  # (network, provider_info)
        self._provider_cache_timestamp: Optional[datetime] = None

        # Statistics
        self.stats = {
            'alerts_checked': 0,
            'alerts_suppressed': 0,
            'alerts_suppressed_by_global_category': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

        # Global allowed service categories (from config)
        # Traffic to these categories is allowed for ALL devices
        self._global_allowed_categories = set(
            self.config.get('alerts', {}).get('allowed_service_categories', [])
        )

        # Load initial data
        self._refresh_service_providers()

        self.logger.info(f"BehaviorMatcher initialized (global allowed categories: {self._global_allowed_categories})")

    def _refresh_service_providers(self):
        """Refresh the service provider IP ranges cache"""
        if not self.db:
            return

        try:
            providers = self.db.get_service_providers()
            ranges = []

            for provider in providers:
                ip_ranges = provider.get('ip_ranges', [])
                if isinstance(ip_ranges, str):
                    import json
                    ip_ranges = json.loads(ip_ranges)

                provider_info = {
                    'id': provider['id'],
                    'name': provider['name'],
                    'category': provider['category']
                }

                for ip_range in ip_ranges:
                    try:
                        network = ipaddress.ip_network(ip_range, strict=False)
                        ranges.append((network, provider_info))
                    except ValueError:
                        continue

            self._service_provider_ranges = ranges
            self._provider_cache_timestamp = datetime.now()
            self.logger.debug(f"Loaded {len(ranges)} service provider IP ranges")

        except Exception as e:
            self.logger.error(f"Error refreshing service providers: {e}")

    def _get_device_template(self, ip_address: str) -> Optional[Dict]:
        """
        Get device template for an IP address (with caching).

        Returns:
            Template dict with behaviors, or None if no template assigned
        """
        now = datetime.now()

        with self._cache_lock:
            # Check cache
            if ip_address in self._device_cache:
                cache_time = self._cache_timestamps.get(ip_address)
                if cache_time and (now - cache_time).total_seconds() < self._cache_ttl:
                    self.stats['cache_hits'] += 1
                    return self._device_cache[ip_address]

            self.stats['cache_misses'] += 1

        # Periodieke cache cleanup (max elke 60 seconden)
        if time.time() - self._last_cache_cleanup > 60:
            self._cleanup_cache()

        # Fetch from database
        if not self.db:
            return None

        try:
            device = self.db.get_device_by_ip(ip_address)
            if not device or not device.get('template_id'):
                # Cache the "no template" result too
                with self._cache_lock:
                    self._device_cache[ip_address] = None
                    self._cache_timestamps[ip_address] = now
                return None

            template = self.db.get_device_template_by_id(device['template_id'])
            if template:
                template['device_info'] = device

            with self._cache_lock:
                self._device_cache[ip_address] = template
                self._cache_timestamps[ip_address] = now

            return template

        except Exception as e:
            self.logger.error(f"Error getting device template for {ip_address}: {e}")
            return None

    def _cleanup_cache(self):
        """Verwijder verlopen en overtollige cache entries om geheugenlek te voorkomen."""
        now = datetime.now()
        removed = 0

        with self._cache_lock:
            # Verwijder verlopen entries (ouder dan TTL)
            expired = [
                ip for ip, ts in self._cache_timestamps.items()
                if (now - ts).total_seconds() >= self._cache_ttl
            ]
            for ip in expired:
                self._device_cache.pop(ip, None)
                self._cache_timestamps.pop(ip, None)
                removed += 1

            # Als cache nog steeds te groot is, verwijder oudste entries
            if len(self._device_cache) > self._max_cache_size:
                sorted_entries = sorted(
                    self._cache_timestamps.items(), key=lambda x: x[1]
                )
                excess = len(self._device_cache) - self._max_cache_size
                for ip, _ in sorted_entries[:excess]:
                    self._device_cache.pop(ip, None)
                    self._cache_timestamps.pop(ip, None)
                    removed += 1

        self._last_cache_cleanup = time.time()
        if removed > 0:
            self.logger.debug(f"Cache cleanup: {removed} entries verwijderd, {len(self._device_cache)} over")

    def _check_ip_in_service_providers(self, ip_str: str) -> Optional[Dict]:
        """Check if IP belongs to a service provider"""
        # Refresh cache if stale
        if (not self._provider_cache_timestamp or
            (datetime.now() - self._provider_cache_timestamp).total_seconds() > self._cache_ttl):
            self._refresh_service_providers()

        try:
            ip = ipaddress.ip_address(ip_str)
            for network, provider_info in self._service_provider_ranges:
                if ip in network:
                    return provider_info
        except ValueError:
            pass

        return None

    def _check_explicit_alert_suppression(self, src_ip: str, dst_ip: str, threat_type: str) -> bool:
        """
        Check if there's an explicit suppress_alert_types behavior for this threat.

        This allows templates to suppress specific CRITICAL alerts (e.g., HTTP_SENSITIVE_DATA
        for management interfaces like UniFi controllers).

        Returns:
            True if this threat_type should be explicitly suppressed
        """
        # Check source template
        if src_ip:
            src_template = self._get_device_template(src_ip)
            if src_template:
                for behavior in src_template.get('behaviors', []):
                    if behavior.get('behavior_type') == 'suppress_alert_types':
                        params = behavior.get('parameters', {})
                        alert_types = params.get('alert_types', [])
                        if threat_type in alert_types:
                            return True

        # Check destination template
        if dst_ip:
            dst_template = self._get_device_template(dst_ip)
            if dst_template:
                for behavior in dst_template.get('behaviors', []):
                    if behavior.get('behavior_type') == 'suppress_alert_types':
                        params = behavior.get('parameters', {})
                        alert_types = params.get('alert_types', [])
                        if threat_type in alert_types:
                            return True

        return False

    def should_suppress_alert(self, threat: Dict, packet=None) -> Tuple[bool, Optional[str]]:
        """
        Determine if an alert should be suppressed based on device template.

        Checks BOTH source and destination devices:
        - Source device: Does this device's template allow SENDING this traffic?
        - Destination device: Does this device's template allow RECEIVING this traffic?

        Args:
            threat: Threat dictionary with type, severity, source_ip, etc.
            packet: Optional scapy packet for additional context

        Returns:
            Tuple of (should_suppress: bool, reason: str or None)
        """
        self.stats['alerts_checked'] += 1

        # Defensive check for malformed threats
        if not isinstance(threat, dict):
            return False, None

        src_ip = threat.get('source_ip')
        dst_ip = threat.get('destination_ip')
        threat_type = threat.get('type', '')

        self.logger.debug(f"Checking suppression for: {threat_type} from {src_ip} → {dst_ip} (severity: {threat.get('severity')})")

        if not src_ip:
            return False, None

        # Never suppress threat feed matches or C2 communication
        if threat_type in ('THREAT_FEED_MATCH', 'C2_COMMUNICATION', 'BLACKLISTED_IP'):
            return False, None

        # Check if there's an explicit suppress_alert_types rule before applying CRITICAL filter
        # This allows templates to suppress specific CRITICAL alerts (e.g., HTTP_SENSITIVE_DATA for management interfaces)
        has_explicit_suppression = self._check_explicit_alert_suppression(src_ip, dst_ip, threat_type)

        # Never suppress CRITICAL threats unless explicitly allowed by template
        if threat.get('severity') == 'CRITICAL' and not has_explicit_suppression:
            return False, None

        # Global service category check - applies to ALL devices
        # This allows globally allowing traffic to RMM tools, CDNs, etc.
        if dst_ip and self._global_allowed_categories:
            provider = self._check_ip_in_service_providers(dst_ip)
            if provider and provider['category'] in self._global_allowed_categories:
                self.stats['alerts_suppressed'] += 1
                self.stats['alerts_suppressed_by_global_category'] += 1
                return True, f"Global allowed category: {provider['name']} ({provider['category']})"

        # Check 1: Source device template (outbound behavior)
        # Does the source device's template allow SENDING this type of traffic?
        src_template = self._get_device_template(src_ip)
        if src_template:
            behaviors = src_template.get('behaviors', [])
            template_name = src_template.get('name', 'Unknown')

            for behavior in behaviors:
                if behavior.get('action') != 'allow':
                    continue

                behavior_type = behavior.get('behavior_type')
                params = behavior.get('parameters', {})
                direction = params.get('direction')

                # For source device, check outbound or bidirectional behaviors
                if direction == 'inbound':
                    continue  # Skip inbound-only behaviors for source check

                suppress, reason = self._match_behavior(
                    threat_type, behavior_type, params, threat, packet, dst_ip
                )

                if suppress:
                    self.stats['alerts_suppressed'] += 1
                    return True, f"Source template '{template_name}': {reason}"

        # Check 2: Destination device template (inbound behavior)
        # Does the destination device's template allow RECEIVING this type of traffic?
        if dst_ip:
            dst_template = self._get_device_template(dst_ip)
            if dst_template:
                behaviors = dst_template.get('behaviors', [])
                template_name = dst_template.get('name', 'Unknown')

                for behavior in behaviors:
                    if behavior.get('action') != 'allow':
                        continue

                    behavior_type = behavior.get('behavior_type')
                    params = behavior.get('parameters', {})
                    direction = params.get('direction')

                    # For destination device, check inbound or bidirectional behaviors
                    if direction == 'outbound':
                        continue  # Skip outbound-only behaviors for destination check

                    suppress, reason = self._match_behavior_inbound(
                        threat_type, behavior_type, params, threat, packet, src_ip
                    )

                    if suppress:
                        self.stats['alerts_suppressed'] += 1
                        return True, f"Destination template '{template_name}': {reason}"

        return False, None

    def _match_behavior_inbound(self, threat_type: str, behavior_type: str,
                                params: Dict, threat: Dict, packet, src_ip: str) -> Tuple[bool, Optional[str]]:
        """
        Match a specific behavior rule against inbound traffic to a destination device.

        This is called when checking if the DESTINATION device expects to receive this traffic.

        Returns:
            Tuple of (matches: bool, reason: str or None)
        """
        # Port-based matching for inbound traffic
        if behavior_type == 'allowed_ports':
            allowed_ports = set(params.get('ports', []))

            # For inbound traffic to destination, check the destination port (with defensive check)
            dst_port = None
            if isinstance(threat, dict):
                metadata = threat.get('metadata', {})
                if isinstance(metadata, dict):
                    dst_port = metadata.get('destination_port')

            if packet:
                from scapy.layers.inet import TCP, UDP
                if packet.haslayer(TCP):
                    dst_port = dst_port or packet[TCP].dport
                elif packet.haslayer(UDP):
                    dst_port = dst_port or packet[UDP].dport

            # Only suppress connection/traffic threats on allowed ports, not attacks
            if dst_port in allowed_ports:
                if threat_type in ('PORT_SCAN', 'CONNECTION_FLOOD', 'UNUSUAL_PACKET_SIZE',
                                   'HTTP_NON_STANDARD_PORT', 'SSH_NON_STANDARD_PORT',
                                   'DNS_NON_STANDARD_PORT', 'FTP_NON_STANDARD_PORT',
                                   'BEACONING', 'HIGH_INBOUND_VOLUME'):
                    return True, f"Inbound port {dst_port} is allowed"

        # Source subnet matching (allow connections from specific subnets)
        elif behavior_type == 'allowed_sources':
            allowed_subnets = params.get('subnets', [])
            allowed_internal = params.get('internal', False)

            self.logger.debug(f"Checking allowed_sources: src_ip={src_ip}, allowed_subnets={allowed_subnets}, allowed_internal={allowed_internal}")

            try:
                src = ipaddress.ip_address(src_ip)

                # Check if source is internal
                if allowed_internal:
                    internal_nets = [
                        ipaddress.ip_network('10.0.0.0/8'),
                        ipaddress.ip_network('172.16.0.0/12'),
                        ipaddress.ip_network('192.168.0.0/16')
                    ]
                    if any(src in net for net in internal_nets):
                        return True, "Internal source is allowed"

                # Check specific subnets/IPs
                for subnet in allowed_subnets:
                    try:
                        # Handle both plain IPs and CIDR notation
                        if '/' not in str(subnet):
                            # Plain IP - compare directly
                            if src == ipaddress.ip_address(subnet):
                                self.logger.debug(f"MATCH: Source {subnet} is allowed")
                                return True, f"Source {subnet} is allowed"
                        else:
                            # CIDR notation
                            network = ipaddress.ip_network(subnet, strict=False)
                            if src in network:
                                self.logger.debug(f"MATCH: Source from {subnet} is allowed")
                                return True, f"Source from {subnet} is allowed"
                    except ValueError as e:
                        self.logger.debug(f"ValueError checking subnet {subnet}: {e}")
                        continue
            except ValueError as e:
                self.logger.debug(f"ValueError parsing src_ip {src_ip}: {e}")
                pass

        # Protocol-based matching
        elif behavior_type == 'allowed_protocols':
            # Handle mixed types in protocols list (could be strings or ints)
            raw_protocols = params.get('protocols', [])
            allowed_protocols = [str(p).upper() for p in raw_protocols if p is not None]

            if packet:
                from scapy.layers.inet import TCP, UDP, ICMP
                if packet.haslayer(TCP) and 'TCP' in allowed_protocols:
                    return True, "Inbound TCP is allowed"
                if packet.haslayer(UDP) and 'UDP' in allowed_protocols:
                    return True, "Inbound UDP is allowed"
                if packet.haslayer(ICMP) and 'ICMP' in allowed_protocols:
                    return True, "Inbound ICMP is allowed"

        # Connection behavior matching for servers
        elif behavior_type == 'connection_behavior':
            # Server expects high connection rate
            if params.get('high_connection_rate') or params.get('accepts_connections'):
                if threat_type in ('CONNECTION_FLOOD', 'PORT_SCAN', 'HIGH_RISK_ATTACK_CHAIN',
                                   'UNUSUAL_PACKET_SIZE', 'HTTP_EXCESSIVE_POSTS'):
                    return True, "High connection rate is expected for this server"

            # API server behavior
            if params.get('api_server'):
                if threat_type in ('HIGH_RISK_ATTACK_CHAIN', 'CONNECTION_FLOOD',
                                   'UNUSUAL_PACKET_SIZE', 'HTTP_EXCESSIVE_POSTS',
                                   'API_ABUSE_RATE_LIMIT', 'API_ABUSE_ENDPOINT'):
                    return True, "API server expects many connections"

        # Traffic pattern matching
        elif behavior_type == 'traffic_pattern':
            if params.get('high_bandwidth') or params.get('receives_streams'):
                if threat_type in ('HIGH_INBOUND_VOLUME', 'UNUSUAL_PACKET_SIZE', 'BANDWIDTH_SATURATION'):
                    return True, "High inbound bandwidth is expected"

        # Explicit alert type suppression (for management interfaces, etc.)
        elif behavior_type == 'suppress_alert_types':
            alert_types = params.get('alert_types', [])
            if threat_type in alert_types:
                return True, f"Alert type {threat_type} is explicitly allowed"

        return False, None

    def _match_behavior(self, threat_type: str, behavior_type: str,
                       params: Dict, threat: Dict, packet, dst_ip: str) -> Tuple[bool, Optional[str]]:
        """
        Match a specific behavior rule against a threat.

        Returns:
            Tuple of (matches: bool, reason: str or None)
        """
        # Port-based matching
        if behavior_type == 'allowed_ports':
            allowed_ports = set(params.get('ports', []))
            direction = params.get('direction')  # 'inbound', 'outbound', or None (both)

            # Extract port from threat metadata or packet (with defensive check)
            dst_port = None
            src_port = None
            if isinstance(threat, dict):
                metadata = threat.get('metadata', {})
                if isinstance(metadata, dict):
                    dst_port = metadata.get('destination_port')
                    src_port = metadata.get('source_port')

            if packet:
                from scapy.layers.inet import TCP, UDP
                if packet.haslayer(TCP):
                    dst_port = dst_port or packet[TCP].dport
                    src_port = src_port or packet[TCP].sport
                elif packet.haslayer(UDP):
                    dst_port = dst_port or packet[UDP].dport
                    src_port = src_port or packet[UDP].sport

            # Check if port matches allowed list
            if direction == 'outbound' and dst_port in allowed_ports:
                return True, f"Outbound port {dst_port} is allowed"
            elif direction == 'inbound' and src_port in allowed_ports:
                return True, f"Inbound port {src_port} is allowed"
            elif direction is None:
                if dst_port in allowed_ports:
                    return True, f"Port {dst_port} is allowed"
                if src_port in allowed_ports:
                    return True, f"Port {src_port} is allowed"

        # Protocol-based matching
        elif behavior_type == 'allowed_protocols':
            # Handle mixed types in protocols list (could be strings or ints)
            raw_protocols = params.get('protocols', [])
            allowed_protocols = [str(p).upper() for p in raw_protocols if p is not None]

            if packet:
                from scapy.layers.inet import TCP, UDP, ICMP
                if packet.haslayer(TCP) and 'TCP' in allowed_protocols:
                    return True, "TCP protocol is allowed"
                if packet.haslayer(UDP) and 'UDP' in allowed_protocols:
                    return True, "UDP protocol is allowed"
                if packet.haslayer(ICMP) and 'ICMP' in allowed_protocols:
                    return True, "ICMP protocol is allowed"

                # Check for RTSP (typically TCP/554 or UDP/554)
                if 'RTSP' in allowed_protocols:
                    if packet.haslayer(TCP) and packet[TCP].dport in (554, 8554):
                        return True, "RTSP protocol is allowed"
                    if packet.haslayer(UDP) and packet[UDP].dport in (554, 8554):
                        return True, "RTSP protocol is allowed"

        # Destination-based matching (streaming services, CDN, specific IPs, etc.)
        elif behavior_type == 'expected_destinations':
            allowed_categories = params.get('categories', [])
            allowed_ips = params.get('allowed_ips', [])
            internal_only = params.get('internal_only', False)

            # Check explicit allowed IPs/CIDRs first (for cases like UniFi controller)
            if allowed_ips and dst_ip:
                try:
                    dst = ipaddress.ip_address(dst_ip)
                    for allowed in allowed_ips:
                        try:
                            if '/' in str(allowed):
                                # CIDR notation
                                if dst in ipaddress.ip_network(allowed, strict=False):
                                    return True, f"Destination {dst_ip} is in allowed network {allowed}"
                            else:
                                # Single IP
                                if dst == ipaddress.ip_address(allowed):
                                    return True, f"Destination {dst_ip} is explicitly allowed"
                        except ValueError:
                            continue
                except ValueError:
                    pass

            if internal_only:
                # Check if destination is internal
                try:
                    dst = ipaddress.ip_address(dst_ip)
                    internal_nets = [
                        ipaddress.ip_network('10.0.0.0/8'),
                        ipaddress.ip_network('172.16.0.0/12'),
                        ipaddress.ip_network('192.168.0.0/16')
                    ]
                    if any(dst in net for net in internal_nets):
                        return True, "Internal destination is allowed"
                except ValueError:
                    pass
            else:
                # Check if destination is a known service provider
                provider = self._check_ip_in_service_providers(dst_ip)
                if provider and provider['category'] in allowed_categories:
                    return True, f"Destination is {provider['name']} ({provider['category']})"

        # Traffic pattern matching
        elif behavior_type == 'traffic_pattern':
            # High bandwidth devices (NAS, Smart TV streaming)
            if params.get('high_bandwidth') or params.get('streaming'):
                # Suppress high volume alerts for streaming devices
                if threat_type in ('HIGH_OUTBOUND_VOLUME', 'UNUSUAL_PACKET_SIZE', 'BANDWIDTH_SATURATION'):
                    return True, "High bandwidth traffic is expected"

            # Continuous streams (cameras)
            if params.get('continuous'):
                if threat_type in ('BEACONING', 'HIGH_OUTBOUND_VOLUME'):
                    return True, "Continuous streaming is expected"

        # Connection behavior matching
        elif behavior_type == 'connection_behavior':
            # High connection rate servers
            if params.get('high_connection_rate') or params.get('accepts_connections'):
                if threat_type in ('CONNECTION_FLOOD', 'PORT_SCAN', 'HIGH_RISK_ATTACK_CHAIN',
                                   'UNUSUAL_PACKET_SIZE', 'HTTP_EXCESSIVE_POSTS'):
                    return True, "High connection rate is expected for servers"

            # API server behavior
            if params.get('api_server'):
                if threat_type in ('HTTP_EXCESSIVE_POSTS', 'API_ABUSE_RATE_LIMIT', 'API_ABUSE_ENDPOINT'):
                    return True, "API server expects many requests"

            # Low frequency IoT devices
            if params.get('low_frequency') and params.get('periodic'):
                if threat_type == 'BEACONING':
                    return True, "Periodic connections expected for IoT sensor"

        # DNS behavior matching
        elif behavior_type == 'dns_behavior':
            if threat_type in ('DNS_TUNNEL', 'DNS_ANOMALY'):
                # Smart devices often make many cloud DNS queries
                if params.get('allow_cloud_dns'):
                    return True, "Cloud DNS queries are expected"

        # Explicit alert type suppression (for management interfaces, etc.)
        elif behavior_type == 'suppress_alert_types':
            alert_types = params.get('alert_types', [])
            if threat_type in alert_types:
                return True, f"Alert type {threat_type} is explicitly allowed"

        return False, None

    def filter_threats(self, threats: List[Dict], packet=None) -> List[Dict]:
        """
        Filter a list of threats, marking suppressed ones.

        Args:
            threats: List of threat dictionaries
            packet: Optional scapy packet for context

        Returns:
            Filtered list with suppressed threats marked
        """
        filtered = []

        for threat in threats:
            # Skip non-dict items (malformed threats)
            if not isinstance(threat, dict):
                self.logger.warning(f"Skipping non-dict threat: {type(threat)}")
                continue

            suppress, reason = self.should_suppress_alert(threat, packet)

            if suppress:
                # Mark as suppressed instead of removing
                # This preserves audit trail
                threat['suppressed'] = True
                threat['suppression_reason'] = reason
                self.logger.debug(
                    f"Suppressed {threat.get('type')} for {threat.get('source_ip')}: {reason}"
                )
            else:
                threat['suppressed'] = False

            filtered.append(threat)

        return filtered

    def get_active_threats(self, threats: List[Dict]) -> List[Dict]:
        """
        Get only non-suppressed threats from a filtered list.

        Args:
            threats: List of threat dictionaries (already filtered)

        Returns:
            List of threats that were not suppressed
        """
        return [t for t in threats if not t.get('suppressed', False)]

    def invalidate_cache(self, ip_address: str = None):
        """
        Invalidate cache entries.

        Args:
            ip_address: Specific IP to invalidate, or None for all
        """
        with self._cache_lock:
            if ip_address:
                self._device_cache.pop(ip_address, None)
                self._cache_timestamps.pop(ip_address, None)
            else:
                self._device_cache.clear()
                self._cache_timestamps.clear()

        self.logger.debug(f"Cache invalidated: {ip_address or 'all'}")

    def get_statistics(self) -> Dict:
        """Get suppression statistics"""
        return {
            **self.stats,
            'suppression_rate': round(
                (self.stats['alerts_suppressed'] / self.stats['alerts_checked'] * 100)
                if self.stats['alerts_checked'] > 0 else 0, 2
            ),
            'cache_hit_rate': round(
                (self.stats['cache_hits'] / (self.stats['cache_hits'] + self.stats['cache_misses']) * 100)
                if (self.stats['cache_hits'] + self.stats['cache_misses']) > 0 else 0, 2
            ),
            'cached_devices': len(self._device_cache),
            'service_provider_ranges': len(self._service_provider_ranges),
            'global_allowed_categories': list(self._global_allowed_categories)
        }
