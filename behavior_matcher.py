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

        # Service provider IP ranges cache
        self._service_provider_ranges: List[Tuple] = []  # (network, provider_info)
        self._provider_cache_timestamp: Optional[datetime] = None

        # Statistics
        self.stats = {
            'alerts_checked': 0,
            'alerts_suppressed': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

        # Load initial data
        self._refresh_service_providers()

        self.logger.info("BehaviorMatcher initialized")

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

    def should_suppress_alert(self, threat: Dict, packet=None) -> Tuple[bool, Optional[str]]:
        """
        Determine if an alert should be suppressed based on device template.

        Args:
            threat: Threat dictionary with type, severity, source_ip, etc.
            packet: Optional scapy packet for additional context

        Returns:
            Tuple of (should_suppress: bool, reason: str or None)
        """
        self.stats['alerts_checked'] += 1

        src_ip = threat.get('source_ip')
        dst_ip = threat.get('destination_ip')
        threat_type = threat.get('type', '')

        if not src_ip:
            return False, None

        # Never suppress critical security threats
        if threat.get('severity') == 'CRITICAL':
            return False, None

        # Never suppress threat feed matches or C2 communication
        if threat_type in ('THREAT_FEED_MATCH', 'C2_COMMUNICATION', 'BLACKLISTED_IP'):
            return False, None

        # Get template for source device
        template = self._get_device_template(src_ip)

        if not template:
            return False, None

        behaviors = template.get('behaviors', [])
        template_name = template.get('name', 'Unknown')

        # Check each behavior rule
        for behavior in behaviors:
            if behavior.get('action') != 'allow':
                continue

            behavior_type = behavior.get('behavior_type')
            params = behavior.get('parameters', {})

            # Match behavior type to threat type
            suppress, reason = self._match_behavior(
                threat_type, behavior_type, params, threat, packet, dst_ip
            )

            if suppress:
                self.stats['alerts_suppressed'] += 1
                return True, f"Template '{template_name}': {reason}"

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

            # Extract port from threat metadata or packet
            dst_port = threat.get('metadata', {}).get('destination_port')
            src_port = threat.get('metadata', {}).get('source_port')

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
            allowed_protocols = [p.upper() for p in params.get('protocols', [])]

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

        # Destination-based matching (streaming services, CDN, etc.)
        elif behavior_type == 'expected_destinations':
            allowed_categories = params.get('categories', [])
            internal_only = params.get('internal_only', False)

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
                if threat_type in ('HIGH_OUTBOUND_VOLUME', 'UNUSUAL_PACKET_SIZE'):
                    return True, "High bandwidth traffic is expected"

            # Continuous streams (cameras)
            if params.get('continuous'):
                if threat_type in ('BEACONING', 'HIGH_OUTBOUND_VOLUME'):
                    return True, "Continuous streaming is expected"

        # Connection behavior matching
        elif behavior_type == 'connection_behavior':
            # High connection rate servers
            if params.get('high_connection_rate'):
                if threat_type == 'CONNECTION_FLOOD':
                    return True, "High connection rate is expected for servers"

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
            'service_provider_ranges': len(self._service_provider_ranges)
        }
