# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Behavior Detection Module
Detecteert verdacht gedrag van interne machines
"""

import time
import logging
import json
import ipaddress
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Tuple

from scapy.layers.inet import IP, TCP, UDP


class BehaviorDetector:
    """Detecteert behavior-based threats"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('NetMonitor.Behavior')

        # Internal network ranges
        self.internal_networks = self._parse_internal_networks()

        # Beaconing detection
        # Track: IP -> [(timestamp, dest_ip, dest_port), ...]
        self.connection_tracker = defaultdict(lambda: deque(maxlen=1000))

        # Outbound traffic volume tracking
        # Track: src_ip -> {total_bytes, last_reset_time, dest_ips: {ip: bytes}}
        self.outbound_volume = defaultdict(lambda: {
            'total_bytes': 0,
            'last_reset': time.time(),
            'dest_ips': defaultdict(int),
            'packet_count': 0
        })

        # Lateral movement detection
        # Track: src_ip -> {scanned_ips: set(), protocols: defaultdict(int)}
        self.lateral_tracker = defaultdict(lambda: {
            'scanned_ips': set(),
            'protocols': defaultdict(int),
            'first_seen': None,
            'last_seen': None
        })

        # Known beacons (already alerted to prevent spam)
        self.known_beacons = {}  # (src_ip, dst_ip, dst_port) -> last_alert_time

        self.logger.info("Behavior Detector geïnitialiseerd")

    def _get_threshold(self, *keys, default=None):
        """
        Safely get a threshold value from config with fallback to default.
        Usage: self._get_threshold('beaconing', 'min_connections', default=10)
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

    def _parse_internal_networks(self):
        """Parse internal network ranges"""
        networks = []
        internal_ranges = self.config.get('internal_networks', [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        ])

        # Protect against None
        if internal_ranges is None:
            internal_ranges = [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16'
            ]

        for net_str in internal_ranges:
            try:
                networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError as e:
                self.logger.warning(f"Ongeldig internal network: {net_str}: {e}")

        return networks

    def is_internal_ip(self, ip_str: str) -> bool:
        """Check of IP in internal network zit"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.internal_networks)
        except ValueError:
            return False

    def analyze_packet(self, packet) -> List[dict]:
        """
        Analyseer packet voor behavior-based threats

        Returns:
            Lijst van threat dicts
        """
        threats = []

        if not packet.haslayer(IP):
            return threats

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Alleen interessant als source internal is
        if not self.is_internal_ip(src_ip):
            return threats

        # Beaconing detection
        if self._get_threshold('beaconing', 'enabled', default=True):
            threat = self._detect_beaconing(packet)
            if threat:
                threats.append(threat)

        # Outbound traffic volume
        if self._get_threshold('outbound_volume', 'enabled', default=True):
            threat = self._track_outbound_volume(packet)
            if threat:
                threats.append(threat)

        # Lateral movement
        if self._get_threshold('lateral_movement', 'enabled', default=True):
            threat = self._detect_lateral_movement(packet)
            if threat:
                threats.append(threat)

        return threats

    def _detect_beaconing(self, packet) -> dict:
        """
        Detecteer beaconing behavior (regelmatige callbacks naar C&C)

        Beaconing kenmerken:
        - Regelmatige connecties naar zelfde destination
        - Vergelijkbare tijd intervallen
        - Vaak naar externe IPs
        """
        if not packet.haslayer(TCP) and not packet.haslayer(UDP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Check alleen outbound traffic (internal -> external)
        if self.is_internal_ip(dst_ip):
            return None

        current_time = time.time()

        # Bepaal destination port
        dst_port = None
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        # Skip uitgesloten poorten (bijv. NTP) die inherent periodiek zijn
        excluded_ports = self._get_threshold('beaconing', 'excluded_ports', default=[])
        if dst_port and dst_port in excluded_ports:
            return None

        # Track connection
        connections = self.connection_tracker[src_ip]
        connections.append((current_time, dst_ip, dst_port))

        # Analyseer alleen als we genoeg data hebben
        min_connections = self._get_threshold('beaconing', 'min_connections', default=10)
        if len(connections) < min_connections:
            return None

        # Check voor regelmatige connecties naar zelfde destination
        dest_connections = [(ts, port) for ts, ip, port in connections
                           if ip == dst_ip and port == dst_port]

        if len(dest_connections) < min_connections:
            return None

        # Bereken interval consistentie
        intervals = []
        for i in range(1, len(dest_connections)):
            interval = dest_connections[i][0] - dest_connections[i-1][0]
            intervals.append(interval)

        if not intervals:
            return None

        # Check consistentie: zijn intervallen ongeveer gelijk?
        avg_interval = sum(intervals) / len(intervals)
        max_jitter = self._get_threshold('beaconing', 'max_jitter_percent', default=20) / 100.0

        # Count hoeveel intervallen binnen jitter range zitten
        consistent_intervals = sum(1 for interval in intervals
                                  if abs(interval - avg_interval) <= (avg_interval * max_jitter))

        consistency_ratio = consistent_intervals / len(intervals)

        # Als >70% van intervallen consistent zijn, is het waarschijnlijk beaconing
        if consistency_ratio >= 0.7:
            # Check of we al recent alert voor deze beacon hebben
            beacon_key = (src_ip, dst_ip, dst_port)
            if beacon_key in self.known_beacons:
                last_alert = self.known_beacons[beacon_key]
                if current_time - last_alert < 300:  # 5 minuten
                    return None

            self.known_beacons[beacon_key] = current_time

            return {
                'type': 'BEACONING_DETECTED',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'description': f'Beaconing gedetecteerd: {len(dest_connections)} connecties met avg interval {avg_interval:.1f}s',
                'avg_interval': avg_interval,
                'consistency': consistency_ratio,
                'connection_count': len(dest_connections),
                'metadata': json.dumps({
                    'interval': round(avg_interval, 1),
                    'consistency': round(consistency_ratio, 2),
                    'connection_count': len(dest_connections),
                    'destination_port': dst_port
                })
            }

        return None

    def _track_outbound_volume(self, packet) -> dict:
        """
        Track outbound traffic volume per internal IP

        Alert bij abnormaal hoge data volumes (mogelijk exfiltration)
        """
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Alleen outbound
        if self.is_internal_ip(dst_ip):
            return None

        current_time = time.time()
        packet_size = len(packet)

        # Update tracking
        tracker = self.outbound_volume[src_ip]
        tracker['total_bytes'] += packet_size
        tracker['packet_count'] += 1
        tracker['dest_ips'][dst_ip] += packet_size

        # Reset window als tijd verstreken is
        time_window = self._get_threshold('outbound_volume', 'time_window', default=300)
        if current_time - tracker['last_reset'] >= time_window:
            total_bytes = tracker['total_bytes']
            total_mb = total_bytes / (1024 * 1024)

            threshold_mb = self._get_threshold('outbound_volume', 'threshold_mb', default=100)

            # Check threshold
            if total_mb > threshold_mb:
                # Top 5 destinations
                top_dests = sorted(tracker['dest_ips'].items(),
                                  key=lambda x: x[1], reverse=True)[:5]

                threat = {
                    'type': 'HIGH_OUTBOUND_VOLUME',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'description': f'Hoog outbound volume: {total_mb:.2f} MB in {time_window}s',
                    'volume_mb': total_mb,
                    'packet_count': tracker['packet_count'],
                    'top_destinations': [{'ip': ip, 'mb': bytes / (1024*1024)}
                                        for ip, bytes in top_dests]
                }

                # Reset tracker
                tracker['total_bytes'] = 0
                tracker['packet_count'] = 0
                tracker['dest_ips'].clear()
                tracker['last_reset'] = current_time

                return threat

            # Reset zonder alert
            tracker['total_bytes'] = 0
            tracker['packet_count'] = 0
            tracker['dest_ips'].clear()
            tracker['last_reset'] = current_time

        return None

    def _detect_lateral_movement(self, packet) -> dict:
        """
        Detecteer lateral movement binnen netwerk

        Kenmerken:
        - Internal IP scant andere internal IPs
        - SMB (445), RDP (3389), SSH (22), WinRM (5985) poorten
        - Veel verschillende internal destinations
        """
        if not packet.haslayer(TCP):
            return None

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport

        # Check beide IPs internal
        if not (self.is_internal_ip(src_ip) and self.is_internal_ip(dst_ip)):
            return None

        # Lateral movement ports
        lateral_ports = {
            22: 'SSH',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            3389: 'RDP',
            5985: 'WinRM',
            5986: 'WinRM-HTTPS'
        }

        if dst_port not in lateral_ports:
            return None

        current_time = time.time()

        # Track
        tracker = self.lateral_tracker[src_ip]
        if tracker['first_seen'] is None:
            tracker['first_seen'] = current_time

        tracker['last_seen'] = current_time
        tracker['scanned_ips'].add(dst_ip)
        tracker['protocols'][lateral_ports[dst_port]] += 1

        # Check thresholds
        time_window = self._get_threshold('lateral_movement', 'time_window', default=300)
        if current_time - tracker['first_seen'] > time_window:
            # Reset
            scanned_count = len(tracker['scanned_ips'])
            protocols = dict(tracker['protocols'])

            threshold = self._get_threshold('lateral_movement', 'unique_targets', default=5)

            if scanned_count >= threshold:
                # Alert
                threat = {
                    'type': 'LATERAL_MOVEMENT',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Mogelijk lateral movement: {scanned_count} interne IPs gescand binnen {time_window}s',
                    'targets_scanned': scanned_count,
                    'protocols': protocols,
                    'sample_targets': list(tracker['scanned_ips'])[:10]
                }

                # Reset tracker
                tracker['scanned_ips'].clear()
                tracker['protocols'].clear()
                tracker['first_seen'] = current_time

                return threat

            # Reset zonder alert
            tracker['scanned_ips'].clear()
            tracker['protocols'].clear()
            tracker['first_seen'] = current_time

        return None

    def cleanup_old_data(self):
        """Cleanup oude tracking data (call periodiek)"""
        current_time = time.time()
        max_dest_ips = 500  # Max destination IPs to track per source
        max_scanned_ips = 1000  # Max scanned IPs to track per source

        # Cleanup outbound volume trackers (ouder dan 30 minuten - was 1 uur)
        outbound_cleaned = 0
        for ip in list(self.outbound_volume.keys()):
            tracker = self.outbound_volume[ip]
            if current_time - tracker['last_reset'] > 1800:  # 30 min
                del self.outbound_volume[ip]
                outbound_cleaned += 1
            else:
                # Limit dest_ips to prevent memory leak
                if len(tracker['dest_ips']) > max_dest_ips:
                    # Keep only top IPs by bytes
                    sorted_ips = sorted(tracker['dest_ips'].items(), key=lambda x: x[1], reverse=True)
                    tracker['dest_ips'] = defaultdict(int, dict(sorted_ips[:max_dest_ips]))

        # Cleanup lateral movement trackers (ouder dan 5 minuten - was 10 min)
        lateral_cleaned = 0
        for ip in list(self.lateral_tracker.keys()):
            tracker = self.lateral_tracker[ip]
            if tracker['last_seen'] and (current_time - tracker['last_seen']) > 300:  # 5 min
                del self.lateral_tracker[ip]
                lateral_cleaned += 1
            else:
                # Limit scanned_ips to prevent memory leak
                if len(tracker['scanned_ips']) > max_scanned_ips:
                    tracker['scanned_ips'] = set(list(tracker['scanned_ips'])[-max_scanned_ips:])

        # Cleanup old beacons (ouder dan 30 minuten - was 1 uur)
        beacons_cleaned = 0
        for key in list(self.known_beacons.keys()):
            if current_time - self.known_beacons[key] > 1800:  # 30 min
                del self.known_beacons[key]
                beacons_cleaned += 1

        # Cleanup inactive connection tracker entries (maxlen=1000 deques zijn nooit leeg
        # voor actieve IPs, dus controleer op laatste timestamp i.p.v. lege deque)
        conn_cutoff = current_time - 300  # 5 minuten inactief
        conn_cleaned = 0
        for ip in list(self.connection_tracker.keys()):
            deq = self.connection_tracker[ip]
            if not deq or deq[-1][0] < conn_cutoff:
                del self.connection_tracker[ip]
                conn_cleaned += 1

        if outbound_cleaned + lateral_cleaned + beacons_cleaned + conn_cleaned > 0:
            self.logger.debug(f"Behavior cleanup: outbound={outbound_cleaned}, lateral={lateral_cleaned}, "
                            f"beacons={beacons_cleaned}, conn={conn_cleaned}")
