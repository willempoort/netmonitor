# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Baseline Deviation Detector
Vergelijkt live netwerkverkeer van een apparaat met zijn eigen geleerde
gedragsprofiel (learned_behavior, opgebouwd door device_discovery.py) en
signaleert afwijkingen: een nieuwe bestemming, een nieuwe poort, een nieuw
protocol, of een sterke toename in dataverkeer t.o.v. de eigen historische
baseline van dat specifieke apparaat.

Dit verschilt van BehaviorMatcher, die verkeer toetst aan een generiek
device-template (wat is normaal voor dit apparaat-TYPE). Deze detector kijkt
naar het individueel geleerde gedrag van dit ene apparaat.
"""

import json
import time
import logging
import ipaddress
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from scapy.layers.inet import IP, TCP, UDP

PROTOCOL_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


class BaselineDeviationDetector:
    """Signaleert afwijkingen van het geleerde gedragsprofiel per apparaat."""

    def __init__(self, config, db_manager=None):
        self.config = config
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.BaselineDeviation')

        self.internal_networks = self._parse_internal_networks()

        # Cache van opgehaalde baselines: ip -> baseline dict (of None)
        self._cache: Dict[str, Optional[Dict]] = {}
        self._cache_timestamps: Dict[str, datetime] = {}
        self._cache_ttl = 300  # zelfde interval als learned_behavior refresh

        # Rolling volume tracking per device, voor de volume-toename check
        self._volume_window = defaultdict(lambda: {'bytes': 0, 'last_reset': time.time()})

        # Cooldown om herhaalde identieke alerts te voorkomen
        self._recent_alerts: Dict[tuple, float] = {}
        self._alert_cooldown = 900  # 15 minuten
        self._last_cleanup = time.time()

        self.logger.info("BaselineDeviationDetector geïnitialiseerd")

    def _get_threshold(self, *keys, default=None):
        """Zelfde helper-patroon als behavior_detector.py/detector.py."""
        try:
            value = self.config['thresholds']
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def _parse_internal_networks(self):
        networks = []
        internal_ranges = self.config.get('internal_networks') or [
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
        ]
        for net_str in internal_ranges:
            try:
                networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError as e:
                self.logger.warning(f"Ongeldig internal network: {net_str}: {e}")
        return networks

    def is_internal_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.internal_networks)
        except ValueError:
            return False

    def _get_baseline(self, ip_address: str) -> Optional[Dict]:
        """Haal het geleerde gedragsprofiel van een apparaat op (met cache)."""
        now = datetime.now()
        cached_at = self._cache_timestamps.get(ip_address)
        if cached_at and (now - cached_at).total_seconds() < self._cache_ttl:
            return self._cache.get(ip_address)

        baseline = None
        if self.db:
            try:
                device = self.db.get_device_by_ip(ip_address)
                learned = device.get('learned_behavior') if device else None
                if isinstance(learned, str):
                    try:
                        learned = json.loads(learned)
                    except (json.JSONDecodeError, TypeError):
                        learned = None

                if learned:
                    duration_hours = learned.get('observation_period', {}).get('duration_hours', 0)
                    min_hours = self._get_threshold('baseline_deviation', 'min_observation_hours', default=24)
                    if duration_hours >= min_hours:
                        traffic = learned.get('traffic_summary', {})
                        ports = learned.get('ports', {})
                        baseline = {
                            'device_id': device.get('id'),
                            'destinations': set(learned.get('typical_destinations', [])),
                            'total_destinations': traffic.get('unique_outbound_destinations', 0),
                            'outbound_ports': set(ports.get('outbound_destination_ports', [])),
                            'inbound_ports': set(ports.get('inbound_source_ports', [])),
                            'protocols': set(ports.get('protocols', [])),
                            'bytes_per_hour': traffic.get('bytes_per_hour', 0),
                        }
            except Exception as e:
                self.logger.debug(f"Kon baseline voor {ip_address} niet ophalen: {e}")

        self._cache[ip_address] = baseline
        self._cache_timestamps[ip_address] = now
        return baseline

    def _should_alert(self, key: tuple) -> bool:
        """Cooldown check om herhaalde identieke alerts te onderdrukken."""
        now = time.time()
        last = self._recent_alerts.get(key)
        if last and (now - last) < self._alert_cooldown:
            return False
        self._recent_alerts[key] = now
        return True

    def analyze_packet(self, packet) -> List[Dict]:
        """
        Analyseer packet t.o.v. de geleerde baseline van betrokken apparaten.
        Returns: lijst van threat dicts
        """
        threats = []

        if not self._get_threshold('baseline_deviation', 'enabled', default=True):
            return threats

        if not packet.haslayer(IP):
            return threats

        if time.time() - self._last_cleanup > 300:
            self.cleanup_old_data()

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        dst_port = src_port = None
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            src_port = packet[UDP].sport

        # Outbound: src_ip is het gemonitorde apparaat
        if self.is_internal_ip(src_ip):
            baseline = self._get_baseline(src_ip)
            if baseline:
                threats.extend(self._check_outbound(baseline, src_ip, dst_ip, dst_port, proto))
                if not self.is_internal_ip(dst_ip):
                    vol_threat = self._check_volume(baseline, src_ip, len(packet))
                    if vol_threat:
                        threats.append(vol_threat)

        # Inbound: dst_ip is het gemonitorde apparaat
        if self.is_internal_ip(dst_ip):
            baseline = self._get_baseline(dst_ip)
            if baseline:
                threats.extend(self._check_inbound(baseline, dst_ip, src_ip, src_port, proto))

        return threats

    def _check_outbound(self, baseline: Dict, src_ip: str, dst_ip: str,
                        dst_port: Optional[int], proto: int) -> List[Dict]:
        threats = []
        device_id = baseline['device_id']

        # Nieuwe bestemming - alleen zinvol bij een beperkt, stabiel bestemmingenpalet.
        # Bij apparaten met veel unieke bestemmingen (bv. een laptop) is "nieuwe
        # bestemming" geen bruikbaar signaal en zou het alleen ruis opleveren.
        stable_max = self._get_threshold('baseline_deviation', 'stable_destination_max', default=15)
        if baseline['total_destinations'] and baseline['total_destinations'] <= stable_max:
            if dst_ip not in baseline['destinations']:
                key = (src_ip, 'BASELINE_NEW_DESTINATION', dst_ip)
                if self._should_alert(key):
                    threats.append({
                        'type': 'BASELINE_NEW_DESTINATION',
                        'severity': 'MEDIUM',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': (
                            f'{src_ip} verbindt met nieuwe bestemming {dst_ip}, buiten de '
                            f'geleerde baseline van {len(baseline["destinations"])} bekende bestemmingen'
                        ),
                        'metadata': {'device_id': device_id, 'baseline_destination_count': len(baseline['destinations'])}
                    })

        if dst_port and baseline['outbound_ports'] and dst_port not in baseline['outbound_ports']:
            key = (src_ip, 'BASELINE_NEW_PORT', dst_port)
            if self._should_alert(key):
                threats.append({
                    'type': 'BASELINE_NEW_PORT',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': (
                        f'{src_ip} gebruikt poort {dst_port}, niet eerder gezien in de geleerde '
                        f'baseline ({len(baseline["outbound_ports"])} bekende poorten)'
                    ),
                    'metadata': {'device_id': device_id, 'destination_port': dst_port}
                })

        if baseline['protocols'] and proto not in baseline['protocols']:
            key = (src_ip, 'BASELINE_NEW_PROTOCOL', proto)
            if self._should_alert(key):
                threats.append({
                    'type': 'BASELINE_NEW_PROTOCOL',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': (
                        f'{src_ip} gebruikt protocol {PROTOCOL_NAMES.get(proto, proto)}, '
                        f'niet eerder gezien in de geleerde baseline'
                    ),
                    'metadata': {'device_id': device_id, 'protocol': proto}
                })

        return threats

    def _check_inbound(self, baseline: Dict, dst_ip: str, src_ip: str,
                       src_port: Optional[int], proto: int) -> List[Dict]:
        threats = []
        device_id = baseline['device_id']

        # Alleen zinvol als het apparaat al bekend staat als server (heeft
        # eerder inbound verkeer geaccepteerd) - anders is elke inbound
        # connectie "nieuw" en levert dit alleen ruis op naast port scan/
        # connection flood detectie die dat al dekt.
        if baseline['inbound_ports'] and src_port and src_port not in baseline['inbound_ports']:
            key = (dst_ip, 'BASELINE_NEW_PORT', src_port)
            if self._should_alert(key):
                threats.append({
                    'type': 'BASELINE_NEW_PORT',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': (
                        f'{dst_ip} ontvangt verkeer op poort {src_port}, niet eerder gezien in de '
                        f'geleerde baseline ({len(baseline["inbound_ports"])} bekende poorten)'
                    ),
                    'metadata': {'device_id': device_id, 'destination_port': src_port}
                })

        if baseline['protocols'] and proto not in baseline['protocols']:
            key = (dst_ip, 'BASELINE_NEW_PROTOCOL', proto)
            if self._should_alert(key):
                threats.append({
                    'type': 'BASELINE_NEW_PROTOCOL',
                    'severity': 'MEDIUM',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': (
                        f'{dst_ip} ontvangt protocol {PROTOCOL_NAMES.get(proto, proto)}, '
                        f'niet eerder gezien in de geleerde baseline'
                    ),
                    'metadata': {'device_id': device_id, 'protocol': proto}
                })

        return threats

    def _check_volume(self, baseline: Dict, src_ip: str, packet_len: int) -> Optional[Dict]:
        """Vergelijk het huidige uitgaande volume met de eigen historische baseline."""
        window = self._volume_window[src_ip]
        window['bytes'] += packet_len

        time_window = self._get_threshold('baseline_deviation', 'volume_time_window', default=300)
        now = time.time()
        elapsed = now - window['last_reset']
        if elapsed < time_window:
            return None

        baseline_bytes_per_hour = baseline.get('bytes_per_hour', 0)
        observed_bytes = window['bytes']
        window['bytes'] = 0
        window['last_reset'] = now

        if not baseline_bytes_per_hour:
            return None  # geen betrouwbare baseline om tegen te vergelijken

        observed_bytes_per_hour = observed_bytes / elapsed * 3600
        multiplier = self._get_threshold('baseline_deviation', 'volume_multiplier', default=3.0)

        if observed_bytes_per_hour <= baseline_bytes_per_hour * multiplier:
            return None

        key = (src_ip, 'BASELINE_VOLUME_INCREASE', int(observed_bytes_per_hour // 1_000_000))
        if not self._should_alert(key):
            return None

        return {
            'type': 'BASELINE_VOLUME_INCREASE',
            'severity': 'MEDIUM',
            'source_ip': src_ip,
            'description': (
                f'{src_ip} verstuurt {observed_bytes_per_hour / 1_000_000:.1f} MB/uur, '
                f'{observed_bytes_per_hour / baseline_bytes_per_hour:.1f}x de geleerde baseline '
                f'van {baseline_bytes_per_hour / 1_000_000:.1f} MB/uur'
            ),
            'metadata': {
                'device_id': baseline['device_id'],
                'observed_bytes_per_hour': round(observed_bytes_per_hour),
                'baseline_bytes_per_hour': round(baseline_bytes_per_hour),
            }
        }

    def cleanup_old_data(self):
        """Cleanup oude tracking data om memory leaks te voorkomen (periodiek aangeroepen)."""
        now = time.time()
        self._last_cleanup = now

        for ip in list(self._volume_window.keys()):
            if now - self._volume_window[ip]['last_reset'] > 1800:  # 30 min inactief
                del self._volume_window[ip]

        for key in list(self._recent_alerts.keys()):
            if now - self._recent_alerts[key] > self._alert_cooldown:
                del self._recent_alerts[key]

        cutoff = datetime.now()
        for ip in list(self._cache_timestamps.keys()):
            if (cutoff - self._cache_timestamps[ip]).total_seconds() > self._cache_ttl:
                self._cache.pop(ip, None)
                self._cache_timestamps.pop(ip, None)

    def get_statistics(self) -> Dict:
        return {
            'cached_baselines': len([v for v in self._cache.values() if v]),
            'tracked_volume_windows': len(self._volume_window),
            'recent_alert_cooldowns': len(self._recent_alerts),
        }
