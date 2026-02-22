# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Metrics Collector
Collects and aggregates traffic statistics for dashboard
"""

import time
import logging
import psutil
import socket
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List
import ipaddress


class MetricsCollector:
    """Collects traffic and system metrics"""

    def __init__(self, config, database_manager=None):
        """Initialize metrics collector"""
        self.config = config
        self.db = database_manager
        self.logger = logging.getLogger('NetMonitor.Metrics')

        # Traffic counters
        self.total_packets = 0
        self.total_bytes = 0
        self.inbound_packets = 0
        self.inbound_bytes = 0
        self.outbound_packets = 0
        self.outbound_bytes = 0

        # Track last saved values for delta calculation (Option A)
        # Counters keep running for dashboard display, we only save deltas to database
        self.last_saved_packets = 0
        self.last_saved_bytes = 0
        self.last_saved_inbound_packets = 0
        self.last_saved_inbound_bytes = 0
        self.last_saved_outbound_packets = 0
        self.last_saved_outbound_bytes = 0

        # Per-IP statistics
        self.ip_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'outbound_bytes': 0,
            'inbound_bytes': 0,
            'direction': 'unknown'
        })

        # Alerts counter
        self.alert_count = 0
        self.last_alert_reset = time.time()

        # Packet rate tracking (deque met max 60s aan timestamps bij ~100 pps)
        self.packet_timestamps = deque(maxlen=6000)
        self.last_metrics_save = time.time()
        self.metrics_save_interval = 10  # 10 seconds - was 60, now much faster for dashboard
        self.first_packet_seen = False  # Track if we've seen any packets yet

        # Bandwidth tracking (for real-time Mbps calculation)
        self.bandwidth_window_start = time.time()
        self.bandwidth_window_bytes = 0

        # Internal networks (from config)
        self.internal_networks = self._parse_internal_networks()

        self.logger.info("Metrics Collector geïnitialiseerd")

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

    def track_packet(self, packet):
        """Track een packet voor statistieken"""
        try:
            from scapy.layers.inet import IP

            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            packet_size = len(packet)

            # Update totals
            self.total_packets += 1
            self.total_bytes += packet_size
            self.bandwidth_window_bytes += packet_size

            # Determine direction
            src_internal = self.is_internal_ip(src_ip)
            dst_internal = self.is_internal_ip(dst_ip)

            if src_internal and not dst_internal:
                # Outbound
                self.outbound_packets += 1
                self.outbound_bytes += packet_size
                self.ip_stats[src_ip]['packets'] += 1
                self.ip_stats[src_ip]['bytes'] += packet_size
                self.ip_stats[src_ip]['outbound_bytes'] += packet_size

            elif not src_internal and dst_internal:
                # Inbound (ACKs, responses) - getrackt op het interne doel-IP
                self.inbound_packets += 1
                self.inbound_bytes += packet_size
                self.ip_stats[dst_ip]['packets'] += 1
                self.ip_stats[dst_ip]['bytes'] += packet_size
                self.ip_stats[dst_ip]['inbound_bytes'] += packet_size

            elif src_internal and dst_internal:
                # Internal-to-internal traffic
                # Track both source and destination for top talkers
                # src stuurt (outbound), dst ontvangt (inbound)
                self.ip_stats[src_ip]['packets'] += 1
                self.ip_stats[src_ip]['bytes'] += packet_size
                self.ip_stats[src_ip]['outbound_bytes'] += packet_size
                self.ip_stats[src_ip]['direction'] = 'internal'

                self.ip_stats[dst_ip]['packets'] += 1
                self.ip_stats[dst_ip]['bytes'] += packet_size
                self.ip_stats[dst_ip]['inbound_bytes'] += packet_size
                self.ip_stats[dst_ip]['direction'] = 'internal'

            # Track packet rate
            current_time = time.time()
            self.packet_timestamps.append(current_time)

            # Verwijder timestamps ouder dan 60 seconden (deque is al begrensd op maxlen)
            cutoff = current_time - 60
            while self.packet_timestamps and self.packet_timestamps[0] < cutoff:
                self.packet_timestamps.popleft()

            # Force save on first packet for immediate dashboard feedback
            if not self.first_packet_seen:
                self.first_packet_seen = True
                self.save_metrics()
                self.last_metrics_save = current_time
                self.logger.info("First packet processed - metrics saved to database")
            # Then save metrics periodically
            elif current_time - self.last_metrics_save >= self.metrics_save_interval:
                self.save_metrics()
                self.last_metrics_save = current_time

        except Exception as e:
            self.logger.error(f"Error tracking packet: {e}")

    def track_alert(self):
        """Track een alert"""
        self.alert_count += 1

    def get_current_stats(self) -> Dict:
        """Get current statistics"""
        current_time = time.time()

        # Calculate packets per second
        if self.packet_timestamps:
            cutoff = current_time - 1  # Last second
            recent_packets = sum(1 for ts in self.packet_timestamps if ts > cutoff)
            packets_per_second = recent_packets
        else:
            packets_per_second = 0

        # Calculate alerts per minute
        time_since_reset = current_time - self.last_alert_reset
        if time_since_reset >= 60:
            alerts_per_minute = self.alert_count
            self.alert_count = 0
            self.last_alert_reset = current_time
        else:
            alerts_per_minute = int(self.alert_count / (time_since_reset / 60))

        # Calculate bandwidth in Mbps
        window_duration = current_time - self.bandwidth_window_start
        if window_duration > 0:
            # Convert bytes to Mbps: (bytes * 8) / (duration * 1000000)
            bandwidth_mbps = (self.bandwidth_window_bytes * 8) / (window_duration * 1_000_000)
        else:
            bandwidth_mbps = 0.0

        # NOTE: Don't reset bandwidth_window here - it's reset in save_metrics()
        # This allows consistent measurement windows even when get_current_stats()
        # is called frequently by dashboard polls

        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'inbound_packets': self.inbound_packets,
            'inbound_bytes': self.inbound_bytes,
            'outbound_packets': self.outbound_packets,
            'outbound_bytes': self.outbound_bytes,
            'packets_per_second': packets_per_second,
            'alerts_per_minute': alerts_per_minute,
            'bandwidth_mbps': round(bandwidth_mbps, 2),
            'timestamp': datetime.now().isoformat()
        }

    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get top IPs by traffic volume"""
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )[:limit]

        result = []
        for ip, stats in sorted_ips:
            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ip

            # Bepaal dominante richting op basis van byte-verhouding
            out_b = stats['outbound_bytes']
            in_b = stats['inbound_bytes']
            if out_b == 0 and in_b == 0:
                direction = stats['direction']  # internal traffic
            elif out_b > in_b * 3:
                direction = 'outbound'
            elif in_b > out_b * 3:
                direction = 'inbound'
            else:
                direction = 'bidirectional'

            result.append({
                'ip': ip,
                'hostname': hostname,
                'packets': stats['packets'],
                'bytes': stats['bytes'],
                'mb': round(stats['bytes'] / (1024 * 1024), 2),
                'outbound_mb': round(stats['outbound_bytes'] / (1024 * 1024), 2),
                'inbound_mb': round(stats['inbound_bytes'] / (1024 * 1024), 2),
                'direction': direction
            })

        return result

    def get_system_stats(self) -> Dict:
        """Get system resource statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent

            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'disk_percent': disk_percent,
                'memory_used_gb': round(memory.used / (1024**3), 2),
                'memory_total_gb': round(memory.total / (1024**3), 2)
            }
        except Exception as e:
            self.logger.error(f"Error getting system stats: {e}")
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_percent': 0,
                'memory_used_gb': 0,
                'memory_total_gb': 0
            }

    def save_metrics(self):
        """Save metrics to database"""
        if not self.db:
            return

        try:
            # Calculate deltas since last save (Option A: counters keep running)
            # This gives us interval data for the graph while keeping counters alive for dashboard
            delta_packets = self.total_packets - self.last_saved_packets
            delta_bytes = self.total_bytes - self.last_saved_bytes
            delta_inbound_packets = self.inbound_packets - self.last_saved_inbound_packets
            delta_inbound_bytes = self.inbound_bytes - self.last_saved_inbound_bytes
            delta_outbound_packets = self.outbound_packets - self.last_saved_outbound_packets
            delta_outbound_bytes = self.outbound_bytes - self.last_saved_outbound_bytes

            # Save traffic metrics (deltas for this interval)
            metrics = {
                'total_packets': delta_packets,
                'total_bytes': delta_bytes,
                'inbound_packets': delta_inbound_packets,
                'inbound_bytes': delta_inbound_bytes,
                'outbound_packets': delta_outbound_packets,
                'outbound_bytes': delta_outbound_bytes
            }
            self.db.add_traffic_metrics(metrics, sensor_id='soc-server')

            # Update last saved values (do NOT reset counters to 0!)
            # Counters keep running for real-time dashboard display
            self.last_saved_packets = self.total_packets
            self.last_saved_bytes = self.total_bytes
            self.last_saved_inbound_packets = self.inbound_packets
            self.last_saved_inbound_bytes = self.inbound_bytes
            self.last_saved_outbound_packets = self.outbound_packets
            self.last_saved_outbound_bytes = self.outbound_bytes

            # Save top talkers
            top_talkers = self.get_top_talkers(limit=20)
            if top_talkers:
                self.db.update_top_talkers(top_talkers, sensor_id='soc-server')

            # Reset IP stats after saving (track per interval, not cumulative)
            # This ensures top talkers shows most active hosts in last interval
            self.ip_stats.clear()

            # Save system stats
            current_stats = self.get_current_stats()
            system_stats = self.get_system_stats()

            # Reset bandwidth window after getting stats (consistent 10-second intervals)
            self.bandwidth_window_start = time.time()
            self.bandwidth_window_bytes = 0

            combined_stats = {
                **system_stats,
                'packets_per_second': current_stats['packets_per_second'],
                'alerts_per_minute': current_stats['alerts_per_minute'],
                'threat_feed_iocs': 0  # Will be filled by threat feed manager
            }
            self.db.add_system_stats(combined_stats)

            self.logger.debug("Metrics opgeslagen naar database")

        except Exception as e:
            self.logger.error(f"Error saving metrics: {e}")

    def reset_counters(self):
        """Reset alle counters (voor testing)"""
        self.total_packets = 0
        self.total_bytes = 0
        self.inbound_packets = 0
        self.inbound_bytes = 0
        self.outbound_packets = 0
        self.outbound_bytes = 0
        self.ip_stats.clear()
        self.packet_timestamps.clear()
        self.alert_count = 0
        self.bandwidth_window_start = time.time()
        self.bandwidth_window_bytes = 0

    def get_dashboard_metrics(self) -> Dict:
        """Get alle metrics voor dashboard"""
        current_stats = self.get_current_stats()
        system_stats = self.get_system_stats()
        top_talkers = self.get_top_talkers(limit=10)

        return {
            'traffic': current_stats,
            'system': system_stats,
            'top_talkers': top_talkers,
            'timestamp': datetime.now().isoformat()
        }
