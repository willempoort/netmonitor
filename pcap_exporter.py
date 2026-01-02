# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
PCAP Exporter Module

Provides selective packet capture storage for forensic analysis:
- Save suspicious packets when alerts are triggered
- Export specific traffic flows on demand
- Ring buffer for rolling packet capture
- MCP-accessible packet retrieval
"""

import os
import time
import logging
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable

from scapy.all import wrpcap, rdpcap, Packet
from scapy.layers.inet import IP, TCP, UDP


class PCAPExporter:
    """
    Manages selective PCAP storage for forensic analysis.

    Features:
    - Ring buffer for recent packets (configurable size)
    - Alert-triggered capture (save packets around alert time)
    - On-demand flow export
    - Automatic cleanup of old captures
    """

    def __init__(self, config: Dict = None, output_dir: str = None):
        self.config = config or {}
        self.logger = logging.getLogger('NetMonitor.PCAPExporter')

        # Configure output directory
        # Check both locations for backwards compatibility
        pcap_config = self.config.get('thresholds', {}).get('pcap_export', {})
        if not pcap_config:
            pcap_config = self.config.get('pcap_export', {})
        self.output_dir = Path(output_dir or pcap_config.get('output_dir', '/var/log/netmonitor/pcap'))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Ring buffer configuration
        self.buffer_size = pcap_config.get('buffer_size', 10000)  # packets
        self.packet_buffer = deque(maxlen=self.buffer_size)
        self.buffer_lock = threading.Lock()

        # Alert capture configuration
        self.alert_capture_enabled = pcap_config.get('alert_capture_enabled', True)
        self.pre_alert_packets = pcap_config.get('pre_alert_packets', 100)
        self.post_alert_packets = pcap_config.get('post_alert_packets', 50)

        # Flow tracking for selective export
        self.flow_buffers: Dict[str, deque] = {}
        self.flow_buffer_size = pcap_config.get('flow_buffer_size', 500)

        # Retention settings
        self.max_captures = pcap_config.get('max_captures', 100)
        self.max_age_hours = pcap_config.get('max_age_hours', 24)

        # Statistics
        self.stats = {
            'packets_buffered': 0,
            'captures_saved': 0,
            'alert_captures': 0,
            'flow_exports': 0,
        }

        # Post-alert capture state
        self.pending_captures: List[Dict] = []

        self.logger.info(f"PCAPExporter initialized: buffer={self.buffer_size}, output={self.output_dir}")

    def add_packet(self, packet: Packet):
        """
        Add a packet to the ring buffer.

        Call this for every captured packet to maintain
        a rolling window for alert-triggered captures.
        """
        with self.buffer_lock:
            self.packet_buffer.append({
                'packet': packet,
                'timestamp': time.time(),
            })
            self.stats['packets_buffered'] += 1

            # Track by flow for selective export
            if packet.haslayer(IP):
                flow_key = self._get_flow_key(packet)
                if flow_key not in self.flow_buffers:
                    self.flow_buffers[flow_key] = deque(maxlen=self.flow_buffer_size)
                self.flow_buffers[flow_key].append({
                    'packet': packet,
                    'timestamp': time.time(),
                })

        # Check for pending post-alert captures
        self._process_pending_captures()

    def capture_alert(self, alert: Dict, packet: Packet = None) -> Optional[str]:
        """
        Save packets around an alert for forensic analysis.

        Returns the path to the saved PCAP file.
        """
        if not self.alert_capture_enabled:
            return None

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            alert_type = alert.get('type', 'UNKNOWN').lower()
            src_ip = alert.get('source_ip', 'unknown').replace('.', '_')
            dst_ip = alert.get('destination_ip', 'unknown').replace('.', '_')

            filename = f"alert_{alert_type}_{src_ip}_to_{dst_ip}_{timestamp}.pcap"
            filepath = self.output_dir / filename

            # Get packets from buffer
            with self.buffer_lock:
                # Get pre-alert packets
                buffer_list = list(self.packet_buffer)
                pre_packets = [p['packet'] for p in buffer_list[-self.pre_alert_packets:]]

            # Include the triggering packet
            all_packets = pre_packets.copy()
            if packet:
                all_packets.append(packet)

            # Schedule post-alert capture
            if self.post_alert_packets > 0:
                self.pending_captures.append({
                    'filepath': filepath,
                    'packets': all_packets,
                    'remaining': self.post_alert_packets,
                    'alert': alert,
                    'flow_key': self._get_flow_key(packet) if packet and packet.haslayer(IP) else None,
                })
                self.logger.debug(f"Scheduled post-alert capture for {filepath}")
                return str(filepath)

            # Save immediately if no post-alert capture needed
            if all_packets:
                wrpcap(str(filepath), all_packets)
                self.stats['captures_saved'] += 1
                self.stats['alert_captures'] += 1
                self.logger.info(f"Saved alert PCAP: {filepath} ({len(all_packets)} packets)")
                self._cleanup_old_captures()
                return str(filepath)

            return None

        except Exception as e:
            self.logger.error(f"Error saving alert PCAP: {e}")
            return None

    def _process_pending_captures(self):
        """Process pending post-alert captures."""
        completed = []

        for capture in self.pending_captures:
            # Add packets from the flow if available
            flow_key = capture.get('flow_key')
            if flow_key and flow_key in self.flow_buffers:
                with self.buffer_lock:
                    flow_packets = [p['packet'] for p in self.flow_buffers[flow_key]]
                    # Add new packets not already captured
                    for pkt in flow_packets[-capture['remaining']:]:
                        if pkt not in capture['packets']:
                            capture['packets'].append(pkt)
                            capture['remaining'] -= 1

            # Check if we have enough post-alert packets
            if capture['remaining'] <= 0:
                try:
                    filepath = capture['filepath']
                    wrpcap(str(filepath), capture['packets'])
                    self.stats['captures_saved'] += 1
                    self.stats['alert_captures'] += 1
                    self.logger.info(f"Saved alert PCAP: {filepath} ({len(capture['packets'])} packets)")
                    completed.append(capture)
                except Exception as e:
                    self.logger.error(f"Error saving pending PCAP: {e}")
                    completed.append(capture)

        # Remove completed captures
        for capture in completed:
            self.pending_captures.remove(capture)

        self._cleanup_old_captures()

    def export_flow(self, src_ip: str, dst_ip: str,
                    src_port: int = None, dst_port: int = None,
                    protocol: str = None) -> Optional[str]:
        """
        Export packets for a specific network flow.

        Returns path to saved PCAP or None if no matching packets.
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename_parts = [
                'flow',
                src_ip.replace('.', '_'),
                'to',
                dst_ip.replace('.', '_'),
            ]
            if dst_port:
                filename_parts.append(f'port{dst_port}')
            filename_parts.append(timestamp)
            filename = '_'.join(filename_parts) + '.pcap'
            filepath = self.output_dir / filename

            matching_packets = []

            with self.buffer_lock:
                for entry in self.packet_buffer:
                    pkt = entry['packet']
                    if not pkt.haslayer(IP):
                        continue

                    ip = pkt[IP]
                    # Check IP match (either direction)
                    ip_match = (
                        (ip.src == src_ip and ip.dst == dst_ip) or
                        (ip.src == dst_ip and ip.dst == src_ip)
                    )
                    if not ip_match:
                        continue

                    # Check port match if specified
                    if (src_port or dst_port) and pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        port_match = True
                        if src_port and tcp.sport != src_port and tcp.dport != src_port:
                            port_match = False
                        if dst_port and tcp.sport != dst_port and tcp.dport != dst_port:
                            port_match = False
                        if not port_match:
                            continue
                    elif (src_port or dst_port) and pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        port_match = True
                        if src_port and udp.sport != src_port and udp.dport != src_port:
                            port_match = False
                        if dst_port and udp.sport != dst_port and udp.dport != dst_port:
                            port_match = False
                        if not port_match:
                            continue

                    matching_packets.append(pkt)

            if not matching_packets:
                self.logger.debug(f"No packets found for flow {src_ip} -> {dst_ip}")
                return None

            wrpcap(str(filepath), matching_packets)
            self.stats['captures_saved'] += 1
            self.stats['flow_exports'] += 1
            self.logger.info(f"Exported flow PCAP: {filepath} ({len(matching_packets)} packets)")

            self._cleanup_old_captures()
            return str(filepath)

        except Exception as e:
            self.logger.error(f"Error exporting flow: {e}")
            return None

    def export_by_filter(self, filter_func: Callable[[Packet], bool],
                         name: str = 'filtered') -> Optional[str]:
        """
        Export packets matching a custom filter function.

        Args:
            filter_func: Function that takes a packet and returns True to include
            name: Name for the output file

        Returns path to saved PCAP or None if no matching packets.
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'{name}_{timestamp}.pcap'
            filepath = self.output_dir / filename

            matching_packets = []

            with self.buffer_lock:
                for entry in self.packet_buffer:
                    pkt = entry['packet']
                    try:
                        if filter_func(pkt):
                            matching_packets.append(pkt)
                    except Exception:
                        continue

            if not matching_packets:
                return None

            wrpcap(str(filepath), matching_packets)
            self.stats['captures_saved'] += 1
            self.logger.info(f"Exported filtered PCAP: {filepath} ({len(matching_packets)} packets)")

            self._cleanup_old_captures()
            return str(filepath)

        except Exception as e:
            self.logger.error(f"Error exporting filtered PCAP: {e}")
            return None

    def list_captures(self) -> List[Dict[str, Any]]:
        """List all saved PCAP files with metadata."""
        captures = []
        try:
            for pcap_file in self.output_dir.glob('*.pcap'):
                stat = pcap_file.stat()
                captures.append({
                    'filename': pcap_file.name,
                    'path': str(pcap_file),
                    'size_bytes': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
            # Sort by creation time, newest first
            captures.sort(key=lambda x: x['created'], reverse=True)
        except Exception as e:
            self.logger.error(f"Error listing captures: {e}")
        return captures

    def get_capture(self, filename: str) -> Optional[bytes]:
        """
        Get PCAP file contents for download.

        Returns raw bytes of the PCAP file.
        """
        try:
            filepath = self.output_dir / filename
            if not filepath.exists():
                return None
            if not filepath.is_relative_to(self.output_dir):
                # Security: prevent path traversal
                return None
            return filepath.read_bytes()
        except Exception as e:
            self.logger.error(f"Error reading capture: {e}")
            return None

    def delete_capture(self, filename: str) -> bool:
        """Delete a PCAP file."""
        try:
            filepath = self.output_dir / filename
            if not filepath.exists():
                return False
            if not filepath.is_relative_to(self.output_dir):
                return False
            filepath.unlink()
            self.logger.info(f"Deleted capture: {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting capture: {e}")
            return False

    def _get_flow_key(self, packet: Packet) -> str:
        """Generate a unique key for a network flow."""
        if not packet.haslayer(IP):
            return 'unknown'

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        # Sort IPs to make flow bidirectional
        if src_ip > dst_ip:
            src_ip, dst_ip = dst_ip, src_ip

        port_info = ''
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            ports = sorted([tcp.sport, tcp.dport])
            port_info = f'_tcp_{ports[0]}_{ports[1]}'
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            ports = sorted([udp.sport, udp.dport])
            port_info = f'_udp_{ports[0]}_{ports[1]}'

        return f'{src_ip}_{dst_ip}{port_info}'

    def _cleanup_old_captures(self):
        """Remove old PCAP files based on retention settings."""
        try:
            captures = list(self.output_dir.glob('*.pcap'))

            # Sort by modification time
            captures.sort(key=lambda x: x.stat().st_mtime)

            # Remove by count
            while len(captures) > self.max_captures:
                old_capture = captures.pop(0)
                old_capture.unlink()
                self.logger.debug(f"Removed old capture (count limit): {old_capture.name}")

            # Remove by age
            cutoff_time = time.time() - (self.max_age_hours * 3600)
            for capture in captures:
                if capture.stat().st_mtime < cutoff_time:
                    capture.unlink()
                    self.logger.debug(f"Removed old capture (age limit): {capture.name}")

        except Exception as e:
            self.logger.error(f"Error cleaning up captures: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get exporter statistics."""
        stats = self.stats.copy()
        stats['buffer_size'] = len(self.packet_buffer)
        stats['buffer_capacity'] = self.buffer_size
        stats['active_flows'] = len(self.flow_buffers)
        stats['pending_captures'] = len(self.pending_captures)
        stats['saved_captures'] = len(list(self.output_dir.glob('*.pcap')))
        return stats

    def get_buffer_summary(self) -> Dict[str, Any]:
        """Get summary of packets in the ring buffer."""
        with self.buffer_lock:
            if not self.packet_buffer:
                return {'count': 0}

            entries = list(self.packet_buffer)
            oldest = entries[0]['timestamp'] if entries else None
            newest = entries[-1]['timestamp'] if entries else None

            # Count by protocol
            protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
            for entry in entries:
                pkt = entry['packet']
                if pkt.haslayer(TCP):
                    protocols['TCP'] += 1
                elif pkt.haslayer(UDP):
                    protocols['UDP'] += 1
                elif pkt.haslayer(IP) and pkt[IP].proto == 1:
                    protocols['ICMP'] += 1
                else:
                    protocols['Other'] += 1

            return {
                'count': len(entries),
                'oldest_timestamp': datetime.fromtimestamp(oldest).isoformat() if oldest else None,
                'newest_timestamp': datetime.fromtimestamp(newest).isoformat() if newest else None,
                'time_span_seconds': (newest - oldest) if (oldest and newest) else 0,
                'protocols': protocols,
            }
