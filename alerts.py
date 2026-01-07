# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Alert Management Module
Handelt het versturen en loggen van security alerts
"""

import logging
import time
from collections import deque
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class AlertManager:
    """Beheert security alerts"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('NetMonitor.Alerts')

        # Rate limiting
        self.alert_history = deque(maxlen=1000)
        self.max_alerts_per_minute = config.get('alerts', {}).get('max_per_minute', 100)

        # Alert file
        self.alert_file = None
        if config.get('alerts', {}).get('file_enabled', True):
            alert_file_path = config.get('logging', {}).get('file', '/var/log/netmonitor/alerts.log')
            alert_path = Path(alert_file_path).parent / 'security_alerts.log'
            alert_path.parent.mkdir(parents=True, exist_ok=True)
            self.alert_file = alert_path

        self.logger.info("Alert Manager geïnitialiseerd")

    def send_alert(self, threat, packet):
        """
        Verstuur een security alert

        Args:
            threat: Dict met threat informatie
            packet: Het scapy packet object
        """
        # Rate limiting check
        if not self._check_rate_limit():
            self.logger.warning("Alert rate limit bereikt, alert wordt geskipped")
            return

        # Maak alert bericht
        alert_msg = self._format_alert(threat, packet)

        # Log naar console met kleuren
        severity = threat.get('severity', 'UNKNOWN')
        self._log_to_console(alert_msg, severity)

        # Log naar file
        if self.alert_file:
            self._log_to_file(alert_msg)

        # Log naar syslog indien geconfigureerd
        if self.config.get('alerts', {}).get('syslog_enabled', False):
            self._log_to_syslog(alert_msg, severity)

    def _check_rate_limit(self):
        """Check of we binnen rate limits zijn"""
        current_time = time.time()
        self.alert_history.append(current_time)

        # Tel alerts in laatste minuut
        cutoff_time = current_time - 60
        recent_alerts = sum(1 for ts in self.alert_history if ts > cutoff_time)

        return recent_alerts <= self.max_alerts_per_minute

    def _format_alert(self, threat, packet):
        """Formatteer threat informatie naar alert bericht"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        alert_parts = [
            f"[{timestamp}]",
            f"[{threat.get('severity', 'UNKNOWN')}]",
            f"[{threat.get('type', 'UNKNOWN')}]",
        ]

        # Add description if present
        if 'description' in threat:
            alert_parts.append(f"{threat['description']}")

        # Voeg extra details toe
        if 'source_ip' in threat:
            alert_parts.append(f"Source: {threat['source_ip']}")

        if 'destination_ip' in threat:
            alert_parts.append(f"Destination: {threat['destination_ip']}")

        # Type-specifieke details
        if 'ports_scanned' in threat:
            alert_parts.append(f"Ports: {threat['ports_scanned']}")

        if 'connection_count' in threat:
            alert_parts.append(f"Connections: {threat['connection_count']}")

        if 'packet_size' in threat:
            alert_parts.append(f"Size: {threat['packet_size']} bytes")

        if 'query' in threat:
            alert_parts.append(f"Query: {threat['query']}")

        return " | ".join(alert_parts)

    def _log_to_console(self, message, severity):
        """Log alert naar console met kleuren"""
        if not self.config['logging']['console']:
            return

        if COLORAMA_AVAILABLE:
            color = self._get_severity_color(severity)
            print(f"{color}{message}{Style.RESET_ALL}")
        else:
            print(message)

    def _get_severity_color(self, severity):
        """Get kleur voor severity level"""
        colors = {
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.CYAN,
            'INFO': Fore.GREEN
        }
        return colors.get(severity, Fore.WHITE)

    def _log_to_file(self, message):
        """Log alert naar file"""
        try:
            with open(self.alert_file, 'a') as f:
                f.write(message + '\n')
        except Exception as e:
            self.logger.error(f"Fout bij schrijven naar alert file: {e}")

    def _log_to_syslog(self, message, severity):
        """Log alert naar syslog"""
        # Map severity naar syslog priority
        priority_map = {
            'HIGH': logging.ERROR,
            'MEDIUM': logging.WARNING,
            'LOW': logging.INFO,
            'INFO': logging.INFO
        }

        priority = priority_map.get(severity, logging.INFO)
        self.logger.log(priority, message)

    def get_stats(self):
        """Get alert statistieken"""
        current_time = time.time()
        cutoff_time = current_time - 60

        recent_alerts = sum(1 for ts in self.alert_history if ts > cutoff_time)

        return {
            'total_alerts': len(self.alert_history),
            'alerts_last_minute': recent_alerts,
            'rate_limit': self.max_alerts_per_minute
        }
