# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Syslog output for SIEM integration.

Supports:
- UDP syslog (default)
- TCP syslog
- TLS-encrypted syslog
- Multiple output formats (CEF, LEEF, JSON)
"""

import socket
import ssl
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime

from .base_siem import SIEMOutput
from .formatters import CEFFormatter, LEEFFormatter, JSONFormatter


class SyslogOutput(SIEMOutput):
    """
    Syslog output adapter for SIEM integration.

    Sends NetMonitor alerts to a syslog server in various formats.
    """

    name = "syslog"
    display_name = "Syslog Output"
    description = "Send alerts to syslog server (supports CEF, LEEF, JSON)"
    version = "1.0.0"

    # Syslog facilities
    FACILITIES = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23
    }

    # Syslog severities (RFC 5424)
    SYSLOG_SEVERITIES = {
        'CRITICAL': 2,  # Critical
        'HIGH': 3,      # Error
        'MEDIUM': 4,    # Warning
        'LOW': 5,       # Notice
        'INFO': 6       # Informational
    }

    def __init__(self, config: Dict = None):
        """
        Initialize syslog output.

        Config options:
            host: Syslog server hostname/IP (or SYSLOG_HOST env var)
            port: Syslog server port (or SYSLOG_PORT env var)
            protocol: udp, tcp, or tls (or SYSLOG_PROTOCOL env var)
            format: cef, leef, or json (or SYSLOG_FORMAT env var)
            facility: Syslog facility (default: local0)
            tls_cert: Path to TLS certificate (for tls protocol)
            tls_verify: Verify TLS certificate (default: True)

        Environment variables (take precedence over config):
            SYSLOG_HOST: Syslog server hostname/IP
            SYSLOG_PORT: Syslog server port
            SYSLOG_PROTOCOL: Protocol (udp, tcp, tls)
            SYSLOG_FORMAT: Output format (cef, leef, json)
        """
        super().__init__(config)

        from ..base import get_config_value

        self.host = get_config_value(config, 'host', 'SYSLOG_HOST', 'localhost')
        self.port = int(get_config_value(config, 'port', 'SYSLOG_PORT', 514))
        self.protocol = get_config_value(config, 'protocol', 'SYSLOG_PROTOCOL', 'udp').lower()
        self.format = get_config_value(config, 'format', 'SYSLOG_FORMAT', 'cef').lower()
        self.facility = config.get('facility', 'local0')
        self.tls_cert = config.get('tls_cert')
        self.tls_verify = config.get('tls_verify', True)

        # Get facility number
        self.facility_num = self.FACILITIES.get(self.facility, 16)

        # Initialize formatter
        if self.format == 'cef':
            self.formatter = CEFFormatter(include_raw=config.get('include_raw', False))
        elif self.format == 'leef':
            self.formatter = LEEFFormatter()
        elif self.format == 'json':
            self.formatter = JSONFormatter(include_all=True)
        else:
            self.logger.warning(f"Unknown format '{self.format}', defaulting to CEF")
            self.formatter = CEFFormatter()

        # Socket (lazy initialization)
        self._socket = None
        self._connected = False

    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """Validate syslog configuration"""
        if not self.host:
            return False, "Syslog host is required"

        if self.port < 1 or self.port > 65535:
            return False, f"Invalid port: {self.port}"

        if self.protocol not in ('udp', 'tcp', 'tls'):
            return False, f"Invalid protocol: {self.protocol}"

        if self.protocol == 'tls' and not self.tls_cert:
            return False, "TLS certificate path required for TLS protocol"

        if self.format not in ('cef', 'leef', 'json'):
            return False, f"Invalid format: {self.format}"

        return True, None

    def _connect(self) -> bool:
        """Establish connection to syslog server"""
        try:
            if self.protocol == 'udp':
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._connected = True

            elif self.protocol == 'tcp':
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(10)
                self._socket.connect((self.host, self.port))
                self._connected = True

            elif self.protocol == 'tls':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)

                context = ssl.create_default_context()
                if self.tls_cert:
                    context.load_verify_locations(self.tls_cert)
                if not self.tls_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                self._socket = context.wrap_socket(sock, server_hostname=self.host)
                self._socket.connect((self.host, self.port))
                self._connected = True

            self.logger.info(f"Connected to syslog server {self.host}:{self.port} ({self.protocol})")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to syslog server: {e}")
            self._connected = False
            return False

    def _disconnect(self) -> None:
        """Close connection to syslog server"""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
            self._connected = False

    def health_check(self) -> bool:
        """Check if syslog server is reachable"""
        try:
            # For UDP, we can only verify socket creation
            if self.protocol == 'udp':
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_socket.close()
                self._healthy = True
                self._last_check = datetime.now()
                return True

            # For TCP/TLS, try to connect
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            test_socket.connect((self.host, self.port))
            test_socket.close()

            self._healthy = True
            self._last_check = datetime.now()
            return True

        except Exception as e:
            self._healthy = False
            self._last_check = datetime.now()
            self._last_error = str(e)
            return False

    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to syslog server"""
        try:
            if not self._connect():
                return False, f"Failed to connect to {self.host}:{self.port}"

            # Send a test message
            test_alert = {
                'id': 0,
                'threat_type': 'TEST_CONNECTION',
                'severity': 'INFO',
                'source_ip': '127.0.0.1',
                'destination_ip': '127.0.0.1',
                'description': 'NetMonitor syslog connection test',
                'timestamp': datetime.now(),
                'sensor_id': 'netmonitor'
            }

            success = self.send_alert(test_alert)

            if success:
                return True, f"Successfully connected to {self.host}:{self.port} ({self.protocol}/{self.format})"
            else:
                return False, "Connected but failed to send test message"

        except Exception as e:
            return False, f"Connection test failed: {e}"

    def send_alert(self, alert: Dict) -> bool:
        """
        Send an alert to the syslog server.

        Args:
            alert: Alert dictionary

        Returns:
            True if successful
        """
        if not self.enabled:
            return False

        try:
            # Ensure connection
            if not self._connected:
                if not self._connect():
                    return False

            # Format the alert
            formatted = self.formatter.format(alert)

            # Build syslog message with priority
            severity_str = alert.get('severity', 'MEDIUM')
            syslog_severity = self.SYSLOG_SEVERITIES.get(severity_str, 4)
            priority = (self.facility_num * 8) + syslog_severity

            # RFC 5424 format
            timestamp = datetime.now().strftime('%b %d %H:%M:%S')
            hostname = socket.gethostname()

            syslog_message = f"<{priority}>{timestamp} {hostname} netmonitor: {formatted}"

            # Send based on protocol
            message_bytes = syslog_message.encode('utf-8')

            if self.protocol == 'udp':
                self._socket.sendto(message_bytes, (self.host, self.port))
            else:
                # TCP/TLS - add newline for message framing
                self._socket.send(message_bytes + b'\n')

            self.record_success()
            return True

        except Exception as e:
            self.record_failure(str(e))
            self._disconnect()  # Force reconnect on next send
            return False

    def close(self) -> None:
        """Close the syslog connection"""
        self._disconnect()
