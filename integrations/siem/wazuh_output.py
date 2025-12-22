# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Wazuh SIEM integration.

Provides native integration with Wazuh SIEM using:
- Wazuh API for direct event injection
- Syslog fallback for compatibility
- Custom decoder/rules management
"""

import json
import requests
from typing import Dict, Optional, Tuple, List
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import warnings

from .base_siem import SIEMOutput
from .formatters import CEFFormatter


class WazuhOutput(SIEMOutput):
    """
    Wazuh SIEM native integration.

    Supports both:
    - Direct API integration (recommended)
    - Syslog forwarding (fallback)
    """

    name = "wazuh"
    display_name = "Wazuh SIEM"
    description = "Native Wazuh SIEM integration with API and syslog support"
    version = "1.0.0"

    def __init__(self, config: Dict = None):
        """
        Initialize Wazuh integration.

        Config options:
            api_url: Wazuh API URL (or WAZUH_API_URL env var)
            api_user: API username (or WAZUH_API_USER env var)
            api_password: API password (or WAZUH_API_PASSWORD env var)
            verify_ssl: Verify SSL certificate (default: True)
            use_api: Use API for sending events (default: True)
            syslog_fallback: Fall back to syslog if API fails (default: True)
            syslog_host: Syslog host (or SYSLOG_HOST env var)
            syslog_port: Syslog port (default: 514)

        Environment variables (take precedence over config):
            WAZUH_API_URL: Wazuh API URL
            WAZUH_API_USER: Wazuh API username
            WAZUH_API_PASSWORD: Wazuh API password
            SYSLOG_HOST: Syslog host for fallback
        """
        super().__init__(config)

        from ..base import get_config_value

        self.api_url = get_config_value(config, 'api_url', 'WAZUH_API_URL', '').rstrip('/')
        self.api_user = get_config_value(config, 'api_user', 'WAZUH_API_USER', '')
        self.api_password = get_config_value(config, 'api_password', 'WAZUH_API_PASSWORD', '')
        self.verify_ssl = config.get('verify_ssl', True)
        self.use_api = config.get('use_api', True)
        self.syslog_fallback = config.get('syslog_fallback', True)
        self.syslog_host = get_config_value(config, 'syslog_host', 'SYSLOG_HOST') or self._extract_host(self.api_url)
        self.syslog_port = config.get('syslog_port', 514)

        # API token (obtained during authentication)
        self._token = None
        self._token_expires = None

        # CEF formatter for syslog fallback
        self.cef_formatter = CEFFormatter(include_raw=True)

        # Suppress SSL warnings if verify_ssl is False
        if not self.verify_ssl:
            warnings.filterwarnings('ignore', category=InsecureRequestWarning)

    def _extract_host(self, url: str) -> str:
        """Extract hostname from URL"""
        if not url:
            return 'localhost'
        # Remove protocol
        if '://' in url:
            url = url.split('://', 1)[1]
        # Remove port and path
        return url.split(':')[0].split('/')[0]

    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """Validate Wazuh configuration"""
        if self.use_api:
            if not self.api_url:
                return False, "Wazuh API URL is required"
            if not self.api_user:
                return False, "Wazuh API username is required"
            if not self.api_password:
                return False, "Wazuh API password is required"

        return True, None

    def _authenticate(self) -> bool:
        """Authenticate with Wazuh API and obtain token"""
        if not self.use_api:
            return False

        try:
            response = requests.post(
                f"{self.api_url}/security/user/authenticate",
                auth=(self.api_user, self.api_password),
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self._token = data.get('data', {}).get('token')
                # Token typically valid for 15 minutes
                self._token_expires = datetime.now()
                self.logger.info("Successfully authenticated with Wazuh API")
                return True
            else:
                self.logger.error(f"Wazuh authentication failed: {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(f"Wazuh authentication error: {e}")
            return False

    def _ensure_token(self) -> bool:
        """Ensure we have a valid API token"""
        # Check if token needs refresh (refresh every 10 minutes to be safe)
        if self._token and self._token_expires:
            elapsed = (datetime.now() - self._token_expires).total_seconds()
            if elapsed < 600:  # Token still valid
                return True

        return self._authenticate()

    def _api_headers(self) -> Dict:
        """Get API request headers"""
        return {
            'Authorization': f'Bearer {self._token}',
            'Content-Type': 'application/json'
        }

    def health_check(self) -> bool:
        """Check Wazuh API health"""
        try:
            if self.use_api:
                if not self._ensure_token():
                    return False

                response = requests.get(
                    f"{self.api_url}/manager/status",
                    headers=self._api_headers(),
                    verify=self.verify_ssl,
                    timeout=10
                )

                self._healthy = response.status_code == 200
            else:
                # Just check syslog connectivity
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.syslog_host, self.syslog_port))
                sock.close()
                self._healthy = True

            self._last_check = datetime.now()
            return self._healthy

        except Exception as e:
            self._healthy = False
            self._last_check = datetime.now()
            self._last_error = str(e)
            return False

    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to Wazuh"""
        try:
            if self.use_api:
                if not self._authenticate():
                    return False, "Failed to authenticate with Wazuh API"

                # Get manager info
                response = requests.get(
                    f"{self.api_url}/manager/info",
                    headers=self._api_headers(),
                    verify=self.verify_ssl,
                    timeout=10
                )

                if response.status_code == 200:
                    info = response.json().get('data', {}).get('affected_items', [{}])[0]
                    version = info.get('version', 'unknown')
                    return True, f"Connected to Wazuh {version}"
                else:
                    return False, f"API returned status {response.status_code}"

            else:
                # Test syslog
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.syslog_host, self.syslog_port))
                sock.close()
                return True, f"Syslog connection to {self.syslog_host}:{self.syslog_port} successful"

        except Exception as e:
            return False, f"Connection test failed: {e}"

    def send_alert(self, alert: Dict) -> bool:
        """
        Send an alert to Wazuh.

        Tries API first, falls back to syslog if configured.
        """
        if not self.enabled:
            return False

        success = False

        # Try API first
        if self.use_api:
            success = self._send_via_api(alert)

        # Fall back to syslog
        if not success and self.syslog_fallback:
            success = self._send_via_syslog(alert)

        return success

    def _send_via_api(self, alert: Dict) -> bool:
        """Send alert via Wazuh API"""
        try:
            if not self._ensure_token():
                return False

            # Format event for Wazuh
            event = self._format_wazuh_event(alert)

            response = requests.post(
                f"{self.api_url}/events",
                headers=self._api_headers(),
                json={'events': [event]},
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code in (200, 201):
                self.record_success()
                return True
            else:
                self.logger.warning(f"Wazuh API returned {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(f"Error sending to Wazuh API: {e}")
            return False

    def _send_via_syslog(self, alert: Dict) -> bool:
        """Send alert via syslog"""
        try:
            import socket

            # Format as CEF
            cef_message = self.cef_formatter.format(alert)

            # Build syslog message
            priority = 134  # local0.info
            timestamp = datetime.now().strftime('%b %d %H:%M:%S')
            hostname = socket.gethostname()

            message = f"<{priority}>{timestamp} {hostname} netmonitor: {cef_message}"

            # Send via UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode('utf-8'), (self.syslog_host, self.syslog_port))
            sock.close()

            self.record_success()
            return True

        except Exception as e:
            self.record_failure(str(e))
            return False

    def _format_wazuh_event(self, alert: Dict) -> Dict:
        """Format alert as Wazuh event"""
        # Clean IPs
        src_ip = alert.get('source_ip', '')
        if '/' in src_ip:
            src_ip = src_ip.split('/')[0]

        dst_ip = alert.get('destination_ip', '')
        if '/' in dst_ip:
            dst_ip = dst_ip.split('/')[0]

        return {
            'netmonitor': {
                'alert_id': alert.get('id'),
                'threat_type': alert.get('threat_type'),
                'severity': alert.get('severity'),
                'description': alert.get('description'),
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': alert.get('destination_port'),
                'protocol': alert.get('protocol'),
                'sensor_id': alert.get('sensor_id'),
                'timestamp': alert.get('timestamp').isoformat() if isinstance(alert.get('timestamp'), datetime) else alert.get('timestamp'),
                'acknowledged': alert.get('acknowledged', False),
                'metadata': alert.get('metadata')
            }
        }

    def get_decoder_config(self) -> str:
        """
        Get Wazuh decoder configuration for NetMonitor.

        Returns XML decoder configuration to be placed in
        /var/ossec/etc/decoders/netmonitor_decoder.xml
        """
        return '''<!-- NetMonitor Decoder for Wazuh -->
<decoder name="netmonitor">
  <program_name>netmonitor</program_name>
</decoder>

<decoder name="netmonitor-cef">
  <parent>netmonitor</parent>
  <prematch>CEF:</prematch>
  <regex>CEF:\d+\|NetMonitor\|NetMonitor\|\S+\|(\S+)\|(.+)\|(\d+)\|(.+)</regex>
  <order>threat_type, description, severity, extension</order>
</decoder>

<decoder name="netmonitor-cef-fields">
  <parent>netmonitor-cef</parent>
  <regex offset="after_parent">src=(\S+)</regex>
  <order>srcip</order>
</decoder>

<decoder name="netmonitor-cef-fields">
  <parent>netmonitor-cef</parent>
  <regex offset="after_parent">dst=(\S+)</regex>
  <order>dstip</order>
</decoder>

<decoder name="netmonitor-cef-fields">
  <parent>netmonitor-cef</parent>
  <regex offset="after_parent">dpt=(\d+)</regex>
  <order>dstport</order>
</decoder>
'''

    def get_rules_config(self) -> str:
        """
        Get Wazuh rules configuration for NetMonitor.

        Returns XML rules configuration to be placed in
        /var/ossec/etc/rules/netmonitor_rules.xml
        """
        return '''<!-- NetMonitor Rules for Wazuh -->
<group name="netmonitor,network,">

  <!-- Base rule for all NetMonitor alerts -->
  <rule id="100100" level="5">
    <decoded_as>netmonitor-cef</decoded_as>
    <description>NetMonitor: $(description)</description>
    <group>netmonitor,</group>
  </rule>

  <!-- Port Scan Detection -->
  <rule id="100101" level="10">
    <if_sid>100100</if_sid>
    <field name="threat_type">PORT_SCAN</field>
    <description>NetMonitor: Port scan detected from $(srcip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>netmonitor,attack,recon,</group>
  </rule>

  <!-- Brute Force Detection -->
  <rule id="100102" level="10">
    <if_sid>100100</if_sid>
    <field name="threat_type">BRUTE_FORCE</field>
    <description>NetMonitor: Brute force attempt from $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>netmonitor,attack,authentication_failures,</group>
  </rule>

  <!-- DNS Tunnel Detection -->
  <rule id="100103" level="12">
    <if_sid>100100</if_sid>
    <field name="threat_type">^DNS_TUNNEL</field>
    <description>NetMonitor: DNS tunneling detected</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
    <group>netmonitor,attack,exfiltration,</group>
  </rule>

  <!-- C2 Communication Detection -->
  <rule id="100104" level="14">
    <if_sid>100100</if_sid>
    <field name="threat_type">C2_COMMUNICATION</field>
    <description>NetMonitor: C2 communication detected to $(dstip)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>netmonitor,attack,c2,</group>
  </rule>

  <!-- Data Exfiltration -->
  <rule id="100105" level="14">
    <if_sid>100100</if_sid>
    <field name="threat_type">DATA_EXFILTRATION</field>
    <description>NetMonitor: Data exfiltration detected from $(srcip)</description>
    <mitre>
      <id>T1048</id>
    </mitre>
    <group>netmonitor,attack,exfiltration,</group>
  </rule>

  <!-- Lateral Movement -->
  <rule id="100106" level="12">
    <if_sid>100100</if_sid>
    <field name="threat_type">LATERAL_MOVEMENT</field>
    <description>NetMonitor: Lateral movement detected from $(srcip)</description>
    <mitre>
      <id>T1021</id>
    </mitre>
    <group>netmonitor,attack,lateral_movement,</group>
  </rule>

  <!-- Beaconing Detection -->
  <rule id="100107" level="10">
    <if_sid>100100</if_sid>
    <field name="threat_type">BEACONING</field>
    <description>NetMonitor: Beaconing behavior detected from $(srcip)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>netmonitor,attack,c2,</group>
  </rule>

  <!-- Malicious IP Detection -->
  <rule id="100108" level="12">
    <if_sid>100100</if_sid>
    <field name="threat_type">KNOWN_MALICIOUS_IP</field>
    <description>NetMonitor: Connection to known malicious IP $(dstip)</description>
    <group>netmonitor,threat_intel,</group>
  </rule>

  <!-- Critical severity override -->
  <rule id="100199" level="15">
    <if_sid>100100</if_sid>
    <field name="severity">10</field>
    <description>NetMonitor Critical Alert: $(description)</description>
    <group>netmonitor,critical,</group>
  </rule>

</group>
'''
