#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Remote Sensor Client
Lightweight network monitor for distributed deployment (e.g., Nano Pi)

Captures and analyzes traffic locally, then batches alerts to central SOC server.
"""

import os
import sys
import time
import logging
import socket
import psutil
import requests
import argparse
import signal
from datetime import datetime
from collections import deque
from pathlib import Path

# Add current dir to path
sys.path.insert(0, str(Path(__file__).parent))

from config_loader import load_config
from detector import ThreatDetector
from threat_feeds import ThreatFeedManager
from behavior_detector import BehaviorDetector
from abuseipdb_client import AbuseIPDBClient

# Optional PCAP exporter (may not be needed on lightweight sensors)
try:
    from pcap_exporter import PCAPExporter
    PCAP_AVAILABLE = True
except ImportError:
    PCAPExporter = None
    PCAP_AVAILABLE = False


def load_sensor_config(config_file):
    """
    Load sensor configuration from either YAML or bash-style .conf file

    Supports both formats:
    - YAML: sensor.yaml (full config)
    - Bash: sensor.conf (KEY=value format, minimal config)
    """
    if not os.path.exists(config_file):
        return {}

    # Try to detect format by reading first non-comment line
    with open(config_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # If line has KEY=value format, it's bash-style
            if '=' in line and not line.startswith(' ') and ':' not in line:
                return _load_bash_config(config_file)
            # Otherwise assume YAML
            break

    # Try YAML first
    try:
        return load_config(config_file)
    except:
        # Fallback to bash-style
        return _load_bash_config(config_file)


def _load_bash_config(config_file):
    """Load bash-style configuration (KEY=value format)"""
    # Start with minimal defaults for detector
    config = {
        'thresholds': {},  # Will be filled by SOC server
        'whitelist': [],
        'blacklist': [],
        'internal_networks': [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]
    }

    with open(config_file, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Parse KEY=value
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]

                # Convert to nested dict structure expected by sensor_client
                if key == 'INTERFACE':
                    config['interface'] = value
                elif key == 'SOC_SERVER_URL':
                    config.setdefault('server', {})['url'] = value
                elif key == 'SENSOR_ID':
                    config.setdefault('sensor', {})['id'] = value
                elif key == 'SENSOR_LOCATION':
                    config.setdefault('sensor', {})['location'] = value
                elif key == 'SENSOR_TOKEN':
                    if value:  # Only set if not empty
                        config.setdefault('server', {})['token'] = value
                elif key == 'SSL_VERIFY':
                    config.setdefault('server', {})['ssl_verify'] = value.lower() in ('true', 'yes', '1')
                elif key == 'SENSOR_WHITELIST':
                    # Comma-separated list of IPs/CIDRs to whitelist
                    if value:
                        config['whitelist'] = [ip.strip() for ip in value.split(',')]

    return config

# Try scapy import
try:
    from scapy.all import sniff, conf
    conf.verb = 0  # Quiet mode
except ImportError:
    print("ERROR: scapy not installed. Install with: pip install scapy")
    sys.exit(1)


class SensorClient:
    """Remote sensor client that sends alerts to central SOC"""

    def __init__(self, config_file='config.yaml', server_url=None, sensor_id=None,
                 location=None, batch_interval=30):
        """
        Initialize sensor client

        Args:
            config_file: Path to config file
            server_url: Central SOC server URL (e.g., http://soc.example.com:8080)
            sensor_id: Unique sensor identifier
            location: Sensor location description
            batch_interval: Seconds between alert batch uploads
        """
        self.config = load_sensor_config(config_file)

        # Setup logging first (before anything that might need to log)
        self._setup_logging()
        self.logger = logging.getLogger('NetMonitor.Sensor')

        # Priority: CLI parameter > Environment variable > Config file
        self.server_url = (
            server_url or
            os.environ.get('SOC_SERVER_URL') or
            self.config.get('server', {}).get('url')
        )
        self.sensor_id = (
            sensor_id or
            os.environ.get('SENSOR_ID') or
            self.config.get('sensor', {}).get('id') or
            self._generate_sensor_id()
        )
        self.location = (
            location or
            os.environ.get('SENSOR_LOCATION') or
            self.config.get('sensor', {}).get('location', 'Unknown')
        )
        self.batch_interval = batch_interval
        self.running = False

        # Config ETag for caching (prevents unnecessary config downloads)
        self.config_etag = None

        # Authentication token
        self.token = (
            os.environ.get('SENSOR_TOKEN') or
            self.config.get('server', {}).get('token') or
            self.config.get('sensor', {}).get('token')
        )

        # SSL verification setting
        self.ssl_verify = self.config.get('server', {}).get('ssl_verify', True)
        if isinstance(self.ssl_verify, str):
            self.ssl_verify = self.ssl_verify.lower() in ('true', 'yes', '1')

        # Normalize server URL (add default port if missing)
        self.server_url = self._normalize_server_url(self.server_url)

        # Statistics
        self.packets_captured = 0
        self.alerts_sent = 0
        self.start_time = time.time()

        # Bandwidth tracking
        self.bytes_received = 0
        self.bytes_sent = 0
        self.bandwidth_window_start = time.time()
        self.bandwidth_window_bytes = 0  # Bytes in current measurement window

        # Alert buffer for batching
        self.alert_buffer = deque(maxlen=10000)  # Max 10k alerts in buffer

        # Validate configuration
        if not self.server_url:
            self.logger.error("SOC_SERVER_URL not configured!")
            print("ERROR: Set SOC_SERVER_URL environment variable or pass --server-url")
            sys.exit(1)

        self.logger.info(f"Sensor ID: {self.sensor_id}")
        self.logger.info(f"Location: {self.location}")
        self.logger.info(f"SOC Server: {self.server_url}")

        # Initialize components
        self._init_components()

        # Register with server
        self._register_sensor()

    def _generate_sensor_id(self):
        """Generate sensor ID from hostname if not specified"""
        hostname = socket.gethostname()
        self.logger.info(f"SENSOR_ID not specified, using hostname: {hostname}")
        return hostname

    def _normalize_server_url(self, url):
        """
        Normalize server URL by adding default port if missing

        Examples:
            https://soc.example.com           → https://soc.example.com:443
            http://soc.example.com            → http://soc.example.com:80
            https://soc.example.com:8443      → https://soc.example.com:8443 (unchanged)
            http://192.168.1.1:8080           → http://192.168.1.1:8080 (unchanged)
        """
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)

        # If port is already specified, return as-is
        if parsed.port:
            return url

        # Add default port based on scheme
        if parsed.scheme == 'https':
            default_port = 443
        elif parsed.scheme == 'http':
            default_port = 80
        else:
            # Unknown scheme, return as-is
            return url

        # Log warning when default port is used
        logger = logging.getLogger('NetMonitor.Sensor')
        logger.warning(f"⚠️  No port specified in SOC_SERVER_URL, using default port {default_port} for {parsed.scheme.upper()}")
        logger.warning(f"⚠️  Original URL: {url}")
        logger.warning(f"⚠️  If your SOC server runs on a different port (e.g., 8080), please specify it explicitly:")
        logger.warning(f"⚠️  Example: {parsed.scheme}://{parsed.hostname}:8080")

        # Reconstruct URL with explicit port
        netloc_with_port = f"{parsed.hostname}:{default_port}"
        normalized = urlunparse((
            parsed.scheme,
            netloc_with_port,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        return normalized

    def _get_headers(self):
        """Get HTTP headers with authentication token if available"""
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def _setup_logging(self):
        """Setup logging with fallback to console-only if file logging fails"""
        handlers = []

        # Try to setup file logging
        log_dir = '/var/log/netmonitor'
        log_file = os.path.join(log_dir, 'sensor.log')

        try:
            # Create log directory if it doesn't exist
            os.makedirs(log_dir, exist_ok=True)
            # Add file handler
            handlers.append(logging.FileHandler(log_file))
        except (OSError, PermissionError) as e:
            # If we can't create log directory or file, just use console
            print(f"Warning: Cannot create log file {log_file}: {e}")
            print("Logging to console only")

        # Always add console handler
        handlers.append(logging.StreamHandler())

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers
        )

    def _init_components(self):
        """Initialize threat detection components"""
        self.logger.info("Initializing threat detection components...")

        # Initialize threat feeds
        if self.config.get('threat_feeds', {}).get('enabled', False):
            try:
                cache_dir = self.config.get('threat_feeds', {}).get('cache_dir', '/var/cache/netmonitor/feeds')
                self.threat_feeds = ThreatFeedManager(cache_dir=cache_dir)
                self.logger.info("Threat Feed Manager enabled")
            except Exception as e:
                self.logger.error(f"Failed to initialize threat feeds: {e}")
                self.threat_feeds = None
        else:
            self.threat_feeds = None

        # Initialize behavior detector
        self.behavior_detector = BehaviorDetector(self.config)
        self.logger.info("Behavior Detector enabled")

        # Initialize AbuseIPDB client
        if self.config.get('abuseipdb', {}).get('enabled', False):
            api_key = self.config.get('abuseipdb', {}).get('api_key', '')
            if api_key:
                try:
                    rate_limit = self.config.get('abuseipdb', {}).get('rate_limit', 1000)
                    self.abuseipdb = AbuseIPDBClient(api_key, rate_limit=rate_limit)
                    self.logger.info("AbuseIPDB client enabled")
                except Exception as e:
                    self.logger.error(f"Failed to initialize AbuseIPDB: {e}")
                    self.abuseipdb = None
            else:
                self.abuseipdb = None
        else:
            self.abuseipdb = None

        # Initialize threat detector
        self.detector = ThreatDetector(
            config=self.config,
            threat_feed_manager=self.threat_feeds,
            behavior_detector=self.behavior_detector,
            abuseipdb_client=self.abuseipdb
        )
        self.logger.info("Threat Detector initialized")

        # Initialize PCAP exporter for NIS2 forensic evidence
        # Default: enabled for compliance, uploads to SOC server
        self.pcap_exporter = None
        pcap_config = self.config.get('thresholds', {}).get('pcap_export', {})
        # Default to ENABLED on sensors for NIS2 compliance
        pcap_enabled = pcap_config.get('enabled', True)
        # Upload PCAP to SOC server (default: True for centralized forensics)
        self.pcap_upload_enabled = pcap_config.get('upload_to_soc', True)
        # Keep local copy after upload (default: False to save storage)
        self.pcap_keep_local = pcap_config.get('keep_local_copy', False)

        if PCAP_AVAILABLE and pcap_enabled:
            try:
                self.pcap_exporter = PCAPExporter(config=self.config)
                upload_msg = "upload to SOC" if self.pcap_upload_enabled else "local only"
                self.logger.info(f"PCAP Exporter enabled for NIS2 forensic capture ({upload_msg})")
            except Exception as e:
                self.logger.warning(f"Could not initialize PCAP Exporter: {e}")
                self.pcap_exporter = None
        elif not PCAP_AVAILABLE:
            self.logger.debug("PCAP Exporter module not available")
        else:
            self.logger.debug("PCAP export disabled on sensor")

        # Fetch and cache server whitelist
        self._update_whitelist()

        # Fetch and merge server configuration
        self._update_config()

    def _update_config(self):
        """Fetch configuration from SOC server and merge with local config

        Uses ETag-based caching to minimize bandwidth:
        - Sends If-None-Match header with cached ETag
        - 304 response: config unchanged, skip update
        - 200 response: config changed, update and cache new ETag
        """
        try:
            # Prepare headers with ETag if we have one
            headers = self._get_headers()
            if self.config_etag:
                headers['If-None-Match'] = self.config_etag

            response = requests.get(
                f"{self.server_url}/api/config",
                headers=headers,
                params={
                    'sensor_id': self.sensor_id,
                    'include_defaults': 'false'  # Sensors use local config as base
                },
                timeout=10,
                verify=self.ssl_verify
            )

            # Handle 304 Not Modified (config unchanged)
            if response.status_code == 304:
                self.logger.debug("✓ Config unchanged (304 Not Modified)")
                return

            # Handle 200 OK (config available)
            if response.status_code == 200:
                # Save new ETag for next request
                new_etag = response.headers.get('ETag')
                if new_etag:
                    self.config_etag = new_etag

                result = response.json()
                if result.get('success'):
                    server_config = result.get('config', {})

                    if not server_config:
                        self.logger.info("No server-side config overrides")
                        return

                    # Deep merge server config with local config
                    # Server config takes precedence
                    merged_config = self._deep_merge_config(self.config.copy(), server_config)

                    # Update detector's config
                    self.detector.config = merged_config

                    # Update sensor location if changed
                    new_location = merged_config.get('sensor', {}).get('location')
                    if new_location and new_location != self.location:
                        old_location = self.location
                        self.location = new_location
                        self.logger.info(f"✓ Location updated: {old_location} → {new_location}")

                    # Log what changed
                    changes = self._count_config_differences(self.config, server_config)
                    if changes > 0:
                        self.logger.info(f"✓ Config updated from server: {changes} parameter(s) overridden")
                    else:
                        self.logger.info("✓ Config synced (no changes)")

                    # Update local config reference
                    self.config = merged_config

                else:
                    self.logger.warning(f"Failed to fetch config: {result.get('error')}")
            else:
                self.logger.warning(f"Config fetch returned status {response.status_code}")

        except Exception as e:
            self.logger.warning(f"Failed to update config from server: {e}")
            self.logger.info("Continuing with local config...")

    def _deep_merge_config(self, base: dict, override: dict) -> dict:
        """Deep merge two config dicts (override takes precedence)"""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_config(result[key], value)
            else:
                result[key] = value

        return result

    def _count_config_differences(self, base: dict, override: dict, prefix: str = "") -> int:
        """Count how many parameters are different between configs"""
        count = 0

        for key, value in override.items():
            path = f"{prefix}.{key}" if prefix else key

            if key not in base:
                count += 1
            elif isinstance(value, dict) and isinstance(base.get(key), dict):
                count += self._count_config_differences(base[key], value, path)
            elif base[key] != value:
                count += 1

        return count

    def _update_whitelist(self):
        """Fetch whitelist from SOC server and merge with local config"""
        try:
            response = requests.get(
                f"{self.server_url}/api/whitelist",
                headers=self._get_headers(),
                params={'sensor_id': self.sensor_id},
                timeout=10,
                verify=self.ssl_verify
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    entries = result.get('entries', [])

                    # Extract IP CIDRs from whitelist entries
                    server_whitelist = [entry['ip_cidr'] for entry in entries]

                    # Merge with config whitelist
                    config_whitelist = self.config.get('whitelist', [])
                    combined_whitelist = list(set(config_whitelist + server_whitelist))

                    # Update detector's whitelist
                    self.detector.config['whitelist'] = combined_whitelist
                    self.detector.config_whitelist = self.detector._parse_ip_list(combined_whitelist)

                    self.logger.info(f"✓ Whitelist updated: {len(config_whitelist)} config + {len(server_whitelist)} server = {len(combined_whitelist)} total")
                else:
                    self.logger.warning(f"Failed to fetch whitelist: {result.get('error')}")
            else:
                self.logger.warning(f"Whitelist fetch returned status {response.status_code}")

        except Exception as e:
            self.logger.warning(f"Failed to update whitelist from server: {e}")
            self.logger.info("Continuing with config-only whitelist...")

    def _register_sensor(self):
        """Register sensor with central SOC server"""
        self.logger.info("Registering sensor with SOC server...")

        try:
            # Get sensor information
            hostname = socket.gethostname()

            # Get IP address from the monitoring interface (not loopback)
            ip_address = None
            try:
                interface_config = self.config.get('interface', 'eth0')
                net_addrs = psutil.net_if_addrs()

                # Parse interface (handle comma-separated list)
                interfaces_to_check = []
                if interface_config in ('any', 'all') or interface_config is None:
                    # Will use fallback logic below
                    pass
                elif isinstance(interface_config, str) and ',' in interface_config:
                    # Multiple interfaces - use first one
                    interfaces_to_check = [iface.strip() for iface in interface_config.split(',')]
                else:
                    # Single interface
                    interfaces_to_check = [interface_config]

                # Try to get IP from specified interfaces
                for iface in interfaces_to_check:
                    if iface in net_addrs:
                        for addr in net_addrs[iface]:
                            if addr.family == socket.AF_INET:  # IPv4
                                ip_address = addr.address
                                break
                    if ip_address:
                        break

                # Fallback: try to get any non-loopback IP
                if not ip_address:
                    for iface, addrs in net_addrs.items():
                        if iface.startswith('lo'):  # Skip loopback
                            continue
                        for addr in addrs:
                            if addr.family == socket.AF_INET:
                                ip_address = addr.address
                                break
                        if ip_address:
                            break
            except Exception as e:
                self.logger.warning(f"Could not detect IP address: {e}")
                ip_address = None

            # Get version
            version = "1.0.0"  # TODO: Get from package

            response = requests.post(
                f"{self.server_url}/api/sensors/register",
                headers=self._get_headers(),
                json={
                    'sensor_id': self.sensor_id,
                    'hostname': hostname,
                    'location': self.location,
                    'ip_address': ip_address,
                    'version': version,
                    'config': {
                        'interface': self.config.get('interface', 'unknown'),
                        'batch_interval': self.batch_interval
                    }
                },
                timeout=10,
                verify=self.ssl_verify
            )

            if response.status_code == 200:
                self.logger.info("✓ Sensor registered successfully")
            else:
                self.logger.warning(f"Registration failed: {response.text}")

        except Exception as e:
            self.logger.error(f"Failed to register sensor: {e}")
            self.logger.warning("Continuing without registration...")

    def _send_heartbeat(self):
        """Send heartbeat to server"""
        try:
            response = requests.post(
                f"{self.server_url}/api/sensors/{self.sensor_id}/heartbeat",
                headers=self._get_headers(),
                timeout=5,
                verify=self.ssl_verify
            )
            if response.status_code == 200:
                return True
            else:
                self.logger.warning(f"Heartbeat failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            self.logger.debug(f"Heartbeat error: {e}")
            return False

    def _poll_commands(self):
        """Poll server for pending commands"""
        try:
            response = requests.get(
                f"{self.server_url}/api/sensors/{self.sensor_id}/commands",
                headers=self._get_headers(),
                timeout=10,
                verify=self.ssl_verify
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success') and result.get('commands'):
                    return result['commands']
            return []

        except Exception as e:
            self.logger.error(f"Error polling commands: {e}")
            return []

    def _execute_command(self, command):
        """Execute a sensor command"""
        command_id = command['id']
        command_type = command['command_type']
        parameters = command.get('parameters', {})

        self.logger.info(f"Executing command: {command_type} (ID: {command_id})")

        try:
            # Update status to executing
            requests.put(
                f"{self.server_url}/api/sensors/{self.sensor_id}/commands/{command_id}",
                json={'status': 'executing'},
                timeout=10,
                verify=self.ssl_verify
            )

            result = {'success': False, 'message': 'Unknown command'}

            # Execute based on command type
            if command_type == 'restart':
                result = {
                    'success': True,
                    'message': 'Sensor will restart in 5 seconds'
                }
                self.logger.warning("RESTART command received - sensor will restart")
                # Update status before restarting
                requests.put(
                    f"{self.server_url}/api/sensors/{self.sensor_id}/commands/{command_id}",
                    json={'status': 'completed', 'result': result},
                    timeout=10,
                    verify=self.ssl_verify
                )
                # Schedule restart
                import subprocess
                subprocess.Popen(['sleep', '5', '&&', 'systemctl', 'restart', 'netmonitor-sensor'])
                return

            elif command_type == 'change_interval':
                new_interval = parameters.get('interval', self.batch_interval)
                old_interval = self.batch_interval
                self.batch_interval = int(new_interval)
                result = {
                    'success': True,
                    'message': f'Batch interval changed from {old_interval}s to {self.batch_interval}s'
                }
                self.logger.info(f"Batch interval changed to {self.batch_interval}s")

            elif command_type == 'get_status':
                uptime = int(time.time() - self.start_time)
                result = {
                    'success': True,
                    'data': {
                        'uptime_seconds': uptime,
                        'packets_captured': self.packets_captured,
                        'alerts_sent': self.alerts_sent,
                        'buffer_size': len(self.alert_buffer),
                        'batch_interval': self.batch_interval
                    }
                }

            elif command_type == 'flush_buffer':
                buffer_size = len(self.alert_buffer)
                self._upload_alerts()
                result = {
                    'success': True,
                    'message': f'Flushed {buffer_size} alerts from buffer'
                }
                self.logger.info(f"Manual buffer flush: {buffer_size} alerts")

            elif command_type == 'update_config':
                # Force config update from server
                try:
                    old_config_snapshot = str(self.config)  # Simple string comparison
                    self._update_config()
                    new_config_snapshot = str(self.config)

                    if old_config_snapshot != new_config_snapshot:
                        result = {
                            'success': True,
                            'message': 'Configuration updated from server'
                        }
                    else:
                        result = {
                            'success': True,
                            'message': 'Configuration synced (no changes)'
                        }
                    self.logger.info(f"Config manually updated via command")
                except Exception as e:
                    result = {
                        'success': False,
                        'message': f'Config update failed: {e}'
                    }

            elif command_type == 'update_whitelist':
                # Force whitelist update from server
                old_count = len(self.detector.config.get('whitelist', []))
                self._update_whitelist()
                new_count = len(self.detector.config.get('whitelist', []))
                result = {
                    'success': True,
                    'message': f'Whitelist updated: {old_count} → {new_count} entries'
                }
                self.logger.info(f"Whitelist manually updated via command")

            elif command_type == 'reboot':
                # Reboot the sensor system
                result = {
                    'success': True,
                    'message': 'System will reboot in 5 seconds'
                }
                self.logger.warning("REBOOT command received - system will reboot in 5 seconds")
                # Update status before rebooting
                requests.put(
                    f"{self.server_url}/api/sensors/{self.sensor_id}/commands/{command_id}",
                    json={'status': 'completed', 'result': result},
                    timeout=10,
                    verify=self.ssl_verify
                )
                # Schedule reboot
                import subprocess
                subprocess.Popen(['bash', '-c', 'sleep 5 && shutdown -r now'])
                return

            elif command_type == 'update':
                # Update sensor software from git
                import subprocess
                branch = parameters.get('branch', '')  # Optional branch parameter

                self.logger.info(f"UPDATE command received - updating from git{f' (branch: {branch})' if branch else ''}")

                try:
                    # Change to installation directory
                    install_dir = '/opt/netmonitor'

                    # Build git pull command
                    if branch:
                        git_cmd = f'cd {install_dir} && git fetch origin && git checkout {branch} && git pull origin {branch}'
                    else:
                        git_cmd = f'cd {install_dir} && git pull'

                    # Execute git pull
                    git_result = subprocess.run(
                        git_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if git_result.returncode == 0:
                        result = {
                            'success': True,
                            'message': f'Git pull successful. Sensor will restart in 5 seconds.',
                            'git_output': git_result.stdout
                        }
                        self.logger.info(f"Git pull successful: {git_result.stdout}")

                        # Update status before restarting
                        requests.put(
                            f"{self.server_url}/api/sensors/{self.sensor_id}/commands/{command_id}",
                            json={'status': 'completed', 'result': result},
                            timeout=10,
                            verify=self.ssl_verify
                        )

                        # Schedule service restart
                        subprocess.Popen(['bash', '-c', 'sleep 5 && systemctl restart netmonitor-sensor'])
                        return
                    else:
                        result = {
                            'success': False,
                            'message': f'Git pull failed: {git_result.stderr}',
                            'git_output': git_result.stderr
                        }
                        self.logger.error(f"Git pull failed: {git_result.stderr}")

                except subprocess.TimeoutExpired:
                    result = {
                        'success': False,
                        'message': 'Git pull timed out after 30 seconds'
                    }
                except Exception as e:
                    result = {
                        'success': False,
                        'message': f'Update failed: {str(e)}'
                    }

            # Config editing removed - now uses centralized config via database
            # Sensors pull config from SOC server automatically via _update_config()
            # Edit sensor settings in dashboard UI (uses /api/config/parameter)

            # Report result
            requests.put(
                f"{self.server_url}/api/sensors/{self.sensor_id}/commands/{command_id}",
                json={'status': 'completed', 'result': result},
                timeout=10,
                verify=self.ssl_verify
            )

            self.logger.info(f"Command {command_type} completed: {result.get('message', 'OK')}")

        except Exception as e:
            self.logger.error(f"Error executing command {command_type}: {e}")
            # Report failure
            try:
                requests.put(
                    f"{self.server_url}/api/sensors/{self.sensor_id}/commands/{command_id}",
                    json={'status': 'failed', 'result': {'error': str(e)}},
                    timeout=10,
                    verify=self.ssl_verify
                )
            except:
                pass

    def _send_metrics(self):
        """Send performance metrics to server"""
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            uptime = int(time.time() - self.start_time)

            # Calculate bandwidth (Mbps) over measurement window
            now = time.time()
            window_duration = now - self.bandwidth_window_start

            if window_duration > 0:
                # Convert bytes to Mbps: (bytes * 8) / (duration * 1000000)
                mbps = (self.bandwidth_window_bytes * 8) / (window_duration * 1_000_000)

                # Debug logging for bandwidth calculation
                mb_captured = self.bandwidth_window_bytes / (1024 * 1024)  # Convert to MB
                self.logger.info(f"Bandwidth: {mb_captured:.2f} MB captured in {window_duration:.1f}s = {mbps:.2f} Mbps")
            else:
                mbps = 0.0

            # Reset bandwidth window
            self.bandwidth_window_start = now
            self.bandwidth_window_bytes = 0

            response = requests.post(
                f"{self.server_url}/api/sensors/{self.sensor_id}/metrics",
                headers=self._get_headers(),
                json={
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'disk_percent': disk.percent,
                    'uptime_seconds': uptime,
                    'packets_captured': self.packets_captured,
                    'alerts_sent': self.alerts_sent,
                    'network_interface': self.config.get('interface', 'unknown'),
                    'bandwidth_mbps': round(mbps, 2)  # Add bandwidth in Mbps
                },
                timeout=10,
                verify=self.ssl_verify
            )

            if response.status_code == 200:
                self.logger.debug("Metrics sent")
            else:
                self.logger.warning(f"Failed to send metrics: {response.text}")

        except Exception as e:
            self.logger.error(f"Error sending metrics: {e}")

    def _upload_alert_immediate(self, alert, pcap_path=None):
        """Upload a single high-priority alert immediately

        Args:
            alert: Alert dict with threat details
            pcap_path: Optional path to PCAP file for forensic evidence (NIS2)
        """
        import base64

        try:
            # Include PCAP data if available (NIS2 forensic evidence)
            alert_with_pcap = alert.copy()
            if pcap_path:
                try:
                    with open(pcap_path, 'rb') as f:
                        pcap_data = f.read()
                    # Base64 encode for JSON transport
                    alert_with_pcap['pcap_data'] = base64.b64encode(pcap_data).decode('utf-8')
                    self.logger.debug(f"Including PCAP ({len(pcap_data)} bytes) with alert upload")
                except Exception as read_err:
                    self.logger.warning(f"Could not read PCAP for upload: {read_err}")

            response = requests.post(
                f"{self.server_url}/api/sensors/{self.sensor_id}/alerts",
                headers=self._get_headers(),
                json={'alerts': [alert_with_pcap]},
                timeout=30,  # Longer timeout for PCAP upload
                verify=self.ssl_verify
            )

            if response.status_code == 200:
                result = response.json()
                self.alerts_sent += result.get('inserted', 0)
                pcap_msg = f" + PCAP" if result.get('pcap_received', 0) > 0 else ""
                self.logger.info(f"⚡ Immediate upload: [{alert['severity']}] {alert['threat_type']}{pcap_msg}")
                return True
            else:
                self.logger.warning(f"Failed to upload immediate alert: {response.text}")
                return False

        except Exception as e:
            self.logger.error(f"Error uploading immediate alert: {e}")
            return False

    def _upload_alerts(self):
        """Upload buffered alerts to server in batch"""
        if not self.alert_buffer:
            return

        # Get all alerts from buffer
        alerts = []
        while self.alert_buffer and len(alerts) < 1000:  # Max 1000 per batch
            alerts.append(self.alert_buffer.popleft())

        if not alerts:
            return

        try:
            response = requests.post(
                f"{self.server_url}/api/sensors/{self.sensor_id}/alerts",
                headers=self._get_headers(),
                json={'alerts': alerts},
                timeout=30,
                verify=self.ssl_verify
            )

            if response.status_code == 200:
                result = response.json()
                self.alerts_sent += result.get('inserted', 0)
                self.logger.info(f"✓ Uploaded {result.get('inserted', 0)} alerts (buffer: {len(self.alert_buffer)})")
            else:
                self.logger.warning(f"Failed to upload alerts: {response.text}")
                # Put alerts back in buffer
                for alert in reversed(alerts):
                    self.alert_buffer.appendleft(alert)

        except Exception as e:
            self.logger.error(f"Error uploading alerts: {e}")
            # Put alerts back in buffer
            for alert in reversed(alerts):
                self.alert_buffer.appendleft(alert)

    def _handle_packet(self, packet):
        """Process captured packet"""
        try:
            self.packets_captured += 1

            # Track bandwidth (packet size in bytes)
            # Note: len(packet) includes all layers starting from where scapy captures
            packet_size = len(packet) if hasattr(packet, '__len__') else 0
            self.bandwidth_window_bytes += packet_size

            # Debug: log high packet rates (every 1000 packets)
            if self.packets_captured % 1000 == 0:
                elapsed = time.time() - self.start_time
                pps = self.packets_captured / elapsed if elapsed > 0 else 0
                self.logger.debug(f"Captured {self.packets_captured} packets, avg {pps:.0f} pps")

            # Add packet to PCAP buffer (if enabled)
            if self.pcap_exporter:
                try:
                    self.pcap_exporter.add_packet(packet)
                except Exception:
                    pass  # Don't log every packet error

            # Detect threats
            threats = self.detector.analyze_packet(packet)

            # Process alerts with priority handling
            for threat in threats:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'severity': threat.get('severity', 'INFO'),
                    'threat_type': threat.get('type', 'UNKNOWN'),
                    'source_ip': threat.get('source_ip'),
                    'destination_ip': threat.get('destination_ip'),
                    'description': threat.get('description', ''),
                    'metadata': threat.get('metadata', {})
                }

                # Priority-based upload strategy
                severity = threat.get('severity')
                if severity in ['CRITICAL', 'HIGH']:
                    # Upload immediately for high-priority alerts
                    self.logger.warning(f"⚠️  [{severity}] {threat.get('type')}: {threat.get('description')}")

                    # Capture PCAP FIRST for high-severity alerts (NIS2 compliance)
                    pcap_path = None
                    if self.pcap_exporter:
                        try:
                            pcap_path = self.pcap_exporter.capture_alert(threat, packet)
                            if pcap_path:
                                self.logger.info(f"PCAP captured: {pcap_path}")
                        except Exception as pcap_err:
                            self.logger.debug(f"PCAP capture error: {pcap_err}")

                    # Upload alert with PCAP data (if upload enabled)
                    upload_pcap = pcap_path if self.pcap_upload_enabled else None
                    success = self._upload_alert_immediate(alert, upload_pcap)

                    # Delete local PCAP after successful upload (unless keep_local is set)
                    if success and pcap_path and not self.pcap_keep_local:
                        try:
                            import os
                            if os.path.exists(pcap_path):
                                os.remove(pcap_path)
                                self.logger.debug(f"Local PCAP deleted after upload: {pcap_path}")
                        except Exception as del_err:
                            self.logger.debug(f"Could not delete local PCAP: {del_err}")

                    # If immediate upload fails, add to buffer as fallback
                    if not success:
                        self.alert_buffer.append(alert)
                else:
                    # Batch upload for lower priority alerts
                    self.alert_buffer.append(alert)

        except Exception as e:
            import traceback
            self.logger.error(f"Error processing packet: {e}")
            self.logger.debug(traceback.format_exc())

    def start(self):
        """Start sensor client"""
        self.running = True
        self.logger.info("=" * 60)
        self.logger.info("Remote Sensor Client Starting")
        self.logger.info("=" * 60)

        # Parse interface configuration (support comma-separated list)
        interface_config = self.config.get('interface', 'eth0')

        if interface_config in ('any', 'all') or interface_config is None:
            interface = None  # Listen on all interfaces
            interface_display = "all interfaces"
        elif isinstance(interface_config, str) and ',' in interface_config:
            # Multiple interfaces: "ens192, ens224" -> ["ens192", "ens224"]
            interface = [iface.strip() for iface in interface_config.split(',')]
            interface_display = ', '.join(interface)
        else:
            # Single interface
            interface = interface_config
            interface_display = interface_config

        self.logger.info(f"Monitoring interface: {interface_display}")
        self.logger.info(f"Batch upload interval: {self.batch_interval}s")

        # Start upload thread
        import threading

        def upload_loop():
            """Background thread for uploading alerts, metrics, and polling commands"""
            last_upload = time.time()
            last_metrics = time.time()
            last_command_poll = time.time()
            last_whitelist_update = time.time()
            last_config_update = time.time()

            while self.running:
                now = time.time()

                # Upload alerts every batch_interval
                if now - last_upload >= self.batch_interval:
                    self._upload_alerts()
                    last_upload = now

                # Send metrics every X seconds (configurable)
                metrics_interval = self.config.get('performance', {}).get('metrics_interval', 60)
                heartbeat_interval = self.config.get('performance', {}).get('heartbeat_interval', 30)
                if now - last_metrics >= metrics_interval:
                    self._send_metrics()
                    last_metrics = now
                # Send heartbeat every X seconds (configurable)
                elif now - last_metrics >= heartbeat_interval:
                    self._send_heartbeat()

                # Poll for commands every X seconds (configurable)
                command_poll_interval = self.config.get('performance', {}).get('command_poll_interval', 30)
                if now - last_command_poll >= command_poll_interval:
                    commands = self._poll_commands()
                    for command in commands:
                        self._execute_command(command)
                    last_command_poll = now

                # Update whitelist every X minutes (configurable)
                whitelist_interval = self.config.get('performance', {}).get('whitelist_sync_interval', 300)
                if now - last_whitelist_update >= whitelist_interval:
                    self._update_whitelist()
                    last_whitelist_update = now

                # Update config every X minutes (configurable)
                config_interval = self.config.get('performance', {}).get('config_sync_interval', 300)
                if now - last_config_update >= config_interval:
                    self._update_config()
                    last_config_update = now

                time.sleep(1)

        upload_thread = threading.Thread(target=upload_loop, daemon=True)
        upload_thread.start()

        # Start packet capture
        self.logger.info("Starting packet capture...")
        try:
            sniff(
                iface=interface,
                prn=self._handle_packet,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: not self.running
            )
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop sensor client"""
        if not self.running:
            return

        self.logger.info("Stopping sensor client...")
        self.running = False

        # Upload remaining alerts
        if self.alert_buffer:
            self.logger.info(f"Uploading {len(self.alert_buffer)} remaining alerts...")
            self._upload_alerts()

        # Send final metrics
        self._send_metrics()

        self.logger.info("Sensor client stopped")
        self.logger.info(f"Total packets captured: {self.packets_captured}")
        self.logger.info(f"Total alerts sent: {self.alerts_sent}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Remote Sensor Client for Network Monitor SOC')
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file path')
    parser.add_argument('-s', '--server-url', help='SOC server URL (e.g., http://soc.example.com:8080)')
    parser.add_argument('--sensor-id', help='Unique sensor ID (auto-generated if not provided)')
    parser.add_argument('-l', '--location', help='Sensor location (e.g., "Building A - VLAN 10")')
    parser.add_argument('-i', '--interval', type=int, default=30, help='Batch upload interval in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create sensor client
    sensor = SensorClient(
        config_file=args.config,
        server_url=args.server_url,
        sensor_id=args.sensor_id,
        location=args.location,
        batch_interval=args.interval
    )

    # Handle signals
    def signal_handler(sig, frame):
        sensor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start sensor
    sensor.start()


if __name__ == '__main__':
    main()
