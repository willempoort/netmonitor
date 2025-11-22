#!/usr/bin/env python3
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
        self.config = load_config(config_file)
        self.server_url = server_url or os.environ.get('SOC_SERVER_URL')
        self.sensor_id = sensor_id or os.environ.get('SENSOR_ID') or self._generate_sensor_id()
        self.location = location or os.environ.get('SENSOR_LOCATION', 'Unknown')
        self.batch_interval = batch_interval
        self.running = False

        # Statistics
        self.packets_captured = 0
        self.alerts_sent = 0
        self.start_time = time.time()

        # Alert buffer for batching
        self.alert_buffer = deque(maxlen=10000)  # Max 10k alerts in buffer

        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger('NetMonitor.Sensor')

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
        """Generate unique sensor ID from hostname and MAC address"""
        hostname = socket.gethostname()
        # Try to get MAC address of first non-loopback interface
        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                           for elements in range(0, 2*6, 2)][::-1])
            return f"{hostname}-{mac[:8]}"
        except:
            return f"{hostname}-{int(time.time())}"

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
            self.threat_feeds = ThreatFeedManager(self.config)
            self.logger.info("Threat Feed Manager enabled")
        else:
            self.threat_feeds = None

        # Initialize behavior detector
        self.behavior_detector = BehaviorDetector(self.config)
        self.logger.info("Behavior Detector enabled")

        # Initialize AbuseIPDB client
        if self.config.get('abuseipdb', {}).get('enabled', False):
            api_key = self.config['abuseipdb'].get('api_key')
            if api_key:
                self.abuseipdb = AbuseIPDBClient(self.config)
                self.logger.info("AbuseIPDB client enabled")
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

    def _register_sensor(self):
        """Register sensor with central SOC server"""
        self.logger.info("Registering sensor with SOC server...")

        try:
            # Get sensor information
            hostname = socket.gethostname()
            try:
                ip_address = socket.gethostbyname(hostname)
            except:
                ip_address = None

            # Get version
            version = "1.0.0"  # TODO: Get from package

            response = requests.post(
                f"{self.server_url}/api/sensors/register",
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
                timeout=10
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
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

    def _send_metrics(self):
        """Send performance metrics to server"""
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            uptime = int(time.time() - self.start_time)

            response = requests.post(
                f"{self.server_url}/api/sensors/{self.sensor_id}/metrics",
                json={
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'disk_percent': disk.percent,
                    'uptime_seconds': uptime,
                    'packets_captured': self.packets_captured,
                    'alerts_sent': self.alerts_sent,
                    'network_interface': self.config.get('interface', 'unknown')
                },
                timeout=10
            )

            if response.status_code == 200:
                self.logger.debug("Metrics sent")
            else:
                self.logger.warning(f"Failed to send metrics: {response.text}")

        except Exception as e:
            self.logger.error(f"Error sending metrics: {e}")

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
                json={'alerts': alerts},
                timeout=30
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

            # Detect threats
            threats = self.detector.analyze_packet(packet)

            # Add to buffer
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
                self.alert_buffer.append(alert)

                # Log critical threats immediately
                if threat.get('severity') in ['CRITICAL', 'HIGH']:
                    self.logger.warning(f"[{threat.get('severity')}] {threat.get('type')}: {threat.get('description')}")

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def start(self):
        """Start sensor client"""
        self.running = True
        self.logger.info("=" * 60)
        self.logger.info("Remote Sensor Client Starting")
        self.logger.info("=" * 60)

        interface = self.config.get('interface', 'eth0')
        self.logger.info(f"Monitoring interface: {interface}")
        self.logger.info(f"Batch upload interval: {self.batch_interval}s")

        # Start upload thread
        import threading

        def upload_loop():
            """Background thread for uploading alerts and metrics"""
            last_upload = time.time()
            last_metrics = time.time()

            while self.running:
                now = time.time()

                # Upload alerts every batch_interval
                if now - last_upload >= self.batch_interval:
                    self._upload_alerts()
                    last_upload = now

                # Send metrics every 60 seconds
                if now - last_metrics >= 60:
                    self._send_metrics()
                    last_metrics = now
                # Send heartbeat every 30 seconds
                elif now - last_metrics >= 30:
                    self._send_heartbeat()

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
