#!/usr/bin/env python3
"""
Network Monitor - Detecteert verdacht netwerkverkeer
Geschikt voor gebruik op een monitoring/span port
"""

import sys
import signal
import argparse
import logging
import threading
import time
from pathlib import Path

try:
    from scapy.all import sniff, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
except ImportError:
    print("Error: scapy is niet geïnstalleerd. Installeer met: pip install -r requirements.txt")
    sys.exit(1)

from detector import ThreatDetector
from config_loader import load_config
from alerts import AlertManager
from threat_feeds import ThreatFeedManager
from behavior_detector import BehaviorDetector
from abuseipdb_client import AbuseIPDBClient
from database import DatabaseManager
from metrics_collector import MetricsCollector
from web_dashboard import DashboardServer


class NetworkMonitor:
    """Hoofd netwerk monitor class"""

    def __init__(self, config_file="config.yaml"):
        """Initialiseer de network monitor"""
        self.config = load_config(config_file)
        self.running = False

        # Check if self-monitoring is enabled
        self.self_monitor_config = self.config.get('self_monitor', {})
        self.self_monitor_enabled = self.self_monitor_config.get('enabled', True)
        self.sensor_id = self.self_monitor_config.get('sensor_id', 'soc-server') if self.self_monitor_enabled else None

        # Setup logging
        self.setup_logging()

        # Initialiseer database
        self.db = None
        if self.config.get('dashboard', {}).get('enabled', True):
            try:
                db_config = self.config.get('database', {})
                db_type = db_config.get('type', 'postgresql')

                if db_type == 'postgresql':
                    pg_config = db_config.get('postgresql', {})
                    self.db = DatabaseManager(
                        host=pg_config.get('host', 'localhost'),
                        port=pg_config.get('port', 5432),
                        database=pg_config.get('database', 'netmonitor'),
                        user=pg_config.get('user', 'netmonitor'),
                        password=pg_config.get('password', 'netmonitor'),
                        min_connections=pg_config.get('min_connections', 2),
                        max_connections=pg_config.get('max_connections', 10)
                    )
                    self.logger.info("Database Manager enabled (PostgreSQL + TimescaleDB)")
                else:
                    self.logger.error(f"Unsupported database type: {db_type}")
                    raise ValueError(f"Database type '{db_type}' not supported")

            except Exception as e:
                self.logger.error(f"Fout bij initialiseren database: {e}")
                raise

        # Initialiseer metrics collector
        self.metrics = None
        try:
            self.metrics = MetricsCollector(self.config, database_manager=self.db)
            self.logger.info("Metrics Collector enabled")
        except Exception as e:
            self.logger.error(f"Fout bij initialiseren metrics collector: {e}")

        # Initialiseer threat feed manager
        self.threat_feeds = None
        if self.config.get('threat_feeds', {}).get('enabled', False):
            try:
                cache_dir = self.config['threat_feeds'].get('cache_dir', '/var/cache/netmonitor/feeds')
                self.threat_feeds = ThreatFeedManager(cache_dir=cache_dir)
                self.logger.info("Threat Feed Manager enabled")

                # Initial feed load
                self._load_threat_feeds()
            except Exception as e:
                self.logger.error(f"Fout bij initialiseren threat feeds: {e}")
                self.threat_feeds = None

        # Initialiseer behavior detector
        self.behavior_detector = None
        try:
            self.behavior_detector = BehaviorDetector(self.config)
            self.logger.info("Behavior Detector enabled")
        except Exception as e:
            self.logger.error(f"Fout bij initialiseren behavior detector: {e}")

        # Initialiseer AbuseIPDB client
        self.abuseipdb = None
        if self.config.get('abuseipdb', {}).get('enabled', False):
            api_key = self.config['abuseipdb'].get('api_key', '')
            if api_key:
                try:
                    rate_limit = self.config['abuseipdb'].get('rate_limit', 1000)
                    self.abuseipdb = AbuseIPDBClient(api_key, rate_limit=rate_limit)
                    self.logger.info("AbuseIPDB client enabled")
                except Exception as e:
                    self.logger.error(f"Fout bij initialiseren AbuseIPDB client: {e}")

        # Initialiseer detector en alert manager
        # Load config from database if available (for SOC server self-monitoring)
        if self.db and self.sensor_id:
            try:
                self._load_config_from_database()
            except Exception as e:
                self.logger.warning(f"Could not load config from database, using config.yaml: {e}")

        self.detector = ThreatDetector(
            self.config,
            threat_feed_manager=self.threat_feeds,
            behavior_detector=self.behavior_detector,
            abuseipdb_client=self.abuseipdb,
            db_manager=self.db,  # Pass database for whitelist checks
            sensor_id=self.sensor_id  # Pass sensor_id for SOC server self-monitoring
        )
        self.alert_manager = AlertManager(self.config)

        # Initialiseer web dashboard
        self.dashboard = None
        if self.config.get('dashboard', {}).get('enabled', True):
            try:
                host = self.config.get('dashboard', {}).get('host', '0.0.0.0')
                port = self.config.get('dashboard', {}).get('port', 8080)
                self.dashboard = DashboardServer(config_file=config_file, host=host, port=port)
                self.logger.info("Web Dashboard enabled")
            except Exception as e:
                self.logger.error(f"Fout bij initialiseren dashboard: {e}")

        # Setup signal handlers voor graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.logger.info("Network Monitor geïnitialiseerd")

    def _load_config_from_database(self):
        """Load detection thresholds from database (for SOC server self-monitoring)"""
        if not self.db or not self.sensor_id:
            return

        self.logger.info("Loading detection config from database...")

        try:
            # Get config for this sensor (or global if sensor-specific doesn't exist)
            db_config = self.db.get_sensor_config(sensor_id=self.sensor_id)

            if db_config:
                # Merge database config with config.yaml (database takes precedence)
                if 'thresholds' in db_config:
                    self.logger.info(f"Loaded {len(db_config['thresholds'])} threshold configs from database")

                    # Deep merge: database config overrides config.yaml
                    if 'thresholds' not in self.config:
                        self.config['thresholds'] = {}

                    for category, settings in db_config['thresholds'].items():
                        if category not in self.config['thresholds']:
                            self.config['thresholds'][category] = {}

                        # Merge settings (database overrides)
                        self.config['thresholds'][category].update(settings)

                    self.logger.info("Detection config merged from database (database takes precedence)")
                else:
                    self.logger.info("No threshold config in database, using config.yaml defaults")
            else:
                self.logger.info("No database config found, using config.yaml defaults")

        except Exception as e:
            self.logger.warning(f"Error loading config from database: {e}")
            self.logger.info("Falling back to config.yaml")

    def _sync_config_from_database(self):
        """Periodically sync config from database (called during operation)"""
        if not self.db or not self.sensor_id:
            return

        try:
            self._load_config_from_database()

            # Update detector's config reference (detector uses self.config internally)
            # No need to recreate detector, just reload config
            self.logger.debug("Config synced from database")

        except Exception as e:
            self.logger.error(f"Error syncing config from database: {e}")

    def _config_sync_loop(self, interval):
        """Background thread that periodically syncs config from database"""
        self.logger.info(f"Starting config sync loop (every {interval}s)")

        while self.running:
            try:
                time.sleep(interval)
                if self.running:  # Check again after sleep
                    self.logger.debug("Syncing config from database...")
                    self._sync_config_from_database()
            except Exception as e:
                self.logger.error(f"Error in config sync loop: {e}")

    def setup_logging(self):
        """Setup logging configuratie"""
        log_level = getattr(logging, self.config['logging']['level'], logging.INFO)

        # Create logger
        self.logger = logging.getLogger('NetMonitor')
        self.logger.setLevel(log_level)

        # Console handler
        if self.config['logging']['console']:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            console_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_format)
            self.logger.addHandler(console_handler)

        # File handler
        if 'file' in self.config['logging'] and self.config['logging']['file']:
            log_file = Path(self.config['logging']['file'])
            log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)

    def _load_threat_feeds(self):
        """Laad threat feeds (download en parse)"""
        if not self.threat_feeds:
            return

        self.logger.info("Loading threat feeds...")

        # Check of cached feeds bestaan
        feeds_to_use = self.config['threat_feeds'].get('feeds', ['feodotracker', 'urlhaus', 'threatfox'])

        # Probeer feeds te laden van cache
        results = self.threat_feeds.load_feeds(feeds_to_use)

        # Als geen feeds geladen, download ze
        if sum(results.values()) == 0:
            self.logger.info("No cached feeds found, downloading...")
            self.threat_feeds.update_all_feeds(force=True)
        else:
            self.logger.info(f"Loaded {sum(results.values())} IOCs from cached feeds")

            # Check of feeds oud zijn (> 24 uur)
            # Download in background als nodig
            # Voor nu: simpel laden

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Signal {signum} ontvangen, shutting down...")
        self.running = False
        sys.exit(0)

    def packet_callback(self, packet):
        """Callback functie voor elk ontvangen packet"""
        try:
            # Check of packet IP layer heeft
            if not packet.haslayer(IP):
                return

            # Track packet in metrics
            if self.metrics:
                self.metrics.track_packet(packet)

            # Analyseer packet met detector
            threats = self.detector.analyze_packet(packet)

            # Als threats gevonden, stuur alerts
            if threats:
                for threat in threats:
                    # Send to alert manager (console/file)
                    self.alert_manager.send_alert(threat, packet)

                    # Save to database
                    if self.db:
                        try:
                            # Add sensor_id if self-monitoring is enabled
                            if self.sensor_id:
                                threat['sensor_id'] = self.sensor_id
                            self.db.add_alert(threat)
                        except Exception as db_error:
                            self.logger.error(f"Error saving alert to database: {db_error}")

                    # Broadcast to dashboard
                    if self.dashboard:
                        try:
                            self.dashboard.broadcast_alert(threat)
                        except Exception as dash_error:
                            self.logger.error(f"Error broadcasting alert: {dash_error}")

                    # Track alert in metrics
                    if self.metrics:
                        self.metrics.track_alert()

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}", exc_info=True)

    def start(self):
        """Start het monitoren van netwerkverkeer"""
        # Check if self-monitoring is disabled
        if not self.self_monitor_enabled:
            self.logger.info("Self-monitoring is DISABLED - SOC server will only receive alerts from remote sensors")

            # Start dashboard only (no packet capture)
            if self.dashboard:
                self.dashboard.start()
                self.logger.info(f"Dashboard beschikbaar op: http://{self.config['dashboard']['host']}:{self.config['dashboard']['port']}")

            # Keep running (dashboard thread is daemon)
            try:
                signal.pause()  # Wait for interrupt
            except KeyboardInterrupt:
                self.logger.info("Shutting down...")
            return

        # Self-monitoring is enabled - register as sensor
        if self.db and self.sensor_id:
            try:
                import socket
                hostname = self.self_monitor_config.get('hostname') or socket.gethostname()
                location = self.self_monitor_config.get('location', 'SOC Server')

                self.db.register_sensor(
                    sensor_id=self.sensor_id,
                    hostname=hostname,
                    location=location
                    # Note: status is automatically set to 'online' by register_sensor()
                )
                self.logger.info(f"SOC server registered as sensor: {self.sensor_id} ({hostname})")
            except Exception as e:
                self.logger.warning(f"Could not register SOC server as sensor: {e}")

        # Get interface from self_monitor config, fallback to legacy 'interface' key
        interface = self.self_monitor_config.get('interface', self.config.get('interface', 'lo'))

        self.logger.info(f"Starting network monitor op interface: {interface}")
        self.logger.info("Druk op Ctrl+C om te stoppen")

        # Start dashboard server
        if self.dashboard:
            self.dashboard.start()
            dashboard_host = self.config.get('dashboard', {}).get('host', '0.0.0.0')
            dashboard_port = self.config.get('dashboard', {}).get('port', 8080)
            self.logger.info(f"Dashboard beschikbaar op: http://{dashboard_host}:{dashboard_port}")

        # Start config sync thread (if self-monitoring and database enabled)
        if self.db and self.sensor_id:
            config_sync_interval = 300  # 5 minutes (same as remote sensors)
            self.config_sync_thread = threading.Thread(
                target=self._config_sync_loop,
                args=(config_sync_interval,),
                daemon=True,
                name="ConfigSync"
            )
            self.config_sync_thread.start()
            self.logger.info(f"Config sync enabled (interval: {config_sync_interval}s)")

        # Check of we root privileges hebben
        if conf.L3socket == conf.L3socket6:
            self.logger.warning(
                "Mogelijk onvoldoende privileges. Run als root voor volledige functionaliteit."
            )

        self.running = True

        # Start metrics broadcaster (update dashboard elk 5 seconden)
        def broadcast_metrics():
            while self.running:
                if self.metrics and self.dashboard:
                    try:
                        metrics_data = self.metrics.get_dashboard_metrics()
                        self.dashboard.broadcast_metrics(metrics_data)
                    except Exception as e:
                        self.logger.error(f"Error broadcasting metrics: {e}")
                threading.Event().wait(5)  # 5 seconden

        metrics_thread = threading.Thread(target=broadcast_metrics, daemon=True)
        metrics_thread.start()

        try:
            # Start packet sniffing
            # store=0 betekent packets niet in memory houden (belangrijk voor lange runs)
            sniff(
                iface=interface if interface != 'any' else None,
                prn=self.packet_callback,
                store=0,
                filter="ip"  # Alleen IP packets
            )
        except PermissionError:
            self.logger.error(
                "Onvoldoende privileges om packets te capturen. Run als root (sudo)."
            )
            sys.exit(1)
        except OSError as e:
            self.logger.error(f"Network interface error: {e}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}", exc_info=True)
            sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Network Monitor - Detecteert verdacht netwerkverkeer"
    )
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Pad naar configuratie file (default: config.yaml)'
    )
    parser.add_argument(
        '-i', '--interface',
        help='Network interface om te monitoren (overschrijft config file)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output (DEBUG level)'
    )

    args = parser.parse_args()

    # Check of config file bestaat
    if not Path(args.config).exists():
        print(f"Error: Config file niet gevonden: {args.config}")
        sys.exit(1)

    try:
        monitor = NetworkMonitor(args.config)

        # Override interface als opgegeven via CLI
        if args.interface:
            monitor.config['interface'] = args.interface
            monitor.logger.info(f"Interface overridden naar: {args.interface}")

        # Override log level als verbose
        if args.verbose:
            monitor.logger.setLevel(logging.DEBUG)
            for handler in monitor.logger.handlers:
                handler.setLevel(logging.DEBUG)

        monitor.start()

    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
