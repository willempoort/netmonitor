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
            self.logger.info(f"SOC server self-monitoring enabled as sensor: {self.sensor_id}")
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

    def _deep_merge_config(self, base: dict, override: dict) -> dict:
        """Deep merge two config dicts (override takes precedence), in-place on base"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                # Recursive merge for nested dicts
                self._deep_merge_config(base[key], value)
            else:
                # Direct override for non-dict values or new keys
                base[key] = value
        return base

    def _count_config_differences(self, old_config: dict, new_config: dict, prefix='') -> int:
        """Count number of changed parameters between two configs"""
        changes = 0
        for key, value in new_config.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                if key in old_config and isinstance(old_config[key], dict):
                    changes += self._count_config_differences(old_config[key], value, full_key)
                else:
                    # Entire section is new
                    changes += self._count_dict_params(value)
            else:
                if key not in old_config or old_config[key] != value:
                    changes += 1
        return changes

    def _count_dict_params(self, d: dict) -> int:
        """Count total number of leaf parameters in a dict"""
        count = 0
        for value in d.values():
            if isinstance(value, dict):
                count += self._count_dict_params(value)
            else:
                count += 1
        return count

    def _load_config_from_database(self):
        """Load detection thresholds from database (for SOC server self-monitoring)"""
        if not self.db or not self.sensor_id:
            return

        self.logger.debug("Loading detection config from database...")

        try:
            # Get config for this sensor (or global if sensor-specific doesn't exist)
            db_config = self.db.get_sensor_config(sensor_id=self.sensor_id)

            if db_config:
                # Count changes before merge
                changes = self._count_config_differences(self.config, db_config)

                # Deep merge database config with config.yaml (database takes precedence)
                self._deep_merge_config(self.config, db_config)

                if changes > 0:
                    self.logger.info(f"✓ Config updated from database: {changes} parameter(s) changed")

                    # Log specific threshold changes if any
                    if 'thresholds' in db_config:
                        categories = ', '.join(db_config['thresholds'].keys())
                        self.logger.info(f"  Updated categories: {categories}")
                else:
                    self.logger.debug("Config synced from database (no changes)")
            else:
                self.logger.debug("No database config found, using config.yaml defaults")

        except Exception as e:
            self.logger.warning(f"Error loading config from database: {e}")
            self.logger.info("Falling back to config.yaml")

    def _sync_config_from_database(self):
        """Periodically sync config from database (called during operation)"""
        if not self.db or not self.sensor_id:
            return

        try:
            # Load and merge config from database
            # This updates self.config in-place, which detector uses by reference
            self._load_config_from_database()

            # Detector uses self.config directly, so changes are immediately active
            # No need to recreate detector or manually update detector.config

        except Exception as e:
            self.logger.error(f"Error syncing config from database: {e}")

    def _config_sync_loop(self, interval):
        """Background thread that periodically syncs config from database"""
        self.logger.info(f"Config sync enabled (checking every {interval}s)")

        while self.running:
            try:
                time.sleep(interval)
                if self.running:  # Check again after sleep
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

    def get_dashboard_metrics(self) -> dict:
        """
        Get metrics for dashboard display
        - When self_monitor=true: Use local MetricsCollector
        - When self_monitor=false: Aggregate from database
        - CPU/Memory: Always from SOC server itself
        """
        import psutil
        from datetime import datetime

        # Get system stats (always from SOC server)
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            system_stats = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_gb': round(memory.used / (1024**3), 2),
                'memory_total_gb': round(memory.total / (1024**3), 2)
            }
        except Exception as e:
            self.logger.error(f"Error getting system stats: {e}")
            system_stats = {
                'cpu_percent': 0,
                'memory_percent': 0,
                'memory_used_gb': 0,
                'memory_total_gb': 0
            }

        # Get traffic stats
        if self.self_monitor_enabled and self.metrics:
            # Self-monitoring mode: use local metrics
            metrics_data = self.metrics.get_dashboard_metrics()
            traffic_stats = metrics_data.get('traffic', {})
            top_talkers = metrics_data.get('top_talkers', [])
        else:
            # Management-only mode: aggregate from database
            if self.db:
                agg_metrics = self.db.get_aggregated_metrics()
                traffic_stats = {
                    'packets_per_second': agg_metrics.get('packets_per_sec', 0),
                    'total_packets': agg_metrics.get('total_packets', 0),
                    'bandwidth_mbps': agg_metrics.get('bandwidth_mbps', 0),
                    'alerts': agg_metrics.get('alerts_per_min', 0)
                }
                top_talkers = []
            else:
                traffic_stats = {
                    'packets_per_second': 0,
                    'total_packets': 0,
                    'bandwidth_mbps': 0,
                    'alerts': 0
                }
                top_talkers = []

        return {
            'traffic': traffic_stats,
            'system': system_stats,
            'top_talkers': top_talkers,
            'timestamp': datetime.now().isoformat()
        }

    def start(self):
        """Start het monitoren van netwerkverkeer"""
        self.running = True

        # Start dashboard server (always, regardless of self-monitoring mode)
        if self.dashboard:
            self.dashboard.start()
            dashboard_host = self.config.get('dashboard', {}).get('host', '0.0.0.0')
            dashboard_port = self.config.get('dashboard', {}).get('port', 8080)
            self.logger.info(f"Dashboard beschikbaar op: http://{dashboard_host}:{dashboard_port}")

        # Start metrics broadcaster (ALWAYS - works in both modes)
        def broadcast_metrics():
            """Broadcast metrics to dashboard every 5 seconds"""
            while self.running:
                if self.dashboard:
                    try:
                        metrics_data = self.get_dashboard_metrics()
                        self.dashboard.broadcast_metrics(metrics_data)
                    except Exception as e:
                        self.logger.error(f"Error broadcasting metrics: {e}")
                threading.Event().wait(5)  # 5 seconds

        metrics_thread = threading.Thread(target=broadcast_metrics, daemon=True, name="MetricsBroadcast")
        metrics_thread.start()
        self.logger.info("Dashboard metrics broadcaster started")

        # Check if self-monitoring is disabled
        if not self.self_monitor_enabled:
            self.logger.info("Self-monitoring is DISABLED - SOC server will only receive alerts from remote sensors")
            self.logger.info("Dashboard-only mode active. Press Ctrl+C to stop.")

            # Deregister SOC server as sensor if it was previously registered
            if self.db and self.sensor_id:
                try:
                    self.db.deregister_sensor(self.sensor_id)
                    self.logger.info(f"SOC server deregistered as sensor: {self.sensor_id}")
                except Exception as e:
                    self.logger.warning(f"Could not deregister SOC server as sensor: {e}")

            # Keep main thread alive (dashboard thread is daemon)
            # Use Event.wait() instead of signal.pause() for systemd compatibility
            try:
                shutdown_event = threading.Event()
                # Wait indefinitely until interrupted
                while self.running:
                    shutdown_event.wait(timeout=1)  # Wake up every second to check self.running
            except KeyboardInterrupt:
                self.logger.info("Shutting down...")
                self.running = False
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

        # Check of we root privileges hebben
        if conf.L3socket == conf.L3socket6:
            self.logger.warning(
                "Mogelijk onvoldoende privileges. Run als root voor volledige functionaliteit."
            )

        # Start periodic metrics save to database (for SOC server sensor)
        def save_sensor_metrics_periodically():
            """Save SOC server metrics to database every 60 seconds"""
            while self.running:
                threading.Event().wait(60)  # Wait 60 seconds
                if self.running and self.metrics and self.db and self.sensor_id:
                    try:
                        # Get current metrics
                        dashboard_metrics = self.metrics.get_dashboard_metrics()
                        system_stats = dashboard_metrics.get('system', {})
                        traffic_stats = dashboard_metrics.get('traffic', {})

                        # Calculate bandwidth in Mbps
                        bandwidth_mbps = traffic_stats.get('bandwidth_mbps', 0)

                        # Get network interface
                        interface_name = self.self_monitor_config.get('interface',
                                                                       self.config.get('interface', 'lo'))

                        # Save to database
                        self.db.save_sensor_metrics(
                            sensor_id=self.sensor_id,
                            cpu_percent=system_stats.get('cpu_percent'),
                            memory_percent=system_stats.get('memory_percent'),
                            packets_captured=traffic_stats.get('total_packets'),
                            alerts_sent=traffic_stats.get('alerts'),
                            network_interface=interface_name,
                            bandwidth_mbps=bandwidth_mbps
                        )
                        self.logger.debug(f"Saved SOC server metrics: {traffic_stats.get('total_packets', 0)} packets, {bandwidth_mbps:.2f} Mbps")
                    except Exception as e:
                        self.logger.error(f"Error saving SOC server metrics: {e}")

        metrics_save_thread = threading.Thread(target=save_sensor_metrics_periodically, daemon=True, name="MetricsSave")
        metrics_save_thread.start()

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
