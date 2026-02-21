#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Network Monitor - Detecteert verdacht netwerkverkeer
Geschikt voor gebruik op een monitoring/span port
"""

import sys
import os
import signal
import argparse
import logging
import threading
import time
import psutil
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
from device_discovery import DeviceDiscovery

# Optional integrations (SIEM, Threat Intel)
try:
    from integrations.base import IntegrationManager
    from integrations.threat_intel import ThreatIntelManager
    INTEGRATIONS_AVAILABLE = True
except ImportError:
    INTEGRATIONS_AVAILABLE = False

# Optional PCAP exporter for forensics
try:
    from pcap_exporter import PCAPExporter
    PCAP_AVAILABLE = True
except ImportError:
    PCAPExporter = None
    PCAP_AVAILABLE = False


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
                    # Use config value if set, otherwise fall back to environment variable
                    db_password = pg_config.get('password') or os.environ.get('DB_PASSWORD', 'netmonitor')
                    self.db = DatabaseManager(
                        host=pg_config.get('host') or os.environ.get('DB_HOST', 'localhost'),
                        port=pg_config.get('port') or int(os.environ.get('DB_PORT', '5432')),
                        database=pg_config.get('database') or os.environ.get('DB_NAME', 'netmonitor'),
                        user=pg_config.get('user') or os.environ.get('DB_USER', 'netmonitor'),
                        password=db_password,
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

        # Initialiseer AbuseIPDB client (with database caching)
        self.abuseipdb = None
        # Check both top-level and integrations.threat_intel.abuseipdb paths
        abuseipdb_config = self.config.get('abuseipdb', {})
        if not abuseipdb_config.get('enabled'):
            abuseipdb_config = self.config.get('integrations', {}).get('threat_intel', {}).get('abuseipdb', {})
        if abuseipdb_config.get('enabled', False):
            api_key = abuseipdb_config.get('api_key', '')
            if api_key:
                try:
                    rate_limit = abuseipdb_config.get('rate_limit', 1000)
                    # Pass database for persistent caching across restarts
                    self.abuseipdb = AbuseIPDBClient(api_key, rate_limit=rate_limit, db=self.db)
                    self.logger.info("AbuseIPDB client enabled with database caching")
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

        # Initialiseer device discovery
        self.device_discovery = None
        if self.config.get('device_discovery', {}).get('enabled', True):
            try:
                self.device_discovery = DeviceDiscovery(
                    db_manager=self.db,
                    sensor_id=self.sensor_id,
                    config=self.config
                )
                self.logger.info("Device Discovery enabled")
                # Update vendor info in background to not block startup
                import threading
                def update_vendors_background():
                    try:
                        updated = self.device_discovery.update_missing_vendors()
                        if updated > 0:
                            self.logger.info(f"Updated vendor info for {updated} existing devices")
                    except Exception as e:
                        self.logger.error(f"Error updating vendors in background: {e}")
                thread = threading.Thread(target=update_vendors_background, daemon=True)
                thread.start()
            except Exception as e:
                self.logger.error(f"Fout bij initialiseren device discovery: {e}")

        # Initialiseer integrations (SIEM, Threat Intel) - optioneel
        self.integration_manager = None
        self.threat_intel_manager = None

        if INTEGRATIONS_AVAILABLE:
            integrations_config = self.config.get('integrations', {})

            if integrations_config.get('enabled', False):
                try:
                    # Initialize Integration Manager
                    self.integration_manager = IntegrationManager(integrations_config)
                    self.integration_manager.initialize_from_config(self.config)

                    enabled_count = len(self.integration_manager.get_all(enabled_only=True))
                    self.logger.info(f"Integration Manager enabled with {enabled_count} active integration(s)")

                    # Log which integrations are active
                    for integration in self.integration_manager.get_all(enabled_only=True):
                        self.logger.info(f"  - {integration.display_name}: enabled")

                except Exception as e:
                    self.logger.error(f"Error initializing Integration Manager: {e}")
                    self.integration_manager = None

                # Initialize Threat Intel Manager (separate from SIEM integrations)
                threat_intel_config = integrations_config.get('threat_intel', {})
                if threat_intel_config.get('enabled', False):
                    try:
                        self.threat_intel_manager = ThreatIntelManager(
                            config=threat_intel_config,
                            db_manager=self.db
                        )

                        # Register threat intel sources
                        self._init_threat_intel_sources(threat_intel_config)

                        sources = self.threat_intel_manager.get_sources(enabled_only=True)
                        self.logger.info(f"Threat Intel Manager enabled with {len(sources)} source(s)")

                    except Exception as e:
                        self.logger.error(f"Error initializing Threat Intel Manager: {e}")
                        self.threat_intel_manager = None
            else:
                self.logger.debug("Integrations disabled in config")
        else:
            self.logger.debug("Integrations module not available")

        # Initialize PCAP exporter for forensic packet capture
        self.pcap_exporter = None
        if PCAP_AVAILABLE:
            pcap_config = self.config.get('thresholds', {}).get('pcap_export', {})
            if pcap_config.get('enabled', True):
                try:
                    self.pcap_exporter = PCAPExporter(config=self.config)
                    self.logger.info("PCAP Exporter enabled for forensic capture")
                except Exception as e:
                    self.logger.error(f"Error initializing PCAP Exporter: {e}")
                    self.pcap_exporter = None
            else:
                self.logger.debug("PCAP export disabled in config")
        else:
            self.logger.debug("PCAP Exporter module not available")

        # Initialiseer web dashboard (alleen embedded mode)
        # Als DASHBOARD_SERVER=gunicorn, dan draait dashboard als separate service
        self.dashboard = None
        dashboard_server = os.environ.get('DASHBOARD_SERVER', 'embedded')

        if self.config.get('dashboard', {}).get('enabled', True):
            if dashboard_server == 'embedded':
                # Start embedded Flask dashboard in this process
                try:
                    host = self.config.get('dashboard', {}).get('host', '0.0.0.0')
                    port = self.config.get('dashboard', {}).get('port', 8080)
                    self.dashboard = DashboardServer(config_file=config_file, host=host, port=port)
                    # Pass monitor reference for PCAP and TLS access
                    self.dashboard.app.monitor = self
                    self.dashboard.app.pcap_exporter = self.pcap_exporter
                    self.logger.info("Web Dashboard enabled (embedded Flask mode)")
                except Exception as e:
                    self.logger.error(f"Fout bij initialiseren dashboard: {e}")
            elif dashboard_server == 'gunicorn':
                # Dashboard runs as separate service (netmonitor-dashboard.service)
                self.logger.info("Dashboard mode: gunicorn (running as separate service)")
                self.logger.info("Dashboard should be started via: systemctl start netmonitor-dashboard")
            else:
                self.logger.warning(f"Unknown DASHBOARD_SERVER value: {dashboard_server}, defaulting to embedded")
                try:
                    host = self.config.get('dashboard', {}).get('host', '0.0.0.0')
                    port = self.config.get('dashboard', {}).get('port', 8080)
                    self.dashboard = DashboardServer(config_file=config_file, host=host, port=port)
                    # Pass monitor reference for PCAP and TLS access
                    self.dashboard.app.monitor = self
                    self.dashboard.app.pcap_exporter = self.pcap_exporter
                    self.logger.info("Web Dashboard enabled (embedded Flask mode)")
                except Exception as e:
                    self.logger.error(f"Fout bij initialiseren dashboard: {e}")

        # Setup signal handlers voor graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # Check for missing environment variables (informational only)
        self._check_env_config()

        self.logger.info("Network Monitor geïnitialiseerd")

    def _check_env_config(self):
        """Check for missing environment variables from .env.example"""
        try:
            from config_loader import check_env_config
            from pathlib import Path

            # Find .env.example relative to config file or current dir
            base_dir = Path(__file__).parent
            env_file = base_dir / ".env"
            example_file = base_dir / ".env.example"

            if example_file.exists():
                missing = check_env_config(str(env_file), str(example_file))
                if missing:
                    # Only log at debug level - not critical for operation
                    self.logger.debug(f"Environment: {len(missing)} optional variable(s) not set in .env")
        except Exception as e:
            self.logger.debug(f"Could not check environment config: {e}")

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
        """Background thread that periodically syncs config from database and polls commands"""
        self.logger.info(f"Config/command sync enabled (checking every {interval}s)")

        while self.running:
            try:
                time.sleep(interval)
                if self.running:  # Check again after sleep
                    self._sync_config_from_database()
                    # Also poll and execute commands for SOC server
                    self._poll_and_execute_commands()
            except Exception as e:
                self.logger.error(f"Error in config sync loop: {e}")

    def _poll_and_execute_commands(self):
        """Poll database for pending commands and execute them (for SOC server self-monitoring)"""
        if not self.db or not self.sensor_id:
            return

        try:
            commands = self.db.get_pending_commands(self.sensor_id)
            for command in commands:
                self._execute_local_command(command)
        except Exception as e:
            self.logger.error(f"Error polling commands: {e}")

    def _execute_local_command(self, command):
        """Execute a command for the SOC server (local execution, direct database updates)"""
        import subprocess

        command_id = command['id']
        command_type = command['command_type']
        parameters = command.get('parameters', {}) or {}

        self.logger.info(f"Executing command: {command_type} (ID: {command_id})")

        try:
            # Update status to executing
            self.db.update_command_status(command_id, 'executing')

            result = {'success': False, 'message': 'Unknown command'}

            if command_type == 'restart':
                result = {
                    'success': True,
                    'message': 'SOC server will restart in 5 seconds'
                }
                self.logger.warning("RESTART command received - SOC server will restart")
                # Update status before restarting
                self.db.update_command_status(command_id, 'completed', result)
                # Schedule restart (use netmonitor service, not netmonitor-sensor)
                subprocess.Popen(['bash', '-c', 'sleep 5 && systemctl restart netmonitor'])
                return

            elif command_type == 'update':
                # Update SOC server software from git
                branch = parameters.get('branch', '')

                self.logger.info(f"UPDATE command received - updating from git{f' (branch: {branch})' if branch else ''}")

                try:
                    install_dir = '/opt/netmonitor'

                    # Find SSH key for git operations (try common locations)
                    ssh_key = None
                    for key_path in ['/root/.ssh/netmonitor_id_ed25519', '/root/.ssh/id_ed25519', '/root/.ssh/id_rsa']:
                        if os.path.exists(key_path):
                            ssh_key = key_path
                            break

                    # Check if remote is SSH and convert to HTTPS if no SSH key available
                    # This allows updates on customer systems without SSH keys configured
                    url_override = ''
                    if not ssh_key:
                        try:
                            remote_result = subprocess.run(
                                ['git', '-C', install_dir, 'remote', 'get-url', 'origin'],
                                capture_output=True, text=True, timeout=5
                            )
                            remote_url = remote_result.stdout.strip()
                            # Convert git@github.com:user/repo.git to https://github.com/user/repo.git
                            if remote_url.startswith('git@github.com:'):
                                https_url = remote_url.replace('git@github.com:', 'https://github.com/')
                                url_override = f'git remote set-url origin {https_url}; '
                                self.logger.info(f"No SSH key found, using HTTPS for git pull")
                        except Exception:
                            pass

                    # Set GIT_SSH_COMMAND to use specific key (needed when running as systemd service)
                    ssh_cmd = f'export GIT_SSH_COMMAND="ssh -i {ssh_key} -o StrictHostKeyChecking=accept-new"; ' if ssh_key else ''

                    # Build git command with remount for read-only filesystems
                    if branch:
                        git_cmd = (
                            f'mount -o remount,rw / 2>/dev/null; '
                            f'{url_override}'
                            f'{ssh_cmd}'
                            f'cd {install_dir} && git fetch origin && git checkout {branch} && git pull origin {branch}; '
                            f'git_status=$?; '
                            f'mount -o remount,ro / 2>/dev/null; '
                            f'exit $git_status'
                        )
                    else:
                        git_cmd = (
                            f'mount -o remount,rw / 2>/dev/null; '
                            f'{url_override}'
                            f'{ssh_cmd}'
                            f'cd {install_dir} && git pull; '
                            f'git_status=$?; '
                            f'mount -o remount,ro / 2>/dev/null; '
                            f'exit $git_status'
                        )

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
                            'message': 'Git pull successful. SOC server will restart in 5 seconds.',
                            'git_output': git_result.stdout
                        }
                        self.logger.info(f"Git pull successful: {git_result.stdout}")

                        # Update status before restarting
                        self.db.update_command_status(command_id, 'completed', result)

                        # Schedule service restart (netmonitor, not netmonitor-sensor)
                        subprocess.Popen(['bash', '-c', 'sleep 5 && systemctl restart netmonitor'])
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

            elif command_type == 'reboot':
                result = {
                    'success': True,
                    'message': 'System will reboot in 5 seconds'
                }
                self.logger.warning("REBOOT command received - system will reboot in 5 seconds")
                self.db.update_command_status(command_id, 'completed', result)
                subprocess.Popen(['bash', '-c', 'sleep 5 && shutdown -r now'])
                return

            elif command_type == 'update_config':
                # Force config reload from database
                try:
                    self._load_config_from_database()
                    result = {
                        'success': True,
                        'message': 'Configuration reloaded from database'
                    }
                    self.logger.info("Config manually reloaded via command")
                except Exception as e:
                    result = {
                        'success': False,
                        'message': f'Config reload failed: {e}'
                    }

            elif command_type == 'get_status':
                uptime = int(time.time() - getattr(self, 'start_time', time.time()))
                result = {
                    'success': True,
                    'data': {
                        'uptime_seconds': uptime,
                        'self_monitor_enabled': self.self_monitor_enabled,
                        'sensor_id': self.sensor_id,
                        'interface': getattr(self, 'interface_display', 'unknown')
                    }
                }

            # Report result
            self.db.update_command_status(command_id, 'completed', result)
            self.logger.info(f"Command {command_type} completed: {result.get('message', 'OK')}")

        except Exception as e:
            self.logger.error(f"Error executing command {command_type}: {e}")
            try:
                self.db.update_command_status(command_id, 'failed', {'error': str(e)})
            except:
                pass

    def _init_threat_intel_sources(self, config):
        """Initialize and register threat intelligence sources"""
        if not self.threat_intel_manager:
            return

        # Import sources dynamically to avoid import errors if not needed
        try:
            from integrations.threat_intel.misp_source import MISPSource
            from integrations.threat_intel.otx_source import OTXSource
            from integrations.threat_intel.abuseipdb_source import AbuseIPDBSource
        except ImportError as e:
            self.logger.error(f"Failed to import threat intel sources: {e}")
            return

        # Register MISP source
        misp_config = config.get('misp', {})
        if misp_config.get('enabled', False):
            try:
                misp = MISPSource(misp_config)
                valid, error = misp.validate_config()
                if valid:
                    self.threat_intel_manager.register_source(misp)
                    self.logger.info("  - MISP: registered")
                else:
                    self.logger.warning(f"  - MISP: config invalid - {error}")
            except Exception as e:
                self.logger.error(f"  - MISP: failed to initialize - {e}")

        # Register OTX source
        otx_config = config.get('otx', {})
        if otx_config.get('enabled', False):
            try:
                otx = OTXSource(otx_config)
                valid, error = otx.validate_config()
                if valid:
                    self.threat_intel_manager.register_source(otx)
                    self.logger.info("  - OTX: registered")
                else:
                    self.logger.warning(f"  - OTX: config invalid - {error}")
            except Exception as e:
                self.logger.error(f"  - OTX: failed to initialize - {e}")

        # Register AbuseIPDB source
        abuseipdb_config = config.get('abuseipdb', {})
        if abuseipdb_config.get('enabled', False):
            try:
                abuseipdb = AbuseIPDBSource(abuseipdb_config)
                valid, error = abuseipdb.validate_config()
                if valid:
                    self.threat_intel_manager.register_source(abuseipdb)
                    self.logger.info("  - AbuseIPDB: registered")
                else:
                    self.logger.warning(f"  - AbuseIPDB: config invalid - {error}")
            except Exception as e:
                self.logger.error(f"  - AbuseIPDB: failed to initialize - {e}")

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
        """Laad threat feeds (van cache, download in background indien nodig)"""
        if not self.threat_feeds:
            return

        self.logger.info("Loading threat feeds...")

        # Check of cached feeds bestaan
        feeds_to_use = self.config['threat_feeds'].get('feeds', ['feodotracker', 'urlhaus', 'threatfox'])

        # Probeer feeds te laden van cache
        results = self.threat_feeds.load_feeds(feeds_to_use)

        # Als geen feeds geladen, download in background thread (niet blokkeren)
        if sum(results.values()) == 0:
            self.logger.info("No cached feeds found, downloading in background...")
            import threading
            def background_download():
                try:
                    self.threat_feeds.update_all_feeds(force=True)
                    self.logger.info("Background threat feed download completed")
                except Exception as e:
                    self.logger.error(f"Background threat feed download failed: {e}")
            thread = threading.Thread(target=background_download, daemon=True)
            thread.start()
        else:
            self.logger.info(f"Loaded {sum(results.values())} IOCs from cached feeds")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Signal {signum} ontvangen, shutting down...")
        self.running = False

        # Graceful shutdown of device discovery
        if self.device_discovery:
            try:
                self.device_discovery.shutdown()
            except Exception as e:
                self.logger.error(f"Error shutting down device discovery: {e}")

        sys.exit(0)

    def packet_callback(self, packet):
        """Callback functie voor elk ontvangen packet"""
        try:
            # Device discovery - process all packets (including ARP)
            if self.device_discovery:
                try:
                    self.device_discovery.process_packet(packet)
                except Exception as dd_error:
                    self.logger.debug(f"Device discovery error: {dd_error}")

            # Check of packet IP layer heeft voor threat detection
            if not packet.haslayer(IP):
                return

            # Add packet to PCAP buffer for forensic capture
            if self.pcap_exporter:
                try:
                    self.pcap_exporter.add_packet(packet)
                except Exception as pcap_error:
                    self.logger.debug(f"PCAP buffer error: {pcap_error}")

            # Track packet in metrics
            if self.metrics:
                self.metrics.track_packet(packet)

            # Analyseer packet met detector
            threats = self.detector.analyze_packet(packet)

            # Als threats gevonden, stuur alerts
            if threats:
                for threat in threats:
                    # Enrich with threat intelligence (before storing)
                    if self.threat_intel_manager:
                        try:
                            threat = self.threat_intel_manager.enrich_alert(threat)
                        except Exception as ti_error:
                            self.logger.debug(f"Threat intel enrichment error: {ti_error}")

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

                    # Capture PCAP for high-severity alerts
                    if self.pcap_exporter:
                        severity = threat.get('severity', 'LOW')
                        if severity in ('CRITICAL', 'HIGH'):
                            try:
                                # Use immediate=True to ensure file is written immediately
                                pcap_path = self.pcap_exporter.capture_alert(threat, packet, immediate=True)
                                if pcap_path:
                                    self.logger.info(f"PCAP captured for {threat.get('type')}: {pcap_path}")
                            except Exception as pcap_error:
                                self.logger.debug(f"PCAP capture error: {pcap_error}")

                    # Send to SIEM integrations
                    if self.integration_manager:
                        try:
                            for siem in self.integration_manager.get_all(category='siem', enabled_only=True):
                                siem.send_alert(threat)
                        except Exception as siem_error:
                            self.logger.debug(f"SIEM output error: {siem_error}")

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

                # Detect IP address from monitoring interface
                ip_address = None
                try:
                    interface_config = self.self_monitor_config.get('interface', self.config.get('interface', 'lo'))

                    # Handle 'any', 'all', or None interface
                    if interface_config in ('any', 'all') or interface_config is None:
                        interface = None
                    elif isinstance(interface_config, str) and ',' in interface_config:
                        # For multiple interfaces, use the first one
                        interface = interface_config.split(',')[0].strip()
                    else:
                        interface = interface_config

                    if interface:
                        net_addrs = psutil.net_if_addrs()

                        if interface in net_addrs:
                            # Get IPv4 address from the monitoring interface
                            for addr in net_addrs[interface]:
                                if addr.family == socket.AF_INET:  # IPv4
                                    ip_address = addr.address
                                    break

                    # Fallback: try to get any non-loopback IP
                    if not ip_address:
                        net_addrs = psutil.net_if_addrs()
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
                    self.logger.debug(f"Could not detect IP address: {e}")
                    ip_address = None

                # Detect available network interfaces with PROMISC mode status (same as sensor_client.py)
                available_interfaces = []
                try:
                    net_ifs = psutil.net_if_addrs()
                    net_stats = psutil.net_if_stats()

                    for iface in net_ifs.keys():
                        if iface == 'lo' or iface.startswith('docker'):
                            continue

                        # Check if interface is in promiscuous mode
                        promisc = False
                        try:
                            # On Linux, check /sys/class/net/{iface}/flags
                            # IFF_PROMISC = 0x100 (256 decimal)
                            flags_path = f'/sys/class/net/{iface}/flags'
                            if os.path.exists(flags_path):
                                with open(flags_path, 'r') as f:
                                    flags = int(f.read().strip(), 16)
                                    promisc = bool(flags & 0x100)
                        except:
                            # Fallback: assume not in promisc mode
                            promisc = False

                        # Get interface status
                        is_up = net_stats.get(iface, None)
                        status = 'up' if (is_up and is_up.isup) else 'down'

                        available_interfaces.append({
                            'name': iface,
                            'promisc': promisc,
                            'status': status
                        })
                except Exception as e:
                    self.logger.debug(f"Could not detect available interfaces: {e}")

                # Detect current git branch
                git_branch = None
                try:
                    import subprocess
                    git_result = subprocess.run(
                        ['git', '-C', '/opt/netmonitor', 'branch', '--show-current'],
                        capture_output=True, text=True, timeout=5
                    )
                    if git_result.returncode == 0:
                        git_branch = git_result.stdout.strip()
                except Exception:
                    pass

                # Build config with available_interfaces, current interface, and git branch
                sensor_config = {
                    'interface': self.self_monitor_config.get('interface', self.config.get('interface', 'lo')),
                    'available_interfaces': available_interfaces,
                    'git_branch': git_branch
                }

                self.db.register_sensor(
                    sensor_id=self.sensor_id,
                    hostname=hostname,
                    location=location,
                    ip_address=ip_address,
                    config=sensor_config
                    # Note: status is automatically set to 'online' by register_sensor()
                )
                self.logger.info(f"SOC server registered as sensor: {self.sensor_id} ({hostname}, IP: {ip_address or 'unknown'}, {len(available_interfaces)} interfaces)")
            except Exception as e:
                self.logger.warning(f"Could not register SOC server as sensor: {e}")

        # Get interface from self_monitor config, fallback to legacy 'interface' key
        interface_config = self.self_monitor_config.get('interface', self.config.get('interface', 'lo'))

        # Safety: If interface is empty string, use 'lo' as fallback
        if not interface_config or (isinstance(interface_config, str) and interface_config.strip() == ''):
            self.logger.warning("Interface configuration is empty! Using 'lo' (loopback) as fallback.")
            self.logger.warning("Please configure an interface in the dashboard to ensure correct monitoring.")
            interface_config = 'lo'

        # Parse interface configuration (support comma-separated list)
        if interface_config in ('any', 'all') or interface_config is None:
            interface = None  # Listen on all interfaces
            self.interface_display = "all interfaces"
        elif isinstance(interface_config, str) and ',' in interface_config:
            # Multiple interfaces: "ens33, ens34, ens35" -> ["ens33", "ens34", "ens35"]
            interface = [iface.strip() for iface in interface_config.split(',')]
            self.interface_display = ', '.join(interface)
        else:
            # Single interface
            interface = interface_config
            self.interface_display = interface_config

        self.logger.info(f"Starting network monitor op interface: {self.interface_display}")
        self.logger.info("Druk op Ctrl+C om te stoppen")

        # Start config/command sync thread (if self-monitoring and database enabled)
        # Polls for config changes AND pending commands (update, restart, etc.)
        if self.db and self.sensor_id:
            config_sync_interval = 30  # 30 seconds for near-realtime config and command updates
            self.config_sync_thread = threading.Thread(
                target=self._config_sync_loop,
                args=(config_sync_interval,),
                daemon=True,
                name="ConfigCommandSync"
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

                        # Save to database (use interface_display for human-readable format)
                        self.db.save_sensor_metrics(
                            sensor_id=self.sensor_id,
                            cpu_percent=system_stats.get('cpu_percent'),
                            memory_percent=system_stats.get('memory_percent'),
                            disk_percent=system_stats.get('disk_percent'),
                            packets_captured=traffic_stats.get('total_packets'),
                            alerts_sent=traffic_stats.get('alerts'),
                            network_interface=self.interface_display,
                            bandwidth_mbps=bandwidth_mbps
                        )
                        self.logger.debug(f"Saved SOC server metrics: {traffic_stats.get('total_packets', 0)} packets, {bandwidth_mbps:.2f} Mbps")
                    except Exception as e:
                        self.logger.error(f"Error saving SOC server metrics: {e}")

                # Cleanup oude detector tracking data (voorkomt memory leak)
                if hasattr(self, 'detector') and hasattr(self.detector, 'cleanup_old_data'):
                    try:
                        self.detector.cleanup_old_data()
                    except Exception as e:
                        self.logger.warning(f"Error cleaning up detector data: {e}")
                if hasattr(self, 'behavior_detector') and hasattr(self.behavior_detector, 'cleanup_old_data'):
                    try:
                        self.behavior_detector.cleanup_old_data()
                    except Exception as e:
                        self.logger.warning(f"Error cleaning up behavior_detector data: {e}")

        metrics_save_thread = threading.Thread(target=save_sensor_metrics_periodically, daemon=True, name="MetricsSave")
        metrics_save_thread.start()

        try:
            # Start packet sniffing
            # store=0 betekent packets niet in memory houden (belangrijk voor lange runs)
            # iface can be: None (all), "eth0" (single), or ["eth0", "eth1"] (multiple)
            sniff(
                iface=interface,
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
