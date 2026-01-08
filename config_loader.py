# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Configuration loader
Supports both YAML (for SOC server) and .conf (for sensors)

Configuration hierarchy (highest priority first):
1. Database config (runtime, via dashboard)
2. User's config.yaml
3. Best practice defaults (config_defaults.py)
"""

import yaml
import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Import defaults - uses try/except to handle import from different contexts
try:
    from config_defaults import BEST_PRACTICE_CONFIG
except ImportError:
    try:
        from .config_defaults import BEST_PRACTICE_CONFIG
    except ImportError:
        BEST_PRACTICE_CONFIG = {}

logger = logging.getLogger('NetMonitor.ConfigLoader')


def _parse_conf_file(config_file):
    """
    Parse simple KEY=VALUE configuration file (sensor.conf format)
    Lines starting with # are comments
    """
    config = {}

    with open(config_file, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Parse KEY=VALUE
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]

                config[key] = value

    return config


def _build_sensor_config(conf_dict):
    """
    Build full sensor configuration from minimal .conf file
    Only connection settings are in .conf, all detection settings come from SOC server
    """
    # Required fields validation (SENSOR_ID and SENSOR_LOCATION are optional)
    required = ['INTERFACE', 'SOC_SERVER_URL']
    for field in required:
        if field not in conf_dict or not conf_dict[field]:
            raise ValueError(f"Required field missing in sensor.conf: {field}")

    # Parse internal networks (comma-separated)
    internal_networks = conf_dict.get('INTERNAL_NETWORKS', '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16')
    internal_networks_list = [net.strip() for net in internal_networks.split(',')]

    # Parse boolean values
    ssl_verify = conf_dict.get('SSL_VERIFY', 'true').lower() in ('true', '1', 'yes')

    # Parse integer values
    try:
        heartbeat_interval = int(conf_dict.get('HEARTBEAT_INTERVAL', '30'))
    except ValueError:
        heartbeat_interval = 30

    try:
        config_sync_interval = int(conf_dict.get('CONFIG_SYNC_INTERVAL', '300'))
    except ValueError:
        config_sync_interval = 300

    # Build configuration with minimal defaults
    # Detection thresholds will be loaded from SOC server
    config = {
        'interface': conf_dict['INTERFACE'],
        'internal_networks': internal_networks_list,

        # Sensor mode configuration
        'sensor': {
            'id': conf_dict.get('SENSOR_ID'),  # Optional - will use hostname if not set
            'auth_token': conf_dict.get('SENSOR_SECRET_KEY', ''),
            'location': conf_dict.get('SENSOR_LOCATION', 'Unknown'),  # Optional with default
        },

        # Server connection
        'server': {
            'url': conf_dict['SOC_SERVER_URL'],
            'verify_ssl': ssl_verify,
        },

        # Performance settings
        'performance': {
            'heartbeat_interval': heartbeat_interval,
            'config_sync_interval': config_sync_interval,
        },

        # Minimal logging defaults (sensor mode)
        'logging': {
            'level': 'INFO',
            'file': '/var/log/netmonitor/sensor.log',
            'max_size_mb': 100,
            'backup_count': 5,
        },

        # Minimal thresholds (will be overridden by SOC server)
        'thresholds': {
            'port_scan': {
                'enabled': True,
                'unique_ports': 20,
                'time_window': 60
            },
            'connection_flood': {
                'enabled': True,
                'connections_per_second': 100,
                'time_window': 10
            },
            'packet_size': {
                'enabled': True,
                'min_suspicious_size': 1400,
                'max_normal_size': 1500
            },
            'dns_tunnel': {
                'enabled': True,
                'subdomain_length': 50,
                'query_count': 10,
                'time_window': 60
            },
            'icmp_tunnel': {
                'enabled': False,
                'payload_size_threshold': 64,
                'frequency_threshold': 10
            },
            'http_anomaly': {
                'enabled': False,
                'post_threshold': 50,
                'post_time_window': 300,
                'dlp_min_payload_size': 1024,
                'entropy_threshold': 6.5
            },
            'smtp_ftp_transfer': {
                'enabled': False,
                'size_threshold_mb': 50,
                'time_window': 300
            },
            'dns_enhanced': {
                'dga_threshold': 0.6,
                'entropy_threshold': 4.5,
                'encoding_detection': True
            },
            'beaconing': {
                'enabled': True,
                'min_connections': 5,
                'max_jitter_percent': 20
            },
            'outbound_volume': {
                'enabled': True,
                'threshold_mb': 100,
                'time_window': 300
            },
            'lateral_movement': {
                'enabled': True,
                'unique_targets': 5,
                'time_window': 300
            },
            'brute_force': {
                'enabled': True,
                'attempts_threshold': 5,
                'time_window': 300,
                'exclude_streaming': True,
                'exclude_cdn': True
            },
            'modern_protocols': {
                'quic_detection': True,
                'http3_detection': True,
                'streaming_services': [],  # Loaded from main config
                'cdn_providers': []  # Loaded from main config
            },
            'protocol_mismatch': {
                'enabled': True,
                'detect_http_non_standard': True,
                'detect_ssh_non_standard': True,
                'detect_dns_non_standard': True,
                'detect_ftp_non_standard': True,
                'ignore_quic': True
            },
        },

        # Database disabled for sensors (only SOC server has database)
        'database': {
            'enabled': False
        },

        # Dashboard disabled for sensors
        'dashboard': {
            'enabled': False
        },

        # Threat feeds disabled for sensors
        'threat_feeds': {
            'enabled': False
        },

        # Self-monitoring disabled (sensors report to SOC server)
        'self_monitor': {
            'enabled': False
        }
    }

    return config


def _deep_merge(base: Dict, override: Dict, path: str = "") -> Dict:
    """
    Deep merge two dictionaries.
    Values from 'override' take precedence over 'base'.
    Returns a new merged dict without modifying originals.
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursive merge for nested dicts
            result[key] = _deep_merge(result[key], value, f"{path}.{key}" if path else key)
        else:
            # Override value
            result[key] = value

    return result


def _find_added_keys(base: Dict, merged: Dict, path: str = "") -> List[str]:
    """
    Find keys that were added from defaults (present in merged but not in base).
    Returns list of dotted key paths.
    """
    added = []

    for key, value in merged.items():
        current_path = f"{path}.{key}" if path else key

        if key not in base:
            # This key was added from defaults
            added.append(current_path)
        elif isinstance(value, dict) and isinstance(base.get(key), dict):
            # Recurse into nested dicts
            added.extend(_find_added_keys(base[key], value, current_path))

    return added


def _log_config_status(user_config: Dict, merged_config: Dict):
    """
    Log information about configuration merging.
    """
    added_keys = _find_added_keys(user_config, merged_config)

    if added_keys:
        # Group by top-level section
        sections = {}
        for key in added_keys:
            section = key.split('.')[0]
            if section not in sections:
                sections[section] = []
            sections[section].append(key)

        logger.info(f"Config: {len(added_keys)} parameter(s) auto-populated from defaults")

        # Log sections with most additions
        for section, keys in sorted(sections.items(), key=lambda x: -len(x[1])):
            if len(keys) > 3:
                logger.debug(f"  {section}: {len(keys)} defaults applied")
            else:
                for key in keys:
                    logger.debug(f"  {key}: using default value")
    else:
        logger.debug("Config: all parameters specified in config file")


def _inject_env_secrets(config: Dict) -> Dict:
    """
    Inject secrets from environment variables into configuration.
    Environment variables have priority over config.yaml values.

    Security note: Warns if secrets are found in config.yaml (should be in .env instead)

    Mapping:
    - ABUSEIPDB_API_KEY → integrations.threat_intel.abuseipdb.api_key
    - MISP_API_KEY → integrations.threat_intel.misp.api_key
    - MISP_URL → integrations.threat_intel.misp.url
    - OTX_API_KEY → integrations.threat_intel.otx.api_key
    - WAZUH_API_URL → integrations.siem.wazuh.api_url
    - WAZUH_API_USER → integrations.siem.wazuh.api_user
    - WAZUH_API_PASSWORD → integrations.siem.wazuh.api_password
    - FLASK_SECRET_KEY → dashboard.secret_key
    - DB_PASSWORD → database.postgresql.password
    """
    import os

    # Dashboard secrets
    flask_secret = os.environ.get('FLASK_SECRET_KEY')
    if flask_secret:
        if 'dashboard' not in config:
            config['dashboard'] = {}
        config['dashboard']['secret_key'] = flask_secret
        logger.debug("Using FLASK_SECRET_KEY from environment")
    elif config.get('dashboard', {}).get('secret_key'):
        logger.warning("SECURITY: dashboard.secret_key found in config.yaml - should be in .env as FLASK_SECRET_KEY")

    # Database password
    db_password = os.environ.get('DB_PASSWORD')
    if db_password:
        if 'database' not in config:
            config['database'] = {}
        if 'postgresql' not in config['database']:
            config['database']['postgresql'] = {}
        config['database']['postgresql']['password'] = db_password
        logger.debug("Using DB_PASSWORD from environment")
    elif config.get('database', {}).get('postgresql', {}).get('password'):
        logger.warning("SECURITY: database.postgresql.password found in config.yaml - should be in .env as DB_PASSWORD")

    # Ensure integrations structure exists
    if 'integrations' not in config:
        config['integrations'] = {}
    if 'threat_intel' not in config['integrations']:
        config['integrations']['threat_intel'] = {}
    if 'siem' not in config['integrations']:
        config['integrations']['siem'] = {}

    threat_intel = config['integrations']['threat_intel']
    siem = config['integrations']['siem']

    # AbuseIPDB
    abuseipdb_key = os.environ.get('ABUSEIPDB_API_KEY')
    if abuseipdb_key:
        if 'abuseipdb' not in threat_intel:
            threat_intel['abuseipdb'] = {}
        threat_intel['abuseipdb']['api_key'] = abuseipdb_key
        logger.debug("Using ABUSEIPDB_API_KEY from environment")
    elif threat_intel.get('abuseipdb', {}).get('api_key'):
        logger.warning("SECURITY: abuseipdb.api_key found in config.yaml - should be in .env as ABUSEIPDB_API_KEY")

    # MISP
    misp_url = os.environ.get('MISP_URL')
    misp_key = os.environ.get('MISP_API_KEY')
    if misp_url or misp_key:
        if 'misp' not in threat_intel:
            threat_intel['misp'] = {}
        if misp_url:
            threat_intel['misp']['url'] = misp_url
            logger.debug("Using MISP_URL from environment")
        if misp_key:
            threat_intel['misp']['api_key'] = misp_key
            logger.debug("Using MISP_API_KEY from environment")
    elif threat_intel.get('misp', {}).get('api_key'):
        logger.warning("SECURITY: misp.api_key found in config.yaml - should be in .env as MISP_API_KEY")

    # OTX
    otx_key = os.environ.get('OTX_API_KEY')
    if otx_key:
        if 'otx' not in threat_intel:
            threat_intel['otx'] = {}
        threat_intel['otx']['api_key'] = otx_key
        logger.debug("Using OTX_API_KEY from environment")
    elif threat_intel.get('otx', {}).get('api_key'):
        logger.warning("SECURITY: otx.api_key found in config.yaml - should be in .env as OTX_API_KEY")

    # Wazuh
    wazuh_url = os.environ.get('WAZUH_API_URL')
    wazuh_user = os.environ.get('WAZUH_API_USER')
    wazuh_password = os.environ.get('WAZUH_API_PASSWORD')
    if wazuh_url or wazuh_user or wazuh_password:
        if 'wazuh' not in siem:
            siem['wazuh'] = {}
        if wazuh_url:
            siem['wazuh']['api_url'] = wazuh_url
            logger.debug("Using WAZUH_API_URL from environment")
        if wazuh_user:
            siem['wazuh']['api_user'] = wazuh_user
            logger.debug("Using WAZUH_API_USER from environment")
        if wazuh_password:
            siem['wazuh']['api_password'] = wazuh_password
            logger.debug("Using WAZUH_API_PASSWORD from environment")
    elif siem.get('wazuh', {}).get('api_password'):
        logger.warning("SECURITY: wazuh.api_password found in config.yaml - should be in .env as WAZUH_API_PASSWORD")

    return config


def load_config(config_file, apply_defaults: bool = True):
    """
    Load configuration from file with automatic default population.

    Supports:
    - .yaml / .yml: Full configuration (SOC server)
    - .conf: Minimal sensor configuration (sensors)

    Args:
        config_file: Path to configuration file
        apply_defaults: If True, merge with BEST_PRACTICE_CONFIG defaults

    Configuration hierarchy (highest to lowest priority):
    1. Database config (applied later at runtime)
    2. User's config file
    3. Best practice defaults (config_defaults.py)

    This allows users to maintain a minimal config.yaml with only
    the settings they want to override. All other settings come
    from sensible defaults and can be further tuned via the database.
    """
    config_path = Path(config_file)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file niet gevonden: {config_file}")

    # Determine file type by extension
    if config_path.suffix.lower() in ['.conf', '.env']:
        # Sensor configuration (minimal .conf format)
        # Sensors have their own defaults in _build_sensor_config
        conf_dict = _parse_conf_file(config_path)
        config = _build_sensor_config(conf_dict)

    elif config_path.suffix.lower() in ['.yaml', '.yml']:
        # SOC server configuration (full YAML format)
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f) or {}

        # Merge with defaults if enabled
        if apply_defaults and BEST_PRACTICE_CONFIG:
            config = _deep_merge(BEST_PRACTICE_CONFIG, user_config)
            _log_config_status(user_config, config)
        else:
            config = user_config

        # Validate minimal configuration for SOC server
        # With defaults applied, these should always be present
        required_keys = ['interface', 'thresholds', 'logging']
        missing_keys = [key for key in required_keys if key not in config]

        if missing_keys:
            # If using defaults, only 'interface' truly needs to be specified
            if 'interface' in missing_keys:
                raise ValueError(
                    f"Required config key 'interface' not found. "
                    f"Please specify the network interface to monitor in {config_file}"
                )
            # Other keys should come from defaults
            for key in missing_keys:
                if key != 'interface':
                    logger.warning(f"Config key '{key}' missing and not in defaults")

    else:
        raise ValueError(f"Unsupported config file format: {config_path.suffix}. Use .yaml or .conf")

    # Inject environment variables (secrets) with priority over config.yaml
    config = _inject_env_secrets(config)

    return config


def check_env_config(env_file: str = ".env", example_file: str = ".env.example") -> List[Tuple[str, str]]:
    """
    Check for missing environment variables by comparing .env with .env.example.

    Returns:
        List of tuples (variable_name, default_value) for missing variables
    """
    env_path = Path(env_file)
    example_path = Path(example_file)

    if not example_path.exists():
        return []

    # Parse both files
    def parse_env(filepath):
        variables = {}
        if filepath.exists():
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        variables[key.strip()] = value.strip()
        return variables

    example_vars = parse_env(example_path)
    current_vars = parse_env(env_path) if env_path.exists() else {}

    # Find missing variables
    missing = []
    for key, default_value in example_vars.items():
        if key not in current_vars:
            missing.append((key, default_value))

    return missing


def sync_env_config(env_file: str = ".env", example_file: str = ".env.example",
                    dry_run: bool = True) -> List[str]:
    """
    Sync missing environment variables from .env.example to .env.

    Args:
        env_file: Path to .env file
        example_file: Path to .env.example file
        dry_run: If True, only report what would be added (default)

    Returns:
        List of variable names that were (or would be) added
    """
    missing = check_env_config(env_file, example_file)

    if not missing:
        logger.info("Environment: all variables from .env.example are present in .env")
        return []

    added = []
    env_path = Path(env_file)

    if dry_run:
        logger.info(f"Environment: {len(missing)} variable(s) missing from .env")
        for key, value in missing:
            # Hide sensitive values
            display_value = "***" if any(s in key.lower() for s in ['password', 'key', 'secret', 'token']) else value
            logger.info(f"  {key}={display_value} (from .env.example)")
            added.append(key)
    else:
        # Actually append to .env file
        with open(env_path, 'a') as f:
            f.write(f"\n# Auto-added from .env.example\n")
            for key, value in missing:
                f.write(f"{key}={value}\n")
                added.append(key)
                logger.info(f"Added to .env: {key}")

    return added

