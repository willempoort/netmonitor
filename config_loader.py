"""
Configuration loader
Supports both YAML (for SOC server) and .conf (for sensors)
"""

import yaml
import os
from pathlib import Path


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
                'time_window': 300
            },
            'protocol_mismatch': {
                'enabled': True,
                'detect_http_non_standard': True,
                'detect_ssh_non_standard': True,
                'detect_dns_non_standard': True,
                'detect_ftp_non_standard': True
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


def load_config(config_file):
    """
    Load configuration from file
    Supports:
    - .yaml / .yml: Full configuration (SOC server)
    - .conf: Minimal sensor configuration (sensors)
    """
    config_path = Path(config_file)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file niet gevonden: {config_file}")

    # Determine file type by extension
    if config_path.suffix.lower() in ['.conf', '.env']:
        # Sensor configuration (minimal .conf format)
        conf_dict = _parse_conf_file(config_path)
        config = _build_sensor_config(conf_dict)

    elif config_path.suffix.lower() in ['.yaml', '.yml']:
        # SOC server configuration (full YAML format)
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Validate minimal configuration for SOC server
        required_keys = ['interface', 'thresholds', 'logging']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Vereiste configuratie key ontbreekt: {key}")

    else:
        raise ValueError(f"Unsupported config file format: {config_path.suffix}. Use .yaml or .conf")

    return config

