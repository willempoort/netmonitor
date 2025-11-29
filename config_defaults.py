"""
Best Practice Configuration Defaults for NetMonitor
These are recommended values based on typical enterprise network environments
"""

# Best practice defaults for network monitoring
BEST_PRACTICE_CONFIG = {
    # Detection Rules - Enabled by default for comprehensive threat coverage
    "thresholds": {
        "port_scan": {
            "enabled": True,
            "unique_ports": 10,         # Alert if >10 ports scanned
            "time_window": 60           # Within 60 seconds
        },
        "dns_tunnel": {
            "enabled": True,
            "query_length_threshold": 50,   # Suspiciously long domain names
            "queries_per_minute": 150       # High DNS query rate (for networks with monitoring sensors)
        },
        "beaconing": {
            "enabled": True,
            "interval_threshold": 5,    # Regular intervals (C2 beacon detection)
            "min_connections": 10       # Minimum connections to detect pattern
        },
        "outbound_volume": {
            "enabled": True,
            "threshold_mb": 100,        # Alert if >100MB uploaded in window
            "time_window": 300          # 5 minute window
        },
        "brute_force": {
            "enabled": True,
            "attempts_threshold": 5,    # Failed login attempts
            "time_window": 300          # Within 5 minutes
        },
        "icmp_tunnel": {
            "enabled": True,
            "size_threshold": 500,      # ICMP payload >500 bytes
            "rate_threshold": 10        # >10 large ICMP packets per minute
        },
        "http_anomaly": {
            "enabled": True,
            "post_threshold": 50,       # Alert if >50 POST requests
            "post_time_window": 300,    # Within 5 minutes
            "dlp_min_payload_size": 1024,  # Only scan payloads >1KB
            "entropy_threshold": 6.5    # High entropy threshold for plaintext HTTP
        },
        "smtp_ftp_transfer": {
            "enabled": True,
            "size_threshold_mb": 50,    # Alert if >50MB transferred
            "time_window": 300          # Within 5 minutes
        },
        "dns_enhanced": {
            "dga_threshold": 0.6,       # DGA score threshold (0-1)
            "entropy_threshold": 4.5,   # Shannon entropy threshold
            "encoding_detection": True   # Detect Base64/Hex encoding
        },
        # Performance thresholds
        "packet_rate_warning": 10000,   # Packets/sec warning threshold
        "packet_rate_critical": 50000,  # Packets/sec critical threshold
        "connection_rate_warning": 1000,
        "connection_rate_critical": 5000,
        "bandwidth_warning_mbps": 80,   # Bandwidth utilization warning
        "bandwidth_critical_mbps": 200  # Bandwidth utilization critical
    },

    # Logging - Balanced verbosity for operational visibility
    "logging": {
        "level": "INFO",               # INFO for production, DEBUG for troubleshooting
        "console": True,
        "file": "/var/log/netmonitor/sensor.log",
        "max_file_size_mb": 100,
        "backup_count": 5
    },

    # Alert Management - Optimized for real-time response
    "alerts": {
        "batch_upload_interval": 60,    # Upload alerts every 60 seconds
        "immediate_upload_severities": ["CRITICAL", "HIGH"],  # Immediate upload for high-priority
        "buffer_size": 1000,            # Max alerts in buffer before forced upload
        "retention_days": 30            # Keep alerts for 30 days
    },

    # Performance - Optimized for typical hardware
    "performance": {
        "metrics_interval": 60,         # Report metrics every 60 seconds
        "heartbeat_interval": 30,       # Heartbeat every 30 seconds
        "command_poll_interval": 30,    # Check for commands every 30 seconds
        "config_sync_interval": 300,    # Sync config every 5 minutes
        "whitelist_sync_interval": 300  # Sync whitelist every 5 minutes
    },

    # Threat Intelligence - Recommended feeds for comprehensive coverage
    "threat_feeds": {
        "enabled": True,
        "feeds": ["feodotracker", "urlhaus", "threatfox"],
        "update_interval": 3600,        # Update feeds hourly
        "cache_dir": "/var/cache/netmonitor/feeds"
    },

    # AbuseIPDB Integration - Rate-limited for free tier
    "abuseipdb": {
        "enabled": False,               # Disabled by default (requires API key)
        "rate_limit": 1000,            # Free tier: 1000 queries/day
        "confidence_threshold": 80      # Only report IPs with >80% confidence
    },

    # Internal Networks - RFC1918 private ranges (customize for your network)
    "internal_networks": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ],

    # Whitelist - Common services that should not trigger alerts
    "whitelist": [
        "224.0.0.0/4",      # Multicast (mDNS, SSDP, etc.)
        "239.0.0.0/8",      # Administratively scoped multicast
        # Add your DNS servers, gateways, and trusted services here
    ]
}

# Parameter descriptions for dashboard UI
PARAMETER_DESCRIPTIONS = {
    "thresholds.port_scan.enabled": "Enable port scan detection",
    "thresholds.port_scan.unique_ports": "Number of ports that trigger a port scan alert",
    "thresholds.port_scan.time_window": "Time window (seconds) for port scan detection",

    "thresholds.dns_tunnel.enabled": "Enable DNS tunneling detection",
    "thresholds.dns_tunnel.query_length_threshold": "Domain name length that triggers DNS tunnel alert",
    "thresholds.dns_tunnel.queries_per_minute": "DNS queries per minute that trigger rate alert",

    "thresholds.beaconing.enabled": "Enable C2 beaconing detection",
    "thresholds.beaconing.interval_threshold": "Regular interval (seconds) that indicates beaconing",
    "thresholds.beaconing.min_connections": "Minimum connections to establish beaconing pattern",

    "thresholds.outbound_volume.enabled": "Enable data exfiltration detection",
    "thresholds.outbound_volume.threshold_mb": "MB uploaded that triggers exfiltration alert",
    "thresholds.outbound_volume.time_window": "Time window (seconds) for exfiltration detection",

    "thresholds.brute_force.enabled": "Enable brute force detection",
    "thresholds.brute_force.attempts_threshold": "Failed attempts that trigger brute force alert",
    "thresholds.brute_force.time_window": "Time window (seconds) for brute force detection",

    "thresholds.icmp_tunnel.enabled": "Enable ICMP tunneling detection",
    "thresholds.icmp_tunnel.size_threshold": "ICMP payload size (bytes) that triggers alert",
    "thresholds.icmp_tunnel.rate_threshold": "Large ICMP packets per minute that trigger alert",

    "thresholds.http_anomaly.enabled": "Enable HTTP/HTTPS anomaly detection",
    "thresholds.http_anomaly.post_threshold": "POST requests that trigger exfiltration alert",
    "thresholds.http_anomaly.post_time_window": "Time window (seconds) for POST detection",
    "thresholds.http_anomaly.dlp_min_payload_size": "Minimum payload size (bytes) for DLP scanning",
    "thresholds.http_anomaly.entropy_threshold": "Entropy threshold for encrypted data in plaintext HTTP",

    "thresholds.smtp_ftp_transfer.enabled": "Enable SMTP/FTP large transfer detection",
    "thresholds.smtp_ftp_transfer.size_threshold_mb": "Transfer size (MB) that triggers alert",
    "thresholds.smtp_ftp_transfer.time_window": "Time window (seconds) for transfer detection",

    "thresholds.dns_enhanced.dga_threshold": "DGA score threshold for Domain Generation Algorithm detection (0-1)",
    "thresholds.dns_enhanced.entropy_threshold": "Shannon entropy threshold for DNS queries",
    "thresholds.dns_enhanced.encoding_detection": "Enable detection of Base64/Hex encoded DNS queries",

    "thresholds.bandwidth_warning_mbps": "Bandwidth utilization (Mbps) for warning alerts",
    "thresholds.bandwidth_critical_mbps": "Bandwidth utilization (Mbps) for critical alerts",

    "alerts.batch_upload_interval": "Seconds between batch alert uploads",
    "alerts.immediate_upload_severities": "Severities that upload immediately (CRITICAL, HIGH, MEDIUM, LOW)",

    "performance.metrics_interval": "Seconds between metric reports to SOC server",
    "performance.heartbeat_interval": "Seconds between heartbeat signals",
    "performance.config_sync_interval": "Seconds between configuration synchronizations",
    "performance.whitelist_sync_interval": "Seconds between whitelist synchronizations"
}

# Categories for UI grouping
PARAMETER_CATEGORIES = {
    "Detection Rules": [
        "thresholds.port_scan",
        "thresholds.dns_tunnel",
        "thresholds.dns_enhanced",
        "thresholds.beaconing",
        "thresholds.outbound_volume",
        "thresholds.brute_force",
        "thresholds.icmp_tunnel",
        "thresholds.http_anomaly",
        "thresholds.smtp_ftp_transfer"
    ],
    "Thresholds": [
        "thresholds.packet_rate_warning",
        "thresholds.packet_rate_critical",
        "thresholds.bandwidth_warning_mbps",
        "thresholds.bandwidth_critical_mbps"
    ],
    "Alert Management": [
        "alerts.batch_upload_interval",
        "alerts.immediate_upload_severities",
        "alerts.buffer_size"
    ],
    "Performance": [
        "performance.metrics_interval",
        "performance.heartbeat_interval",
        "performance.command_poll_interval",
        "performance.config_sync_interval"
    ],
    "Threat Intelligence": [
        "threat_feeds.enabled",
        "threat_feeds.update_interval"
    ]
}

def get_default_value(parameter_path: str):
    """Get default value for a parameter path (e.g., 'detection.port_scan.enabled')"""
    parts = parameter_path.split('.')
    value = BEST_PRACTICE_CONFIG

    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None

    return value

def flatten_config(config: dict, prefix: str = "") -> dict:
    """Flatten nested config dict to parameter paths"""
    result = {}

    for key, value in config.items():
        path = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            result.update(flatten_config(value, path))
        else:
            result[path] = value

    return result
