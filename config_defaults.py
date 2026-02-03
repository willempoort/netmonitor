# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
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
        "connection_flood": {
            "enabled": True,
            "connections_per_second": 100,  # Alert if >100 connections/second
            "time_window": 10           # Within 10 seconds
        },
        "packet_size": {
            "enabled": True,
            "min_suspicious_size": 1400,    # Packets >1400 bytes suspicious
            "max_normal_size": 1500         # Max normal packet size
        },
        "dns_tunnel": {
            "enabled": True,
            "query_length_threshold": 50,   # Suspiciously long domain names
            "queries_per_minute": 150       # High DNS query rate (for networks with monitoring sensors)
        },
        "dns_enhanced": {
            "dga_threshold": 0.6,       # DGA score threshold (0-1)
            "entropy_threshold": 4.5,   # Shannon entropy threshold
            "encoding_detection": True   # Detect Base64/Hex encoding
        },
        "beaconing": {
            "enabled": True,
            "min_connections": 5,       # Minimum connections to detect pattern
            "max_jitter_percent": 20    # Max timing jitter in beacon intervals
        },
        "outbound_volume": {
            "enabled": True,
            "threshold_mb": 100,        # Alert if >100MB uploaded in window
            "time_window": 300          # 5 minute window
        },
        "lateral_movement": {
            "enabled": True,
            "unique_targets": 5,        # Number of internal IPs scanned
            "time_window": 300          # Within 5 minutes
        },
        "brute_force": {
            "enabled": True,
            "attempts_threshold": 5,    # Failed login attempts
            "time_window": 300,         # Within 5 minutes
            "exclude_streaming": True,  # Exclude streaming services (Netflix, YouTube, etc.)
            "exclude_cdn": True         # Exclude CDN providers (Cloudflare, Akamai, etc.)
        },
        "modern_protocols": {
            "quic_detection": True,     # Detect QUIC/HTTP3 traffic (informational)
            "http3_detection": True,    # Detect HTTP/3 over QUIC
            "streaming_services": [],   # Populated from config.yaml
            "cdn_providers": []         # Populated from config.yaml
        },
        "protocol_mismatch": {
            "enabled": True,
            "detect_http_non_standard": True,   # HTTP on non-standard ports
            "detect_ssh_non_standard": True,    # SSH on non-standard ports
            "detect_dns_non_standard": True,    # DNS on non-standard ports
            "detect_ftp_non_standard": True,    # FTP on non-standard ports
            "ignore_quic": True                 # Ignore QUIC (UDP 443) for mismatch detection
        },
        "icmp_tunnel": {
            "enabled": True,
            "payload_size_threshold": 500,  # ICMP payload >500 bytes
            "frequency_threshold": 10       # >10 large ICMP packets per minute
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
        # TLS/SSL Analysis - JA3 fingerprinting and certificate validation
        "tls_analysis": {
            "enabled": True,
            "ja3_detection": True,          # Extract JA3 fingerprints
            "ja3s_detection": True,         # Extract JA3S fingerprints
            "sni_extraction": True,         # Extract Server Name Indication
            "certificate_validation": True,  # Validate certificate chains
            "detect_weak_ciphers": True,    # Alert on weak cipher suites
            "detect_deprecated_tls": True,  # Alert on TLS 1.0/1.1
            "detect_expired_certs": True,   # Alert on expired certificates
            "detect_missing_sni": False,    # Alert on missing SNI (noisy)
            "ja3_blacklist": {}             # Custom JA3 fingerprints to block
        },
        # PCAP Export - Forensic packet capture (NIS2 compliant)
        "pcap_export": {
            "enabled": True,
            "output_dir": "/var/log/netmonitor/pcap",
            "buffer_size": 10000,           # Ring buffer size (packets)
            "alert_capture_enabled": True,  # Save packets around alerts
            "pre_alert_packets": 100,       # Packets before alert
            "post_alert_packets": 50,       # Packets after alert
            "flow_buffer_size": 500,        # Per-flow buffer size
            "max_captures": 100,            # Max saved PCAP files
            "max_age_hours": 24,            # Delete captures after 24 hours
            # Sensor-specific options (NIS2 compliance)
            "upload_to_soc": True,          # Upload PCAP to SOC server (required for NIS2)
            "keep_local_copy": False        # Keep local copy after upload (saves disk space)
        },
        # Kerberos/Active Directory attack detection
        "kerberos": {
            "enabled": True,
            "tgs_req_threshold": 10,        # TGS requests per window for Kerberoasting detection
            "tgs_req_window": 300,          # Time window in seconds (5 min)
            "asrep_threshold": 5,           # AS-REP responses with weak encryption
            "asrep_window": 300,            # Time window in seconds
            "tgt_lifetime_max": 36000       # Max TGT lifetime in seconds (10 hours)
        },
        # Kill chain / multi-stage attack correlation
        "kill_chain": {
            "enabled": True,
            "chain_window": 3600,           # Correlation window in seconds (1 hour)
            "activity_timeout": 1800,       # Inactivity timeout for chain (30 min)
            "min_events": 3,                # Minimum events for chain detection
            "min_stages": 2                 # Minimum stages for chain alert
        },
        # Protocol deep parsing (SMB/LDAP)
        "protocol_parsing": {
            "enabled": True,
            "flag_smb1": True,              # Flag SMB1 usage (deprecated)
            "detect_admin_shares": True,    # Detect admin share access (C$, ADMIN$, etc.)
            "detect_sensitive_files": True, # Detect access to NTDS.dit, SAM, etc.
            "detect_ldap_sensitive": True   # Detect sensitive LDAP attribute queries
        },
        # Asset risk scoring
        "risk_scoring": {
            "enabled": True,
            "decay_rate": 0.1,              # Risk score decay rate per hour (10%)
            "decay_interval": 3600          # Decay check interval in seconds
        },
        # Enhanced encrypted traffic analysis (additions to tls_analysis)
        "encrypted_traffic": {
            "enabled": True,
            "detect_self_signed": True,     # Detect self-signed certificates
            "detect_domain_fronting": True, # Detect domain fronting (C2 evasion)
            "detect_esni_ech": True         # Detect ESNI/ECH (hidden hostnames)
        },
        # Performance thresholds
        "packet_rate_warning": 10000,   # Packets/sec warning threshold
        "packet_rate_critical": 50000,  # Packets/sec critical threshold
        "connection_rate_warning": 1000,
        "connection_rate_critical": 5000,
        "bandwidth_warning_mbps": 80,   # Bandwidth utilization warning
        "bandwidth_critical_mbps": 200  # Bandwidth utilization critical
    },

    # SOAR (Security Orchestration, Automation and Response)
    "soar": {
        "enabled": True,
        "dry_run": True,                    # IMPORTANT: true = no real blocking actions
        "require_approval": True,           # Require approval for playbook execution
        "max_blocks_per_hour": 10,          # Maximum IP blocks per hour
        "webhook_url": "",                  # Webhook URL for notifications (e.g., Slack)
        "email_enabled": False,             # Enable email notifications
        "email_recipients": []              # Email addresses for notifications
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
        "retention_days": 30,           # Keep alerts for 30 days

        # Global service provider filtering
        # Traffic to/from these service categories is allowed for ALL devices
        # Available categories: streaming, cdn, cloud, social, gaming, rmm, other
        "allowed_service_categories": [
            "streaming",    # Netflix, YouTube, etc.
            "cdn",          # Cloudflare, Akamai, CloudFront
            # "rmm",        # Uncomment to allow RMM tools (Datto, ConnectWise, TeamViewer, etc.)
        ]
    },

    # Performance - Optimized for typical hardware
    "performance": {
        "metrics_interval": 60,         # Report metrics every 60 seconds
        "heartbeat_interval": 30,       # Heartbeat every 30 seconds
        "command_poll_interval": 30,    # Check for commands every 30 seconds
        "config_sync_interval": 300,    # Sync config every 5 minutes
        "whitelist_sync_interval": 300  # Sync whitelist every 5 minutes
    },

    # Advanced Threat Detection - Database-backed threat intelligence
    # Note: Uses 'threat.' prefix to match database parameter naming
    "threat": {
        # Cryptomining detection (Stratum protocol)
        "cryptomining": {
            "enabled": False,
            "stratum_ports": [3333, 4444, 8333, 9999, 14444, 45560],
            "min_connections": 3
        },

        # Phishing domain detection (OpenPhish feed)
        "phishing": {
            "enabled": False,
            "feed_url": "https://openphish.com/feed.txt",
            "update_interval": 3600,
            "cache_ttl": 86400,
            "check_dns": True,
            "check_connections": True
        },

        # Tor exit node detection
        "tor": {
            "enabled": False,
            "feed_url": "https://check.torproject.org/torbulkexitlist",
            "update_interval": 3600,
            "alert_exit_node": True,
            "alert_onion": True
        },

        # VPN tunnel detection
        "vpn": {
            "enabled": False,
            "detect_openvpn": True,
            "detect_wireguard": True,
            "detect_ipsec": True
        },

        # Cloud metadata access (SSRF / IMDS)
        "cloud_metadata": {
            "enabled": False,
            "aws_ip": "169.254.169.254",
            "azure_ip": "169.254.169.254",
            "gcp_hostname": "metadata.google.internal"
        },

        # DNS anomaly detection (DGA, tunneling)
        "dns_anomaly": {
            "enabled": False,
            "queries_per_minute": 100,
            "unique_domains": 50,
            "time_window": 60
        },

        # ===== Phase 2: Web Application Security =====

        # SQL Injection detection
        "sql_injection": {
            "enabled": False,
            "check_http": True,
            "check_query_string": True,
            "check_post_data": True,
            "sensitivity": "medium"
        },

        # XSS (Cross-Site Scripting) detection
        "xss": {
            "enabled": False,
            "check_http": True,
            "check_query_string": True,
            "check_post_data": True,
            "sensitivity": "medium"
        },

        # Command Injection detection
        "command_injection": {
            "enabled": False,
            "check_http": True,
            "check_shell_chars": True,
            "check_common_commands": True
        },

        # Path Traversal detection
        "path_traversal": {
            "enabled": False,
            "check_http": True,
            "check_encoded": True,
            "check_absolute_paths": True
        },

        # XXE (XML External Entity) detection
        "xxe": {
            "enabled": False,
            "check_post_requests": True,
            "check_put_requests": True
        },

        # SSRF (Server-Side Request Forgery) detection
        "ssrf": {
            "enabled": False,
            "check_internal_ips": True,
            "check_localhost": True,
            "check_cloud_metadata": True
        },

        # WebShell detection
        "webshell": {
            "enabled": False,
            "check_uploads": True,
            "check_suspicious_files": True,
            "check_php_functions": True
        },

        # API Abuse detection
        "api_abuse": {
            "enabled": False,
            "rate_limit_per_minute": 100,
            "endpoint_limit_per_minute": 50,
            "time_window": 60
        },

        # ===== Phase 3: DDoS & Resource Exhaustion =====

        # SYN Flood detection
        "syn_flood": {
            "enabled": False,
            "threshold_per_sec": 100,
            "time_window": 1
        },

        # UDP Flood detection
        "udp_flood": {
            "enabled": False,
            "threshold_per_sec": 500,
            "time_window": 1
        },

        # HTTP Flood detection
        "http_flood": {
            "enabled": False,
            "threshold_per_sec": 200,
            "time_window": 1
        },

        # Slowloris detection
        "slowloris": {
            "enabled": False,
            "incomplete_request_threshold": 50
        },

        # DNS Amplification detection
        "dns_amplification": {
            "enabled": False,
            "amplification_factor_threshold": 10,
            "time_window": 10
        },

        # NTP Amplification detection
        "ntp_amplification": {
            "enabled": False,
            "amplification_factor_threshold": 10
        },

        # Connection Exhaustion detection
        "connection_exhaustion": {
            "enabled": False,
            "max_connections": 1000
        },

        # Bandwidth Saturation detection
        "bandwidth_saturation": {
            "enabled": False,
            "threshold_mbps": 100,
            "time_window": 1
        },

        # ===== Phase 4: Ransomware Indicators =====

        # SMB Mass Encryption detection
        "ransomware_smb": {
            "enabled": False,
            "file_ops_per_minute": 100,
            "time_window": 60
        },

        # Crypto Extension detection
        "ransomware_crypto_ext": {
            "enabled": False,
            "min_file_count": 5
        },

        # Ransom Note detection
        "ransomware_ransom_note": {
            "enabled": False,
            "min_keyword_matches": 3,
            "min_file_creates": 2
        },

        # Shadow Copy Deletion detection
        "ransomware_shadow_copy": {
            "enabled": False
        },

        # Backup Deletion detection
        "ransomware_backup_deletion": {
            "enabled": False
        },

        # ===== Phase 5: IoT & Smart Device Security =====

        # IoT Botnet detection
        "iot_botnet": {
            "enabled": False,
            "telnet_attempts_threshold": 10,
            "default_creds_threshold": 3
        },

        # UPnP Exploit detection
        "upnp_exploit": {
            "enabled": False,
            "ssdp_threshold": 100
        },

        # MQTT Abuse detection
        "mqtt_abuse": {
            "enabled": False,
            "publish_threshold_per_minute": 1000,
            "time_window": 60
        },

        # Smart Home Protocol Abuse
        "smart_home_abuse": {
            "enabled": False
        },

        # Insecure RTSP Streams
        "insecure_rtsp": {
            "enabled": False
        },

        # CoAP Protocol Abuse
        "coap_abuse": {
            "enabled": False
        },

        # Z-Wave Attack detection
        "zwave_attack": {
            "enabled": False
        },

        # Zigbee Attack detection
        "zigbee_attack": {
            "enabled": False
        },

        # ===== Phase 6: OT/ICS Protocol Security =====

        # Modbus Attack detection
        "modbus_attack": {
            "enabled": False,
            "write_ops_threshold": 50,
            "time_window": 60
        },

        # DNP3 Attack detection
        "dnp3_attack": {
            "enabled": False,
            "ops_threshold": 100,
            "time_window": 60
        },

        # IEC-104 Attack detection
        "iec104_attack": {
            "enabled": False,
            "control_commands_threshold": 50,
            "time_window": 60
        },

        # BACnet Attack detection
        "bacnet_attack": {
            "enabled": False
        },

        # Profinet Attack detection
        "profinet_attack": {
            "enabled": False
        },

        # EtherNet/IP Attack detection
        "ethernetip_attack": {
            "enabled": False
        },

        # ===== Phase 7: Container & Orchestration =====

        # Docker Container Escape detection
        "docker_escape": {
            "enabled": False,
            "privileged_ops_threshold": 3,
            "time_window": 300
        },

        # Kubernetes Exploitation detection
        "k8s_exploit": {
            "enabled": False,
            "api_calls_threshold": 100,
            "time_window": 300
        },

        # Container Registry Poisoning detection
        "container_registry_poisoning": {
            "enabled": False
        },

        # Privileged Container detection
        "privileged_container": {
            "enabled": False
        },

        # ===== Phase 8: Advanced Evasion =====

        # IP Fragmentation Attack detection
        "fragmentation_attack": {
            "enabled": False,
            "fragment_threshold": 100,
            "overlapping_threshold": 10,
            "time_window": 60
        },

        # Protocol Tunneling detection
        "tunneling": {
            "enabled": False,
            "packet_threshold": 50,
            "time_window": 60
        },

        # Polymorphic Malware detection
        "polymorphic_malware": {
            "enabled": False,
            "signature_variation_threshold": 20,
            "time_window": 1800
        },

        # Domain Generation Algorithm (DGA) detection
        "dga": {
            "enabled": False,
            "subdomain_length_threshold": 12,
            "random_pattern_threshold": 5
        },

        # ===== Phase 9: Completion Boost =====

        # Lateral Movement detection
        "lateral_movement": {
            "enabled": False,
            "smb_targets_threshold": 5,
            "rdp_attempts_threshold": 3,
            "time_window": 300
        },

        # Data Exfiltration detection
        "data_exfiltration": {
            "enabled": False,
            "megabytes_threshold": 100,
            "destinations_threshold": 20,
            "time_window": 60
        },

        # Privilege Escalation detection
        "privilege_escalation": {
            "enabled": False,
            "attempts_threshold": 5,
            "time_window": 300
        },

        # Persistence Mechanism detection
        "persistence": {
            "enabled": False,
            "mechanisms_threshold": 3,
            "time_window": 300
        },

        # Credential Dumping detection
        "credential_dumping": {
            "enabled": False,
            "indicators_threshold": 2,
            "time_window": 300
        },

        # Living-off-the-Land Binaries (LOLBins) detection
        "lolbins": {
            "enabled": False
        },

        # Memory Injection detection
        "memory_injection": {
            "enabled": False
        },

        # Process Hollowing detection
        "process_hollowing": {
            "enabled": False
        },

        # Registry Manipulation detection
        "registry_manipulation": {
            "enabled": False
        },

        # Scheduled Task Abuse detection
        "scheduled_task_abuse": {
            "enabled": False
        }
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
    ],

    # ==========================================================================
    # INTEGRATIONS - Optional connections to external security systems
    # All integrations are disabled by default for simple deployments
    # ==========================================================================

    "integrations": {
        # Master switch for all integrations
        "enabled": False,

        # SIEM Integration - Send alerts to external SIEM
        "siem": {
            "enabled": False,

            # Syslog output (supports CEF, LEEF, JSON)
            "syslog": {
                "enabled": False,
                "host": "localhost",
                "port": 514,
                "protocol": "udp",         # udp, tcp, tls
                "format": "cef",           # cef, leef, json
                "facility": "local0",
                "forward_severities": ["HIGH", "CRITICAL"],
                "forward_all": False
            },

            # Wazuh SIEM native integration
            "wazuh": {
                "enabled": False,
                "api_url": "",             # e.g., https://wazuh-manager:55000
                "api_user": "",
                "api_password": "",
                "verify_ssl": True,
                "use_api": True,           # Use Wazuh API (recommended)
                "syslog_fallback": True    # Fall back to syslog if API fails
            }
        },

        # Threat Intelligence - Enrich alerts with external threat data
        "threat_intel": {
            "enabled": False,
            "cache_ttl_hours": 24,

            # MISP - Malware Information Sharing Platform
            "misp": {
                "enabled": False,
                "url": "",                 # e.g., https://misp.local
                "api_key": "",
                "verify_ssl": True,
                "timeout": 30
            },

            # AlienVault OTX - Open Threat Exchange
            "otx": {
                "enabled": False,
                "api_key": "",             # Get free key at otx.alienvault.com
                "timeout": 30
            },

            # AbuseIPDB
            "abuseipdb": {
                "enabled": False,
                "api_key": "",
                "max_age_days": 90,
                "min_confidence": 50,
                "timeout": 30
            }
        },

        # Notifications - External alerting (future)
        "notifications": {
            "enabled": False,

            # Webhook notifications
            "webhook": {
                "enabled": False,
                "url": "",
                "method": "POST",
                "headers": {},
                "forward_severities": ["CRITICAL"]
            }
        }
    }
}

# Parameter descriptions for dashboard UI
PARAMETER_DESCRIPTIONS = {
    "thresholds.port_scan.enabled": "Enable port scan detection",
    "thresholds.port_scan.unique_ports": "Number of ports that trigger a port scan alert",
    "thresholds.port_scan.time_window": "Time window (seconds) for port scan detection",

    "thresholds.connection_flood.enabled": "Enable connection flood detection (SYN floods)",
    "thresholds.connection_flood.connections_per_second": "Connections per second that trigger alert",
    "thresholds.connection_flood.time_window": "Time window (seconds) for connection flood detection",

    "thresholds.packet_size.enabled": "Enable unusual packet size detection",
    "thresholds.packet_size.min_suspicious_size": "Packet size (bytes) that is considered suspicious",
    "thresholds.packet_size.max_normal_size": "Maximum normal packet size (bytes)",

    "thresholds.dns_tunnel.enabled": "Enable DNS tunneling detection",
    "thresholds.dns_tunnel.query_length_threshold": "Domain name length that triggers DNS tunnel alert",
    "thresholds.dns_tunnel.queries_per_minute": "DNS queries per minute that trigger rate alert",

    "thresholds.dns_enhanced.dga_threshold": "DGA score threshold for Domain Generation Algorithm detection (0-1)",
    "thresholds.dns_enhanced.entropy_threshold": "Shannon entropy threshold for DNS queries",
    "thresholds.dns_enhanced.encoding_detection": "Enable detection of Base64/Hex encoded DNS queries",

    "thresholds.beaconing.enabled": "Enable C2 beaconing detection",
    "thresholds.beaconing.min_connections": "Minimum connections to establish beaconing pattern",
    "thresholds.beaconing.max_jitter_percent": "Maximum jitter percentage in beacon intervals",

    "thresholds.outbound_volume.enabled": "Enable data exfiltration detection",
    "thresholds.outbound_volume.threshold_mb": "MB uploaded that triggers exfiltration alert",
    "thresholds.outbound_volume.time_window": "Time window (seconds) for exfiltration detection",

    "thresholds.lateral_movement.enabled": "Enable lateral movement detection",
    "thresholds.lateral_movement.unique_targets": "Number of internal IPs scanned that triggers alert",
    "thresholds.lateral_movement.time_window": "Time window (seconds) for lateral movement detection",

    "thresholds.brute_force.enabled": "Enable brute force detection",
    "thresholds.brute_force.attempts_threshold": "Failed attempts that trigger brute force alert",
    "thresholds.brute_force.time_window": "Time window (seconds) for brute force detection",
    "thresholds.brute_force.exclude_streaming": "Exclude known streaming services (Netflix, YouTube) from detection",
    "thresholds.brute_force.exclude_cdn": "Exclude known CDN providers (Cloudflare, Akamai) from detection",

    "thresholds.modern_protocols.quic_detection": "Enable QUIC/HTTP3 protocol detection (informational)",
    "thresholds.modern_protocols.http3_detection": "Enable HTTP/3 over QUIC detection",
    "thresholds.modern_protocols.streaming_services": "IP ranges for known streaming services (Netflix, YouTube, Prime Video) - CIDR notation",
    "thresholds.modern_protocols.cdn_providers": "IP ranges for known CDN providers (Cloudflare, Akamai, etc.) - CIDR notation",

    "thresholds.protocol_mismatch.enabled": "Enable protocol mismatch detection",
    "thresholds.protocol_mismatch.detect_http_non_standard": "Detect HTTP on non-standard ports",
    "thresholds.protocol_mismatch.detect_ssh_non_standard": "Detect SSH on non-standard ports",
    "thresholds.protocol_mismatch.detect_dns_non_standard": "Detect DNS on non-standard ports",
    "thresholds.protocol_mismatch.detect_ftp_non_standard": "Detect FTP on non-standard ports",
    "thresholds.protocol_mismatch.ignore_quic": "Ignore QUIC (UDP 443/80) for HTTP mismatch detection",

    "thresholds.icmp_tunnel.enabled": "Enable ICMP tunneling detection",
    "thresholds.icmp_tunnel.payload_size_threshold": "ICMP payload size (bytes) that triggers alert",
    "thresholds.icmp_tunnel.frequency_threshold": "Large ICMP packets per minute that trigger alert",

    "thresholds.http_anomaly.enabled": "Enable HTTP/HTTPS anomaly detection",
    "thresholds.http_anomaly.post_threshold": "POST requests that trigger exfiltration alert",
    "thresholds.http_anomaly.post_time_window": "Time window (seconds) for POST detection",
    "thresholds.http_anomaly.dlp_min_payload_size": "Minimum payload size (bytes) for DLP scanning",
    "thresholds.http_anomaly.entropy_threshold": "Entropy threshold for encrypted data in plaintext HTTP",

    "thresholds.smtp_ftp_transfer.enabled": "Enable SMTP/FTP large transfer detection",
    "thresholds.smtp_ftp_transfer.size_threshold_mb": "Transfer size (MB) that triggers alert",
    "thresholds.smtp_ftp_transfer.time_window": "Time window (seconds) for transfer detection",

    # Kerberos/Active Directory
    "thresholds.kerberos.enabled": "Enable Kerberos/AD attack detection (Kerberoasting, AS-REP roasting)",
    "thresholds.kerberos.tgs_req_threshold": "TGS requests per window that trigger Kerberoasting alert",
    "thresholds.kerberos.tgs_req_window": "Time window (seconds) for Kerberoasting detection",
    "thresholds.kerberos.asrep_threshold": "AS-REP responses with weak encryption that trigger alert",
    "thresholds.kerberos.asrep_window": "Time window (seconds) for AS-REP roasting detection",
    "thresholds.kerberos.tgt_lifetime_max": "Maximum TGT lifetime in seconds (Golden Ticket detection)",

    # Kill Chain Correlation
    "thresholds.kill_chain.enabled": "Enable multi-stage attack chain correlation",
    "thresholds.kill_chain.chain_window": "Time window (seconds) for correlating attack chain events",
    "thresholds.kill_chain.activity_timeout": "Inactivity timeout (seconds) before chain expires",
    "thresholds.kill_chain.min_events": "Minimum events required to form an attack chain",
    "thresholds.kill_chain.min_stages": "Minimum kill chain stages for HIGH_RISK alert",

    # Protocol Deep Parsing (SMB/LDAP)
    "thresholds.protocol_parsing.enabled": "Enable deep protocol parsing for SMB/LDAP",
    "thresholds.protocol_parsing.flag_smb1": "Flag deprecated SMB1 protocol usage",
    "thresholds.protocol_parsing.detect_admin_shares": "Detect access to admin shares (C$, ADMIN$, IPC$)",
    "thresholds.protocol_parsing.detect_sensitive_files": "Detect access to sensitive files (NTDS.dit, SAM, SECURITY)",
    "thresholds.protocol_parsing.detect_ldap_sensitive": "Detect sensitive LDAP attribute queries (userPassword, etc.)",

    # Risk Scoring
    "thresholds.risk_scoring.enabled": "Enable asset risk scoring based on alert history",
    "thresholds.risk_scoring.decay_rate": "Risk score decay rate per hour (0.1 = 10%)",
    "thresholds.risk_scoring.decay_interval": "Interval (seconds) between decay calculations",

    # Encrypted Traffic (Advanced)
    "thresholds.encrypted_traffic.enabled": "Enable advanced encrypted traffic analysis",
    "thresholds.encrypted_traffic.detect_self_signed": "Detect self-signed certificates (potential C2)",
    "thresholds.encrypted_traffic.detect_domain_fronting": "Detect domain fronting (CDN-based C2 evasion)",
    "thresholds.encrypted_traffic.detect_esni_ech": "Detect ESNI/ECH usage (hidden hostnames)",

    # TLS/SSL Analysis
    "thresholds.tls_analysis.enabled": "Enable TLS/SSL analysis (JA3 fingerprinting)",
    "thresholds.tls_analysis.ja3_detection": "Extract JA3 fingerprints from TLS handshakes",
    "thresholds.tls_analysis.ja3s_detection": "Extract JA3S server fingerprints",
    "thresholds.tls_analysis.sni_extraction": "Extract Server Name Indication from TLS",
    "thresholds.tls_analysis.certificate_validation": "Validate certificate chains",
    "thresholds.tls_analysis.detect_weak_ciphers": "Alert on weak cipher suites",
    "thresholds.tls_analysis.detect_deprecated_tls": "Alert on TLS 1.0/1.1 usage",
    "thresholds.tls_analysis.detect_expired_certs": "Alert on expired certificates",
    "thresholds.tls_analysis.detect_missing_sni": "Alert on missing SNI (can be noisy)",
    "thresholds.tls_analysis.ja3_blacklist": "Custom JA3 fingerprints to block (dict of hash:name)",

    # Advanced Threat Detection - Database-backed intelligence
    "threat.cryptomining.enabled": "Enable cryptomining detection (Stratum protocol)",
    "threat.cryptomining.stratum_ports": "List of Stratum mining ports to monitor",
    "threat.cryptomining.min_connections": "Minimum connections to same mining pool to trigger alert",

    "threat.phishing.enabled": "Enable phishing domain detection (OpenPhish feed)",
    "threat.phishing.feed_url": "OpenPhish feed URL",
    "threat.phishing.update_interval": "Feed update interval (seconds)",
    "threat.phishing.cache_ttl": "Feed cache TTL (seconds)",
    "threat.phishing.check_dns": "Check DNS queries against phishing feed",
    "threat.phishing.check_connections": "Check HTTP connections against phishing feed",

    "threat.tor.enabled": "Enable Tor exit node detection",
    "threat.tor.feed_url": "Tor Project exit node list URL",
    "threat.tor.update_interval": "Feed update interval (seconds)",
    "threat.tor.alert_exit_node": "Alert on connections to Tor exit nodes",
    "threat.tor.alert_onion": "Alert on .onion domain queries",

    "threat.vpn.enabled": "Enable VPN tunnel detection",
    "threat.vpn.detect_openvpn": "Detect OpenVPN tunnels",
    "threat.vpn.detect_wireguard": "Detect WireGuard tunnels",
    "threat.vpn.detect_ipsec": "Detect IPsec tunnels",

    "threat.cloud_metadata.enabled": "Enable cloud metadata access detection (SSRF/IMDS)",
    "threat.cloud_metadata.aws_ip": "AWS metadata service IP",
    "threat.cloud_metadata.azure_ip": "Azure metadata service IP",
    "threat.cloud_metadata.gcp_hostname": "GCP metadata service hostname",

    "threat.dns_anomaly.enabled": "Enable DNS anomaly detection (DGA, tunneling)",
    "threat.dns_anomaly.queries_per_minute": "DNS queries per minute threshold",
    "threat.dns_anomaly.unique_domains": "Unique domains per time window threshold",
    "threat.dns_anomaly.time_window": "Time window (seconds) for DNS anomaly detection",

    # ===== Phase 2: Web Application Security =====

    # SQL Injection
    "threat.sql_injection.enabled": "Enable SQL injection detection in HTTP traffic",
    "threat.sql_injection.check_http": "Check HTTP requests for SQLi patterns",
    "threat.sql_injection.check_query_string": "Check URL query strings for SQLi",
    "threat.sql_injection.check_post_data": "Check POST data for SQLi",
    "threat.sql_injection.sensitivity": "Detection sensitivity (low/medium/high)",

    # XSS (Cross-Site Scripting)
    "threat.xss.enabled": "Enable XSS detection in HTTP traffic",
    "threat.xss.check_http": "Check HTTP requests for XSS patterns",
    "threat.xss.check_query_string": "Check URL query strings for XSS",
    "threat.xss.check_post_data": "Check POST data for XSS",
    "threat.xss.sensitivity": "Detection sensitivity (low/medium/high)",

    # Command Injection
    "threat.command_injection.enabled": "Enable command injection detection",
    "threat.command_injection.check_http": "Check HTTP requests for command injection",
    "threat.command_injection.check_shell_chars": "Detect shell metacharacters",
    "threat.command_injection.check_common_commands": "Detect common system commands",

    # Path Traversal
    "threat.path_traversal.enabled": "Enable path traversal detection",
    "threat.path_traversal.check_http": "Check HTTP requests for path traversal",
    "threat.path_traversal.check_encoded": "Detect URL-encoded traversal attempts",
    "threat.path_traversal.check_absolute_paths": "Detect absolute path access",

    # XXE (XML External Entity)
    "threat.xxe.enabled": "Enable XXE attack detection",
    "threat.xxe.check_post_requests": "Check POST requests for XXE",
    "threat.xxe.check_put_requests": "Check PUT requests for XXE",

    # SSRF (Server-Side Request Forgery)
    "threat.ssrf.enabled": "Enable SSRF detection",
    "threat.ssrf.check_internal_ips": "Detect internal IP targeting",
    "threat.ssrf.check_localhost": "Detect localhost access attempts",
    "threat.ssrf.check_cloud_metadata": "Detect cloud metadata endpoint access",

    # WebShell
    "threat.webshell.enabled": "Enable webshell detection",
    "threat.webshell.check_uploads": "Detect suspicious file uploads",
    "threat.webshell.check_suspicious_files": "Detect known webshell filenames",
    "threat.webshell.check_php_functions": "Detect dangerous PHP functions",

    # API Abuse
    "threat.api_abuse.enabled": "Enable API abuse detection",
    "threat.api_abuse.rate_limit_per_minute": "Maximum API requests per minute",
    "threat.api_abuse.endpoint_limit_per_minute": "Max requests per endpoint per minute",
    "threat.api_abuse.time_window": "Time window (seconds) for rate limiting",

    # ===== Phase 3: DDoS & Resource Exhaustion =====

    # SYN Flood
    "threat.syn_flood.enabled": "Enable SYN flood detection",
    "threat.syn_flood.threshold_per_sec": "SYN packets per second threshold",
    "threat.syn_flood.time_window": "Time window (seconds) for SYN counting",

    # UDP Flood
    "threat.udp_flood.enabled": "Enable UDP flood detection",
    "threat.udp_flood.threshold_per_sec": "UDP packets per second threshold",
    "threat.udp_flood.time_window": "Time window (seconds) for UDP counting",

    # HTTP Flood
    "threat.http_flood.enabled": "Enable HTTP flood (Layer 7 DDoS) detection",
    "threat.http_flood.threshold_per_sec": "HTTP requests per second threshold",
    "threat.http_flood.time_window": "Time window (seconds) for HTTP counting",

    # Slowloris
    "threat.slowloris.enabled": "Enable Slowloris slow HTTP attack detection",
    "threat.slowloris.incomplete_request_threshold": "Incomplete requests threshold",

    # DNS Amplification
    "threat.dns_amplification.enabled": "Enable DNS amplification attack detection",
    "threat.dns_amplification.amplification_factor_threshold": "Amplification factor threshold",
    "threat.dns_amplification.time_window": "Time window (seconds) for amplification",

    # NTP Amplification
    "threat.ntp_amplification.enabled": "Enable NTP amplification attack detection",
    "threat.ntp_amplification.amplification_factor_threshold": "Amplification factor threshold",

    # Connection Exhaustion
    "threat.connection_exhaustion.enabled": "Enable connection exhaustion detection",
    "threat.connection_exhaustion.max_connections": "Maximum concurrent connections threshold",

    # Bandwidth Saturation
    "threat.bandwidth_saturation.enabled": "Enable bandwidth saturation detection",
    "threat.bandwidth_saturation.threshold_mbps": "Bandwidth threshold (Mbps)",
    "threat.bandwidth_saturation.time_window": "Time window (seconds) for bandwidth",

    # ===== Phase 4: Ransomware Indicators =====

    # SMB Mass Encryption
    "threat.ransomware_smb.enabled": "Enable SMB mass file encryption detection",
    "threat.ransomware_smb.file_ops_per_minute": "File operations per minute threshold",
    "threat.ransomware_smb.time_window": "Time window (seconds) for file ops",

    # Crypto Extension
    "threat.ransomware_crypto_ext.enabled": "Enable ransomware crypto extension detection",
    "threat.ransomware_crypto_ext.min_file_count": "Minimum suspicious file count",

    # Ransom Note
    "threat.ransomware_ransom_note.enabled": "Enable ransom note detection",
    "threat.ransomware_ransom_note.min_keyword_matches": "Minimum keyword matches",
    "threat.ransomware_ransom_note.min_file_creates": "Minimum ransom note files",

    # Shadow Copy Deletion
    "threat.ransomware_shadow_copy.enabled": "Enable shadow copy deletion detection",

    # Backup Deletion
    "threat.ransomware_backup_deletion.enabled": "Enable backup deletion detection",

    # ===== Phase 5: IoT & Smart Device Security =====

    # IoT Botnet
    "threat.iot_botnet.enabled": "Enable IoT botnet (Mirai-like) detection",
    "threat.iot_botnet.telnet_attempts_threshold": "Telnet brute force attempts threshold",
    "threat.iot_botnet.default_creds_threshold": "Default credentials attempts threshold",

    # UPnP Exploit
    "threat.upnp_exploit.enabled": "Enable UPnP exploitation detection",
    "threat.upnp_exploit.ssdp_threshold": "SSDP request threshold",

    # MQTT Abuse
    "threat.mqtt_abuse.enabled": "Enable MQTT protocol abuse detection",
    "threat.mqtt_abuse.publish_threshold_per_minute": "MQTT publish messages per minute",
    "threat.mqtt_abuse.time_window": "Time window (seconds) for MQTT",

    # Smart Home Protocol Abuse
    "threat.smart_home_abuse.enabled": "Enable smart home protocol abuse detection",

    # Insecure RTSP Streams
    "threat.insecure_rtsp.enabled": "Enable insecure RTSP stream detection",

    # CoAP Protocol Abuse
    "threat.coap_abuse.enabled": "Enable CoAP protocol abuse detection",

    # Z-Wave Attack
    "threat.zwave_attack.enabled": "Enable Z-Wave attack detection",

    # Zigbee Attack
    "threat.zigbee_attack.enabled": "Enable Zigbee attack detection",

    # ===== Phase 6: OT/ICS Protocol Security =====

    # Modbus Attack
    "threat.modbus_attack.enabled": "Enable Modbus protocol attack detection",
    "threat.modbus_attack.write_ops_threshold": "Write operations threshold per time window",
    "threat.modbus_attack.time_window": "Time window (seconds) for Modbus attack detection",

    # DNP3 Attack
    "threat.dnp3_attack.enabled": "Enable DNP3 protocol attack detection",
    "threat.dnp3_attack.ops_threshold": "DNP3 operations threshold per time window",
    "threat.dnp3_attack.time_window": "Time window (seconds) for DNP3 attack detection",

    # IEC-104 Attack
    "threat.iec104_attack.enabled": "Enable IEC-104 protocol attack detection",
    "threat.iec104_attack.control_commands_threshold": "Control command threshold per time window",
    "threat.iec104_attack.time_window": "Time window (seconds) for IEC-104 attack detection",

    # BACnet Attack
    "threat.bacnet_attack.enabled": "Enable BACnet protocol attack detection",

    # Profinet Attack
    "threat.profinet_attack.enabled": "Enable Profinet protocol attack detection",

    # EtherNet/IP Attack
    "threat.ethernetip_attack.enabled": "Enable EtherNet/IP protocol attack detection",

    # ===== Phase 7: Container & Orchestration =====

    # Docker Container Escape
    "threat.docker_escape.enabled": "Enable Docker container escape detection",
    "threat.docker_escape.privileged_ops_threshold": "Privileged operations threshold",
    "threat.docker_escape.time_window": "Time window (seconds) for Docker escape detection",

    # Kubernetes Exploitation
    "threat.k8s_exploit.enabled": "Enable Kubernetes API exploitation detection",
    "threat.k8s_exploit.api_calls_threshold": "K8s API calls threshold per time window",
    "threat.k8s_exploit.time_window": "Time window (seconds) for K8s exploit detection",

    # Container Registry Poisoning
    "threat.container_registry_poisoning.enabled": "Enable container registry poisoning detection",

    # Privileged Container
    "threat.privileged_container.enabled": "Enable privileged container detection",

    # ===== Phase 8: Advanced Evasion =====

    # IP Fragmentation Attack
    "threat.fragmentation_attack.enabled": "Enable IP fragmentation attack detection",
    "threat.fragmentation_attack.fragment_threshold": "Fragment count threshold",
    "threat.fragmentation_attack.overlapping_threshold": "Overlapping fragments threshold",
    "threat.fragmentation_attack.time_window": "Time window (seconds) for fragmentation detection",

    # Protocol Tunneling
    "threat.tunneling.enabled": "Enable protocol tunneling detection (DNS/ICMP)",
    "threat.tunneling.packet_threshold": "Tunneling packets threshold per time window",
    "threat.tunneling.time_window": "Time window (seconds) for tunneling detection",

    # Polymorphic Malware
    "threat.polymorphic_malware.enabled": "Enable polymorphic malware detection",
    "threat.polymorphic_malware.signature_variation_threshold": "Signature variation threshold",
    "threat.polymorphic_malware.time_window": "Time window (seconds) for malware detection",

    # Domain Generation Algorithm (DGA)
    "threat.dga.enabled": "Enable DGA (Domain Generation Algorithm) detection",
    "threat.dga.subdomain_length_threshold": "Minimum subdomain length for DGA detection",
    "threat.dga.random_pattern_threshold": "Random DNS query count threshold",

    # ===== Phase 9: Completion Boost =====

    # Lateral Movement
    "threat.lateral_movement.enabled": "Enable lateral movement detection (SMB/RDP/PSExec)",
    "threat.lateral_movement.smb_targets_threshold": "Unique SMB targets threshold",
    "threat.lateral_movement.rdp_attempts_threshold": "RDP connection attempts threshold",
    "threat.lateral_movement.time_window": "Time window (seconds) for lateral movement detection",

    # Data Exfiltration
    "threat.data_exfiltration.enabled": "Enable data exfiltration detection",
    "threat.data_exfiltration.megabytes_threshold": "Outbound data threshold (MB)",
    "threat.data_exfiltration.destinations_threshold": "External destinations threshold",
    "threat.data_exfiltration.time_window": "Time window (seconds) for exfiltration detection",

    # Privilege Escalation
    "threat.privilege_escalation.enabled": "Enable privilege escalation detection",
    "threat.privilege_escalation.attempts_threshold": "Privilege escalation attempts threshold",
    "threat.privilege_escalation.time_window": "Time window (seconds) for escalation detection",

    # Persistence Mechanism
    "threat.persistence.enabled": "Enable persistence mechanism detection",
    "threat.persistence.mechanisms_threshold": "Persistence indicators threshold",
    "threat.persistence.time_window": "Time window (seconds) for persistence detection",

    # Credential Dumping
    "threat.credential_dumping.enabled": "Enable credential dumping detection (Mimikatz, LSASS)",
    "threat.credential_dumping.indicators_threshold": "Credential dumping indicators threshold",
    "threat.credential_dumping.time_window": "Time window (seconds) for dumping detection",

    # Living-off-the-Land Binaries (LOLBins)
    "threat.lolbins.enabled": "Enable LOLBins detection (PowerShell/WMI abuse)",

    # Memory Injection
    "threat.memory_injection.enabled": "Enable memory injection detection",

    # Process Hollowing
    "threat.process_hollowing.enabled": "Enable process hollowing detection",

    # Registry Manipulation
    "threat.registry_manipulation.enabled": "Enable registry manipulation detection",

    # Scheduled Task Abuse
    "threat.scheduled_task_abuse.enabled": "Enable scheduled task abuse detection",

    # PCAP Export (NIS2 Forensics)
    "thresholds.pcap_export.enabled": "Enable PCAP forensic capture",
    "thresholds.pcap_export.output_dir": "Directory for PCAP file storage",
    "thresholds.pcap_export.buffer_size": "Ring buffer size (packets) for recent traffic",
    "thresholds.pcap_export.alert_capture_enabled": "Save packets around alerts for forensics",
    "thresholds.pcap_export.pre_alert_packets": "Number of packets to save before alert",
    "thresholds.pcap_export.post_alert_packets": "Number of packets to save after alert",
    "thresholds.pcap_export.flow_buffer_size": "Per-flow buffer size for targeted export",
    "thresholds.pcap_export.max_captures": "Maximum number of PCAP files to retain",
    "thresholds.pcap_export.max_age_hours": "Delete PCAP files older than this (hours)",
    "thresholds.pcap_export.upload_to_soc": "Upload PCAP to SOC server (NIS2 requirement)",
    "thresholds.pcap_export.keep_local_copy": "Keep local PCAP copy after upload",

    "thresholds.bandwidth_warning_mbps": "Bandwidth utilization (Mbps) for warning alerts",
    "thresholds.bandwidth_critical_mbps": "Bandwidth utilization (Mbps) for critical alerts",

    "alerts.batch_upload_interval": "Seconds between batch alert uploads",
    "alerts.immediate_upload_severities": "Severities that upload immediately (CRITICAL, HIGH, MEDIUM, LOW)",

    "performance.metrics_interval": "Seconds between metric reports to SOC server",
    "performance.heartbeat_interval": "Seconds between heartbeat signals",
    "performance.config_sync_interval": "Seconds between configuration synchronizations",
    "performance.whitelist_sync_interval": "Seconds between whitelist synchronizations",

    # SOAR (Security Orchestration, Automation and Response)
    "soar.enabled": "Enable SOAR automated response capabilities",
    "soar.dry_run": "Dry run mode - log actions but don't execute (recommended for testing)",
    "soar.require_approval": "Require manual approval before executing playbook actions",
    "soar.max_blocks_per_hour": "Maximum IP blocks allowed per hour (rate limiting)",
    "soar.webhook_url": "Webhook URL for external notifications (Slack, Teams, etc.)",
    "soar.email_enabled": "Enable email notifications for SOAR actions",
    "soar.email_recipients": "Email addresses for SOAR notifications (comma-separated)"
}

# Categories for UI grouping
PARAMETER_CATEGORIES = {
    "Detection Rules": [
        "thresholds.port_scan",
        "thresholds.connection_flood",
        "thresholds.packet_size",
        "thresholds.dns_tunnel",
        "thresholds.dns_enhanced",
        "thresholds.beaconing",
        "thresholds.outbound_volume",
        "thresholds.lateral_movement",
        "thresholds.brute_force",
        "thresholds.modern_protocols",
        "thresholds.protocol_mismatch",
        "thresholds.icmp_tunnel",
        "thresholds.http_anomaly",
        "thresholds.smtp_ftp_transfer",
        "thresholds.tls_analysis"
    ],
    "Active Directory Security": [
        "thresholds.kerberos",
        "thresholds.protocol_parsing"
    ],
    "Attack Chain Correlation": [
        "thresholds.kill_chain",
        "thresholds.risk_scoring"
    ],
    "Advanced Encrypted Traffic": [
        "thresholds.encrypted_traffic"
    ],
    "Forensics (NIS2)": [
        "thresholds.pcap_export"
    ],
    "Advanced Threat Detection": [
        # Phase 1
        "threat.cryptomining",
        "threat.phishing",
        "threat.tor",
        "threat.vpn",
        "threat.cloud_metadata",
        "threat.dns_anomaly",
        # Phase 2: Web Application Security
        "threat.sql_injection",
        "threat.xss",
        "threat.command_injection",
        "threat.path_traversal",
        "threat.xxe",
        "threat.ssrf",
        "threat.webshell",
        "threat.api_abuse",
        # Phase 3: DDoS & Resource Exhaustion
        "threat.syn_flood",
        "threat.udp_flood",
        "threat.http_flood",
        "threat.slowloris",
        "threat.dns_amplification",
        "threat.ntp_amplification",
        "threat.connection_exhaustion",
        "threat.bandwidth_saturation",
        # Phase 4: Ransomware Indicators
        "threat.ransomware_smb",
        "threat.ransomware_crypto_ext",
        "threat.ransomware_ransom_note",
        "threat.ransomware_shadow_copy",
        "threat.ransomware_backup_deletion",
        # Phase 5: IoT & Smart Device Security
        "threat.iot_botnet",
        "threat.upnp_exploit",
        "threat.mqtt_abuse",
        "threat.smart_home_abuse",
        "threat.insecure_rtsp",
        "threat.coap_abuse",
        "threat.zwave_attack",
        "threat.zigbee_attack",
        # Phase 6: OT/ICS Protocol Security
        "threat.modbus_attack",
        "threat.dnp3_attack",
        "threat.iec104_attack",
        "threat.bacnet_attack",
        "threat.profinet_attack",
        "threat.ethernetip_attack",
        # Phase 7: Container & Orchestration
        "threat.docker_escape",
        "threat.k8s_exploit",
        "threat.container_registry_poisoning",
        "threat.privileged_container",
        # Phase 8: Advanced Evasion
        "threat.fragmentation_attack",
        "threat.tunneling",
        "threat.polymorphic_malware",
        "threat.dga",
        # Phase 9: Completion Boost
        "threat.lateral_movement",
        "threat.data_exfiltration",
        "threat.privilege_escalation",
        "threat.persistence",
        "threat.credential_dumping",
        "threat.lolbins",
        "threat.memory_injection",
        "threat.process_hollowing",
        "threat.registry_manipulation",
        "threat.scheduled_task_abuse"
    ],
    "SOAR (Automated Response)": [
        "soar.enabled",
        "soar.dry_run",
        "soar.require_approval",
        "soar.max_blocks_per_hour",
        "soar.webhook_url",
        "soar.email_enabled",
        "soar.email_recipients"
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
    ],
    "Integrations": [
        "integrations.enabled",
        "integrations.siem.enabled",
        "integrations.siem.syslog",
        "integrations.siem.wazuh",
        "integrations.threat_intel.enabled",
        "integrations.threat_intel.misp",
        "integrations.threat_intel.otx",
        "integrations.threat_intel.abuseipdb"
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
