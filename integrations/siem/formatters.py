# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Alert formatters for SIEM integration.

Supports:
- CEF (Common Event Format) - ArcSight, Wazuh, QRadar
- LEEF (Log Event Extended Format) - IBM QRadar
- JSON - Elastic, Splunk, generic SIEM
"""

import json
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Optional


class AlertFormatter(ABC):
    """Base class for alert formatters"""

    @abstractmethod
    def format(self, alert: Dict) -> str:
        """Format an alert for SIEM consumption"""
        pass


class CEFFormatter(AlertFormatter):
    """
    Common Event Format (CEF) formatter.

    CEF is widely supported by SIEM systems including:
    - Wazuh
    - ArcSight
    - QRadar
    - Splunk (with CEF app)
    - LogRhythm

    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """

    CEF_VERSION = "0"
    DEVICE_VENDOR = "NetMonitor"
    DEVICE_PRODUCT = "NetMonitor"
    DEVICE_VERSION = "1.0"

    # Severity mapping (NetMonitor -> CEF 0-10 scale)
    SEVERITY_MAP = {
        'INFO': 1,
        'LOW': 3,
        'MEDIUM': 5,
        'HIGH': 7,
        'CRITICAL': 10
    }

    # MITRE ATT&CK mapping for common threat types
    MITRE_MAP = {
        'PORT_SCAN': 'T1046',              # Network Service Discovery
        'BRUTE_FORCE_ATTEMPT': 'T1110',    # Brute Force
        'DNS_TUNNEL': 'T1071.004',         # DNS Protocol
        'DNS_TUNNEL_SUSPICIOUS_LENGTH': 'T1071.004',
        'BEACONING': 'T1071',              # Application Layer Protocol
        'C2_COMMUNICATION': 'T1071',
        'DATA_EXFILTRATION': 'T1048',      # Exfiltration Over Alternative Protocol
        'LATERAL_MOVEMENT': 'T1021',       # Remote Services
        'PROTOCOL_MISMATCH': 'T1571',      # Non-Standard Port
        'ICMP_TUNNEL': 'T1095',            # Non-Application Layer Protocol
    }

    def __init__(self, include_raw: bool = False):
        """
        Initialize CEF formatter.

        Args:
            include_raw: Include raw alert data in extension
        """
        self.include_raw = include_raw

    def _escape_cef_value(self, value: str) -> str:
        """Escape special characters for CEF values"""
        if not value:
            return ''
        # Escape backslash, equals, and pipe
        value = str(value)
        value = value.replace('\\', '\\\\')
        value = value.replace('=', '\\=')
        value = value.replace('|', '\\|')
        value = value.replace('\n', '\\n')
        value = value.replace('\r', '\\r')
        return value

    def _escape_cef_header(self, value: str) -> str:
        """Escape special characters for CEF header fields"""
        if not value:
            return ''
        value = str(value)
        value = value.replace('\\', '\\\\')
        value = value.replace('|', '\\|')
        return value

    def format(self, alert: Dict) -> str:
        """
        Format alert as CEF string.

        Args:
            alert: Alert dictionary with keys:
                - id: Alert ID
                - threat_type: Type of threat (e.g., BRUTE_FORCE_ATTEMPT)
                - severity: LOW, MEDIUM, HIGH, CRITICAL
                - source_ip: Source IP address
                - destination_ip: Destination IP address
                - destination_port: Destination port (optional)
                - protocol: Protocol (optional)
                - description: Human-readable description
                - timestamp: Alert timestamp
                - sensor_id: Sensor that detected the alert
                - metadata: Additional metadata (optional)

        Returns:
            CEF formatted string
        """
        # Extract values
        threat_type = alert.get('threat_type', 'UNKNOWN')
        severity_str = alert.get('severity', 'MEDIUM')
        severity = self.SEVERITY_MAP.get(severity_str, 5)

        # Build CEF header
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
        header = (
            f"CEF:{self.CEF_VERSION}|"
            f"{self._escape_cef_header(self.DEVICE_VENDOR)}|"
            f"{self._escape_cef_header(self.DEVICE_PRODUCT)}|"
            f"{self._escape_cef_header(self.DEVICE_VERSION)}|"
            f"{self._escape_cef_header(threat_type)}|"
            f"{self._escape_cef_header(alert.get('description', threat_type)[:128])}|"
            f"{severity}|"
        )

        # Build CEF extension (key=value pairs)
        extensions = []

        # Standard CEF fields
        if alert.get('source_ip'):
            src_ip = self._clean_ip(alert['source_ip'])
            extensions.append(f"src={src_ip}")

        if alert.get('destination_ip'):
            dst_ip = self._clean_ip(alert['destination_ip'])
            extensions.append(f"dst={dst_ip}")

        if alert.get('destination_port'):
            extensions.append(f"dpt={alert['destination_port']}")

        if alert.get('source_port'):
            extensions.append(f"spt={alert['source_port']}")

        if alert.get('protocol'):
            extensions.append(f"proto={self._escape_cef_value(alert['protocol'])}")

        # Timestamp
        if alert.get('timestamp'):
            ts = alert['timestamp']
            if isinstance(ts, str):
                extensions.append(f"rt={self._escape_cef_value(ts)}")
            elif isinstance(ts, datetime):
                extensions.append(f"rt={ts.strftime('%b %d %Y %H:%M:%S')}")

        # Alert ID
        if alert.get('id'):
            extensions.append(f"externalId={alert['id']}")

        # Sensor ID
        if alert.get('sensor_id'):
            extensions.append(f"cs1={self._escape_cef_value(alert['sensor_id'])}")
            extensions.append("cs1Label=SensorID")

        # Device/hostname info
        if alert.get('source_hostname'):
            extensions.append(f"shost={self._escape_cef_value(alert['source_hostname'])}")

        if alert.get('destination_hostname'):
            extensions.append(f"dhost={self._escape_cef_value(alert['destination_hostname'])}")

        # MITRE ATT&CK technique
        mitre_id = self.MITRE_MAP.get(threat_type)
        if mitre_id:
            extensions.append(f"cs2={mitre_id}")
            extensions.append("cs2Label=MITREAttackID")

        # Threat intel enrichment
        if alert.get('threat_intel'):
            ti = alert['threat_intel']
            if ti.get('source'):
                extensions.append(f"cs3={self._escape_cef_value(ti['source'])}")
                extensions.append("cs3Label=ThreatIntelSource")
            if ti.get('category'):
                extensions.append(f"cs4={self._escape_cef_value(ti['category'])}")
                extensions.append("cs4Label=ThreatCategory")
            if ti.get('confidence'):
                extensions.append(f"cfp1={ti['confidence']}")
                extensions.append("cfp1Label=ThreatConfidence")

        # Acknowledged status
        if 'acknowledged' in alert:
            extensions.append(f"cs5={'true' if alert['acknowledged'] else 'false'}")
            extensions.append("cs5Label=Acknowledged")

        # Include raw metadata if requested
        if self.include_raw and alert.get('metadata'):
            metadata_str = self._escape_cef_value(
                json.dumps(alert['metadata']) if isinstance(alert['metadata'], dict)
                else str(alert['metadata'])
            )
            extensions.append(f"msg={metadata_str[:1024]}")

        return header + ' '.join(extensions)

    def _clean_ip(self, ip: str) -> str:
        """Remove CIDR notation from IP if present"""
        if '/' in ip:
            return ip.split('/')[0]
        return ip


class LEEFFormatter(AlertFormatter):
    """
    Log Event Extended Format (LEEF) formatter.

    LEEF is IBM's format, primarily used by QRadar.
    Format: LEEF:Version|Vendor|Product|Version|EventID|Key1=Value1<tab>Key2=Value2
    """

    LEEF_VERSION = "2.0"
    VENDOR = "NetMonitor"
    PRODUCT = "NetMonitor"
    VERSION = "1.0"

    SEVERITY_MAP = {
        'INFO': 1,
        'LOW': 3,
        'MEDIUM': 5,
        'HIGH': 7,
        'CRITICAL': 10
    }

    def format(self, alert: Dict) -> str:
        """Format alert as LEEF string"""
        threat_type = alert.get('threat_type', 'UNKNOWN')

        # LEEF header
        header = (
            f"LEEF:{self.LEEF_VERSION}|"
            f"{self.VENDOR}|"
            f"{self.PRODUCT}|"
            f"{self.VERSION}|"
            f"{threat_type}|"
        )

        # LEEF uses tab-separated key=value pairs
        attrs = []

        if alert.get('source_ip'):
            attrs.append(f"src={self._clean_ip(alert['source_ip'])}")

        if alert.get('destination_ip'):
            attrs.append(f"dst={self._clean_ip(alert['destination_ip'])}")

        if alert.get('destination_port'):
            attrs.append(f"dstPort={alert['destination_port']}")

        if alert.get('severity'):
            attrs.append(f"sev={self.SEVERITY_MAP.get(alert['severity'], 5)}")

        if alert.get('description'):
            attrs.append(f"msg={alert['description'][:256]}")

        if alert.get('sensor_id'):
            attrs.append(f"devName={alert['sensor_id']}")

        return header + '\t'.join(attrs)

    def _clean_ip(self, ip: str) -> str:
        if '/' in ip:
            return ip.split('/')[0]
        return ip


class JSONFormatter(AlertFormatter):
    """
    JSON formatter for SIEM integration.

    Outputs alerts as structured JSON, compatible with:
    - Elasticsearch
    - Splunk
    - Any JSON-capable SIEM
    """

    def __init__(self, pretty: bool = False, include_all: bool = True):
        """
        Initialize JSON formatter.

        Args:
            pretty: Pretty-print JSON output
            include_all: Include all alert fields (vs minimal set)
        """
        self.pretty = pretty
        self.include_all = include_all

    def format(self, alert: Dict) -> str:
        """Format alert as JSON string"""

        if self.include_all:
            output = alert.copy()
        else:
            # Minimal set of fields
            output = {
                'timestamp': alert.get('timestamp'),
                'threat_type': alert.get('threat_type'),
                'severity': alert.get('severity'),
                'source_ip': alert.get('source_ip'),
                'destination_ip': alert.get('destination_ip'),
                'description': alert.get('description'),
            }

        # Add metadata
        output['_netmonitor'] = {
            'version': '1.0',
            'type': 'alert'
        }

        # Clean up IPs
        if output.get('source_ip'):
            output['source_ip'] = self._clean_ip(output['source_ip'])
        if output.get('destination_ip'):
            output['destination_ip'] = self._clean_ip(output['destination_ip'])

        # Convert datetime objects
        output = self._serialize_dates(output)

        if self.pretty:
            return json.dumps(output, indent=2, default=str)
        return json.dumps(output, default=str)

    def _clean_ip(self, ip: str) -> str:
        if '/' in ip:
            return ip.split('/')[0]
        return ip

    def _serialize_dates(self, obj):
        """Recursively convert datetime objects to ISO strings"""
        if isinstance(obj, dict):
            return {k: self._serialize_dates(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_dates(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return obj
