# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Asset Risk Scoring Module

Calculates dynamic risk scores for network assets based on:
- Alert history (type, severity, frequency)
- Exposure level (internal/external, services exposed)
- Security posture (device type, patch status indicators)
- Threat intelligence matches
- Kill chain progression
- Behavioral anomalies

Risk scores help prioritize incident response and identify
high-value targets for attackers.
"""

import logging
import time
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class AssetCategory(IntEnum):
    """Asset criticality categories."""
    UNKNOWN = 0
    LOW = 1           # IoT, printers, etc.
    MEDIUM = 2        # Workstations, laptops
    HIGH = 3          # Servers, network devices
    CRITICAL = 4      # Domain controllers, core infrastructure


class ExposureLevel(IntEnum):
    """Network exposure levels."""
    INTERNAL_ONLY = 0    # Only internal traffic
    DMZ = 1              # In DMZ/semi-exposed
    INTERNET_FACING = 2  # Directly exposed to internet


# Asset classification based on characteristics
ASSET_CATEGORY_HINTS = {
    # By port usage
    'domain_controller': AssetCategory.CRITICAL,  # Ports 88, 389, 636, etc.
    'database': AssetCategory.HIGH,               # Ports 1433, 3306, 5432, etc.
    'web_server': AssetCategory.HIGH,             # Ports 80, 443
    'file_server': AssetCategory.HIGH,            # SMB, NFS
    'mail_server': AssetCategory.HIGH,            # Ports 25, 587, 993, etc.
    'workstation': AssetCategory.MEDIUM,
    'laptop': AssetCategory.MEDIUM,
    'printer': AssetCategory.LOW,
    'iot_device': AssetCategory.LOW,
    'camera': AssetCategory.LOW,
}

# Alert severity weights for risk calculation
SEVERITY_WEIGHTS = {
    'LOW': 1.0,
    'MEDIUM': 3.0,
    'HIGH': 7.0,
    'CRITICAL': 15.0
}

# Alert type weights (based on attack significance)
ALERT_TYPE_WEIGHTS = {
    # Critical attack indicators
    'DCSYNC_ATTACK': 20.0,
    'KERBEROASTING_ATTACK': 15.0,
    'ASREP_ROASTING_ATTACK': 15.0,
    'PASS_THE_HASH_SUSPECTED': 15.0,
    'C2_COMMUNICATION': 18.0,
    'MALICIOUS_JA3_FINGERPRINT': 15.0,
    'NTDS_DIT_ACCESS': 20.0,
    'LSASS_DUMP_ACCESS': 20.0,
    'RANSOMWARE_DETECTED': 25.0,
    'HIGH_RISK_ATTACK_CHAIN': 20.0,

    # High-priority indicators
    'LATERAL_MOVEMENT': 12.0,
    'DATA_EXFILTRATION': 14.0,
    'BRUTE_FORCE': 8.0,
    'KERBEROS_BRUTEFORCE': 8.0,
    'SMB_ADMIN_SHARE_ACCESS': 10.0,
    'BEACON_DETECTED': 12.0,
    'DNS_TUNNEL': 10.0,

    # Medium indicators
    'PORT_SCAN': 5.0,
    'INTERNAL_PORT_SCAN': 6.0,
    'SMB_ENUMERATION': 6.0,
    'LDAP_ENUMERATION': 6.0,
    'LDAP_SENSITIVE_ATTR_QUERY': 8.0,

    # Low indicators
    'THREAT_FEED_MATCH': 10.0,
    'BLACKLISTED_IP': 8.0,
    'CONNECTION_FLOOD': 4.0,
    'UNUSUAL_PACKET_SIZE': 2.0,
}


@dataclass
class AlertRecord:
    """Record of an alert for risk calculation."""
    timestamp: float
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    is_source: bool  # True if this asset is the attacker
    details: Dict = field(default_factory=dict)


@dataclass
class AssetRiskProfile:
    """Risk profile for a network asset."""
    ip_address: str
    hostname: Optional[str]
    mac_address: Optional[str]
    device_type: Optional[str]

    # Categorization
    category: AssetCategory
    exposure: ExposureLevel

    # Risk metrics
    current_risk_score: float
    max_risk_score: float
    risk_trend: str  # 'increasing', 'stable', 'decreasing'

    # Alert history
    total_alerts: int
    alerts_24h: int
    alerts_7d: int
    alert_types: Dict[str, int]

    # Attack indicators
    is_attacker: bool          # Has been source of attacks
    is_victim: bool            # Has been target of attacks
    attack_chain_count: int    # Number of attack chains involved in
    kill_chain_stage: Optional[str]  # Highest kill chain stage reached

    # Last update
    last_seen: float
    last_alert: Optional[float]

    def to_dict(self) -> Dict:
        """Convert to serializable dictionary."""
        return {
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'mac_address': self.mac_address,
            'device_type': self.device_type,
            'category': self.category.name,
            'exposure': self.exposure.name,
            'current_risk_score': round(self.current_risk_score, 1),
            'max_risk_score': round(self.max_risk_score, 1),
            'risk_trend': self.risk_trend,
            'risk_level': self._get_risk_level(),
            'total_alerts': self.total_alerts,
            'alerts_24h': self.alerts_24h,
            'alerts_7d': self.alerts_7d,
            'alert_types': self.alert_types,
            'is_attacker': self.is_attacker,
            'is_victim': self.is_victim,
            'attack_chain_count': self.attack_chain_count,
            'kill_chain_stage': self.kill_chain_stage,
            'last_seen': self.last_seen,
            'last_alert': self.last_alert
        }

    def _get_risk_level(self) -> str:
        """Get risk level label."""
        if self.current_risk_score >= 80:
            return 'CRITICAL'
        elif self.current_risk_score >= 60:
            return 'HIGH'
        elif self.current_risk_score >= 40:
            return 'MEDIUM'
        elif self.current_risk_score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'


class RiskScorer:
    """
    Calculates and tracks risk scores for network assets.
    """

    def __init__(self, config: dict = None, db_manager=None, kill_chain_detector=None):
        self.config = config or {}
        self.db = db_manager
        self.kill_chain = kill_chain_detector
        self.logger = logging.getLogger('NetMonitor.RiskScorer')

        # Configuration
        risk_config = self.config.get('thresholds', {}).get('risk_scoring', {})
        self.enabled = risk_config.get('enabled', True)

        # Decay settings (risk scores decrease over time without new alerts)
        self.decay_rate = risk_config.get('decay_rate', 0.1)  # 10% per hour
        self.decay_interval = risk_config.get('decay_interval', 3600)  # 1 hour

        # Category multipliers
        self.category_multipliers = {
            AssetCategory.CRITICAL: 2.0,
            AssetCategory.HIGH: 1.5,
            AssetCategory.MEDIUM: 1.0,
            AssetCategory.LOW: 0.7,
            AssetCategory.UNKNOWN: 1.0
        }

        # Exposure multipliers
        self.exposure_multipliers = {
            ExposureLevel.INTERNET_FACING: 1.5,
            ExposureLevel.DMZ: 1.2,
            ExposureLevel.INTERNAL_ONLY: 1.0
        }

        # Asset profiles
        # Key: IP address, Value: AssetRiskProfile
        self.profiles: Dict[str, AssetRiskProfile] = {}

        # Alert history per asset
        # Key: IP address, Value: deque of AlertRecord
        self.alert_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # Risk score history for trend analysis
        self.score_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Internal networks for exposure detection
        self.internal_networks = self._parse_internal_networks()

        self.logger.info("RiskScorer initialized for asset risk calculation")

    def _parse_internal_networks(self) -> List:
        """Parse internal network ranges from config."""
        import ipaddress
        networks = []
        internal_config = self.config.get('internal_networks', [
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
        ])
        for net in internal_config:
            try:
                networks.append(ipaddress.ip_network(net, strict=False))
            except:
                pass
        return networks

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in internal networks."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.internal_networks:
                if ip_obj in network:
                    return True
        except:
            pass
        return False

    def process_alert(self, alert: Dict) -> None:
        """
        Process an alert and update risk scores.

        Args:
            alert: Alert dictionary
        """
        if not self.enabled:
            return

        current_time = time.time()
        source_ip = alert.get('source_ip', '')
        destination_ip = alert.get('destination_ip', '')
        alert_type = alert.get('type', 'UNKNOWN')
        severity = alert.get('severity', 'MEDIUM')

        # Update source IP profile (attacker role)
        if source_ip:
            self._update_profile(
                source_ip,
                AlertRecord(
                    timestamp=current_time,
                    alert_type=alert_type,
                    severity=severity,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    is_source=True,
                    details=alert.get('details', {})
                )
            )

        # Update destination IP profile (victim role)
        if destination_ip and destination_ip != source_ip:
            self._update_profile(
                destination_ip,
                AlertRecord(
                    timestamp=current_time,
                    alert_type=alert_type,
                    severity=severity,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    is_source=False,
                    details=alert.get('details', {})
                )
            )

    def _update_profile(self, ip: str, alert_record: AlertRecord) -> None:
        """Update risk profile for an IP address."""
        current_time = alert_record.timestamp

        # Get or create profile
        if ip not in self.profiles:
            self.profiles[ip] = self._create_profile(ip)

        profile = self.profiles[ip]

        # Add to alert history
        self.alert_history[ip].append(alert_record)

        # Update profile metrics
        profile.total_alerts += 1
        profile.last_alert = current_time
        profile.last_seen = current_time

        # Update alert type counts
        alert_type = alert_record.alert_type
        profile.alert_types[alert_type] = profile.alert_types.get(alert_type, 0) + 1

        # Update attacker/victim flags
        if alert_record.is_source:
            profile.is_attacker = True
        else:
            profile.is_victim = True

        # Recalculate risk score
        self._calculate_risk_score(profile)

        # Update trend
        self._update_trend(ip, profile.current_risk_score)

    def _create_profile(self, ip: str) -> AssetRiskProfile:
        """Create a new risk profile for an IP."""
        # Get device info from database if available
        hostname = None
        mac_address = None
        device_type = None
        category = AssetCategory.UNKNOWN

        if self.db:
            try:
                device = self.db.get_device_by_ip(ip)
                if device:
                    hostname = device.get('hostname')
                    mac_address = device.get('mac_address')
                    # Get device type from template or ML classification
                    template_id = device.get('template_id')
                    if template_id:
                        template = self.db.get_device_template_by_id(template_id)
                        if template:
                            device_type = template.get('name')
                            category = self._categorize_device(device_type)
            except Exception as e:
                self.logger.debug(f"Error getting device info: {e}")

        # Determine exposure level
        exposure = ExposureLevel.INTERNAL_ONLY
        if not self._is_internal_ip(ip):
            exposure = ExposureLevel.INTERNET_FACING

        return AssetRiskProfile(
            ip_address=ip,
            hostname=hostname,
            mac_address=mac_address,
            device_type=device_type,
            category=category,
            exposure=exposure,
            current_risk_score=0.0,
            max_risk_score=0.0,
            risk_trend='stable',
            total_alerts=0,
            alerts_24h=0,
            alerts_7d=0,
            alert_types={},
            is_attacker=False,
            is_victim=False,
            attack_chain_count=0,
            kill_chain_stage=None,
            last_seen=time.time(),
            last_alert=None
        )

    def _categorize_device(self, device_type: str) -> AssetCategory:
        """Categorize device based on type."""
        if not device_type:
            return AssetCategory.UNKNOWN

        device_lower = device_type.lower()

        # Check for critical infrastructure
        if any(x in device_lower for x in ['domain controller', 'dc', 'active directory']):
            return AssetCategory.CRITICAL

        # Check for servers
        if any(x in device_lower for x in ['server', 'database', 'sql', 'web server', 'mail']):
            return AssetCategory.HIGH

        # Check for workstations
        if any(x in device_lower for x in ['workstation', 'desktop', 'laptop']):
            return AssetCategory.MEDIUM

        # Check for IoT/low priority
        if any(x in device_lower for x in ['printer', 'camera', 'iot', 'sensor', 'smart']):
            return AssetCategory.LOW

        return AssetCategory.UNKNOWN

    def _calculate_risk_score(self, profile: AssetRiskProfile) -> None:
        """Calculate risk score for a profile."""
        current_time = time.time()
        score = 0.0

        # Get alerts from different time windows
        alerts = list(self.alert_history[profile.ip_address])

        # Calculate time-weighted alert score
        for record in alerts:
            age = current_time - record.timestamp
            time_weight = self._get_time_weight(age)

            # Base score from alert type
            type_weight = ALERT_TYPE_WEIGHTS.get(record.alert_type, 5.0)
            severity_weight = SEVERITY_WEIGHTS.get(record.severity, 1.0)

            # Higher weight if this asset is the attacker
            role_weight = 1.5 if record.is_source else 1.0

            score += type_weight * severity_weight * time_weight * role_weight

        # Apply category multiplier
        score *= self.category_multipliers.get(profile.category, 1.0)

        # Apply exposure multiplier
        score *= self.exposure_multipliers.get(profile.exposure, 1.0)

        # Check for attack chain involvement
        if self.kill_chain:
            chains = self.kill_chain.get_chains_for_ip(profile.ip_address)
            profile.attack_chain_count = len(chains)

            if chains:
                # Get highest stage from chains
                max_stage = None
                for chain in chains:
                    if chain.get('max_stage'):
                        if not max_stage or chain['max_stage'] > max_stage:
                            max_stage = chain['max_stage']
                profile.kill_chain_stage = max_stage

                # Bonus for attack chain involvement
                score *= 1.3

        # Update alert counts
        profile.alerts_24h = sum(1 for a in alerts if current_time - a.timestamp < 86400)
        profile.alerts_7d = sum(1 for a in alerts if current_time - a.timestamp < 604800)

        # Normalize to 0-100
        profile.current_risk_score = min(100.0, score)

        # Update max score
        if profile.current_risk_score > profile.max_risk_score:
            profile.max_risk_score = profile.current_risk_score

    def _get_time_weight(self, age_seconds: float) -> float:
        """Get time-based weight for alert (more recent = higher weight)."""
        hours = age_seconds / 3600

        if hours < 1:
            return 1.0
        elif hours < 6:
            return 0.9
        elif hours < 24:
            return 0.7
        elif hours < 72:
            return 0.5
        elif hours < 168:  # 7 days
            return 0.3
        else:
            return 0.1

    def _update_trend(self, ip: str, current_score: float) -> None:
        """Update risk score trend for an IP."""
        current_time = time.time()
        self.score_history[ip].append((current_time, current_score))

        history = list(self.score_history[ip])
        if len(history) < 3:
            self.profiles[ip].risk_trend = 'stable'
            return

        # Compare recent average to older average
        recent = [s for t, s in history[-5:]]
        older = [s for t, s in history[:-5]]

        if not older:
            self.profiles[ip].risk_trend = 'stable'
            return

        recent_avg = sum(recent) / len(recent)
        older_avg = sum(older) / len(older)

        if recent_avg > older_avg * 1.2:
            self.profiles[ip].risk_trend = 'increasing'
        elif recent_avg < older_avg * 0.8:
            self.profiles[ip].risk_trend = 'decreasing'
        else:
            self.profiles[ip].risk_trend = 'stable'

    def apply_decay(self) -> None:
        """Apply time-based decay to all risk scores."""
        current_time = time.time()

        for ip, profile in self.profiles.items():
            # Only decay if no recent alerts
            if profile.last_alert and current_time - profile.last_alert > self.decay_interval:
                decay_factor = 1.0 - (self.decay_rate *
                                       ((current_time - profile.last_alert) / self.decay_interval))
                decay_factor = max(0.0, min(1.0, decay_factor))
                profile.current_risk_score *= decay_factor

    def get_profile(self, ip: str) -> Optional[Dict]:
        """Get risk profile for an IP."""
        if ip in self.profiles:
            return self.profiles[ip].to_dict()
        return None

    def get_high_risk_assets(self, min_score: float = 50.0) -> List[Dict]:
        """Get all assets above a risk score threshold."""
        return [
            profile.to_dict()
            for profile in sorted(
                self.profiles.values(),
                key=lambda p: p.current_risk_score,
                reverse=True
            )
            if profile.current_risk_score >= min_score
        ]

    def get_top_risks(self, limit: int = 10) -> List[Dict]:
        """Get top N highest risk assets."""
        return [
            profile.to_dict()
            for profile in sorted(
                self.profiles.values(),
                key=lambda p: p.current_risk_score,
                reverse=True
            )[:limit]
        ]

    def get_risk_summary(self) -> Dict:
        """Get summary of risk distribution."""
        critical = sum(1 for p in self.profiles.values() if p.current_risk_score >= 80)
        high = sum(1 for p in self.profiles.values() if 60 <= p.current_risk_score < 80)
        medium = sum(1 for p in self.profiles.values() if 40 <= p.current_risk_score < 60)
        low = sum(1 for p in self.profiles.values() if 20 <= p.current_risk_score < 40)
        minimal = sum(1 for p in self.profiles.values() if p.current_risk_score < 20)

        attackers = sum(1 for p in self.profiles.values() if p.is_attacker)
        victims = sum(1 for p in self.profiles.values() if p.is_victim)

        return {
            'total_assets': len(self.profiles),
            'risk_distribution': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'minimal': minimal
            },
            'attackers': attackers,
            'victims': victims,
            'increasing_risk': sum(1 for p in self.profiles.values() if p.risk_trend == 'increasing'),
            'avg_risk_score': sum(p.current_risk_score for p in self.profiles.values()) / len(self.profiles)
                              if self.profiles else 0.0
        }

    def get_stats(self) -> Dict:
        """Get scorer statistics."""
        return {
            'enabled': self.enabled,
            'total_profiles': len(self.profiles),
            'alerts_tracked': sum(len(h) for h in self.alert_history.values()),
            **self.get_risk_summary()
        }
