# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Kill Chain / Multi-Stage Attack Correlation Module

Correlates individual alerts into attack chains based on:
- Cyber Kill Chain model (Lockheed Martin)
- MITRE ATT&CK framework mapping
- Temporal and spatial relationships

Attack Stages (simplified Kill Chain):
1. Reconnaissance - Port scans, service enumeration
2. Initial Access - Exploitation, credential theft
3. Execution - Code execution, payload delivery
4. Persistence - Scheduled tasks, registry modification
5. Credential Access - Kerberoasting, password dumping
6. Discovery - Internal reconnaissance
7. Lateral Movement - Pass-the-Hash, RDP, SMB
8. Collection - Data staging
9. Exfiltration - Data theft
10. Impact - Ransomware, destruction
"""

import logging
import time
import json
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class AttackStage(IntEnum):
    """Kill Chain attack stages with severity weights."""
    UNKNOWN = 0
    RECONNAISSANCE = 1
    INITIAL_ACCESS = 2
    EXECUTION = 3
    PERSISTENCE = 4
    CREDENTIAL_ACCESS = 5
    DISCOVERY = 6
    LATERAL_MOVEMENT = 7
    COLLECTION = 8
    EXFILTRATION = 9
    IMPACT = 10


# Map alert types to kill chain stages
ALERT_STAGE_MAPPING = {
    # Reconnaissance
    'PORT_SCAN': AttackStage.RECONNAISSANCE,
    'PORT_SCAN_DETECTED': AttackStage.RECONNAISSANCE,
    'INTERNAL_PORT_SCAN': AttackStage.DISCOVERY,
    'SERVICE_ENUMERATION': AttackStage.RECONNAISSANCE,
    'DNS_ENUMERATION': AttackStage.RECONNAISSANCE,
    'LDAP_ENUMERATION': AttackStage.DISCOVERY,

    # Initial Access
    'BRUTE_FORCE': AttackStage.INITIAL_ACCESS,
    'BRUTE_FORCE_ATTACK': AttackStage.INITIAL_ACCESS,
    'KERBEROS_BRUTEFORCE': AttackStage.INITIAL_ACCESS,
    'SSH_BRUTEFORCE': AttackStage.INITIAL_ACCESS,
    'RDP_BRUTEFORCE': AttackStage.INITIAL_ACCESS,
    'EXPLOIT_ATTEMPT': AttackStage.INITIAL_ACCESS,
    'THREAT_FEED_MATCH': AttackStage.INITIAL_ACCESS,

    # Credential Access
    'KERBEROASTING_ATTACK': AttackStage.CREDENTIAL_ACCESS,
    'KERBEROASTING_SUSPECTED': AttackStage.CREDENTIAL_ACCESS,
    'ASREP_ROASTING_ATTACK': AttackStage.CREDENTIAL_ACCESS,
    'ASREP_WEAK_ENCRYPTION': AttackStage.CREDENTIAL_ACCESS,
    'DCSYNC_ATTACK': AttackStage.CREDENTIAL_ACCESS,
    'PASS_THE_HASH_SUSPECTED': AttackStage.CREDENTIAL_ACCESS,
    'KERBEROS_DOWNGRADE_ATTACK': AttackStage.CREDENTIAL_ACCESS,
    'CREDENTIAL_DUMP': AttackStage.CREDENTIAL_ACCESS,
    'MIMIKATZ_DETECTED': AttackStage.CREDENTIAL_ACCESS,

    # Execution / C2
    'C2_COMMUNICATION': AttackStage.EXECUTION,
    'C2_BEACON': AttackStage.EXECUTION,
    'MALICIOUS_JA3_FINGERPRINT': AttackStage.EXECUTION,
    'BEACON_DETECTED': AttackStage.EXECUTION,
    'SUSPICIOUS_BEACON': AttackStage.EXECUTION,
    'DNS_TUNNEL': AttackStage.EXECUTION,
    'DNS_TUNNELING': AttackStage.EXECUTION,
    'ICMP_TUNNEL': AttackStage.EXECUTION,

    # Lateral Movement
    'LATERAL_MOVEMENT': AttackStage.LATERAL_MOVEMENT,
    'LATERAL_MOVEMENT_DETECTED': AttackStage.LATERAL_MOVEMENT,
    'SMB_LATERAL': AttackStage.LATERAL_MOVEMENT,
    'RDP_LATERAL': AttackStage.LATERAL_MOVEMENT,
    'PSEXEC_DETECTED': AttackStage.LATERAL_MOVEMENT,
    'WMIC_LATERAL': AttackStage.LATERAL_MOVEMENT,
    'INTERNAL_SCANNING': AttackStage.LATERAL_MOVEMENT,

    # Exfiltration
    'DATA_EXFILTRATION': AttackStage.EXFILTRATION,
    'LARGE_DATA_TRANSFER': AttackStage.EXFILTRATION,
    'UNUSUAL_UPLOAD': AttackStage.EXFILTRATION,
    'DNS_DATA_EXFIL': AttackStage.EXFILTRATION,
    'EXFIL_DETECTED': AttackStage.EXFILTRATION,

    # Impact
    'RANSOMWARE_DETECTED': AttackStage.IMPACT,
    'ENCRYPTION_ACTIVITY': AttackStage.IMPACT,
    'MASS_FILE_DELETION': AttackStage.IMPACT,
    'DESTRUCTIVE_ACTIVITY': AttackStage.IMPACT,

    # Generic
    'BLACKLISTED_IP': AttackStage.UNKNOWN,
    'CONNECTION_FLOOD': AttackStage.UNKNOWN,
    'UNUSUAL_PACKET_SIZE': AttackStage.UNKNOWN,
}

# MITRE ATT&CK technique mapping
ALERT_MITRE_MAPPING = {
    'PORT_SCAN': ['T1046'],  # Network Service Scanning
    'KERBEROASTING_ATTACK': ['T1558.003'],  # Kerberoasting
    'ASREP_ROASTING_ATTACK': ['T1558.004'],  # AS-REP Roasting
    'DCSYNC_ATTACK': ['T1003.006'],  # DCSync
    'PASS_THE_HASH_SUSPECTED': ['T1550.002'],  # Pass the Hash
    'C2_COMMUNICATION': ['T1071'],  # Application Layer Protocol
    'DNS_TUNNEL': ['T1071.004'],  # DNS
    'LATERAL_MOVEMENT': ['T1021'],  # Remote Services
    'DATA_EXFILTRATION': ['T1041'],  # Exfiltration Over C2 Channel
    'BRUTE_FORCE': ['T1110'],  # Brute Force
}


@dataclass
class AttackChainEvent:
    """Single event in an attack chain."""
    timestamp: float
    alert_type: str
    severity: str
    stage: AttackStage
    source_ip: str
    destination_ip: str
    description: str
    alert_id: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)


@dataclass
class AttackChain:
    """Represents a correlated attack chain."""
    chain_id: str
    source_ips: Set[str]
    target_ips: Set[str]
    events: List[AttackChainEvent]
    first_seen: float
    last_seen: float
    stages_observed: Set[AttackStage]
    max_stage: AttackStage
    risk_score: float
    is_active: bool
    ttps: Set[str]  # MITRE ATT&CK techniques

    def to_dict(self) -> Dict:
        """Convert to serializable dictionary."""
        return {
            'chain_id': self.chain_id,
            'source_ips': list(self.source_ips),
            'target_ips': list(self.target_ips),
            'event_count': len(self.events),
            'events': [
                {
                    'timestamp': e.timestamp,
                    'alert_type': e.alert_type,
                    'severity': e.severity,
                    'stage': e.stage.name,
                    'source_ip': e.source_ip,
                    'destination_ip': e.destination_ip,
                    'description': e.description
                }
                for e in self.events[-20:]  # Last 20 events
            ],
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'duration_seconds': self.last_seen - self.first_seen,
            'stages_observed': [s.name for s in sorted(self.stages_observed)],
            'max_stage': self.max_stage.name,
            'progression': self._get_progression(),
            'risk_score': self.risk_score,
            'is_active': self.is_active,
            'ttps': list(self.ttps)
        }

    def _get_progression(self) -> str:
        """Get attack chain progression as string."""
        stages = sorted(self.stages_observed)
        return ' → '.join(s.name for s in stages)


class KillChainDetector:
    """
    Correlates individual security alerts into attack chains.

    Uses temporal and spatial correlation to identify multi-stage attacks.
    """

    def __init__(self, config: dict = None, db_manager=None):
        self.config = config or {}
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.KillChainDetector')

        # Get configuration
        kc_config = self.config.get('thresholds', {}).get('kill_chain', {})
        self.enabled = kc_config.get('enabled', True)

        # Correlation windows
        self.chain_window = kc_config.get('chain_window', 3600)  # 1 hour
        self.activity_timeout = kc_config.get('activity_timeout', 1800)  # 30 min inactive = chain ends
        self.min_events_for_chain = kc_config.get('min_events', 3)
        self.min_stages_for_chain = kc_config.get('min_stages', 2)

        # Risk scoring weights
        self.stage_weights = {
            AttackStage.RECONNAISSANCE: 1.0,
            AttackStage.INITIAL_ACCESS: 2.0,
            AttackStage.EXECUTION: 3.0,
            AttackStage.PERSISTENCE: 2.5,
            AttackStage.CREDENTIAL_ACCESS: 4.0,
            AttackStage.DISCOVERY: 1.5,
            AttackStage.LATERAL_MOVEMENT: 4.0,
            AttackStage.COLLECTION: 3.0,
            AttackStage.EXFILTRATION: 5.0,
            AttackStage.IMPACT: 5.0,
        }

        self.severity_weights = {
            'LOW': 1.0,
            'MEDIUM': 2.0,
            'HIGH': 3.0,
            'CRITICAL': 5.0
        }

        # Active attack chains
        # Key: chain_id, Value: AttackChain
        self.active_chains: Dict[str, AttackChain] = {}

        # IP to chain mapping for quick lookup
        # Key: ip, Value: set of chain_ids
        self.ip_to_chains: Dict[str, Set[str]] = defaultdict(set)

        # Historical chains (completed/inactive)
        self.historical_chains: deque = deque(maxlen=1000)

        # Recent alerts for correlation
        self.recent_alerts: deque = deque(maxlen=5000)

        # Kill chain alerts generated
        self.chain_alerts: List[Dict] = []

        self.logger.info("KillChainDetector initialized for multi-stage attack correlation")

    def process_alert(self, alert: Dict) -> List[Dict]:
        """
        Process an incoming alert and correlate with attack chains.

        Returns:
            List of chain-related alerts (new chain, progression, etc.)
        """
        if not self.enabled:
            return []

        generated_alerts = []
        current_time = time.time()

        # Clean up old chains
        self._cleanup_inactive_chains(current_time)

        # Extract alert info
        alert_type = alert.get('type', 'UNKNOWN')
        source_ip = alert.get('source_ip', '')
        destination_ip = alert.get('destination_ip', '')
        severity = alert.get('severity', 'MEDIUM')
        description = alert.get('description', '')
        alert_id = alert.get('id', '')

        # Determine attack stage
        stage = ALERT_STAGE_MAPPING.get(alert_type, AttackStage.UNKNOWN)
        if stage == AttackStage.UNKNOWN:
            return []  # Don't track unknown stages

        # Get MITRE techniques
        mitre_techniques = ALERT_MITRE_MAPPING.get(alert_type, [])

        # Create event
        event = AttackChainEvent(
            timestamp=current_time,
            alert_type=alert_type,
            severity=severity,
            stage=stage,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            alert_id=alert_id,
            mitre_techniques=mitre_techniques,
            details=alert.get('details', {})
        )

        # Store in recent alerts
        self.recent_alerts.append(event)

        # Find existing chains this alert might belong to
        matching_chains = self._find_matching_chains(source_ip, destination_ip, current_time)

        if matching_chains:
            # Add to existing chain(s)
            for chain_id in matching_chains:
                chain = self.active_chains[chain_id]
                prev_max_stage = chain.max_stage

                # Update chain
                chain.events.append(event)
                chain.last_seen = current_time
                chain.source_ips.add(source_ip)
                if destination_ip:
                    chain.target_ips.add(destination_ip)
                chain.stages_observed.add(stage)
                chain.ttps.update(mitre_techniques)

                if stage > chain.max_stage:
                    chain.max_stage = stage

                # Recalculate risk score
                chain.risk_score = self._calculate_risk_score(chain)

                # Check for stage progression
                if stage > prev_max_stage:
                    progression_alert = self._create_progression_alert(chain, event)
                    if progression_alert:  # Skip if None (no distinct source/destination)
                        generated_alerts.append(progression_alert)

                # Check for high-risk chain
                if chain.risk_score >= 50 and len(chain.events) >= 5:
                    high_risk_alert = self._create_high_risk_alert(chain)
                    if high_risk_alert:  # Skip if None (no distinct source/destination)
                        generated_alerts.append(high_risk_alert)

        else:
            # Check if we should start a new chain
            related_events = self._find_related_events(source_ip, destination_ip, current_time)

            if len(related_events) >= self.min_events_for_chain - 1:
                # Create new chain with related events
                chain = self._create_chain(event, related_events)
                self.active_chains[chain.chain_id] = chain

                # Update IP mappings
                for ip in chain.source_ips:
                    self.ip_to_chains[ip].add(chain.chain_id)
                for ip in chain.target_ips:
                    self.ip_to_chains[ip].add(chain.chain_id)

                # Check if this is an interesting chain
                if len(chain.stages_observed) >= self.min_stages_for_chain:
                    new_chain_alert = self._create_new_chain_alert(chain)
                    if new_chain_alert:  # Skip if None (no distinct source/destination)
                        generated_alerts.append(new_chain_alert)

        return generated_alerts

    def _find_matching_chains(self, source_ip: str, destination_ip: str,
                              current_time: float) -> List[str]:
        """Find active chains that this alert might belong to."""
        matching = []

        # Check chains associated with these IPs
        candidate_chains = set()
        if source_ip:
            candidate_chains.update(self.ip_to_chains.get(source_ip, set()))
        if destination_ip:
            candidate_chains.update(self.ip_to_chains.get(destination_ip, set()))

        for chain_id in candidate_chains:
            if chain_id not in self.active_chains:
                continue

            chain = self.active_chains[chain_id]

            # Check if chain is still active (within activity timeout)
            if current_time - chain.last_seen > self.activity_timeout:
                continue

            # Check if IPs are related to this chain
            if source_ip in chain.source_ips or source_ip in chain.target_ips:
                matching.append(chain_id)
            elif destination_ip in chain.source_ips or destination_ip in chain.target_ips:
                matching.append(chain_id)

        return matching

    def _find_related_events(self, source_ip: str, destination_ip: str,
                             current_time: float) -> List[AttackChainEvent]:
        """Find recent events related to these IPs."""
        related = []
        window_start = current_time - self.chain_window

        for event in self.recent_alerts:
            if event.timestamp < window_start:
                continue

            # Check IP relationship
            if source_ip and (event.source_ip == source_ip or event.destination_ip == source_ip):
                related.append(event)
            elif destination_ip and (event.source_ip == destination_ip or event.destination_ip == destination_ip):
                related.append(event)

        return related

    def _create_chain(self, trigger_event: AttackChainEvent,
                      related_events: List[AttackChainEvent]) -> AttackChain:
        """Create a new attack chain."""
        # Generate chain ID
        chain_id = hashlib.md5(
            f"{trigger_event.source_ip}:{trigger_event.destination_ip}:{trigger_event.timestamp}".encode()
        ).hexdigest()[:12]

        # Combine events
        all_events = sorted(related_events + [trigger_event], key=lambda e: e.timestamp)

        # Extract IPs
        source_ips = set(e.source_ip for e in all_events if e.source_ip)
        target_ips = set(e.destination_ip for e in all_events if e.destination_ip)

        # Get stages and TTPs
        stages = set(e.stage for e in all_events)
        ttps = set()
        for e in all_events:
            ttps.update(e.mitre_techniques)

        chain = AttackChain(
            chain_id=chain_id,
            source_ips=source_ips,
            target_ips=target_ips,
            events=all_events,
            first_seen=all_events[0].timestamp,
            last_seen=all_events[-1].timestamp,
            stages_observed=stages,
            max_stage=max(stages),
            risk_score=0.0,
            is_active=True,
            ttps=ttps
        )

        chain.risk_score = self._calculate_risk_score(chain)

        return chain

    def _calculate_risk_score(self, chain: AttackChain) -> float:
        """
        Calculate risk score for an attack chain.

        Score is based on:
        - Number and severity of events
        - Attack stage progression
        - Number of targets affected
        - Time span of attack
        """
        score = 0.0

        # Event contribution
        for event in chain.events:
            stage_weight = self.stage_weights.get(event.stage, 1.0)
            severity_weight = self.severity_weights.get(event.severity, 1.0)
            score += stage_weight * severity_weight

        # Stage progression bonus
        if len(chain.stages_observed) >= 3:
            score *= 1.5
        if len(chain.stages_observed) >= 5:
            score *= 1.5

        # High stage bonus
        if chain.max_stage >= AttackStage.LATERAL_MOVEMENT:
            score *= 1.5
        if chain.max_stage >= AttackStage.EXFILTRATION:
            score *= 2.0

        # Target count bonus
        target_count = len(chain.target_ips)
        if target_count >= 3:
            score *= 1.2
        if target_count >= 10:
            score *= 1.5

        # Normalize to 0-100
        return min(100.0, score)

    def _get_distinct_source_and_target(self, chain: AttackChain) -> Tuple[Optional[str], Optional[str]]:
        """
        Get distinct source and destination IPs for an alert.
        Ensures source_ip != destination_ip when possible.
        """
        source_ip = list(chain.source_ips)[0] if chain.source_ips else None

        # Try to find a target IP that's different from source
        if chain.target_ips:
            # Prefer a target that's not also a source
            distinct_targets = chain.target_ips - chain.source_ips
            if distinct_targets:
                destination_ip = list(distinct_targets)[0]
            else:
                # All targets are also sources - pick one that's different from our chosen source
                other_targets = [ip for ip in chain.target_ips if ip != source_ip]
                destination_ip = other_targets[0] if other_targets else None
        else:
            destination_ip = None

        return source_ip, destination_ip

    def _create_new_chain_alert(self, chain: AttackChain) -> Optional[Dict]:
        """Create alert for new attack chain detection. Returns None if no valid alert can be created."""
        source_ip, destination_ip = self._get_distinct_source_and_target(chain)

        # Don't create alert if we can't determine distinct source and destination
        if not source_ip or not destination_ip or source_ip == destination_ip:
            self.logger.debug(f"Skipping chain alert for {chain.chain_id}: no distinct source/destination")
            return None

        return {
            'type': 'ATTACK_CHAIN_DETECTED',
            'severity': 'HIGH' if chain.risk_score >= 30 else 'MEDIUM',
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'description': f'Multi-stage attack chain detected: {len(chain.events)} events across {len(chain.stages_observed)} stages',
            'details': {
                'chain_id': chain.chain_id,
                'event_count': len(chain.events),
                'stages': [s.name for s in sorted(chain.stages_observed)],
                'progression': chain._get_progression(),
                'risk_score': chain.risk_score,
                'source_ips': list(chain.source_ips),
                'target_ips': list(chain.target_ips),
                'ttps': list(chain.ttps),
                'first_seen': chain.first_seen,
                'duration_seconds': chain.last_seen - chain.first_seen
            }
        }

    def _create_progression_alert(self, chain: AttackChain, new_event: AttackChainEvent) -> Optional[Dict]:
        """Create alert for attack chain progression. Returns None if source == destination."""
        source_ip = new_event.source_ip
        destination_ip = new_event.destination_ip

        # Don't create alert if source == destination
        if not source_ip or not destination_ip or source_ip == destination_ip:
            # Try to use chain-level IPs instead
            source_ip, destination_ip = self._get_distinct_source_and_target(chain)
            if not source_ip or not destination_ip or source_ip == destination_ip:
                return None

        return {
            'type': 'ATTACK_CHAIN_PROGRESSION',
            'severity': 'HIGH' if new_event.stage >= AttackStage.LATERAL_MOVEMENT else 'MEDIUM',
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'description': f'Attack chain progressed to {new_event.stage.name}: {new_event.description}',
            'details': {
                'chain_id': chain.chain_id,
                'new_stage': new_event.stage.name,
                'previous_stages': [s.name for s in sorted(chain.stages_observed) if s != new_event.stage],
                'progression': chain._get_progression(),
                'risk_score': chain.risk_score,
                'event_count': len(chain.events)
            }
        }

    def _create_high_risk_alert(self, chain: AttackChain) -> Optional[Dict]:
        """Create alert for high-risk attack chain. Returns None if no valid alert can be created."""
        source_ip, destination_ip = self._get_distinct_source_and_target(chain)

        # Don't create alert if we can't determine distinct source and destination
        if not source_ip or not destination_ip or source_ip == destination_ip:
            self.logger.debug(f"Skipping high-risk alert for chain {chain.chain_id}: no distinct source/destination")
            return None

        return {
            'type': 'HIGH_RISK_ATTACK_CHAIN',
            'severity': 'CRITICAL',
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'description': f'High-risk attack chain (score: {chain.risk_score:.0f}): {chain._get_progression()}',
            'details': {
                'chain_id': chain.chain_id,
                'risk_score': chain.risk_score,
                'event_count': len(chain.events),
                'stages': [s.name for s in sorted(chain.stages_observed)],
                'progression': chain._get_progression(),
                'source_ips': list(chain.source_ips),
                'target_ips': list(chain.target_ips),
                'ttps': list(chain.ttps),
                'duration_seconds': chain.last_seen - chain.first_seen
            }
        }

    def _cleanup_inactive_chains(self, current_time: float):
        """Move inactive chains to historical storage."""
        inactive_ids = []

        for chain_id, chain in self.active_chains.items():
            if current_time - chain.last_seen > self.activity_timeout:
                chain.is_active = False
                self.historical_chains.append(chain)
                inactive_ids.append(chain_id)

        for chain_id in inactive_ids:
            chain = self.active_chains.pop(chain_id)

            # Clean up IP mappings
            for ip in chain.source_ips:
                self.ip_to_chains[ip].discard(chain_id)
            for ip in chain.target_ips:
                self.ip_to_chains[ip].discard(chain_id)

    def get_active_chains(self) -> List[Dict]:
        """Get all active attack chains."""
        return [chain.to_dict() for chain in self.active_chains.values()]

    def get_chain_by_id(self, chain_id: str) -> Optional[Dict]:
        """Get specific chain by ID."""
        if chain_id in self.active_chains:
            return self.active_chains[chain_id].to_dict()

        for chain in self.historical_chains:
            if chain.chain_id == chain_id:
                return chain.to_dict()

        return None

    def get_chains_for_ip(self, ip: str) -> List[Dict]:
        """Get all chains involving an IP address."""
        chains = []

        # Check active chains
        chain_ids = self.ip_to_chains.get(ip, set())
        for chain_id in chain_ids:
            if chain_id in self.active_chains:
                chains.append(self.active_chains[chain_id].to_dict())

        # Check historical chains
        for chain in self.historical_chains:
            if ip in chain.source_ips or ip in chain.target_ips:
                chains.append(chain.to_dict())

        return chains

    def get_stats(self) -> Dict:
        """Get detector statistics."""
        return {
            'enabled': self.enabled,
            'active_chains': len(self.active_chains),
            'historical_chains': len(self.historical_chains),
            'recent_alerts_tracked': len(self.recent_alerts),
            'high_risk_chains': sum(
                1 for c in self.active_chains.values()
                if c.risk_score >= 50
            ),
            'chains_by_max_stage': {
                stage.name: sum(
                    1 for c in self.active_chains.values()
                    if c.max_stage == stage
                )
                for stage in AttackStage
                if sum(1 for c in self.active_chains.values() if c.max_stage == stage) > 0
            }
        }

    def get_mitre_summary(self) -> Dict[str, int]:
        """Get summary of MITRE ATT&CK techniques observed."""
        technique_counts = defaultdict(int)

        for chain in self.active_chains.values():
            for ttp in chain.ttps:
                technique_counts[ttp] += 1

        for chain in self.historical_chains:
            for ttp in chain.ttps:
                technique_counts[ttp] += 1

        return dict(technique_counts)
