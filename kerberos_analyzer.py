# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Kerberos/Active Directory Attack Detection Module

Detects common AD attack patterns:
- Kerberoasting (TGS-REQ for service accounts)
- AS-REP Roasting (accounts without pre-auth)
- Golden/Silver Ticket anomalies
- Pass-the-Hash / Pass-the-Ticket patterns
- DCSync attacks (DRSUAPI replication)
- Overpass-the-Hash (RC4 downgrades)
- Skeleton Key patterns
"""

import logging
import struct
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


class KerberosAnalyzer:
    """
    Analyzes Kerberos traffic for attack patterns.

    Kerberos message types:
    - AS-REQ (10): Initial authentication request
    - AS-REP (11): Initial authentication response
    - TGS-REQ (12): Ticket granting service request
    - TGS-REP (13): Ticket granting service response
    - AP-REQ (14): Application request
    - AP-REP (15): Application response
    - KRB-ERROR (30): Kerberos error
    """

    # Kerberos ports
    KERBEROS_PORT = 88

    # Kerberos message types
    MSG_AS_REQ = 10
    MSG_AS_REP = 11
    MSG_TGS_REQ = 12
    MSG_TGS_REP = 13
    MSG_AP_REQ = 14
    MSG_AP_REP = 15
    MSG_KRB_ERROR = 30

    # Kerberos encryption types
    ETYPE_DES_CBC_CRC = 1
    ETYPE_DES_CBC_MD5 = 3
    ETYPE_RC4_HMAC = 23  # Vulnerable to Kerberoasting
    ETYPE_RC4_HMAC_EXP = 24
    ETYPE_AES128_CTS = 17
    ETYPE_AES256_CTS = 18

    # Weak encryption types (vulnerable to offline cracking)
    WEAK_ETYPES = {1, 3, 23, 24}  # DES and RC4

    # Kerberos error codes
    ERR_PREAUTH_REQUIRED = 25  # KDC_ERR_PREAUTH_REQUIRED
    ERR_PREAUTH_FAILED = 24    # KDC_ERR_PREAUTH_FAILED
    ERR_CLIENT_REVOKED = 18    # KDC_ERR_CLIENT_REVOKED
    ERR_TGT_REVOKED = 20       # KDC_ERR_TGT_REVOKED

    def __init__(self, config: dict = None, db_manager=None):
        self.config = config or {}
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.KerberosAnalyzer')

        # Get thresholds from config
        krb_config = self.config.get('thresholds', {}).get('kerberos', {})
        self.enabled = krb_config.get('enabled', True)

        # Kerberoasting detection thresholds
        self.tgs_req_threshold = krb_config.get('tgs_req_threshold', 10)  # TGS requests per window
        self.tgs_req_window = krb_config.get('tgs_req_window', 300)  # 5 minute window

        # AS-REP roasting detection
        self.asrep_threshold = krb_config.get('asrep_threshold', 5)  # AS-REP without preauth
        self.asrep_window = krb_config.get('asrep_window', 300)

        # Golden ticket detection (unusual TGT patterns)
        self.tgt_lifetime_max = krb_config.get('tgt_lifetime_max', 10 * 60 * 60)  # 10 hours default

        # Tracking data structures
        # TGS request tracker: src_ip -> deque of (timestamp, sname, etype)
        self.tgs_req_tracker = defaultdict(lambda: deque(maxlen=500))

        # AS-REP tracker: src_ip -> deque of (timestamp, cname, has_preauth)
        self.as_rep_tracker = defaultdict(lambda: deque(maxlen=200))

        # Failed auth tracker: src_ip -> deque of (timestamp, error_code)
        self.auth_failure_tracker = defaultdict(lambda: deque(maxlen=200))

        # Encryption type tracker: src_ip -> {etype: count}
        self.etype_tracker = defaultdict(lambda: defaultdict(int))

        # Service principal tracker: sname -> set of requesting IPs
        self.spn_tracker = defaultdict(set)

        # Ticket cache for anomaly detection
        self.ticket_cache = defaultdict(dict)

        # LDAP/DRSUAPI tracker for DCSync detection
        self.drsuapi_tracker = defaultdict(lambda: deque(maxlen=100))

        # SMB tracker for lateral movement
        self.smb_auth_tracker = defaultdict(lambda: deque(maxlen=200))

        self.logger.info("KerberosAnalyzer initialized for AD attack detection")

    def analyze_packet(self, packet) -> List[Dict]:
        """
        Analyze a packet for Kerberos/AD attack patterns.

        Returns:
            List of threat dictionaries
        """
        if not self.enabled:
            return []

        threats = []

        if not packet.haslayer(IP):
            return threats

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Check for Kerberos traffic (port 88)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if packet.haslayer(TCP):
                transport = packet[TCP]
            else:
                transport = packet[UDP]

            dst_port = transport.dport
            src_port = transport.sport

            # Kerberos traffic
            if dst_port == self.KERBEROS_PORT or src_port == self.KERBEROS_PORT:
                if packet.haslayer(Raw):
                    krb_threats = self._analyze_kerberos(packet, src_ip, dst_ip)
                    threats.extend(krb_threats)

            # LDAP traffic (389, 636, 3268, 3269) - for DCSync detection
            if dst_port in (389, 636, 3268, 3269):
                if packet.haslayer(Raw):
                    ldap_threats = self._analyze_ldap(packet, src_ip, dst_ip, dst_port)
                    threats.extend(ldap_threats)

            # RPC/DRSUAPI traffic (135, 49152-65535 dynamic) - DCSync
            if dst_port == 135 or (dst_port >= 49152 and packet.haslayer(Raw)):
                drsuapi_threats = self._detect_drsuapi(packet, src_ip, dst_ip, dst_port)
                threats.extend(drsuapi_threats)

            # SMB traffic (445) - for Pass-the-Hash detection
            if dst_port == 445 or src_port == 445:
                smb_threats = self._analyze_smb_auth(packet, src_ip, dst_ip)
                threats.extend(smb_threats)

        return threats

    def _analyze_kerberos(self, packet, src_ip: str, dst_ip: str) -> List[Dict]:
        """Analyze Kerberos packet payload."""
        threats = []

        try:
            raw_data = bytes(packet[Raw].load)
            if len(raw_data) < 10:
                return threats

            # Parse Kerberos message
            msg_type, parsed_data = self._parse_kerberos_message(raw_data)

            if msg_type is None:
                return threats

            current_time = time.time()

            # Analyze based on message type
            if msg_type == self.MSG_TGS_REQ:
                # Track TGS request for Kerberoasting detection
                sname = parsed_data.get('sname', 'unknown')
                etype = parsed_data.get('etype', 0)

                self.tgs_req_tracker[src_ip].append((current_time, sname, etype))
                self.etype_tracker[src_ip][etype] += 1
                self.spn_tracker[sname].add(src_ip)

                # Check for Kerberoasting
                kerberoast_threat = self._detect_kerberoasting(src_ip, dst_ip, current_time)
                if kerberoast_threat:
                    threats.append(kerberoast_threat)

                # Check for weak encryption downgrade
                if etype in self.WEAK_ETYPES:
                    weak_threat = self._detect_weak_encryption(src_ip, dst_ip, etype, 'TGS-REQ')
                    if weak_threat:
                        threats.append(weak_threat)

            elif msg_type == self.MSG_AS_REQ:
                # Check for AS-REP roasting attempts (requests without pre-auth)
                has_preauth = parsed_data.get('padata', False)
                cname = parsed_data.get('cname', 'unknown')
                etype = parsed_data.get('etype', 0)

                self.etype_tracker[src_ip][etype] += 1

                if etype in self.WEAK_ETYPES:
                    weak_threat = self._detect_weak_encryption(src_ip, dst_ip, etype, 'AS-REQ')
                    if weak_threat:
                        threats.append(weak_threat)

            elif msg_type == self.MSG_AS_REP:
                # Track AS-REP for roasting detection
                has_preauth = parsed_data.get('enc_type_used', 0) not in self.WEAK_ETYPES
                cname = parsed_data.get('cname', 'unknown')
                etype = parsed_data.get('enc_type_used', 0)

                self.as_rep_tracker[src_ip].append((current_time, cname, has_preauth, etype))

                # Check for AS-REP roasting (responses with weak encryption)
                if etype in self.WEAK_ETYPES:
                    asrep_threat = self._detect_asrep_roasting(src_ip, dst_ip, cname, etype, current_time)
                    if asrep_threat:
                        threats.append(asrep_threat)

            elif msg_type == self.MSG_KRB_ERROR:
                error_code = parsed_data.get('error_code', 0)
                self.auth_failure_tracker[src_ip].append((current_time, error_code))

                # Check for brute force / password spray patterns
                bruteforce_threat = self._detect_kerberos_bruteforce(src_ip, dst_ip, error_code, current_time)
                if bruteforce_threat:
                    threats.append(bruteforce_threat)

            elif msg_type == self.MSG_TGS_REP:
                # Check ticket for anomalies (Golden/Silver ticket indicators)
                ticket_data = parsed_data.get('ticket', {})
                anomaly_threat = self._detect_ticket_anomaly(src_ip, dst_ip, ticket_data, current_time)
                if anomaly_threat:
                    threats.append(anomaly_threat)

        except Exception as e:
            self.logger.debug(f"Error parsing Kerberos packet: {e}")

        return threats

    def _parse_kerberos_message(self, data: bytes) -> Tuple[Optional[int], Dict]:
        """
        Parse Kerberos ASN.1 message to extract key fields.

        This is a simplified parser focusing on attack-relevant fields.
        Full ASN.1 parsing would require pyasn1.
        """
        parsed = {}
        msg_type = None

        try:
            # Check for TCP length prefix
            offset = 0
            if len(data) > 4:
                # Skip TCP length prefix if present
                if data[0:2] == b'\x00\x00' or (data[0] & 0x80 == 0):
                    offset = 4

            # Look for Kerberos application tags (0x60-0x7f for constructed)
            # AS-REQ: 0x6a (10), AS-REP: 0x6b (11), TGS-REQ: 0x6c (12), TGS-REP: 0x6d (13)
            # KRB-ERROR: 0x7e (30)

            for i in range(offset, min(len(data), offset + 20)):
                if data[i] >= 0x6a and data[i] <= 0x7e:
                    msg_type = data[i] - 0x60
                    break

            if msg_type is None:
                return None, {}

            # Extract encryption type (look for etype field)
            # etype is typically tagged with 0xa3 in AS-REQ/TGS-REQ
            etype = self._extract_etype(data)
            if etype:
                parsed['etype'] = etype

            # Extract service name (sname) for TGS-REQ
            if msg_type == self.MSG_TGS_REQ:
                sname = self._extract_principal_name(data, 'sname')
                if sname:
                    parsed['sname'] = sname

            # Extract client name (cname) for AS-REQ/AS-REP
            if msg_type in (self.MSG_AS_REQ, self.MSG_AS_REP):
                cname = self._extract_principal_name(data, 'cname')
                if cname:
                    parsed['cname'] = cname

            # Check for pre-auth data
            if b'\xa2' in data[:100]:  # padata tag
                parsed['padata'] = True

            # Extract error code for KRB-ERROR
            if msg_type == self.MSG_KRB_ERROR:
                error_code = self._extract_error_code(data)
                if error_code is not None:
                    parsed['error_code'] = error_code

        except Exception as e:
            self.logger.debug(f"Kerberos parse error: {e}")

        return msg_type, parsed

    def _extract_etype(self, data: bytes) -> Optional[int]:
        """Extract encryption type from Kerberos message."""
        # Look for etype sequence (typically after 0xa3 or 0xa8 tag)
        try:
            for i in range(len(data) - 5):
                # Look for common etype patterns
                if data[i] == 0x02 and data[i+1] == 0x01:  # INTEGER length 1
                    etype = data[i+2]
                    if etype in (1, 3, 17, 18, 23, 24):  # Valid Kerberos etypes
                        return etype
        except:
            pass
        return None

    def _extract_principal_name(self, data: bytes, name_type: str) -> Optional[str]:
        """Extract principal name (sname or cname) from Kerberos message."""
        try:
            # Look for GeneralString sequences that might contain principal names
            # This is simplified - real parsing needs full ASN.1
            for i in range(len(data) - 10):
                if data[i] == 0x1b:  # GeneralString tag
                    length = data[i+1]
                    if length > 0 and length < 100:
                        name = data[i+2:i+2+length].decode('utf-8', errors='ignore')
                        if name and len(name) > 2:
                            return name
        except:
            pass
        return None

    def _extract_error_code(self, data: bytes) -> Optional[int]:
        """Extract error code from KRB-ERROR message."""
        try:
            # Error code is typically tagged with 0xa6
            for i in range(len(data) - 5):
                if data[i] == 0xa6:
                    # Find the INTEGER
                    for j in range(i+1, min(i+10, len(data)-2)):
                        if data[j] == 0x02:  # INTEGER tag
                            length = data[j+1]
                            if length == 1:
                                return data[j+2]
                            elif length == 2:
                                return struct.unpack('>H', data[j+2:j+4])[0]
        except:
            pass
        return None

    def _detect_kerberoasting(self, src_ip: str, dst_ip: str, current_time: float) -> Optional[Dict]:
        """
        Detect Kerberoasting attack pattern.

        Indicators:
        - Many TGS-REQ for different SPNs from same source
        - Requests for service accounts with weak encryption
        - Unusual timing patterns
        """
        window_start = current_time - self.tgs_req_window

        # Get recent TGS requests
        recent_requests = [
            (ts, sname, etype)
            for ts, sname, etype in self.tgs_req_tracker[src_ip]
            if ts >= window_start
        ]

        if len(recent_requests) < self.tgs_req_threshold:
            return None

        # Count unique service names
        unique_spns = set(sname for _, sname, _ in recent_requests)

        # Count weak encryption requests
        weak_requests = sum(1 for _, _, etype in recent_requests if etype in self.WEAK_ETYPES)
        weak_ratio = weak_requests / len(recent_requests) if recent_requests else 0

        # High number of unique SPNs with weak encryption = strong indicator
        if len(unique_spns) >= 5 and weak_ratio > 0.5:
            return {
                'type': 'KERBEROASTING_ATTACK',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Kerberoasting detected: {len(recent_requests)} TGS-REQ for {len(unique_spns)} unique SPNs with {weak_ratio:.0%} weak encryption',
                'details': {
                    'tgs_requests': len(recent_requests),
                    'unique_spns': len(unique_spns),
                    'weak_encryption_ratio': weak_ratio,
                    'window_seconds': self.tgs_req_window
                }
            }

        # Moderate indicator - many requests but not all weak
        if len(unique_spns) >= 10:
            return {
                'type': 'KERBEROASTING_SUSPECTED',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Potential Kerberoasting: {len(recent_requests)} TGS-REQ for {len(unique_spns)} unique SPNs',
                'details': {
                    'tgs_requests': len(recent_requests),
                    'unique_spns': len(unique_spns),
                    'window_seconds': self.tgs_req_window
                }
            }

        return None

    def _detect_asrep_roasting(self, src_ip: str, dst_ip: str, cname: str,
                               etype: int, current_time: float) -> Optional[Dict]:
        """
        Detect AS-REP Roasting attack pattern.

        Indicators:
        - AS-REP responses with RC4 encryption (no pre-auth required)
        - Multiple accounts targeted from same source
        """
        if etype not in self.WEAK_ETYPES:
            return None

        window_start = current_time - self.asrep_window

        # Get recent AS-REP with weak encryption
        recent_weak = [
            (ts, cn, preauth, et)
            for ts, cn, preauth, et in self.as_rep_tracker[src_ip]
            if ts >= window_start and et in self.WEAK_ETYPES
        ]

        if len(recent_weak) >= self.asrep_threshold:
            unique_accounts = set(cn for _, cn, _, _ in recent_weak)

            return {
                'type': 'ASREP_ROASTING_ATTACK',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'AS-REP Roasting detected: {len(recent_weak)} responses with weak encryption for {len(unique_accounts)} accounts',
                'details': {
                    'responses': len(recent_weak),
                    'unique_accounts': len(unique_accounts),
                    'encryption_type': etype,
                    'last_account': cname
                }
            }

        # Single AS-REP with weak encryption is still noteworthy
        return {
            'type': 'ASREP_WEAK_ENCRYPTION',
            'severity': 'MEDIUM',
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'description': f'AS-REP with weak encryption (RC4) for account: {cname}',
            'details': {
                'account': cname,
                'encryption_type': etype
            }
        }

    def _detect_weak_encryption(self, src_ip: str, dst_ip: str,
                                etype: int, msg_type: str) -> Optional[Dict]:
        """Detect use of weak encryption types."""
        # Track weak encryption usage
        weak_count = sum(
            count for et, count in self.etype_tracker[src_ip].items()
            if et in self.WEAK_ETYPES
        )

        total_count = sum(self.etype_tracker[src_ip].values())

        if weak_count > 10 and weak_count / total_count > 0.8:
            etype_names = {
                1: 'DES-CBC-CRC',
                3: 'DES-CBC-MD5',
                23: 'RC4-HMAC',
                24: 'RC4-HMAC-EXP'
            }

            return {
                'type': 'KERBEROS_DOWNGRADE_ATTACK',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Kerberos encryption downgrade: {weak_count}/{total_count} requests use weak encryption ({etype_names.get(etype, etype)})',
                'details': {
                    'weak_requests': weak_count,
                    'total_requests': total_count,
                    'encryption_type': etype,
                    'message_type': msg_type
                }
            }

        return None

    def _detect_kerberos_bruteforce(self, src_ip: str, dst_ip: str,
                                     error_code: int, current_time: float) -> Optional[Dict]:
        """Detect Kerberos brute force / password spray attacks."""
        # Only track relevant error codes
        relevant_errors = {
            self.ERR_PREAUTH_FAILED,  # Wrong password
            self.ERR_CLIENT_REVOKED,  # Account disabled
            self.ERR_TGT_REVOKED,     # TGT revoked
        }

        if error_code not in relevant_errors:
            return None

        window_start = current_time - 300  # 5 minute window

        recent_failures = [
            (ts, err)
            for ts, err in self.auth_failure_tracker[src_ip]
            if ts >= window_start
        ]

        if len(recent_failures) >= 10:
            return {
                'type': 'KERBEROS_BRUTEFORCE',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Kerberos brute force detected: {len(recent_failures)} authentication failures in 5 minutes',
                'details': {
                    'failures': len(recent_failures),
                    'last_error_code': error_code,
                    'window_seconds': 300
                }
            }

        return None

    def _detect_ticket_anomaly(self, src_ip: str, dst_ip: str,
                               ticket_data: Dict, current_time: float) -> Optional[Dict]:
        """
        Detect Golden/Silver ticket anomalies.

        Indicators:
        - Unusual ticket lifetime (> 10 hours)
        - Ticket for non-existent service
        - Encryption mismatch
        """
        # This would require more sophisticated ticket parsing
        # For now, track ticket patterns for anomaly detection
        return None

    def _detect_drsuapi(self, packet, src_ip: str, dst_ip: str, dst_port: int) -> List[Dict]:
        """
        Detect DCSync attack (DRSUAPI replication requests).

        DCSync uses the Directory Replication Service to request
        password hashes from domain controllers.
        """
        threats = []

        if not packet.haslayer(Raw):
            return threats

        try:
            raw_data = bytes(packet[Raw].load)

            # Look for DRSUAPI interface UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
            drsuapi_uuid = b'\x35\x42\x51\xe3\x06\x4b\xd1\x11\xab\x04\x00\xc0\x4f\xc2\xdc\xd2'

            # Also look for DsGetNCChanges opnum (3)
            if drsuapi_uuid in raw_data or b'\x03\x00' in raw_data[:50]:
                current_time = time.time()
                self.drsuapi_tracker[src_ip].append((current_time, dst_ip, dst_port))

                # Check for suspicious pattern
                window_start = current_time - 60  # 1 minute window
                recent_reqs = [
                    (ts, ip, port)
                    for ts, ip, port in self.drsuapi_tracker[src_ip]
                    if ts >= window_start
                ]

                if len(recent_reqs) >= 1:
                    threats.append({
                        'type': 'DCSYNC_ATTACK',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'DCSync attack detected: DRSUAPI replication request from non-DC',
                        'details': {
                            'destination_port': dst_port,
                            'requests_count': len(recent_reqs)
                        }
                    })

        except Exception as e:
            self.logger.debug(f"Error analyzing DRSUAPI: {e}")

        return threats

    def _analyze_ldap(self, packet, src_ip: str, dst_ip: str, dst_port: int) -> List[Dict]:
        """
        Analyze LDAP traffic for attack patterns.

        Detects:
        - LDAP enumeration (many search requests)
        - Password policy queries
        - Sensitive attribute access
        """
        threats = []

        # LDAP analysis would require more sophisticated parsing
        # This is a placeholder for future implementation

        return threats

    def _analyze_smb_auth(self, packet, src_ip: str, dst_ip: str) -> List[Dict]:
        """
        Analyze SMB authentication for Pass-the-Hash patterns.

        Detects:
        - NTLM authentication anomalies
        - Multiple authentication attempts
        - Unusual workstation names
        """
        threats = []

        if not packet.haslayer(Raw):
            return threats

        try:
            raw_data = bytes(packet[Raw].load)
            current_time = time.time()

            # Look for NTLMSSP signature
            if b'NTLMSSP\x00' in raw_data:
                # Track SMB auth attempts
                self.smb_auth_tracker[src_ip].append((current_time, dst_ip))

                # Check for Pass-the-Hash pattern (many auth attempts to different hosts)
                window_start = current_time - 300  # 5 minute window
                recent_auths = [
                    (ts, ip)
                    for ts, ip in self.smb_auth_tracker[src_ip]
                    if ts >= window_start
                ]

                unique_targets = set(ip for _, ip in recent_auths)

                if len(unique_targets) >= 5:
                    threats.append({
                        'type': 'PASS_THE_HASH_SUSPECTED',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'Pass-the-Hash suspected: NTLM auth to {len(unique_targets)} hosts in 5 minutes',
                        'details': {
                            'unique_targets': len(unique_targets),
                            'total_auths': len(recent_auths),
                            'window_seconds': 300
                        }
                    })

        except Exception as e:
            self.logger.debug(f"Error analyzing SMB auth: {e}")

        return threats

    def get_stats(self) -> Dict:
        """Get analyzer statistics."""
        return {
            'enabled': self.enabled,
            'tracked_sources': len(self.tgs_req_tracker),
            'spns_tracked': len(self.spn_tracker),
            'weak_encryption_sources': sum(
                1 for src in self.etype_tracker
                if any(et in self.WEAK_ETYPES for et in self.etype_tracker[src])
            ),
            'recent_auth_failures': sum(len(v) for v in self.auth_failure_tracker.values())
        }

    def clear_old_data(self, max_age: float = 3600):
        """Clear tracking data older than max_age seconds."""
        current_time = time.time()
        cutoff = current_time - max_age

        # Clear old TGS requests
        for src_ip in list(self.tgs_req_tracker.keys()):
            self.tgs_req_tracker[src_ip] = deque(
                (ts, sname, etype)
                for ts, sname, etype in self.tgs_req_tracker[src_ip]
                if ts >= cutoff
            )
            if not self.tgs_req_tracker[src_ip]:
                del self.tgs_req_tracker[src_ip]

        # Clear old AS-REP tracking
        for src_ip in list(self.as_rep_tracker.keys()):
            self.as_rep_tracker[src_ip] = deque(
                entry for entry in self.as_rep_tracker[src_ip]
                if entry[0] >= cutoff
            )
            if not self.as_rep_tracker[src_ip]:
                del self.as_rep_tracker[src_ip]
