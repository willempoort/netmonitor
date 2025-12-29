# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Protocol Deep Parsing Module

Provides deep packet inspection for:
- SMB/CIFS protocol (file sharing, authentication)
- LDAP protocol (directory queries)
- RPC/DCERPC (remote procedure calls)

Detects attack patterns:
- SMB enumeration and relay attacks
- LDAP reconnaissance
- Sensitive attribute access
- Unusual command sequences
"""

import logging
import struct
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import IntEnum

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


class SMBCommand(IntEnum):
    """SMB/SMB2 command codes."""
    # SMB1 commands
    SMB1_NEGOTIATE = 0x72
    SMB1_SESSION_SETUP = 0x73
    SMB1_LOGOFF = 0x74
    SMB1_TREE_CONNECT = 0x75
    SMB1_TREE_DISCONNECT = 0x71
    SMB1_CREATE = 0xa2
    SMB1_CLOSE = 0x04
    SMB1_READ = 0x2e
    SMB1_WRITE = 0x2f
    SMB1_TRANS = 0x25
    SMB1_TRANS2 = 0x32

    # SMB2/3 commands
    SMB2_NEGOTIATE = 0x0000
    SMB2_SESSION_SETUP = 0x0001
    SMB2_LOGOFF = 0x0002
    SMB2_TREE_CONNECT = 0x0003
    SMB2_TREE_DISCONNECT = 0x0004
    SMB2_CREATE = 0x0005
    SMB2_CLOSE = 0x0006
    SMB2_FLUSH = 0x0007
    SMB2_READ = 0x0008
    SMB2_WRITE = 0x0009
    SMB2_IOCTL = 0x000b
    SMB2_QUERY_DIRECTORY = 0x000e
    SMB2_CHANGE_NOTIFY = 0x000f
    SMB2_QUERY_INFO = 0x0010
    SMB2_SET_INFO = 0x0011


class LDAPOperation(IntEnum):
    """LDAP operation codes."""
    BIND_REQUEST = 0
    BIND_RESPONSE = 1
    UNBIND_REQUEST = 2
    SEARCH_REQUEST = 3
    SEARCH_RESULT_ENTRY = 4
    SEARCH_RESULT_DONE = 5
    MODIFY_REQUEST = 6
    MODIFY_RESPONSE = 7
    ADD_REQUEST = 8
    ADD_RESPONSE = 9
    DELETE_REQUEST = 10
    DELETE_RESPONSE = 11
    MODIFY_DN_REQUEST = 12
    MODIFY_DN_RESPONSE = 13
    COMPARE_REQUEST = 14
    COMPARE_RESPONSE = 15
    ABANDON_REQUEST = 16
    SEARCH_RESULT_REFERENCE = 19
    EXTENDED_REQUEST = 23
    EXTENDED_RESPONSE = 24


class ProtocolParser:
    """
    Deep protocol parser for SMB and LDAP traffic.
    """

    # SMB signature
    SMB1_SIGNATURE = b'\xffSMB'
    SMB2_SIGNATURE = b'\xfeSMB'

    # Sensitive LDAP attributes to monitor
    SENSITIVE_LDAP_ATTRS = {
        'userpassword', 'unicodepwd', 'ntpasswordhash', 'lmpasswordhash',
        'supplementalcredentials', 'msds-managedpasswordid',
        'msds-managedpassword', 'msds-groupmsamembership',
        'serviceprincipalname', 'msds-allowedtodelegateto',
        'msds-allowedtoactonbehalfofotheridentity', 'sidhistory',
        'admincount', 'member', 'memberof', 'primarygroupid',
        'objectsid', 'objectguid'
    }

    # Sensitive LDAP search bases
    SENSITIVE_LDAP_BASES = {
        'cn=configuration', 'cn=schema', 'cn=system',
        'cn=builtin', 'cn=ntds quotas', 'cn=infrastructure'
    }

    # Administrative shares
    ADMIN_SHARES = {'c$', 'admin$', 'ipc$', 'd$', 'e$', 'print$', 'sysvol', 'netlogon'}

    # SMB ports
    SMB_PORTS = {445, 139}

    # LDAP ports
    LDAP_PORTS = {389, 636, 3268, 3269}

    def __init__(self, config: dict = None, db_manager=None):
        self.config = config or {}
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.ProtocolParser')

        # Configuration
        proto_config = self.config.get('thresholds', {}).get('protocol_parsing', {})
        self.enabled = proto_config.get('enabled', True)

        # SMB tracking
        self.smb_sessions: Dict[str, Dict] = {}  # (src, dst) -> session info
        self.smb_share_access: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.smb_file_access: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self.smb_enum_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # LDAP tracking
        self.ldap_sessions: Dict[str, Dict] = {}
        self.ldap_query_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.ldap_attr_tracker: Dict[str, Set] = defaultdict(set)

        # Statistics
        self.stats = {
            'smb_packets': 0,
            'smb1_packets': 0,
            'smb2_packets': 0,
            'ldap_packets': 0,
            'admin_share_access': 0,
            'sensitive_ldap_queries': 0
        }

        self.logger.info("ProtocolParser initialized for SMB/LDAP deep inspection")

    def analyze_packet(self, packet) -> List[Dict]:
        """
        Analyze packet for SMB/LDAP content.

        Returns:
            List of threat dictionaries
        """
        if not self.enabled:
            return []

        threats = []

        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return threats

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        if not packet.haslayer(Raw):
            return threats

        raw_data = bytes(packet[Raw].load)

        # SMB analysis
        if dst_port in self.SMB_PORTS or src_port in self.SMB_PORTS:
            smb_threats = self._analyze_smb(raw_data, src_ip, dst_ip, dst_port)
            threats.extend(smb_threats)

        # LDAP analysis
        if dst_port in self.LDAP_PORTS or src_port in self.LDAP_PORTS:
            ldap_threats = self._analyze_ldap(raw_data, src_ip, dst_ip, dst_port)
            threats.extend(ldap_threats)

        return threats

    def _analyze_smb(self, data: bytes, src_ip: str, dst_ip: str, dst_port: int) -> List[Dict]:
        """Analyze SMB packet."""
        threats = []

        if len(data) < 8:
            return threats

        try:
            # Check SMB signature
            if data[4:8] == self.SMB2_SIGNATURE:
                threats.extend(self._parse_smb2(data, src_ip, dst_ip))
            elif data[4:8] == self.SMB1_SIGNATURE:
                threats.extend(self._parse_smb1(data, src_ip, dst_ip))
            # Also check without NetBIOS header
            elif data[0:4] == self.SMB2_SIGNATURE:
                threats.extend(self._parse_smb2(data, src_ip, dst_ip, offset=0))
            elif data[0:4] == self.SMB1_SIGNATURE:
                threats.extend(self._parse_smb1(data, src_ip, dst_ip, offset=0))

        except Exception as e:
            self.logger.debug(f"SMB parse error: {e}")

        return threats

    def _parse_smb2(self, data: bytes, src_ip: str, dst_ip: str, offset: int = 4) -> List[Dict]:
        """Parse SMB2/3 packet."""
        threats = []
        self.stats['smb_packets'] += 1
        self.stats['smb2_packets'] += 1

        try:
            # SMB2 header structure (at least 64 bytes)
            if len(data) < offset + 64:
                return threats

            # Parse header
            header_start = offset
            signature = data[header_start:header_start+4]
            if signature != self.SMB2_SIGNATURE:
                return threats

            header_length = struct.unpack('<H', data[header_start+4:header_start+6])[0]
            command = struct.unpack('<H', data[header_start+12:header_start+14])[0]

            current_time = time.time()
            session_key = f"{src_ip}:{dst_ip}"

            # Track session
            if session_key not in self.smb_sessions:
                self.smb_sessions[session_key] = {
                    'start_time': current_time,
                    'commands': [],
                    'shares': set(),
                    'files': set()
                }

            session = self.smb_sessions[session_key]
            session['commands'].append((current_time, command))

            # Analyze specific commands
            if command == SMBCommand.SMB2_TREE_CONNECT:
                share_threat = self._analyze_tree_connect(data, header_start + 64, src_ip, dst_ip, current_time)
                if share_threat:
                    threats.append(share_threat)

            elif command == SMBCommand.SMB2_CREATE:
                file_threat = self._analyze_file_create(data, header_start + 64, src_ip, dst_ip, current_time)
                if file_threat:
                    threats.append(file_threat)

            elif command == SMBCommand.SMB2_QUERY_DIRECTORY:
                enum_threat = self._detect_smb_enumeration(src_ip, dst_ip, current_time)
                if enum_threat:
                    threats.append(enum_threat)

            # Check for unusual command patterns
            pattern_threat = self._detect_smb_attack_pattern(session, src_ip, dst_ip)
            if pattern_threat:
                threats.append(pattern_threat)

        except Exception as e:
            self.logger.debug(f"SMB2 parse error: {e}")

        return threats

    def _parse_smb1(self, data: bytes, src_ip: str, dst_ip: str, offset: int = 4) -> List[Dict]:
        """Parse SMB1 packet."""
        threats = []
        self.stats['smb_packets'] += 1
        self.stats['smb1_packets'] += 1

        try:
            # SMB1 header (32 bytes minimum)
            if len(data) < offset + 32:
                return threats

            header_start = offset
            signature = data[header_start:header_start+4]
            if signature != self.SMB1_SIGNATURE:
                return threats

            command = data[header_start + 4]
            current_time = time.time()

            # SMB1 is deprecated - flag its use
            if self.config.get('thresholds', {}).get('protocol_parsing', {}).get('flag_smb1', True):
                threats.append({
                    'type': 'SMB1_USAGE_DETECTED',
                    'severity': 'LOW',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': f'SMB1 protocol usage detected (deprecated and insecure)',
                    'details': {
                        'command': command,
                        'recommendation': 'Disable SMB1 and use SMB2/3'
                    }
                })

        except Exception as e:
            self.logger.debug(f"SMB1 parse error: {e}")

        return threats

    def _analyze_tree_connect(self, data: bytes, offset: int, src_ip: str, dst_ip: str,
                              current_time: float) -> Optional[Dict]:
        """Analyze SMB2 TREE_CONNECT request for admin share access."""
        try:
            # Try to extract share path
            # Tree connect structure varies, look for share name patterns
            share_path = self._extract_share_path(data[offset:])

            if share_path:
                share_name = share_path.lower().split('\\')[-1]

                # Track share access
                self.smb_share_access[src_ip].append((current_time, dst_ip, share_name))

                # Check for admin share access
                if share_name in self.ADMIN_SHARES:
                    self.stats['admin_share_access'] += 1

                    return {
                        'type': 'SMB_ADMIN_SHARE_ACCESS',
                        'severity': 'MEDIUM' if share_name == 'ipc$' else 'HIGH',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'Access to administrative share: {share_path}',
                        'details': {
                            'share_name': share_name,
                            'full_path': share_path
                        }
                    }

        except Exception as e:
            self.logger.debug(f"Tree connect parse error: {e}")

        return None

    def _extract_share_path(self, data: bytes) -> Optional[str]:
        """Extract share path from SMB data."""
        try:
            # Look for UNC path pattern (\\server\share)
            for encoding in ['utf-16-le', 'utf-8']:
                try:
                    text = data.decode(encoding, errors='ignore')
                    if '\\\\' in text:
                        # Find the path
                        start = text.find('\\\\')
                        end = text.find('\x00', start)
                        if end == -1:
                            end = min(len(text), start + 200)
                        path = text[start:end].strip('\x00')
                        if len(path) > 4:
                            return path
                except:
                    continue
        except:
            pass
        return None

    def _analyze_file_create(self, data: bytes, offset: int, src_ip: str, dst_ip: str,
                             current_time: float) -> Optional[Dict]:
        """Analyze SMB2 CREATE request for sensitive file access."""
        try:
            # Extract filename from CREATE request
            filename = self._extract_filename(data[offset:])

            if filename:
                self.smb_file_access[src_ip].append((current_time, dst_ip, filename))

                # Check for sensitive file patterns
                filename_lower = filename.lower()

                # NTDS.dit access
                if 'ntds.dit' in filename_lower:
                    return {
                        'type': 'NTDS_DIT_ACCESS',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'Access to NTDS.dit (Active Directory database)',
                        'details': {'filename': filename}
                    }

                # SAM/SYSTEM/SECURITY registry hive access
                if any(x in filename_lower for x in ['system32\\config\\sam',
                                                      'system32\\config\\system',
                                                      'system32\\config\\security']):
                    return {
                        'type': 'REGISTRY_HIVE_ACCESS',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'Access to sensitive registry hive: {filename}',
                        'details': {'filename': filename}
                    }

                # LSASS dump access
                if 'lsass' in filename_lower and '.dmp' in filename_lower:
                    return {
                        'type': 'LSASS_DUMP_ACCESS',
                        'severity': 'CRITICAL',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'Access to LSASS memory dump',
                        'details': {'filename': filename}
                    }

        except Exception as e:
            self.logger.debug(f"File create parse error: {e}")

        return None

    def _extract_filename(self, data: bytes) -> Optional[str]:
        """Extract filename from SMB CREATE data."""
        try:
            # Look for filename in UTF-16-LE
            text = data.decode('utf-16-le', errors='ignore')
            # Clean up and find paths
            for part in text.split('\x00'):
                part = part.strip()
                if len(part) > 3 and ('\\' in part or '/' in part or '.' in part):
                    return part
        except:
            pass
        return None

    def _detect_smb_enumeration(self, src_ip: str, dst_ip: str, current_time: float) -> Optional[Dict]:
        """Detect SMB share/file enumeration patterns."""
        self.smb_enum_tracker[src_ip].append((current_time, dst_ip))

        # Count recent enum operations
        window_start = current_time - 60  # 1 minute window
        recent = [t for t, _ in self.smb_enum_tracker[src_ip] if t >= window_start]

        if len(recent) >= 20:  # 20 directory queries in 1 minute
            return {
                'type': 'SMB_ENUMERATION',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'SMB enumeration detected: {len(recent)} directory queries in 1 minute',
                'details': {
                    'query_count': len(recent),
                    'window_seconds': 60
                }
            }

        return None

    def _detect_smb_attack_pattern(self, session: Dict, src_ip: str, dst_ip: str) -> Optional[Dict]:
        """Detect SMB attack command sequences."""
        if len(session['commands']) < 5:
            return None

        # Get recent commands
        recent_cmds = [cmd for _, cmd in session['commands'][-20:]]

        # Look for suspicious patterns
        # Pattern: Multiple tree connects followed by file access
        tree_connects = sum(1 for c in recent_cmds if c == SMBCommand.SMB2_TREE_CONNECT)
        creates = sum(1 for c in recent_cmds if c == SMBCommand.SMB2_CREATE)

        if tree_connects >= 5 and creates >= 10:
            return {
                'type': 'SMB_LATERAL_MOVEMENT_PATTERN',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'SMB lateral movement pattern: {tree_connects} share connections, {creates} file operations',
                'details': {
                    'tree_connects': tree_connects,
                    'file_creates': creates
                }
            }

        return None

    def _analyze_ldap(self, data: bytes, src_ip: str, dst_ip: str, dst_port: int) -> List[Dict]:
        """Analyze LDAP packet."""
        threats = []
        self.stats['ldap_packets'] += 1

        try:
            # LDAP uses BER encoding
            if len(data) < 10:
                return threats

            current_time = time.time()

            # Parse LDAP message
            parsed = self._parse_ldap_message(data)
            if not parsed:
                return threats

            operation = parsed.get('operation')
            message_id = parsed.get('message_id', 0)

            # Track session
            session_key = f"{src_ip}:{dst_ip}"
            if session_key not in self.ldap_sessions:
                self.ldap_sessions[session_key] = {
                    'start_time': current_time,
                    'operations': [],
                    'search_bases': set(),
                    'requested_attrs': set()
                }

            session = self.ldap_sessions[session_key]

            # Analyze search requests
            if operation == LDAPOperation.SEARCH_REQUEST:
                search_base = parsed.get('base_dn', '')
                search_filter = parsed.get('filter', '')
                attributes = parsed.get('attributes', [])

                session['operations'].append((current_time, 'search', search_base))

                # Track requested attributes
                self.ldap_query_tracker[src_ip].append((current_time, search_base, attributes))

                for attr in attributes:
                    self.ldap_attr_tracker[src_ip].add(attr.lower())

                # Check for sensitive attribute access
                sensitive_requested = [a for a in attributes if a.lower() in self.SENSITIVE_LDAP_ATTRS]
                if sensitive_requested:
                    self.stats['sensitive_ldap_queries'] += 1
                    threats.append({
                        'type': 'LDAP_SENSITIVE_ATTR_QUERY',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'LDAP query for sensitive attributes: {", ".join(sensitive_requested)}',
                        'details': {
                            'base_dn': search_base,
                            'sensitive_attrs': sensitive_requested,
                            'all_attrs': attributes
                        }
                    })

                # Check for sensitive base access
                base_lower = search_base.lower()
                for sensitive_base in self.SENSITIVE_LDAP_BASES:
                    if sensitive_base in base_lower:
                        threats.append({
                            'type': 'LDAP_SENSITIVE_BASE_QUERY',
                            'severity': 'MEDIUM',
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'description': f'LDAP query on sensitive base: {search_base}',
                            'details': {
                                'base_dn': search_base,
                                'filter': search_filter
                            }
                        })
                        break

                # Check for enumeration patterns
                enum_threat = self._detect_ldap_enumeration(src_ip, dst_ip, current_time)
                if enum_threat:
                    threats.append(enum_threat)

                # Check for specific attack patterns
                attack_threat = self._detect_ldap_attack_pattern(search_filter, search_base, src_ip, dst_ip)
                if attack_threat:
                    threats.append(attack_threat)

        except Exception as e:
            self.logger.debug(f"LDAP parse error: {e}")

        return threats

    def _parse_ldap_message(self, data: bytes) -> Optional[Dict]:
        """Parse LDAP BER-encoded message."""
        try:
            result = {}
            offset = 0

            # LDAP message starts with SEQUENCE tag (0x30)
            if data[offset] != 0x30:
                return None

            offset += 1

            # Parse length
            length, offset = self._parse_ber_length(data, offset)
            if length is None:
                return None

            # Parse message ID (INTEGER)
            if data[offset] != 0x02:  # INTEGER tag
                return None
            offset += 1

            id_length, offset = self._parse_ber_length(data, offset)
            if id_length:
                result['message_id'] = int.from_bytes(data[offset:offset+id_length], 'big')
                offset += id_length

            # Parse operation (context-specific tag)
            if offset >= len(data):
                return None

            op_tag = data[offset]
            operation = op_tag & 0x1f  # Get operation from tag
            result['operation'] = operation
            offset += 1

            op_length, offset = self._parse_ber_length(data, offset)

            # Parse operation-specific data
            if operation == LDAPOperation.SEARCH_REQUEST and op_length:
                # Parse search request
                search_data = data[offset:offset+op_length]
                result.update(self._parse_search_request(search_data))

            return result

        except Exception as e:
            self.logger.debug(f"LDAP parse error: {e}")
            return None

    def _parse_ber_length(self, data: bytes, offset: int) -> Tuple[Optional[int], int]:
        """Parse BER length encoding."""
        try:
            if offset >= len(data):
                return None, offset

            length_byte = data[offset]
            offset += 1

            if length_byte & 0x80 == 0:
                # Short form
                return length_byte, offset
            else:
                # Long form
                num_octets = length_byte & 0x7f
                if num_octets == 0 or offset + num_octets > len(data):
                    return None, offset
                length = int.from_bytes(data[offset:offset+num_octets], 'big')
                return length, offset + num_octets

        except:
            return None, offset

    def _parse_search_request(self, data: bytes) -> Dict:
        """Parse LDAP search request."""
        result = {'base_dn': '', 'filter': '', 'attributes': []}

        try:
            offset = 0

            # Parse base DN (OCTET STRING)
            if data[offset] == 0x04:
                offset += 1
                length, offset = self._parse_ber_length(data, offset)
                if length:
                    result['base_dn'] = data[offset:offset+length].decode('utf-8', errors='ignore')
                    offset += length

            # Skip scope, deref, sizelimit, timelimit, typesonly
            for _ in range(5):
                if offset >= len(data):
                    break
                offset += 1  # tag
                length, offset = self._parse_ber_length(data, offset)
                if length:
                    offset += length

            # Parse filter (complex, simplified extraction)
            if offset < len(data):
                filter_data = data[offset:]
                result['filter'] = self._extract_filter_string(filter_data)

            # Try to extract requested attributes
            result['attributes'] = self._extract_ldap_attributes(data)

        except Exception as e:
            self.logger.debug(f"Search request parse error: {e}")

        return result

    def _extract_filter_string(self, data: bytes) -> str:
        """Extract readable filter string from LDAP filter data."""
        try:
            # Simple extraction of string values from filter
            text = data.decode('utf-8', errors='ignore')
            # Clean up and extract recognizable parts
            parts = []
            for part in text.split('\x00'):
                part = part.strip()
                if len(part) > 2 and part.isalnum() or '=' in part:
                    parts.append(part)
            return ' '.join(parts[:10])  # First 10 parts
        except:
            return ''

    def _extract_ldap_attributes(self, data: bytes) -> List[str]:
        """Extract requested attribute names from LDAP data."""
        attributes = []
        try:
            # Look for attribute names (typically ASCII strings)
            text = data.decode('utf-8', errors='ignore')
            # Common attribute patterns
            common_attrs = [
                'objectclass', 'cn', 'sn', 'givenname', 'displayname',
                'samaccountname', 'userprincipalname', 'mail', 'member',
                'memberof', 'distinguishedname', 'objectsid', 'objectguid',
                'serviceprincipalname', 'admincount', 'useraccountcontrol',
                'lastlogon', 'pwdlastset', 'accountexpires', 'description',
                'userpassword', 'unicodepwd', 'ntpasswordhash'
            ]

            text_lower = text.lower()
            for attr in common_attrs:
                if attr in text_lower:
                    attributes.append(attr)

        except:
            pass
        return attributes

    def _detect_ldap_enumeration(self, src_ip: str, dst_ip: str, current_time: float) -> Optional[Dict]:
        """Detect LDAP enumeration patterns."""
        window_start = current_time - 60  # 1 minute window

        recent_queries = [
            (ts, base, attrs)
            for ts, base, attrs in self.ldap_query_tracker[src_ip]
            if ts >= window_start
        ]

        if len(recent_queries) >= 20:
            unique_bases = set(base for _, base, _ in recent_queries)
            all_attrs = self.ldap_attr_tracker[src_ip]

            return {
                'type': 'LDAP_ENUMERATION',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'LDAP enumeration: {len(recent_queries)} queries to {len(unique_bases)} bases in 1 minute',
                'details': {
                    'query_count': len(recent_queries),
                    'unique_bases': len(unique_bases),
                    'unique_attrs': len(all_attrs),
                    'window_seconds': 60
                }
            }

        return None

    def _detect_ldap_attack_pattern(self, search_filter: str, base_dn: str,
                                     src_ip: str, dst_ip: str) -> Optional[Dict]:
        """Detect specific LDAP attack patterns."""
        filter_lower = search_filter.lower()
        base_lower = base_dn.lower()

        # Kerberoasting reconnaissance (SPN enumeration)
        if 'serviceprincipalname' in filter_lower and 'serviceprincipalname' not in base_lower:
            return {
                'type': 'LDAP_SPN_ENUMERATION',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': 'LDAP SPN enumeration (Kerberoasting reconnaissance)',
                'details': {
                    'filter': search_filter,
                    'base_dn': base_dn
                }
            }

        # AS-REP roasting reconnaissance (accounts without pre-auth)
        if 'useraccountcontrol' in filter_lower and '4194304' in search_filter:
            return {
                'type': 'LDAP_ASREP_ENUMERATION',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': 'LDAP enumeration for AS-REP roastable accounts',
                'details': {
                    'filter': search_filter,
                    'base_dn': base_dn
                }
            }

        # Domain admin enumeration
        if 'admincount=1' in filter_lower or 'domain admins' in filter_lower:
            return {
                'type': 'LDAP_ADMIN_ENUMERATION',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': 'LDAP enumeration for privileged accounts',
                'details': {
                    'filter': search_filter,
                    'base_dn': base_dn
                }
            }

        return None

    def get_stats(self) -> Dict:
        """Get parser statistics."""
        return {
            'enabled': self.enabled,
            **self.stats,
            'active_smb_sessions': len(self.smb_sessions),
            'active_ldap_sessions': len(self.ldap_sessions),
            'tracked_sources': len(self.smb_share_access) + len(self.ldap_query_tracker)
        }

    def clear_old_data(self, max_age: float = 3600):
        """Clear tracking data older than max_age seconds."""
        current_time = time.time()
        cutoff = current_time - max_age

        # Clear old SMB sessions
        for key in list(self.smb_sessions.keys()):
            session = self.smb_sessions[key]
            if session['commands']:
                last_time = session['commands'][-1][0]
                if last_time < cutoff:
                    del self.smb_sessions[key]

        # Clear old LDAP sessions
        for key in list(self.ldap_sessions.keys()):
            session = self.ldap_sessions[key]
            if session['operations']:
                last_time = session['operations'][-1][0]
                if last_time < cutoff:
                    del self.ldap_sessions[key]
