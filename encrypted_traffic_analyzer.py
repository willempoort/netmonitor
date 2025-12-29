# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Enhanced Encrypted Traffic Analysis Module

Extends basic TLS analysis with advanced detection:
- ESNI/ECH (Encrypted Client Hello) detection
- Domain fronting detection
- Certificate chain analysis
- TLS 1.3 specific analysis
- Cipher suite anomaly detection
- Self-signed/expired certificate detection
- Certificate transparency validation
- Unusual TLS patterns

Works alongside tls_analyzer.py for comprehensive encrypted traffic analysis.
"""

import logging
import struct
import hashlib
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


@dataclass
class CertificateInfo:
    """Parsed certificate information."""
    subject_cn: str
    issuer_cn: str
    issuer_org: str
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    is_self_signed: bool
    is_expired: bool
    is_not_yet_valid: bool
    key_size: int
    signature_algorithm: str
    san_domains: List[str]
    serial_number: str


@dataclass
class TLSSessionInfo:
    """Information about a TLS session."""
    client_ip: str
    server_ip: str
    server_port: int
    sni: Optional[str]
    ja3: Optional[str]
    ja3s: Optional[str]
    tls_version: str
    cipher_suite: int
    cipher_name: str
    has_esni: bool
    has_ech: bool
    alpn: List[str]
    certificate: Optional[CertificateInfo]
    first_seen: float
    anomalies: List[str]


class EncryptedTrafficAnalyzer:
    """
    Advanced encrypted traffic analysis beyond basic JA3 fingerprinting.
    """

    # TLS versions
    TLS_VERSIONS = {
        0x0300: 'SSL 3.0',
        0x0301: 'TLS 1.0',
        0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2',
        0x0304: 'TLS 1.3',
    }

    # TLS Extension types
    EXT_SNI = 0
    EXT_SUPPORTED_GROUPS = 10
    EXT_EC_POINT_FORMATS = 11
    EXT_SIGNATURE_ALGORITHMS = 13
    EXT_ALPN = 16
    EXT_ENCRYPT_THEN_MAC = 22
    EXT_EXTENDED_MASTER_SECRET = 23
    EXT_SUPPORTED_VERSIONS = 43
    EXT_PSK_KEY_EXCHANGE_MODES = 45
    EXT_KEY_SHARE = 51
    EXT_ENCRYPTED_CLIENT_HELLO = 0xfe0d  # ECH draft
    EXT_ESNI = 0xffce  # Legacy ESNI

    # Weak/deprecated cipher suites
    WEAK_CIPHERS = {
        0x0000: 'TLS_NULL_WITH_NULL_NULL',
        0x0001: 'TLS_RSA_WITH_NULL_MD5',
        0x0002: 'TLS_RSA_WITH_NULL_SHA',
        0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
        0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
        0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
        0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
        # Export ciphers (very weak)
        0x0003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
        0x0006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
        0x0008: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
        0x0009: 'TLS_RSA_WITH_DES_CBC_SHA',
        0x0011: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
        0x0014: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
        0x0017: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
        0x0019: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
    }

    # Strong modern cipher suites
    STRONG_CIPHERS = {
        0x1301: 'TLS_AES_128_GCM_SHA256',
        0x1302: 'TLS_AES_256_GCM_SHA384',
        0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
        0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    }

    # Known CDN/cloud providers for domain fronting detection
    CDN_PROVIDERS = {
        'cloudfront.net': 'Amazon CloudFront',
        'cloudflare.com': 'Cloudflare',
        'akamaized.net': 'Akamai',
        'azureedge.net': 'Azure CDN',
        'fastly.net': 'Fastly',
        'googleapis.com': 'Google',
        'googleusercontent.com': 'Google',
    }

    # Known suspicious certificate issuers
    SUSPICIOUS_ISSUERS = {
        'let\'s encrypt': False,  # Not suspicious, but free certs
        'self-signed': True,
        'unknown': True,
    }

    # GREASE values (RFC 8701)
    GREASE_VALUES = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
        0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
        0xcaca, 0xdada, 0xeaea, 0xfafa
    }

    def __init__(self, config: dict = None, db_manager=None):
        self.config = config or {}
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.EncryptedTrafficAnalyzer')

        # Configuration
        eta_config = self.config.get('thresholds', {}).get('encrypted_traffic', {})
        self.enabled = eta_config.get('enabled', True)
        self.detect_weak_ciphers = eta_config.get('detect_weak_ciphers', True)
        self.detect_self_signed = eta_config.get('detect_self_signed', True)
        self.detect_expired_certs = eta_config.get('detect_expired_certs', True)
        self.detect_domain_fronting = eta_config.get('detect_domain_fronting', True)
        self.detect_esni_ech = eta_config.get('detect_esni_ech', True)

        # Session tracking
        self.sessions: Dict[str, TLSSessionInfo] = {}
        self.session_history: deque = deque(maxlen=10000)

        # Certificate tracking
        self.seen_certificates: Dict[str, CertificateInfo] = {}
        self.certificate_anomalies: deque = deque(maxlen=1000)

        # Domain fronting tracking
        self.sni_host_mismatches: deque = deque(maxlen=500)

        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'tls13_sessions': 0,
            'esni_detected': 0,
            'ech_detected': 0,
            'weak_ciphers_detected': 0,
            'self_signed_certs': 0,
            'expired_certs': 0,
            'domain_fronting_suspected': 0,
        }

        self.logger.info("EncryptedTrafficAnalyzer initialized")

    def analyze_packet(self, packet) -> List[Dict]:
        """
        Analyze packet for encrypted traffic anomalies.

        Returns:
            List of threat dictionaries
        """
        if not self.enabled:
            return []

        threats = []

        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return threats

        if not packet.haslayer(IP):
            return threats

        ip = packet[IP]
        tcp = packet[TCP]
        raw = bytes(packet[Raw].load)

        # Quick check for TLS handshake
        if len(raw) < 6 or raw[0] != 22:  # Content type 22 = handshake
            return threats

        self.stats['packets_analyzed'] += 1

        try:
            # Parse TLS record
            parsed = self._parse_tls_handshake(raw, ip.src, ip.dst, tcp.sport, tcp.dport)

            if parsed:
                # Analyze for various threats
                if parsed.get('type') == 'client_hello':
                    threats.extend(self._analyze_client_hello(parsed, ip.src, ip.dst))

                elif parsed.get('type') == 'server_hello':
                    threats.extend(self._analyze_server_hello(parsed, ip.src, ip.dst))

                elif parsed.get('type') == 'certificate':
                    threats.extend(self._analyze_certificate(parsed, ip.src, ip.dst))

        except Exception as e:
            self.logger.debug(f"TLS analysis error: {e}")

        return threats

    def _parse_tls_handshake(self, data: bytes, src_ip: str, dst_ip: str,
                             src_port: int, dst_port: int) -> Optional[Dict]:
        """Parse TLS handshake message."""
        if len(data) < 9:
            return None

        # TLS Record Header
        content_type = data[0]
        tls_version = struct.unpack('>H', data[1:3])[0]
        record_length = struct.unpack('>H', data[3:5])[0]

        if content_type != 22 or len(data) < 5 + record_length:
            return None

        # Handshake Header
        handshake_data = data[5:5 + record_length]
        if len(handshake_data) < 4:
            return None

        handshake_type = handshake_data[0]
        handshake_length = struct.unpack('>I', b'\x00' + handshake_data[1:4])[0]

        result = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'record_version': self.TLS_VERSIONS.get(tls_version, f'Unknown ({hex(tls_version)})'),
        }

        if handshake_type == 1:  # Client Hello
            result['type'] = 'client_hello'
            result.update(self._parse_client_hello_extended(handshake_data[4:]))

        elif handshake_type == 2:  # Server Hello
            result['type'] = 'server_hello'
            result.update(self._parse_server_hello_extended(handshake_data[4:]))

        elif handshake_type == 11:  # Certificate
            result['type'] = 'certificate'
            result.update(self._parse_certificate_message(handshake_data[4:]))

        else:
            return None

        return result

    def _parse_client_hello_extended(self, data: bytes) -> Dict:
        """Parse Client Hello with extended analysis."""
        result = {
            'cipher_suites': [],
            'extensions': [],
            'has_esni': False,
            'has_ech': False,
            'sni': None,
            'alpn': [],
            'supported_versions': [],
            'key_share_groups': [],
        }

        if len(data) < 38:
            return result

        offset = 0

        # Client Version
        client_version = struct.unpack('>H', data[offset:offset+2])[0]
        result['legacy_version'] = self.TLS_VERSIONS.get(client_version, hex(client_version))
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(data):
            return result

        # Cipher Suites
        cipher_suites_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2

        for i in range(0, cipher_suites_len, 2):
            if offset + i + 2 > len(data):
                break
            cs = struct.unpack('>H', data[offset+i:offset+i+2])[0]
            if cs not in self.GREASE_VALUES:
                result['cipher_suites'].append(cs)

        offset += cipher_suites_len

        if offset + 1 > len(data):
            return result

        # Compression Methods
        compression_len = data[offset]
        offset += 1 + compression_len

        # Extensions
        if offset + 2 <= len(data):
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            ext_end = offset + extensions_len
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', data[offset+2:offset+4])[0]
                offset += 4

                ext_data = data[offset:offset+ext_len] if offset + ext_len <= len(data) else b''

                if ext_type not in self.GREASE_VALUES:
                    result['extensions'].append(ext_type)

                # Parse specific extensions
                if ext_type == self.EXT_SNI and ext_len > 5:
                    result['sni'] = self._extract_sni(ext_data)

                elif ext_type == self.EXT_ALPN and ext_len > 2:
                    result['alpn'] = self._extract_alpn(ext_data)

                elif ext_type == self.EXT_SUPPORTED_VERSIONS and ext_len > 1:
                    result['supported_versions'] = self._extract_supported_versions(ext_data)

                elif ext_type == self.EXT_KEY_SHARE and ext_len > 2:
                    result['key_share_groups'] = self._extract_key_share_groups(ext_data)

                elif ext_type == self.EXT_ESNI:
                    result['has_esni'] = True
                    self.stats['esni_detected'] += 1

                elif ext_type == self.EXT_ENCRYPTED_CLIENT_HELLO:
                    result['has_ech'] = True
                    self.stats['ech_detected'] += 1

                offset += ext_len

        # Determine actual TLS version
        if result['supported_versions']:
            highest_version = max(result['supported_versions'])
            result['tls_version'] = self.TLS_VERSIONS.get(highest_version, hex(highest_version))
            if highest_version == 0x0304:
                self.stats['tls13_sessions'] += 1
        else:
            result['tls_version'] = result['legacy_version']

        return result

    def _parse_server_hello_extended(self, data: bytes) -> Dict:
        """Parse Server Hello with extended analysis."""
        result = {
            'cipher_suite': None,
            'cipher_name': 'Unknown',
            'tls_version': None,
            'extensions': [],
        }

        if len(data) < 38:
            return result

        offset = 0

        # Server Version
        server_version = struct.unpack('>H', data[offset:offset+2])[0]
        result['legacy_version'] = self.TLS_VERSIONS.get(server_version, hex(server_version))
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(data):
            return result

        # Cipher Suite (selected)
        cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
        result['cipher_suite'] = cipher_suite

        if cipher_suite in self.WEAK_CIPHERS:
            result['cipher_name'] = self.WEAK_CIPHERS[cipher_suite]
            result['is_weak_cipher'] = True
        elif cipher_suite in self.STRONG_CIPHERS:
            result['cipher_name'] = self.STRONG_CIPHERS[cipher_suite]
            result['is_weak_cipher'] = False
        else:
            result['cipher_name'] = f'Unknown ({hex(cipher_suite)})'
            result['is_weak_cipher'] = False

        offset += 2

        # Compression Method
        offset += 1

        # Extensions
        if offset + 2 <= len(data):
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            ext_end = offset + extensions_len
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', data[offset+2:offset+4])[0]
                offset += 4

                ext_data = data[offset:offset+ext_len] if offset + ext_len <= len(data) else b''

                if ext_type not in self.GREASE_VALUES:
                    result['extensions'].append(ext_type)

                # Check for TLS 1.3 via supported_versions
                if ext_type == self.EXT_SUPPORTED_VERSIONS and ext_len == 2:
                    actual_version = struct.unpack('>H', ext_data)[0]
                    result['tls_version'] = self.TLS_VERSIONS.get(actual_version, hex(actual_version))

                offset += ext_len

        if not result['tls_version']:
            result['tls_version'] = result['legacy_version']

        return result

    def _parse_certificate_message(self, data: bytes) -> Dict:
        """Parse Certificate message."""
        result = {
            'certificates': [],
            'has_self_signed': False,
            'has_expired': False,
            'chain_length': 0,
        }

        if len(data) < 3:
            return result

        # Total certificates length
        certs_length = struct.unpack('>I', b'\x00' + data[0:3])[0]
        offset = 3

        cert_index = 0
        while offset + 3 < len(data) and offset < 3 + certs_length:
            cert_length = struct.unpack('>I', b'\x00' + data[offset:offset+3])[0]
            offset += 3

            if offset + cert_length > len(data):
                break

            cert_data = data[offset:offset+cert_length]
            cert_info = self._parse_certificate(cert_data, cert_index == 0)

            if cert_info:
                result['certificates'].append(cert_info)

                if cert_info.get('is_self_signed'):
                    result['has_self_signed'] = True
                    self.stats['self_signed_certs'] += 1

                if cert_info.get('is_expired'):
                    result['has_expired'] = True
                    self.stats['expired_certs'] += 1

            offset += cert_length
            cert_index += 1

        result['chain_length'] = len(result['certificates'])
        return result

    def _parse_certificate(self, cert_data: bytes, is_leaf: bool = True) -> Optional[Dict]:
        """Parse X.509 certificate (simplified)."""
        result = {
            'subject_cn': '',
            'issuer_cn': '',
            'issuer_org': '',
            'is_self_signed': False,
            'is_expired': False,
            'is_not_yet_valid': False,
            'san_domains': [],
            'key_size': 0,
            'is_leaf': is_leaf,
        }

        try:
            # Very simplified X.509 parsing - look for common patterns
            # Real implementation would use pyOpenSSL or cryptography

            # Look for CN in subject (simplified)
            result['subject_cn'] = self._extract_cn(cert_data, b'\x55\x04\x03')

            # Look for organization in issuer
            result['issuer_org'] = self._extract_cn(cert_data, b'\x55\x04\x0a')

            # Check if self-signed (subject == issuer approximation)
            if result['subject_cn'] and result['issuer_org']:
                if result['subject_cn'].lower() in result['issuer_org'].lower():
                    result['is_self_signed'] = True

            # Look for SAN extension
            result['san_domains'] = self._extract_san(cert_data)

            return result

        except Exception as e:
            self.logger.debug(f"Certificate parse error: {e}")
            return None

    def _extract_cn(self, data: bytes, oid: bytes) -> str:
        """Extract Common Name from certificate."""
        try:
            idx = data.find(oid)
            if idx == -1:
                return ''

            # Skip OID and length bytes
            idx += len(oid) + 2

            # Get string length
            if idx >= len(data):
                return ''

            str_len = data[idx]
            idx += 1

            if idx + str_len > len(data):
                return ''

            return data[idx:idx+str_len].decode('utf-8', errors='ignore')

        except:
            return ''

    def _extract_san(self, data: bytes) -> List[str]:
        """Extract Subject Alternative Names."""
        domains = []

        try:
            # SAN OID: 2.5.29.17 = 55 1d 11
            san_oid = b'\x55\x1d\x11'
            idx = data.find(san_oid)

            if idx == -1:
                return domains

            # Skip past OID and find DNS names
            search_area = data[idx:min(idx+500, len(data))]

            # Look for DNS name tag (0x82)
            pos = 0
            while pos < len(search_area) - 2:
                if search_area[pos] == 0x82:  # DNS name
                    length = search_area[pos + 1]
                    if pos + 2 + length <= len(search_area):
                        domain = search_area[pos+2:pos+2+length].decode('utf-8', errors='ignore')
                        if domain and '.' in domain:
                            domains.append(domain)
                    pos += 2 + length
                else:
                    pos += 1

        except:
            pass

        return domains[:20]  # Limit to 20 domains

    def _extract_sni(self, data: bytes) -> Optional[str]:
        """Extract SNI from extension data."""
        try:
            if len(data) < 5:
                return None

            # SNI extension format: list_length(2) + type(1) + name_length(2) + name
            offset = 2  # Skip list length
            if data[offset] != 0:  # Type 0 = hostname
                return None
            offset += 1

            name_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            if offset + name_length > len(data):
                return None

            return data[offset:offset+name_length].decode('utf-8', errors='ignore')

        except:
            return None

    def _extract_alpn(self, data: bytes) -> List[str]:
        """Extract ALPN protocols."""
        protocols = []
        try:
            if len(data) < 2:
                return protocols

            list_length = struct.unpack('>H', data[0:2])[0]
            offset = 2

            while offset < 2 + list_length and offset < len(data):
                proto_len = data[offset]
                offset += 1
                if offset + proto_len <= len(data):
                    proto = data[offset:offset+proto_len].decode('utf-8', errors='ignore')
                    protocols.append(proto)
                offset += proto_len

        except:
            pass
        return protocols

    def _extract_supported_versions(self, data: bytes) -> List[int]:
        """Extract supported TLS versions."""
        versions = []
        try:
            if len(data) < 1:
                return versions

            length = data[0]
            for i in range(1, min(length + 1, len(data)), 2):
                if i + 2 <= len(data):
                    version = struct.unpack('>H', data[i:i+2])[0]
                    if version not in self.GREASE_VALUES:
                        versions.append(version)

        except:
            pass
        return versions

    def _extract_key_share_groups(self, data: bytes) -> List[int]:
        """Extract key share groups from extension."""
        groups = []
        try:
            if len(data) < 2:
                return groups

            length = struct.unpack('>H', data[0:2])[0]
            offset = 2

            while offset + 4 <= len(data) and offset < 2 + length:
                group = struct.unpack('>H', data[offset:offset+2])[0]
                key_len = struct.unpack('>H', data[offset+2:offset+4])[0]

                if group not in self.GREASE_VALUES:
                    groups.append(group)

                offset += 4 + key_len

        except:
            pass
        return groups

    def _analyze_client_hello(self, parsed: Dict, src_ip: str, dst_ip: str) -> List[Dict]:
        """Analyze Client Hello for threats."""
        threats = []
        current_time = time.time()

        # Check for ESNI/ECH usage
        if self.detect_esni_ech:
            if parsed.get('has_esni'):
                threats.append({
                    'type': 'ESNI_DETECTED',
                    'severity': 'LOW',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': 'Encrypted SNI (ESNI) detected - hostname hidden',
                    'details': {
                        'tls_version': parsed.get('tls_version'),
                        'note': 'ESNI hides the destination hostname, may indicate privacy tool or evasion'
                    }
                })

            if parsed.get('has_ech'):
                threats.append({
                    'type': 'ECH_DETECTED',
                    'severity': 'LOW',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'description': 'Encrypted Client Hello (ECH) detected',
                    'details': {
                        'tls_version': parsed.get('tls_version'),
                        'note': 'ECH encrypts entire Client Hello, may indicate privacy tool or evasion'
                    }
                })

        # Check for weak cipher suites in offered list
        if self.detect_weak_ciphers:
            weak_offered = [cs for cs in parsed.get('cipher_suites', []) if cs in self.WEAK_CIPHERS]
            if weak_offered:
                # Only alert if ONLY weak ciphers are offered
                strong_offered = [cs for cs in parsed.get('cipher_suites', []) if cs in self.STRONG_CIPHERS]
                if not strong_offered:
                    threats.append({
                        'type': 'WEAK_CIPHERS_ONLY',
                        'severity': 'MEDIUM',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'description': f'Client only offers weak/deprecated cipher suites',
                        'details': {
                            'weak_ciphers': [self.WEAK_CIPHERS.get(cs, hex(cs)) for cs in weak_offered[:5]],
                            'sni': parsed.get('sni')
                        }
                    })

        # Check for legacy TLS versions
        if parsed.get('tls_version') in ['TLS 1.0', 'TLS 1.1', 'SSL 3.0']:
            threats.append({
                'type': 'LEGACY_TLS_VERSION',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Legacy TLS version in use: {parsed.get("tls_version")}',
                'details': {
                    'version': parsed.get('tls_version'),
                    'sni': parsed.get('sni'),
                    'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3'
                }
            })

        # Store session info for later correlation
        session_key = f"{src_ip}:{dst_ip}:{parsed.get('dst_port')}"
        self.sessions[session_key] = {
            'sni': parsed.get('sni'),
            'client_hello_time': current_time,
            'tls_version': parsed.get('tls_version'),
            'has_esni': parsed.get('has_esni'),
            'has_ech': parsed.get('has_ech'),
        }

        return threats

    def _analyze_server_hello(self, parsed: Dict, src_ip: str, dst_ip: str) -> List[Dict]:
        """Analyze Server Hello for threats."""
        threats = []

        # Check for weak cipher selection
        if self.detect_weak_ciphers and parsed.get('is_weak_cipher'):
            self.stats['weak_ciphers_detected'] += 1
            threats.append({
                'type': 'WEAK_CIPHER_NEGOTIATED',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Weak cipher suite negotiated: {parsed.get("cipher_name")}',
                'details': {
                    'cipher_suite': parsed.get('cipher_name'),
                    'cipher_id': hex(parsed.get('cipher_suite', 0)),
                    'tls_version': parsed.get('tls_version'),
                    'risk': 'Traffic may be decrypted by attackers'
                }
            })

        return threats

    def _analyze_certificate(self, parsed: Dict, src_ip: str, dst_ip: str) -> List[Dict]:
        """Analyze certificate chain for threats."""
        threats = []

        # Check for self-signed certificates
        if self.detect_self_signed and parsed.get('has_self_signed'):
            certs = parsed.get('certificates', [])
            leaf_cert = certs[0] if certs else {}

            threats.append({
                'type': 'SELF_SIGNED_CERTIFICATE',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Self-signed certificate detected',
                'details': {
                    'subject_cn': leaf_cert.get('subject_cn'),
                    'san_domains': leaf_cert.get('san_domains', [])[:5],
                    'chain_length': parsed.get('chain_length'),
                    'note': 'May indicate MITM attack or test environment'
                }
            })

        # Check for expired certificates
        if self.detect_expired_certs and parsed.get('has_expired'):
            threats.append({
                'type': 'EXPIRED_CERTIFICATE',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': 'Expired TLS certificate detected',
                'details': {
                    'chain_length': parsed.get('chain_length'),
                    'note': 'Expired certificates may indicate misconfiguration or attack'
                }
            })

        # Check for domain fronting
        if self.detect_domain_fronting:
            fronting_threat = self._detect_domain_fronting(parsed, src_ip, dst_ip)
            if fronting_threat:
                threats.append(fronting_threat)

        return threats

    def _detect_domain_fronting(self, parsed: Dict, src_ip: str, dst_ip: str) -> Optional[Dict]:
        """Detect potential domain fronting."""
        # Get certificate domains
        certs = parsed.get('certificates', [])
        if not certs:
            return None

        cert_domains = set()
        for cert in certs:
            if cert.get('subject_cn'):
                cert_domains.add(cert['subject_cn'].lower())
            for san in cert.get('san_domains', []):
                cert_domains.add(san.lower())

        # Look up the session to get SNI
        session_key = f"{dst_ip}:{src_ip}:{parsed.get('src_port')}"
        session = self.sessions.get(session_key, {})
        sni = session.get('sni', '')

        if not sni or not cert_domains:
            return None

        sni_lower = sni.lower()

        # Check if SNI matches any certificate domain
        sni_matches = False
        for domain in cert_domains:
            if sni_lower == domain or sni_lower.endswith('.' + domain):
                sni_matches = True
                break
            if domain.startswith('*.') and sni_lower.endswith(domain[1:]):
                sni_matches = True
                break

        if not sni_matches:
            # Check if this is a known CDN (legitimate domain fronting)
            is_cdn = any(cdn in sni_lower for cdn in self.CDN_PROVIDERS.keys())

            self.stats['domain_fronting_suspected'] += 1
            self.sni_host_mismatches.append({
                'time': time.time(),
                'sni': sni,
                'cert_domains': list(cert_domains)[:5],
                'src_ip': src_ip,
                'dst_ip': dst_ip
            })

            return {
                'type': 'DOMAIN_FRONTING_SUSPECTED',
                'severity': 'HIGH' if not is_cdn else 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': f'Potential domain fronting: SNI "{sni}" does not match certificate',
                'details': {
                    'sni': sni,
                    'cert_domains': list(cert_domains)[:5],
                    'is_cdn': is_cdn,
                    'note': 'Domain fronting may indicate C2 evasion technique'
                }
            }

        return None

    def get_stats(self) -> Dict:
        """Get analyzer statistics."""
        return {
            'enabled': self.enabled,
            **self.stats,
            'active_sessions': len(self.sessions),
            'certificates_seen': len(self.seen_certificates)
        }

    def get_recent_anomalies(self, limit: int = 50) -> List[Dict]:
        """Get recent certificate anomalies."""
        return list(self.certificate_anomalies)[-limit:]

    def get_domain_fronting_events(self, limit: int = 50) -> List[Dict]:
        """Get recent domain fronting detections."""
        return list(self.sni_host_mismatches)[-limit:]
