# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
TLS/SSL Traffic Analyzer

Extracts metadata from TLS handshakes without decryption:
- JA3 fingerprints (client identification)
- JA3S fingerprints (server identification)
- SNI (Server Name Indication)
- Certificate metadata
- TLS version and cipher suites
"""

import hashlib
import logging
import struct
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


class TLSAnalyzer:
    """
    Analyzes TLS handshakes to extract security-relevant metadata.

    This works on encrypted traffic by analyzing the unencrypted
    TLS handshake messages (Client Hello, Server Hello).
    """

    # TLS Content Types
    CONTENT_TYPE_HANDSHAKE = 22

    # TLS Handshake Types
    HANDSHAKE_CLIENT_HELLO = 1
    HANDSHAKE_SERVER_HELLO = 2
    HANDSHAKE_CERTIFICATE = 11

    # TLS Extensions
    EXT_SNI = 0
    EXT_SUPPORTED_GROUPS = 10
    EXT_EC_POINT_FORMATS = 11
    EXT_ALPN = 16

    # GREASE values to filter out (RFC 8701)
    GREASE_VALUES = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
        0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
        0xcaca, 0xdada, 0xeaea, 0xfafa
    }

    # Known malicious JA3 fingerprints (examples - should be loaded from threat feeds)
    KNOWN_MALICIOUS_JA3 = {
        # Cobalt Strike default
        "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
        # Metasploit Meterpreter
        "6734f37431670b3ab4292b8f60f29984": "Metasploit Meterpreter",
        # Empire
        "e7d705a3286e19ea42f587b344ee6865": "Empire",
        # TrickBot
        "51c64c77e60f3980eea90869b68c58a8": "TrickBot",
        # Emotet
        "4d7a28d6f2263ed61de88ca66eb2e04b": "Emotet",
        # Dridex
        "51c64c77e60f3980eea90869b68c58a8": "Dridex",
    }

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger('NetMonitor.TLSAnalyzer')

        # Cache for JA3 lookups and connection tracking
        self.ja3_cache = {}  # ja3_hash -> count
        self.connection_cache = defaultdict(dict)  # (src, dst, port) -> metadata

        # Statistics
        self.stats = {
            'handshakes_analyzed': 0,
            'client_hellos': 0,
            'server_hellos': 0,
            'certificates_extracted': 0,
            'malicious_ja3_detected': 0,
        }

        # Load custom JA3 blacklist from config
        self.ja3_blacklist = {}
        if config:
            custom_ja3 = config.get('tls_analysis', {}).get('ja3_blacklist', {})
            self.ja3_blacklist.update(custom_ja3)
        self.ja3_blacklist.update(self.KNOWN_MALICIOUS_JA3)

    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Analyze a packet for TLS handshake data.

        Returns dict with extracted metadata or None if not a TLS handshake.
        """
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None

        tcp = packet[TCP]
        raw = bytes(packet[Raw])

        # Quick check for TLS record (content type 22 = handshake)
        if len(raw) < 6 or raw[0] != self.CONTENT_TYPE_HANDSHAKE:
            return None

        try:
            return self._parse_tls_record(packet, raw)
        except Exception as e:
            self.logger.debug(f"TLS parse error: {e}")
            return None

    def _parse_tls_record(self, packet, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse TLS record layer and handshake message."""
        if len(data) < 5:
            return None

        # TLS Record Header
        content_type = data[0]
        tls_version = struct.unpack('>H', data[1:3])[0]
        record_length = struct.unpack('>H', data[3:5])[0]

        if content_type != self.CONTENT_TYPE_HANDSHAKE:
            return None

        if len(data) < 5 + record_length:
            return None

        # Handshake Header
        handshake_data = data[5:5 + record_length]
        if len(handshake_data) < 4:
            return None

        handshake_type = handshake_data[0]
        handshake_length = struct.unpack('>I', b'\x00' + handshake_data[1:4])[0]

        ip = packet[IP]
        result = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'tls_record_version': self._version_string(tls_version),
        }

        self.stats['handshakes_analyzed'] += 1

        if handshake_type == self.HANDSHAKE_CLIENT_HELLO:
            client_hello = self._parse_client_hello(handshake_data[4:])
            if client_hello:
                result.update(client_hello)
                result['handshake_type'] = 'client_hello'
                self.stats['client_hellos'] += 1

                # Check for malicious JA3
                ja3_hash = result.get('ja3')
                if ja3_hash and ja3_hash in self.ja3_blacklist:
                    result['malicious'] = True
                    result['malware_family'] = self.ja3_blacklist[ja3_hash]
                    self.stats['malicious_ja3_detected'] += 1

        elif handshake_type == self.HANDSHAKE_SERVER_HELLO:
            server_hello = self._parse_server_hello(handshake_data[4:])
            if server_hello:
                result.update(server_hello)
                result['handshake_type'] = 'server_hello'
                self.stats['server_hellos'] += 1

        elif handshake_type == self.HANDSHAKE_CERTIFICATE:
            cert_info = self._parse_certificate(handshake_data[4:])
            if cert_info:
                result.update(cert_info)
                result['handshake_type'] = 'certificate'
                self.stats['certificates_extracted'] += 1
        else:
            return None

        return result

    def _parse_client_hello(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse TLS Client Hello and compute JA3 fingerprint.

        JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
        """
        if len(data) < 38:
            return None

        result = {}
        offset = 0

        # Client Version (2 bytes)
        client_version = struct.unpack('>H', data[offset:offset+2])[0]
        result['tls_version'] = self._version_string(client_version)
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID Length + Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(data):
            return None

        # Cipher Suites
        cipher_suites_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2

        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            if offset + i + 2 > len(data):
                break
            cs = struct.unpack('>H', data[offset+i:offset+i+2])[0]
            if cs not in self.GREASE_VALUES:
                cipher_suites.append(cs)
        offset += cipher_suites_len

        if offset + 1 > len(data):
            return None

        # Compression Methods
        compression_len = data[offset]
        offset += 1 + compression_len

        # Extensions
        extensions = []
        supported_groups = []
        ec_point_formats = []
        sni = None
        alpn = []

        if offset + 2 <= len(data):
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            ext_end = offset + extensions_len
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', data[offset+2:offset+4])[0]
                offset += 4

                if ext_type not in self.GREASE_VALUES:
                    extensions.append(ext_type)

                ext_data = data[offset:offset+ext_len] if offset + ext_len <= len(data) else b''

                # Parse specific extensions
                if ext_type == self.EXT_SNI and len(ext_data) >= 5:
                    # SNI extension
                    sni = self._parse_sni(ext_data)

                elif ext_type == self.EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                    # Elliptic curves
                    groups_len = struct.unpack('>H', ext_data[0:2])[0]
                    for i in range(2, min(2 + groups_len, len(ext_data)), 2):
                        group = struct.unpack('>H', ext_data[i:i+2])[0]
                        if group not in self.GREASE_VALUES:
                            supported_groups.append(group)

                elif ext_type == self.EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
                    # EC Point Formats
                    formats_len = ext_data[0]
                    for i in range(1, min(1 + formats_len, len(ext_data))):
                        ec_point_formats.append(ext_data[i])

                elif ext_type == self.EXT_ALPN and len(ext_data) >= 2:
                    # ALPN
                    alpn = self._parse_alpn(ext_data)

                offset += ext_len

        # Build JA3 string
        ja3_string = ','.join([
            str(client_version),
            '-'.join(str(c) for c in cipher_suites),
            '-'.join(str(e) for e in extensions),
            '-'.join(str(g) for g in supported_groups),
            '-'.join(str(f) for f in ec_point_formats)
        ])

        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        result['ja3'] = ja3_hash
        result['ja3_string'] = ja3_string
        result['cipher_suites'] = cipher_suites
        result['extensions'] = extensions
        result['supported_groups'] = supported_groups
        result['ec_point_formats'] = ec_point_formats

        if sni:
            result['sni'] = sni
        if alpn:
            result['alpn'] = alpn

        return result

    def _parse_server_hello(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse TLS Server Hello and compute JA3S fingerprint.

        JA3S = MD5(TLSVersion,CipherSuite,Extensions)
        """
        if len(data) < 38:
            return None

        result = {}
        offset = 0

        # Server Version
        server_version = struct.unpack('>H', data[offset:offset+2])[0]
        result['tls_version'] = self._version_string(server_version)
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(data):
            return None

        # Selected Cipher Suite
        cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
        result['cipher_suite'] = cipher_suite
        result['cipher_suite_name'] = self._cipher_name(cipher_suite)
        offset += 2

        # Compression Method
        offset += 1

        # Extensions
        extensions = []
        if offset + 2 <= len(data):
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            ext_end = offset + extensions_len
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', data[offset+2:offset+4])[0]

                if ext_type not in self.GREASE_VALUES:
                    extensions.append(ext_type)

                offset += 4 + ext_len

        # Build JA3S string
        ja3s_string = ','.join([
            str(server_version),
            str(cipher_suite),
            '-'.join(str(e) for e in extensions)
        ])

        ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()

        result['ja3s'] = ja3s_hash
        result['ja3s_string'] = ja3s_string
        result['extensions'] = extensions

        return result

    def _parse_certificate(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse TLS Certificate message to extract certificate metadata.

        Note: Full X.509 parsing requires additional libraries (cryptography).
        This extracts basic info from the raw certificate.
        """
        if len(data) < 3:
            return None

        # Certificates length (3 bytes)
        certs_len = struct.unpack('>I', b'\x00' + data[0:3])[0]

        if len(data) < 3 + certs_len:
            return None

        result = {
            'certificates': [],
            'certificate_chain_length': 0,
        }

        offset = 3
        cert_index = 0

        while offset + 3 < 3 + certs_len and offset + 3 < len(data):
            cert_len = struct.unpack('>I', b'\x00' + data[offset:offset+3])[0]
            offset += 3

            if offset + cert_len > len(data):
                break

            cert_data = data[offset:offset+cert_len]
            cert_info = self._extract_cert_info(cert_data, cert_index)
            if cert_info:
                result['certificates'].append(cert_info)

            offset += cert_len
            cert_index += 1

        result['certificate_chain_length'] = len(result['certificates'])

        return result if result['certificates'] else None

    def _extract_cert_info(self, cert_data: bytes, index: int) -> Optional[Dict[str, Any]]:
        """
        Extract basic information from X.509 certificate (DER format).

        For full parsing, use the cryptography library.
        """
        try:
            # Try to use cryptography library if available
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert = x509.load_der_x509_certificate(cert_data, default_backend())

            return {
                'index': index,
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'not_before': cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat(),
                'signature_algorithm': cert.signature_algorithm_oid.dotted_string,
                'public_key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else None,
            }
        except ImportError:
            # Fallback: extract basic info without cryptography library
            return {
                'index': index,
                'raw_length': len(cert_data),
                'sha256': hashlib.sha256(cert_data).hexdigest(),
            }
        except Exception as e:
            self.logger.debug(f"Certificate parse error: {e}")
            return {
                'index': index,
                'raw_length': len(cert_data),
                'sha256': hashlib.sha256(cert_data).hexdigest(),
                'parse_error': str(e),
            }

    def _parse_sni(self, data: bytes) -> Optional[str]:
        """Parse SNI extension to extract hostname."""
        try:
            # SNI list length (2 bytes)
            if len(data) < 2:
                return None
            list_len = struct.unpack('>H', data[0:2])[0]

            offset = 2
            while offset + 3 < len(data):
                name_type = data[offset]
                name_len = struct.unpack('>H', data[offset+1:offset+3])[0]
                offset += 3

                if name_type == 0:  # host_name
                    if offset + name_len <= len(data):
                        return data[offset:offset+name_len].decode('utf-8', errors='ignore')

                offset += name_len

            return None
        except Exception:
            return None

    def _parse_alpn(self, data: bytes) -> List[str]:
        """Parse ALPN extension to extract protocol list."""
        try:
            alpn_list = []
            if len(data) < 2:
                return alpn_list

            list_len = struct.unpack('>H', data[0:2])[0]
            offset = 2

            while offset < 2 + list_len and offset < len(data):
                proto_len = data[offset]
                offset += 1
                if offset + proto_len <= len(data):
                    alpn_list.append(data[offset:offset+proto_len].decode('utf-8', errors='ignore'))
                offset += proto_len

            return alpn_list
        except Exception:
            return []

    def _version_string(self, version: int) -> str:
        """Convert TLS version number to string."""
        versions = {
            0x0300: 'SSL 3.0',
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3',
        }
        return versions.get(version, f'Unknown (0x{version:04x})')

    def _cipher_name(self, cipher: int) -> str:
        """Get human-readable cipher suite name."""
        # Common cipher suites
        ciphers = {
            0x1301: 'TLS_AES_128_GCM_SHA256',
            0x1302: 'TLS_AES_256_GCM_SHA384',
            0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
            0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
            0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
            0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
            0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
            0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        }
        return ciphers.get(cipher, f'Unknown (0x{cipher:04x})')

    def get_stats(self) -> Dict[str, int]:
        """Return analyzer statistics."""
        return self.stats.copy()

    def check_ja3(self, ja3_hash: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a JA3 hash is known to be malicious.

        Returns: (is_malicious, malware_family or None)
        """
        if ja3_hash in self.ja3_blacklist:
            return True, self.ja3_blacklist[ja3_hash]
        return False, None

    def add_ja3_blacklist(self, ja3_hash: str, malware_family: str):
        """Add a JA3 hash to the blacklist."""
        self.ja3_blacklist[ja3_hash] = malware_family
        self.logger.info(f"Added JA3 {ja3_hash} to blacklist: {malware_family}")


# Weak cipher detection for security auditing
WEAK_CIPHERS = {
    0x0000: 'TLS_NULL_WITH_NULL_NULL',
    0x0001: 'TLS_RSA_WITH_NULL_MD5',
    0x0002: 'TLS_RSA_WITH_NULL_SHA',
    0x002c: 'TLS_PSK_WITH_NULL_SHA',
    0x002d: 'TLS_DHE_PSK_WITH_NULL_SHA',
    0x002e: 'TLS_RSA_PSK_WITH_NULL_SHA',
    0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
    0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
    0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
}

DEPRECATED_VERSIONS = {
    0x0300: 'SSL 3.0',
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
}


def detect_tls_anomalies(tls_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect TLS configuration anomalies that might indicate security issues.

    Returns list of anomaly dicts with type, severity, and description.
    """
    anomalies = []

    # Check for weak cipher suites in client hello
    cipher_suites = tls_metadata.get('cipher_suites', [])
    for cs in cipher_suites:
        if cs in WEAK_CIPHERS:
            anomalies.append({
                'type': 'WEAK_CIPHER_OFFERED',
                'severity': 'MEDIUM',
                'description': f'Client offers weak cipher: {WEAK_CIPHERS[cs]}',
                'cipher': WEAK_CIPHERS[cs],
            })

    # Check selected cipher (server hello)
    selected_cipher = tls_metadata.get('cipher_suite')
    if selected_cipher and selected_cipher in WEAK_CIPHERS:
        anomalies.append({
            'type': 'WEAK_CIPHER_SELECTED',
            'severity': 'HIGH',
            'description': f'Server selected weak cipher: {WEAK_CIPHERS[selected_cipher]}',
            'cipher': WEAK_CIPHERS[selected_cipher],
        })

    # Check for deprecated TLS versions
    tls_version = tls_metadata.get('tls_version', '')
    for version_code, version_name in DEPRECATED_VERSIONS.items():
        if version_name in tls_version:
            anomalies.append({
                'type': 'DEPRECATED_TLS_VERSION',
                'severity': 'MEDIUM',
                'description': f'Deprecated TLS version: {version_name}',
                'version': version_name,
            })
            break

    # Check for missing SNI (might indicate C2 or old client)
    if tls_metadata.get('handshake_type') == 'client_hello' and not tls_metadata.get('sni'):
        anomalies.append({
            'type': 'MISSING_SNI',
            'severity': 'LOW',
            'description': 'Client Hello without SNI extension',
        })

    # Check certificate validity
    certs = tls_metadata.get('certificates', [])
    for cert in certs:
        if cert.get('not_after'):
            try:
                from datetime import datetime
                not_after = datetime.fromisoformat(cert['not_after'].replace('Z', '+00:00'))
                if not_after < datetime.now(not_after.tzinfo):
                    anomalies.append({
                        'type': 'EXPIRED_CERTIFICATE',
                        'severity': 'HIGH',
                        'description': f'Expired certificate: {cert.get("subject", "unknown")}',
                        'expired_on': cert['not_after'],
                    })
            except Exception:
                pass

    return anomalies
