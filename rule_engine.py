# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Detectieregels uit de database (tabel ``detection_rules``).

Een regel beschrijft WAT er moet matchen, niet HOE: een vaste set velden
(protocol, poorten, richting, payload, HTTP, DNS, TLS, apparaattype) plus een
drempel (aantal per tijdvenster). Er wordt nooit code uit de database
uitgevoerd; alleen deze velden worden geïnterpreteerd.

Prestaties:
- regels worden één keer gecompileerd en in het geheugen gehouden;
- DNS-, TLS- en HTTP-regels worden alleen bekeken als het pakket een
  DNS-query, TLS ClientHello of HTTP-request is;
- overige regels zijn geïndexeerd op (protocol, doelpoort);
- payload wordt maximaal MAX_SCAN_BYTES bytes doorzocht, wat samen met de
  regex-controle in ``_check_regex_safety`` ReDoS beperkt.
"""

import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable, Dict, List, Optional, Tuple

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

MAX_SCAN_BYTES = 4096
MAX_REGEX_LENGTH = 512
MAX_LIST_ITEMS = 200
MAX_PORT_INDEX_SPAN = 256      # bredere poortbereiken gaan in de generieke bak
MAX_STATE_ENTRIES = 50000

SEVERITIES = ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
TRACK_BY = ('src', 'dst', 'pair')
DIRECTIONS = ('inbound', 'outbound', 'internal', 'any')
PROTOCOLS = ('tcp', 'udp', 'icmp', 'any')
DEFAULT_ALERT_TYPE = 'DETECTION_RULE'
ALERT_TYPE_RE = re.compile(r'^[A-Z][A-Z0-9_]{2,49}$')
RULE_KEY_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,79}$')

HTTP_METHODS = (b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS',
                b'PATCH', b'CONNECT', b'TRACE', b'PROPFIND')

DNS_QTYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY',
}
DNS_QTYPE_NAMES = set(DNS_QTYPES.values())

# Toegestane match-velden en hun soort. Alles wat hier niet staat wordt geweigerd.
LIST_FIELDS = {
    'src_cidr', 'dst_cidr', 'payload_contains', 'http_method',
    'http_uri_contains', 'dns_qname_suffix', 'dns_qtype', 'tls_sni_suffix',
    'ja3', 'device_class',
}
REGEX_FIELDS = {
    'payload_regex', 'http_uri_regex', 'http_host_regex', 'http_header_regex',
    'http_user_agent_regex', 'dns_qname_regex', 'tls_sni_regex',
}
PORT_FIELDS = {'src_port', 'dst_port', 'payload_size'}
OTHER_FIELDS = {'protocol', 'direction', 'payload_hex_prefix', 'new_connection',
                'nocase', 'device_class_of'}
ALLOWED_MATCH_FIELDS = LIST_FIELDS | REGEX_FIELDS | PORT_FIELDS | OTHER_FIELDS

DNS_FIELDS = {'dns_qname_suffix', 'dns_qname_regex', 'dns_qtype'}
TLS_FIELDS = {'tls_sni_suffix', 'tls_sni_regex', 'ja3'}
HTTP_FIELDS = {'http_method', 'http_uri_contains', 'http_uri_regex',
               'http_host_regex', 'http_header_regex', 'http_user_agent_regex'}

# Gekwantificeerde groep met een kwantor erin, zoals (a+)+ of (\w*x)* :
# het klassieke patroon achter catastrofale backtracking.
_NESTED_QUANTIFIER_RE = re.compile(r'\((?:[^()\\]|\\.)*[*+}](?:[^()\\]|\\.)*\)\s*[*+{]')
_BACKREF_RE = re.compile(r'\\[1-9]|\(\?P=')


class RuleValidationError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Validatie
# ---------------------------------------------------------------------------

def _check_regex_safety(pattern: str) -> None:
    if len(pattern) > MAX_REGEX_LENGTH:
        raise RuleValidationError(f'regex langer dan {MAX_REGEX_LENGTH} tekens')
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise RuleValidationError(
            'geneste kwantor (zoals (a+)+) is niet toegestaan: risico op ReDoS')
    if _BACKREF_RE.search(pattern):
        raise RuleValidationError('backreferences zijn niet toegestaan')
    try:
        re.compile(pattern)
    except re.error as e:
        raise RuleValidationError(f'ongeldige regex: {e}')


def parse_port_spec(value) -> List[Tuple[int, int]]:
    """'80,443,8000-8100' of [80, 443] -> [(80,80), (443,443), (8000,8100)]."""
    if value is None or value == '':
        return []
    if isinstance(value, int) and not isinstance(value, bool):
        items = [str(value)]
    elif isinstance(value, (list, tuple)):
        items = [str(v) for v in value]
    elif isinstance(value, str):
        items = [p for p in value.replace(' ', '').split(',') if p]
    else:
        raise RuleValidationError(f'ongeldige poortwaarde: {value!r}')
    ranges = []
    for item in items:
        m = re.fullmatch(r'(\d{1,5})(?:-(\d{1,5}))?', item.strip())
        if not m:
            raise RuleValidationError(f'ongeldige poort of bereik: {item!r}')
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if lo > hi or hi > 65535:
            raise RuleValidationError(f'ongeldig bereik: {item!r}')
        ranges.append((lo, hi))
    return ranges


def _as_list(name: str, value) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)) or not value:
        raise RuleValidationError(f'{name}: verwacht een lijst met waarden')
    if len(value) > MAX_LIST_ITEMS:
        raise RuleValidationError(f'{name}: maximaal {MAX_LIST_ITEMS} waarden')
    out = []
    for v in value:
        if not isinstance(v, (str, int)) or isinstance(v, bool) or str(v).strip() == '':
            raise RuleValidationError(f'{name}: ongeldige waarde {v!r}')
        out.append(str(v).strip())
    return out


def validate_match(match: Any) -> Dict[str, Any]:
    """Controleer en normaliseer het match-object. Gooit RuleValidationError."""
    if isinstance(match, str):
        try:
            match = json.loads(match)
        except ValueError as e:
            raise RuleValidationError(f'match is geen geldige JSON: {e}')
    if not isinstance(match, dict) or not match:
        raise RuleValidationError('match moet een niet-leeg object zijn')

    unknown = set(match) - ALLOWED_MATCH_FIELDS
    if unknown:
        raise RuleValidationError(f'onbekende velden: {", ".join(sorted(unknown))}')

    clean: Dict[str, Any] = {}
    for key, value in match.items():
        if key in LIST_FIELDS:
            items = _as_list(key, value)
            if key in ('src_cidr', 'dst_cidr'):
                for c in items:
                    try:
                        ipaddress.ip_network(c, strict=False)
                    except ValueError:
                        raise RuleValidationError(f'{key}: ongeldig netwerk {c!r}')
            elif key == 'dns_qtype':
                items = [i.upper() for i in items]
                bad = [i for i in items if i not in DNS_QTYPE_NAMES]
                if bad:
                    raise RuleValidationError(
                        f'dns_qtype: onbekend type {", ".join(bad)} '
                        f'(kies uit {", ".join(sorted(DNS_QTYPE_NAMES))})')
            elif key == 'http_method':
                items = [i.upper() for i in items]
            elif key in ('dns_qname_suffix', 'tls_sni_suffix'):
                items = [i.lower().strip('.') for i in items]
            elif key == 'ja3':
                items = [i.lower() for i in items]
                if any(not re.fullmatch(r'[0-9a-f]{32}', i) for i in items):
                    raise RuleValidationError('ja3: verwacht MD5-hashes (32 hex-tekens)')
            elif key == 'device_class':
                items = [i.lower() for i in items]
            clean[key] = items
        elif key in REGEX_FIELDS:
            if not isinstance(value, str) or not value:
                raise RuleValidationError(f'{key}: verwacht een regex-tekst')
            _check_regex_safety(value)
            clean[key] = value
        elif key in PORT_FIELDS:
            ranges = parse_port_spec(value)
            if not ranges:
                raise RuleValidationError(f'{key}: leeg')
            if key == 'payload_size':
                if any(hi > MAX_SCAN_BYTES * 16 for _, hi in ranges):
                    raise RuleValidationError('payload_size: te groot')
            clean[key] = ','.join(f'{lo}' if lo == hi else f'{lo}-{hi}' for lo, hi in ranges)
        elif key == 'protocol':
            v = str(value).lower()
            if v not in PROTOCOLS:
                raise RuleValidationError(f'protocol: kies uit {", ".join(PROTOCOLS)}')
            clean[key] = v
        elif key == 'direction':
            v = str(value).lower()
            if v not in DIRECTIONS:
                raise RuleValidationError(f'direction: kies uit {", ".join(DIRECTIONS)}')
            clean[key] = v
        elif key == 'payload_hex_prefix':
            v = str(value).replace(' ', '').lower()
            if not re.fullmatch(r'(?:[0-9a-f]{2}){1,64}', v):
                raise RuleValidationError('payload_hex_prefix: verwacht hex-bytes, bijv. "01000000"')
            clean[key] = v
        elif key in ('new_connection', 'nocase'):
            if not isinstance(value, bool):
                raise RuleValidationError(f'{key}: verwacht true of false')
            clean[key] = value
        elif key == 'device_class_of':
            v = str(value).lower()
            if v not in ('src', 'dst'):
                raise RuleValidationError('device_class_of: kies src of dst')
            clean[key] = v

    kinds = [n for n, fields in (('dns', DNS_FIELDS), ('tls', TLS_FIELDS), ('http', HTTP_FIELDS))
             if fields & set(clean)]
    if len(kinds) > 1:
        raise RuleValidationError(
            f'een regel kan niet tegelijk {" en ".join(kinds).upper()}-velden gebruiken')
    if kinds == ['dns'] and clean.get('protocol') == 'icmp':
        raise RuleValidationError('DNS-velden gaan niet samen met protocol icmp')
    if kinds and kinds[0] in ('tls', 'http') and clean.get('protocol') in ('udp', 'icmp'):
        raise RuleValidationError(f'{kinds[0].upper()}-velden vereisen protocol tcp')
    if clean.get('new_connection') and clean.get('protocol') in ('udp', 'icmp'):
        raise RuleValidationError('new_connection geldt alleen voor tcp')

    # Een regel die op elk pakket matcht is vrijwel zeker een vergissing
    meaningful = set(clean) - {'protocol', 'direction', 'nocase', 'device_class_of', 'new_connection'}
    if not meaningful:
        raise RuleValidationError(
            'regel is te breed: voeg minstens een poort-, adres-, inhoud-, DNS-, TLS- of apparaatveld toe')
    return clean


def validate_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Valideer een volledige regel (zoals uit API of database). Geeft een schone kopie terug."""
    if not isinstance(rule, dict):
        raise RuleValidationError('regel moet een object zijn')
    name = str(rule.get('name') or '').strip()
    if not name or len(name) > 200:
        raise RuleValidationError('name is verplicht (max 200 tekens)')

    rule_key = str(rule.get('rule_key') or '').strip().lower()
    if not rule_key:
        rule_key = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')[:80] or 'regel'
    if not RULE_KEY_RE.match(rule_key):
        raise RuleValidationError('rule_key: alleen kleine letters, cijfers, punt, - en _ (max 80 tekens)')

    severity = str(rule.get('severity') or 'MEDIUM').upper()
    if severity not in SEVERITIES:
        raise RuleValidationError(f'severity: kies uit {", ".join(SEVERITIES)}')

    alert_type = str(rule.get('alert_type') or DEFAULT_ALERT_TYPE).upper()
    if not ALERT_TYPE_RE.match(alert_type):
        raise RuleValidationError('alert_type: hoofdletters, cijfers en _ (3-50 tekens)')

    def _int(name, default, lo, hi):
        value = rule.get(name)
        if value is None or value == '':
            return default
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise RuleValidationError(f'{name}: verwacht een geheel getal')
        if not lo <= value <= hi:
            raise RuleValidationError(f'{name}: tussen {lo} en {hi}')
        return value

    track_by = str(rule.get('track_by') or 'src').lower()
    if track_by not in TRACK_BY:
        raise RuleValidationError(f'track_by: kies uit {", ".join(TRACK_BY)}')

    cve = str(rule.get('cve') or '').strip().upper() or None
    if cve and not re.fullmatch(r'CVE-\d{4}-\d{4,7}(?:\s*,\s*CVE-\d{4}-\d{4,7})*', cve):
        raise RuleValidationError('cve: verwacht CVE-JJJJ-NNNN (meerdere gescheiden door komma)')

    reference_url = str(rule.get('reference_url') or '').strip() or None
    if reference_url and not re.match(r'^https?://', reference_url):
        raise RuleValidationError('reference_url moet met http:// of https:// beginnen')

    return {
        'rule_key': rule_key,
        'name': name,
        'description': (str(rule.get('description') or '').strip() or None),
        'cve': cve,
        'reference_url': reference_url,
        'severity': severity,
        'alert_type': alert_type,
        'match': validate_match(rule.get('match')),
        'threshold_count': _int('threshold_count', 1, 1, 100000),
        'threshold_window': _int('threshold_window', 60, 1, 86400),
        'cooldown': _int('cooldown', 300, 0, 7 * 86400),
        'track_by': track_by,
        'enabled': bool(rule.get('enabled', True)),
    }


def rules_version(rules: List[Dict[str, Any]], device_classes: Optional[Dict[str, str]] = None) -> str:
    """Stabiele hash over regels + apparaatklassen, zodat sensors alleen bij wijziging herladen."""
    payload = json.dumps({'r': rules, 'd': device_classes or {}}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Gecompileerde regel
# ---------------------------------------------------------------------------

class CompiledRule:
    __slots__ = (
        'id', 'key', 'name', 'description', 'cve', 'reference_url', 'severity',
        'alert_type', 'threshold_count', 'threshold_window', 'cooldown',
        'track_by', 'kind', 'protocol', 'direction', 'src_nets', 'dst_nets',
        'src_ports', 'dst_ports', 'payload_size', 'payload_prefix',
        'payload_contains', 'payload_regex', 'new_connection', 'http_method',
        'http_uri_contains', 'http_uri_regex', 'http_host_regex',
        'http_header_regex', 'http_ua_regex', 'dns_suffixes', 'dns_regex',
        'dns_qtypes', 'sni_suffixes', 'sni_regex', 'ja3', 'device_class',
        'device_class_of', 'needs_payload', '_nocase',
    )

    def __init__(self, rule: Dict[str, Any]):
        clean = validate_rule(rule)
        m = clean['match']
        nocase = m.get('nocase', True)
        flags = re.IGNORECASE if nocase else 0

        self.id = rule.get('id')
        self.key = clean['rule_key']
        self.name = clean['name']
        self.description = clean['description']
        self.cve = clean['cve']
        self.reference_url = clean['reference_url']
        self.severity = clean['severity']
        self.alert_type = clean['alert_type']
        self.threshold_count = clean['threshold_count']
        self.threshold_window = clean['threshold_window']
        self.cooldown = clean['cooldown']
        self.track_by = clean['track_by']

        if DNS_FIELDS & set(m):
            self.kind = 'dns'
        elif TLS_FIELDS & set(m):
            self.kind = 'tls'
        elif HTTP_FIELDS & set(m):
            self.kind = 'http'
        else:
            self.kind = 'packet'

        self.protocol = m.get('protocol', 'any')
        if self.kind in ('tls', 'http'):
            self.protocol = 'tcp'
        self.direction = m.get('direction', 'any')
        self.src_nets = [ipaddress.ip_network(c, strict=False) for c in m.get('src_cidr', [])]
        self.dst_nets = [ipaddress.ip_network(c, strict=False) for c in m.get('dst_cidr', [])]
        self.src_ports = parse_port_spec(m.get('src_port'))
        self.dst_ports = parse_port_spec(m.get('dst_port'))
        self.payload_size = parse_port_spec(m.get('payload_size'))
        self.payload_prefix = bytes.fromhex(m['payload_hex_prefix']) if 'payload_hex_prefix' in m else None
        contains = m.get('payload_contains', [])
        self.payload_contains = [c.encode('utf-8', 'surrogateescape').lower() if nocase
                                 else c.encode('utf-8', 'surrogateescape') for c in contains]
        self.payload_regex = (re.compile(m['payload_regex'].encode('utf-8'), flags)
                              if 'payload_regex' in m else None)
        self.new_connection = bool(m.get('new_connection', False))

        self.http_method = set(m.get('http_method', []))
        self.http_uri_contains = [c.lower() if nocase else c for c in m.get('http_uri_contains', [])]
        self.http_uri_regex = re.compile(m['http_uri_regex'], flags) if 'http_uri_regex' in m else None
        self.http_host_regex = re.compile(m['http_host_regex'], flags) if 'http_host_regex' in m else None
        self.http_header_regex = re.compile(m['http_header_regex'], flags) if 'http_header_regex' in m else None
        self.http_ua_regex = re.compile(m['http_user_agent_regex'], flags) if 'http_user_agent_regex' in m else None

        self.dns_suffixes = tuple(m.get('dns_qname_suffix', []))
        self.dns_regex = re.compile(m['dns_qname_regex'], flags) if 'dns_qname_regex' in m else None
        self.dns_qtypes = set(m.get('dns_qtype', []))
        self.sni_suffixes = tuple(m.get('tls_sni_suffix', []))
        self.sni_regex = re.compile(m['tls_sni_regex'], flags) if 'tls_sni_regex' in m else None
        self.ja3 = set(m.get('ja3', []))
        self.device_class = set(m.get('device_class', []))
        self.device_class_of = m.get('device_class_of', 'src')

        self.needs_payload = bool(self.payload_size or self.payload_prefix or
                                  self.payload_contains or self.payload_regex)
        self._nocase = nocase

    # Hulpfuncties ---------------------------------------------------------

    @staticmethod
    def _in_ranges(value, ranges) -> bool:
        if value is None:
            return False
        for lo, hi in ranges:
            if lo <= value <= hi:
                return True
        return False

    @staticmethod
    def _suffix_match(name: str, suffixes) -> bool:
        for s in suffixes:
            if name == s or name.endswith('.' + s):
                return True
        return False

    def index_ports(self) -> Optional[List[int]]:
        """Poorten voor de index, of None als de regel in de generieke bak hoort."""
        if self.kind != 'packet' or not self.dst_ports:
            return None
        span = sum(hi - lo + 1 for lo, hi in self.dst_ports)
        if span > MAX_PORT_INDEX_SPAN:
            return None
        ports = []
        for lo, hi in self.dst_ports:
            ports.extend(range(lo, hi + 1))
        return ports

    def matches(self, ctx: 'PacketContext') -> bool:
        if self.protocol != 'any' and self.protocol != ctx.proto:
            return False
        if self.direction != 'any' and self.direction != ctx.direction:
            return False
        if self.dst_ports and not self._in_ranges(ctx.dst_port, self.dst_ports):
            return False
        if self.src_ports and not self._in_ranges(ctx.src_port, self.src_ports):
            return False
        if self.new_connection and not ctx.is_syn:
            return False
        if self.src_nets and not any(ctx.src_addr in n for n in self.src_nets):
            return False
        if self.dst_nets and not any(ctx.dst_addr in n for n in self.dst_nets):
            return False

        if self.device_class:
            ip = ctx.src_ip if self.device_class_of == 'src' else ctx.dst_ip
            cls = ctx.device_classes.get(ip, 'unclassified')
            if cls not in self.device_class:
                return False

        if self.needs_payload:
            payload = ctx.payload
            if not payload:
                return False
            if self.payload_size and not self._in_ranges(ctx.payload_len, self.payload_size):
                return False
            if self.payload_prefix and not payload.startswith(self.payload_prefix):
                return False
            if self.payload_contains:
                hay = ctx.payload_lower if self._nocase else payload
                if not any(c in hay for c in self.payload_contains):
                    return False
            if self.payload_regex and not self.payload_regex.search(payload):
                return False

        if self.kind == 'dns':
            qname = ctx.dns_qname
            if self.dns_suffixes and not self._suffix_match(qname, self.dns_suffixes):
                return False
            if self.dns_regex and not self.dns_regex.search(qname):
                return False
            if self.dns_qtypes and ctx.dns_qtype not in self.dns_qtypes:
                return False
        elif self.kind == 'tls':
            sni = ctx.tls_sni
            if (self.sni_suffixes or self.sni_regex) and not sni:
                return False
            if self.sni_suffixes and not self._suffix_match(sni, self.sni_suffixes):
                return False
            if self.sni_regex and not self.sni_regex.search(sni):
                return False
            if self.ja3 and ctx.tls_ja3 not in self.ja3:
                return False
        elif self.kind == 'http':
            http = ctx.http
            if self.http_method and http['method'] not in self.http_method:
                return False
            if self.http_uri_contains:
                uri = http['uri'].lower() if self._nocase else http['uri']
                if not any(c in uri for c in self.http_uri_contains):
                    return False
            if self.http_uri_regex and not self.http_uri_regex.search(http['uri']):
                return False
            if self.http_host_regex and not self.http_host_regex.search(http['host']):
                return False
            if self.http_ua_regex and not self.http_ua_regex.search(http['user_agent']):
                return False
            if self.http_header_regex and not self.http_header_regex.search(http['headers']):
                return False
        return True


# ---------------------------------------------------------------------------
# Pakketcontext (lui berekend, zodat goedkope pakketten goedkoop blijven)
# ---------------------------------------------------------------------------

class PacketContext:
    def __init__(self, packet, is_internal: Callable[[str], bool],
                 device_classes: Dict[str, str], tls_meta: Optional[Dict] = None):
        ip = packet[IP]
        self.packet = packet
        self.src_ip = ip.src
        self.dst_ip = ip.dst
        self.device_classes = device_classes
        self.tls_meta = tls_meta
        self._payload = None
        self._payload_lower = None
        self._addr = {}

        self.src_port = self.dst_port = None
        self.is_syn = False
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            self.proto = 'tcp'
            self.src_port, self.dst_port = tcp.sport, tcp.dport
            flags = int(tcp.flags)
            self.is_syn = bool(flags & 0x02) and not (flags & 0x10)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            self.proto = 'udp'
            self.src_port, self.dst_port = udp.sport, udp.dport
        elif packet.haslayer(ICMP):
            self.proto = 'icmp'
        else:
            self.proto = 'other'

        src_int = is_internal(self.src_ip)
        dst_int = is_internal(self.dst_ip)
        if src_int and dst_int:
            self.direction = 'internal'
        elif src_int:
            self.direction = 'outbound'
        elif dst_int:
            self.direction = 'inbound'
        else:
            self.direction = 'external'

        # DNS-query (geen antwoorden)
        self.dns_qname = None
        self.dns_qtype = None
        if packet.haslayer(DNSQR) and packet.haslayer(DNS) and packet[DNS].qr == 0:
            try:
                q = packet[DNSQR]
                qname = q.qname
                if isinstance(qname, bytes):
                    qname = qname.decode('utf-8', 'replace')
                self.dns_qname = qname.rstrip('.').lower()
                self.dns_qtype = DNS_QTYPES.get(int(q.qtype), str(q.qtype))
            except Exception:
                self.dns_qname = None

        self.tls_sni = ''
        self.tls_ja3 = None
        if tls_meta and tls_meta.get('handshake_type') == 'client_hello':
            self.tls_sni = (tls_meta.get('sni') or '').lower().rstrip('.')
            self.tls_ja3 = tls_meta.get('ja3')

        self._http = False  # False = nog niet geparsed, None = geen HTTP

    @property
    def src_addr(self):
        if 'src' not in self._addr:
            self._addr['src'] = ipaddress.ip_address(self.src_ip)
        return self._addr['src']

    @property
    def dst_addr(self):
        if 'dst' not in self._addr:
            self._addr['dst'] = ipaddress.ip_address(self.dst_ip)
        return self._addr['dst']

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            # De volledige L4-payload, niet packet[Raw]: scapy ontleedt bekende
            # poorten (DNS op 53, HTTP op 80, ...) in eigen lagen en dan is er
            # geen Raw-laag meer.
            l4 = None
            if self.proto == 'tcp':
                l4 = self.packet[TCP].payload
            elif self.proto == 'udp':
                l4 = self.packet[UDP].payload
            elif self.proto == 'icmp':
                l4 = self.packet[ICMP].payload
            try:
                self._payload = bytes(l4) if l4 is not None else b''
            except Exception:
                self._payload = bytes(self.packet[Raw].load) if self.packet.haslayer(Raw) else b''
            self.payload_len = len(self._payload)
            self._payload = self._payload[:MAX_SCAN_BYTES]
        return self._payload

    @property
    def payload_len(self) -> int:
        if self._payload is None:
            _ = self.payload
        return self.__dict__.get('_payload_len', 0)

    @payload_len.setter
    def payload_len(self, value):
        self.__dict__['_payload_len'] = value

    @property
    def payload_lower(self) -> bytes:
        if self._payload_lower is None:
            self._payload_lower = self.payload.lower()
        return self._payload_lower

    @property
    def http(self) -> Optional[Dict[str, str]]:
        if self._http is False:
            self._http = parse_http_request(self.payload) if self.proto == 'tcp' else None
        return self._http


def parse_http_request(payload: bytes) -> Optional[Dict[str, str]]:
    """Eenvoudige parser voor het begin van een HTTP-request, op elke poort."""
    if not payload:
        return None
    sp = payload.find(b' ', 0, 12)
    if sp <= 0 or payload[:sp] not in HTTP_METHODS:
        return None
    eol = payload.find(b'\r\n')
    if eol == -1:
        eol = len(payload)
    parts = payload[:eol].split(b' ')
    if len(parts) < 2:
        return None
    end = payload.find(b'\r\n\r\n')
    header_block = payload[eol + 2:end if end != -1 else len(payload)]
    host = ua = ''
    for line in header_block.split(b'\r\n'):
        name, _, value = line.partition(b':')
        lname = name.strip().lower()
        if lname == b'host':
            host = value.strip().decode('latin-1')
        elif lname == b'user-agent':
            ua = value.strip().decode('latin-1')
    return {
        'method': parts[0].decode('latin-1'),
        'uri': parts[1].decode('latin-1'),
        'host': host,
        'user_agent': ua,
        'headers': header_block.decode('latin-1'),
    }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class _RuleSet:
    """Onveranderlijke set gecompileerde regels; wordt in één keer vervangen."""

    def __init__(self, rules: List[CompiledRule], device_classes: Dict[str, str], version: str):
        self.rules = rules
        self.device_classes = device_classes
        self.version = version
        self.dns: List[CompiledRule] = []
        self.tls: List[CompiledRule] = []
        self.http: List[CompiledRule] = []
        self.by_port: Dict[Tuple[str, int], List[CompiledRule]] = defaultdict(list)
        self.generic: Dict[str, List[CompiledRule]] = defaultdict(list)
        for r in rules:
            if r.kind == 'dns':
                self.dns.append(r)
            elif r.kind == 'tls':
                self.tls.append(r)
            elif r.kind == 'http':
                self.http.append(r)
            else:
                ports = r.index_ports()
                protos = ('tcp', 'udp', 'icmp') if r.protocol == 'any' else (r.protocol,)
                for proto in protos:
                    if ports is None:
                        self.generic[proto].append(r)
                    else:
                        for p in ports:
                            self.by_port[(proto, p)].append(r)


class RuleEngine:
    def __init__(self, is_internal: Optional[Callable[[str], bool]] = None, logger=None):
        self.logger = logger or logging.getLogger('NetMonitor.RuleEngine')
        self._is_internal = is_internal or self._default_is_internal
        self._set = _RuleSet([], {}, rules_version([]))
        self._hits: Dict[Tuple, deque] = {}
        self._last_alert: Dict[Tuple, float] = {}
        self._refresh_thread = None
        self._stop = threading.Event()
        self.errors: List[Dict[str, Any]] = []

    @staticmethod
    def _default_is_internal(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @property
    def rule_count(self) -> int:
        return len(self._set.rules)

    @property
    def version(self) -> str:
        return self._set.version

    def load(self, rules: List[Dict[str, Any]], device_classes: Optional[Dict[str, str]] = None,
             version: Optional[str] = None) -> int:
        """Laad regels (alleen enabled). Ongeldige regels worden overgeslagen en gelogd."""
        compiled, errors = [], []
        for rule in rules or []:
            if not rule.get('enabled', True):
                continue
            try:
                compiled.append(CompiledRule(rule))
            except RuleValidationError as e:
                errors.append({'id': rule.get('id'), 'rule_key': rule.get('rule_key'), 'error': str(e)})
                self.logger.warning(f"Detectieregel {rule.get('rule_key') or rule.get('id')} overgeslagen: {e}")
        classes = {str(k): str(v).lower() for k, v in (device_classes or {}).items() if v}
        new_version = version or rules_version(rules or [], classes)
        old_count = self.rule_count
        self._set = _RuleSet(compiled, classes, new_version)
        self.errors = errors
        live_ids = {r.id for r in compiled}
        self._hits = {k: v for k, v in self._hits.items() if k[0] in live_ids}
        self._last_alert = {k: v for k, v in self._last_alert.items() if k[0] in live_ids}
        if len(compiled) != old_count or errors:
            self.logger.info(f"Detectieregels geladen: {len(compiled)} actief"
                             + (f", {len(errors)} ongeldig" if errors else ''))
        return len(compiled)

    def start_auto_refresh(self, loader: Callable[[], Tuple[List[Dict], Dict[str, str]]],
                           interval: int = 60) -> None:
        """Ververs de regels periodiek via ``loader`` (server-kant, met database)."""
        def _refresh_once():
            try:
                rules, classes = loader()
                version = rules_version(rules, classes)
                if version != self.version:
                    self.load(rules, classes, version)
            except Exception as e:
                self.logger.warning(f"Detectieregels verversen mislukt: {e}")

        _refresh_once()

        def _loop():
            while not self._stop.wait(interval):
                _refresh_once()

        self._refresh_thread = threading.Thread(target=_loop, name='rule-refresh', daemon=True)
        self._refresh_thread.start()

    def stop(self):
        self._stop.set()

    # Matching -------------------------------------------------------------

    def _candidates(self, ruleset: _RuleSet, ctx: PacketContext) -> List[CompiledRule]:
        cands: List[CompiledRule] = []
        if ruleset.generic or ruleset.by_port:
            cands.extend(ruleset.generic.get(ctx.proto, ()))
            if ctx.dst_port is not None:
                cands.extend(ruleset.by_port.get((ctx.proto, ctx.dst_port), ()))
        if ruleset.dns and ctx.dns_qname:
            cands.extend(ruleset.dns)
        if ruleset.tls and ctx.tls_meta and ctx.tls_meta.get('handshake_type') == 'client_hello':
            cands.extend(ruleset.tls)
        if ruleset.http and ctx.proto == 'tcp' and ctx.http:
            cands.extend(ruleset.http)
        return cands

    def match(self, packet, tls_meta: Optional[Dict] = None) -> List[Dict[str, Any]]:
        ruleset = self._set
        if not ruleset.rules or not packet.haslayer(IP):
            return []
        ctx = PacketContext(packet, self._is_internal, ruleset.device_classes, tls_meta)
        if ctx.proto == 'other':
            return []
        candidates = self._candidates(ruleset, ctx)
        if not candidates:
            return []

        threats = []
        now = time.time()
        for rule in candidates:
            try:
                if not rule.matches(ctx):
                    continue
            except Exception as e:  # een defecte regel mag de detectie niet stoppen
                self.logger.debug(f"Regel {rule.key} gaf fout: {e}")
                continue
            threat = self._register_hit(rule, ctx, now)
            if threat:
                threats.append(threat)
        return threats

    def _register_hit(self, rule: CompiledRule, ctx: PacketContext, now: float) -> Optional[Dict[str, Any]]:
        if rule.track_by == 'src':
            track = ctx.src_ip
        elif rule.track_by == 'dst':
            track = ctx.dst_ip
        else:
            track = f'{ctx.src_ip}>{ctx.dst_ip}'
        key = (rule.id if rule.id is not None else rule.key, track)

        last = self._last_alert.get(key)
        if last is not None and rule.cooldown and now - last < rule.cooldown:
            return None

        count = 1
        if rule.threshold_count > 1:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= MAX_STATE_ENTRIES:
                    self._prune(now)
                hits = deque(maxlen=rule.threshold_count)
                self._hits[key] = hits
            hits.append(now)
            while hits and now - hits[0] > rule.threshold_window:
                hits.popleft()
            count = len(hits)
            if count < rule.threshold_count:
                return None
            hits.clear()

        if len(self._last_alert) >= MAX_STATE_ENTRIES:
            self._prune(now)
        self._last_alert[key] = now
        return self._build_threat(rule, ctx, count)

    def _prune(self, now: float) -> None:
        self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < 3600}
        self._last_alert = {k: v for k, v in self._last_alert.items() if now - v < 7 * 86400}

    @staticmethod
    def _build_threat(rule: CompiledRule, ctx: PacketContext, count: int) -> Dict[str, Any]:
        detail = ''
        if rule.kind == 'dns' and ctx.dns_qname:
            detail = f' (DNS {ctx.dns_qtype} {ctx.dns_qname})'
        elif rule.kind == 'tls' and ctx.tls_sni:
            detail = f' (TLS SNI {ctx.tls_sni})'
        elif rule.kind == 'http' and ctx.http:
            detail = f" (HTTP {ctx.http['method']} {ctx.http['uri'][:120]})"
        elif ctx.dst_port is not None:
            detail = f' ({ctx.proto.upper()}/{ctx.dst_port})'
        if count > 1:
            detail += f', {count}x binnen {rule.threshold_window}s'
        prefix = f'[{rule.cve}] ' if rule.cve else ''

        metadata = {
            'rule_id': rule.id,
            'rule_key': rule.key,
            'rule_name': rule.name,
            'match_count': count,
            'protocol': ctx.proto,
            'direction': ctx.direction,
        }
        for attr, value in (('cve', rule.cve), ('reference_url', rule.reference_url),
                            ('dns_query', ctx.dns_qname), ('tls_sni', ctx.tls_sni or None),
                            ('destination_port', ctx.dst_port),
                            ('device_class', ctx.device_classes.get(ctx.src_ip))):
            if value:
                metadata[attr] = value
        if rule.kind == 'http' and ctx.http:
            metadata['http_method'] = ctx.http['method']
            metadata['http_uri'] = ctx.http['uri'][:500]
            if ctx.http['host']:
                metadata['http_host'] = ctx.http['host'][:255]

        return {
            'type': rule.alert_type,
            'severity': rule.severity,
            'source_ip': ctx.src_ip,
            'destination_ip': ctx.dst_ip,
            'description': f'{prefix}{rule.name}{detail}',
            'metadata': metadata,
        }


# ---------------------------------------------------------------------------
# Standaardregels (worden bij een schema-update toegevoegd als ze nog niet
# bestaan; een beheerder kan ze uitzetten of aanpassen, niet verwijderen).
# ---------------------------------------------------------------------------

_DOH_HOSTS = [
    'dns.google', 'dns.google.com', 'cloudflare-dns.com', 'one.one.one.one',
    'dns.quad9.net', 'doh.opendns.com', 'dns.adguard-dns.com', 'dns.nextdns.io',
    'doh.cleanbrowsing.org', 'doh.mullvad.net', 'dns.controld.com',
]
_DOH_IPS = [
    '1.1.1.1/32', '1.0.0.1/32', '8.8.8.8/32', '8.8.4.4/32', '9.9.9.9/32',
    '149.112.112.112/32', '208.67.222.222/32', '208.67.220.220/32',
    '94.140.14.14/32', '94.140.15.15/32',
]

BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        'rule_key': 'builtin.doh-from-iot',
        'name': 'IoT-apparaat gebruikt DNS-over-HTTPS',
        'description': 'IoT-botnets (o.a. JackSkid) zoeken hun C2-adres op via DoH, '
                       'waardoor DNS-tunnel- en DGA-detectie het niet ziet. '
                       'Een IoT-apparaat hoort de lokale resolver te gebruiken.',
        'reference_url': 'https://github.com/deepfield/public-research/blob/main/reports/2026-03-20-aisuru-ecosystem.md',
        'severity': 'MEDIUM', 'alert_type': 'DOH_FROM_IOT',
        'match': {'tls_sni_suffix': _DOH_HOSTS, 'direction': 'outbound', 'device_class': ['iot']},
        'threshold_count': 1, 'threshold_window': 60, 'cooldown': 3600, 'track_by': 'src',
    },
    {
        'rule_key': 'builtin.doh-ip-from-iot',
        'name': 'IoT-apparaat verbindt met publieke DoH-resolver op IP',
        'description': 'Zelfde patroon als DoH via hostnaam, maar direct naar het IP-adres '
                       '(zonder SNI) van een publieke resolver op poort 443.',
        'severity': 'MEDIUM', 'alert_type': 'DOH_FROM_IOT',
        'match': {'protocol': 'tcp', 'dst_port': '443', 'dst_cidr': _DOH_IPS,
                  'new_connection': True, 'direction': 'outbound', 'device_class': ['iot']},
        'threshold_count': 1, 'threshold_window': 60, 'cooldown': 3600, 'track_by': 'src',
    },
    {
        'rule_key': 'builtin.dns-txt-burst-iot',
        'name': 'IoT-apparaat doet veel DNS TXT-opvragingen',
        'description': 'AISURU en TuxBot v3 halen C2-gegevens op via TXT-records. '
                       'IoT-apparaten hebben TXT-records normaal nauwelijks nodig.',
        'reference_url': 'https://thehackernews.com/2026/07/tuxbot-v3-evolution-shows-signs-of-llm.html',
        'severity': 'MEDIUM', 'alert_type': 'DNS_TXT_C2_SUSPECTED',
        'match': {'dns_qtype': ['TXT'], 'device_class': ['iot']},
        'threshold_count': 10, 'threshold_window': 600, 'cooldown': 3600, 'track_by': 'src',
    },
    {
        'rule_key': 'builtin.ens-blockchain-c2',
        'name': 'Opvraging van ENS-/blockchain-domein',
        'description': 'Botnets als Dysphoria vinden hun C2-server via Ethereum Name Service '
                       '(.eth) of publieke Ethereum-RPC-diensten.',
        'reference_url': 'https://thehackernews.com/2026/07/dysphoria-iot-botnet-adds-blockchain-c2.html',
        'severity': 'MEDIUM', 'alert_type': 'BLOCKCHAIN_C2_SUSPECTED',
        'match': {'dns_qname_suffix': ['eth', 'eth.limo', 'eth.link', 'eth.sucks']},
        'threshold_count': 1, 'threshold_window': 60, 'cooldown': 3600, 'track_by': 'src',
    },
    {
        'rule_key': 'builtin.eth-rpc-from-device',
        'name': 'IoT-/serverapparaat praat met Ethereum-RPC-dienst',
        'description': 'Blockchain-RPC wordt gebruikt om C2-adressen uit smart contracts te lezen. '
                       'Op werkplekken kan dit legitiem zijn (wallets), daarom alleen voor '
                       'IoT, infrastructuur en servers.',
        'severity': 'MEDIUM', 'alert_type': 'BLOCKCHAIN_C2_SUSPECTED',
        'match': {'dns_qname_suffix': ['infura.io', 'alchemy.com', 'alchemyapi.io',
                                       'cloudflare-eth.com', 'rpc.ankr.com', 'llamarpc.com',
                                       'ethereum-rpc.publicnode.com', 'etherscan.io',
                                       'quiknode.pro', 'blastapi.io'],
                  'device_class': ['iot', 'infrastructure', 'server']},
        'threshold_count': 1, 'threshold_window': 60, 'cooldown': 3600, 'track_by': 'src',
    },
    {
        'rule_key': 'builtin.dead-drop-from-iot',
        'name': 'IoT-/netwerkapparaat bezoekt dead-drop-dienst',
        'description': 'Malware haalt C2-instructies op van Telegram, Pastebin en vergelijkbare '
                       'diensten (dead drop resolver). Voor IoT en netwerkapparatuur is dat '
                       'vrijwel nooit legitiem.',
        'reference_url': 'https://www.trellix.com/advanced-research-center/threat-reports/november-2026/',
        'severity': 'HIGH', 'alert_type': 'DEAD_DROP_RESOLVER',
        'match': {'dns_qname_suffix': ['api.telegram.org', 'pastebin.com', 'paste.ee',
                                       'rentry.co', 'telegra.ph', 'hastebin.com',
                                       'ghostbin.site', 'dpaste.org'],
                  'device_class': ['iot', 'infrastructure']},
        'threshold_count': 1, 'threshold_window': 60, 'cooldown': 3600, 'track_by': 'src',
    },
    {
        'rule_key': 'builtin.wireguard-handshake-out',
        'name': 'Uitgaande WireGuard-tunnel opgezet',
        'description': 'WireGuard handshake-initiatie (type 1, 148 bytes) naar buiten. '
                       'Aanvallers installeren VPN-clients om C2-verkeer te verbergen '
                       '(CISA AA26-281A). Whitelist bekende VPN-gateways.',
        'reference_url': 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a',
        'severity': 'MEDIUM', 'alert_type': 'VPN_TUNNEL_DETECTED',
        'match': {'protocol': 'udp', 'direction': 'outbound',
                  'payload_hex_prefix': '01000000', 'payload_size': '148'},
        'threshold_count': 1, 'threshold_window': 60, 'cooldown': 21600, 'track_by': 'pair',
    },
    {
        'rule_key': 'builtin.openvpn-out',
        'name': 'Uitgaande OpenVPN-verbinding',
        'description': 'Verbinding naar de standaard OpenVPN-poort 1194. '
                       'Aanvallers installeren VPN-clients om C2-verkeer te verbergen '
                       '(CISA AA26-281A). Whitelist bekende VPN-gateways.',
        'reference_url': 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a',
        'severity': 'MEDIUM', 'alert_type': 'VPN_TUNNEL_DETECTED',
        'match': {'dst_port': '1194', 'direction': 'outbound'},
        'threshold_count': 3, 'threshold_window': 60, 'cooldown': 21600, 'track_by': 'pair',
    },
    {
        'rule_key': 'builtin.remote-access-tool',
        'name': 'Remote-access- of tunneldienst gebruikt',
        'description': 'AnyDesk, RustDesk, ScreenConnect, Tailscale, ZeroTier, ngrok en '
                       'Cloudflare-tunnels worden door aanvallers gebruikt voor blijvende '
                       'toegang. Kan legitiem zijn; whitelist bekend gebruik.',
        'severity': 'LOW', 'alert_type': 'REMOTE_ACCESS_TOOL',
        'match': {'dns_qname_suffix': ['net.anydesk.com', 'anydesk.com', 'rustdesk.com',
                                       'screenconnect.com', 'controlplane.tailscale.com',
                                       'my.zerotier.com', 'ngrok.io', 'ngrok-free.app',
                                       'ngrok.app', 'trycloudflare.com']},
        'threshold_count': 1, 'threshold_window': 60, 'cooldown': 86400, 'track_by': 'src',
    },
]
