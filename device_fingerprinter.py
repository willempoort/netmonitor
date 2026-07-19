# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Device Fingerprinting

Improves device classification with identity evidence instead of purely
behavioral (traffic) features:

Passive (always available, no packets sent):
- Hostname heuristics: DHCP/mDNS hostnames often literally name the device
  ("iPhone", "Tab-A8-van-Willem", "MacBook", "sonos*", "shsw-*").

Active (LAN-only, low-risk, config-gated):
- mDNS query (UDP 5353): reverse PTR -> .local hostname, service enumeration
  (_airplay, _sonos, _ipp, ...), and Apple's _device-info TXT (model=...).
- SSDP M-SEARCH (UDP multicast 1900) + description XML: friendlyName,
  modelName, manufacturer for TVs, speakers, printers, routers.
- NetBIOS node status query (UDP 137): Windows machine name + workgroup.
- LLMNR reverse PTR (UDP 5355): Windows hostname fallback.
- SNMP v2c sysDescr/sysName (UDP 161): network gear self-description.

All probes are single small UDP packets (plus one HTTP GET for the SSDP
description XML) with short timeouts - nothing here scans ports or fuzzes
services. Active probes must run from an interface with L2/L3 reach to the
devices (the management interface - a SPAN port is receive-only).

Identity evidence from this module outranks the behavioral ML classifier in
ml_classifier.py: a RandomForest trained on a skewed dataset will confidently
call a tablet an "iot_sensor", but a hostname "Tab-A8-..." or an mDNS model
string is direct identity information.
"""

import logging
import os
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional
from xml.etree import ElementTree

logger = logging.getLogger('NetMonitor.DeviceFingerprinter')

try:
    import dns.message
    import dns.rdatatype
    import dns.reversename
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ==================== Passive: hostname heuristics ====================

# Ordered: first match wins, so specific patterns go before generic ones.
# template_name None means "use the default template for the device_type"
# (DEVICE_CATEGORIES in ml_classifier.py).
# Confidences are deliberately below fingerprint-based evidence (~0.95):
# a hostname is user-editable, a probed model string is not.
HOSTNAME_PATTERNS = [
    # Apple mobile/wearable/desktop
    (re.compile(r'ipad', re.I), 'mobile', 'Tablet (iOS)', 0.9,
     'Hostname contains "iPad"'),
    (re.compile(r'iphone', re.I), 'mobile', 'Smartphone (iOS)', 0.9,
     'Hostname contains "iPhone"'),
    (re.compile(r'(apple[-_ ]?watch|galaxy[-_ ]?watch|(^|[-_])watch([-_.]|$))', re.I),
     'smartwatch', 'Smartwatch', 0.85, 'Hostname suggests a smartwatch'),
    (re.compile(r'(macbook|imac|mac[-_ ]?(mini|pro|studio))', re.I),
     'workstation', 'Workstation', 0.9, 'Hostname suggests a Mac'),
    # Android tablets ("Tab-A8-van-Willem", "galaxy-tab-s7", "Lenovo-Tab")
    (re.compile(r'(galaxy[-_ ]?tab|(^|[-_])tab[-_][a-z0-9]|tablet)', re.I),
     'mobile', 'Tablet (Android)', 0.85, 'Hostname suggests an Android tablet'),
    # Windows default hostnames
    (re.compile(r'^(desktop|laptop)-[a-z0-9]+', re.I),
     'workstation', 'Workstation', 0.85, 'Windows default hostname pattern'),
    # Speakers / TV
    (re.compile(r'sonos', re.I), 'smart_speaker', 'Smart Speaker', 0.9,
     'Hostname contains "sonos"'),
    (re.compile(r'(chromecast|appletv|apple[-_ ]?tv|(^|[-_])(bravia|webos)([-_.]|$))', re.I),
     'smart_tv', 'Smart TV', 0.85, 'Hostname suggests a TV/cast device'),
    # Shelly smart-home devices announce as shsw-/shdm-/shplg-/shelly*
    (re.compile(r'(shelly|(^|[-_.])sh(sw|dm|plg|rgbw)-)', re.I),
     'iot_sensor', None, 0.85, 'Shelly hostname pattern'),
    # Cameras / doorbells
    (re.compile(r'(camera|(^|[-_.])cam[0-9]*([-_.]|$)|doorbell|front[-_]?door|reolink)', re.I),
     'iot_camera', None, 0.8, 'Hostname suggests a camera'),
    # Generic sensor naming ("sensor-edfe33", "temp-sensor")
    (re.compile(r'(^|[-_.])sensor([-_.]|$|[0-9a-f])', re.I),
     'iot_sensor', None, 0.8, 'Hostname suggests a sensor'),
    # Printers
    (re.compile(r'(printer|laserjet|officejet|deskjet|(^|[-_.])(epson|brother|canon)[-_.]?[a-z0-9]*)', re.I),
     'printer', None, 0.8, 'Hostname suggests a printer'),
]


def infer_from_hostname(hostname: Optional[str]) -> Optional[Dict]:
    """
    Infer device type from a hostname pattern.

    Returns {'device_type', 'template_name', 'confidence', 'reason'} or None.
    template_name may be None (use the type's default template).
    """
    if not hostname:
        return None
    # Strip domain suffix so patterns anchor on the bare name
    bare = hostname.split('.')[0]
    for pattern, device_type, template_name, confidence, reason in HOSTNAME_PATTERNS:
        if pattern.search(bare):
            return {
                'device_type': device_type,
                'template_name': template_name,
                'confidence': confidence,
                'reason': f'{reason} ("{bare}")',
                'source': 'hostname'
            }
    return None


# ==================== Fingerprint interpretation ====================

# Substring -> (device_type, template_name) for probed model/description
# strings. Checked lowercase, first match wins; specific before generic.
MODEL_KEYWORDS = [
    ('ipad', ('mobile', 'Tablet (iOS)')),
    ('iphone', ('mobile', 'Smartphone (iOS)')),
    ('watch', ('smartwatch', 'Smartwatch')),
    ('macbook', ('workstation', 'Workstation')),
    ('imac', ('workstation', 'Workstation')),
    ('macmini', ('workstation', 'Workstation')),
    ('appletv', ('smart_tv', 'Smart TV')),
    ('audioaccessory', ('smart_speaker', 'Smart Speaker')),  # HomePod
    ('sonos', ('smart_speaker', None)),
    ('chromecast', ('smart_tv', None)),
    ('google home', ('smart_speaker', None)),
    ('nest', ('smart_speaker', None)),
    ('roku', ('smart_tv', None)),
    ('bravia', ('smart_tv', None)),
    (' tv', ('smart_tv', None)),
    ('television', ('smart_tv', None)),
    ('printer', ('printer', None)),
    ('laserjet', ('printer', None)),
    ('officejet', ('printer', None)),
    ('camera', ('iot_camera', None)),
    ('hue bridge', ('iot_sensor', 'Home Automation Hub')),
    ('homey', ('iot_sensor', 'Home Automation Hub')),
    ('router', ('network_device', None)),
    ('gateway', ('network_device', None)),
    ('access point', ('network_device', 'Access Point')),
    ('switch', ('network_device', 'Network Switch')),
    ('firewall', ('network_device', None)),
    ('nas', ('nas', None)),
    ('diskstation', ('nas', None)),
    ('synology', ('nas', None)),
]

# mDNS service type -> (device_type, template_name, confidence)
SERVICE_HINTS = [
    ('_sonos', ('smart_speaker', None, 0.95)),
    ('_ipp', ('printer', None, 0.9)),
    ('_printer', ('printer', None, 0.9)),
    ('_pdl-datastream', ('printer', None, 0.9)),
    ('_googlecast', ('smart_tv', None, 0.75)),
    ('_spotify-connect', ('smart_speaker', None, 0.7)),
    ('_raop', ('smart_speaker', None, 0.7)),  # AirPlay audio
    ('_hap', ('iot_sensor', None, 0.7)),      # HomeKit accessory
    ('_smb', ('nas', None, 0.7)),
    ('_afpovertcp', ('nas', None, 0.7)),
    # Not a service type but a service *instance* prefix: Shelly devices
    # advertise e.g. "shellydimmer-D3E7B4._http._tcp".
    ('shelly', ('iot_sensor', None, 0.9)),
]


def _match_model_keywords(text: str) -> Optional[tuple]:
    text_lower = text.lower()
    for keyword, mapping in MODEL_KEYWORDS:
        if keyword in text_lower:
            return mapping
    return None


def interpret_fingerprint(fingerprint: Optional[Dict]) -> Optional[Dict]:
    """
    Turn raw probe evidence into a classification suggestion.

    Returns {'device_type', 'template_name', 'confidence', 'reason'} or None.
    Evidence order: probed model strings (strongest - the device names its own
    model), then SNMP sysDescr, then mDNS service types, then NetBIOS
    presence (weakest - only proves "a Windows machine").
    """
    if not fingerprint:
        return None

    mdns = fingerprint.get('mdns') or {}
    ssdp = fingerprint.get('ssdp') or {}
    netbios = fingerprint.get('netbios') or {}
    snmp = fingerprint.get('snmp') or {}

    # 1. Explicit model strings (mDNS device-info, SSDP description XML)
    model_sources = [
        (mdns.get('model'), 'mDNS device-info model'),
        (ssdp.get('model'), 'SSDP modelName'),
        (ssdp.get('friendly_name'), 'SSDP friendlyName'),
        (ssdp.get('manufacturer'), 'SSDP manufacturer'),
        (ssdp.get('server'), 'SSDP server header'),
    ]
    for value, source in model_sources:
        if not value:
            continue
        match = _match_model_keywords(str(value))
        if match:
            device_type, template_name = match
            return {
                'device_type': device_type,
                'template_name': template_name,
                'confidence': 0.95,
                'reason': f'{source}: "{value}"',
                'source': 'fingerprint'
            }

    # 2. SNMP self-description (network gear, printers)
    sysdescr = snmp.get('sysdescr')
    if sysdescr:
        match = _match_model_keywords(str(sysdescr))
        if match:
            device_type, template_name = match
            return {
                'device_type': device_type,
                'template_name': template_name,
                'confidence': 0.9,
                'reason': f'SNMP sysDescr: "{str(sysdescr)[:80]}"',
                'source': 'fingerprint'
            }

    # 3. Advertised mDNS service types
    services = mdns.get('services') or []
    for service_prefix, (device_type, template_name, confidence) in SERVICE_HINTS:
        if any(service_prefix in s for s in services):
            return {
                'device_type': device_type,
                'template_name': template_name,
                'confidence': confidence,
                'reason': f'mDNS service {service_prefix} advertised',
                'source': 'fingerprint'
            }

    # 4. NetBIOS answer = a Windows machine; workstation unless the name
    #    suggests otherwise (servers usually carry it in their name).
    nb_name = netbios.get('name')
    if nb_name:
        if re.search(r'(srv|server|dc[0-9]|sql|exch)', nb_name, re.I):
            return {
                'device_type': 'server',
                'template_name': None,
                'confidence': 0.75,
                'reason': f'NetBIOS name "{nb_name}" suggests a server',
                'source': 'fingerprint'
            }
        return {
            'device_type': 'workstation',
            'template_name': None,
            'confidence': 0.75,
            'reason': f'Responds to NetBIOS as "{nb_name}" (Windows)',
            'source': 'fingerprint'
        }

    return None


# ==================== Active probes ====================

class DeviceFingerprinter:
    """
    Light active LAN polling. All probes are config-gated and degrade
    silently: a device that doesn't answer simply contributes no evidence.
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        fp_config = self.config.get('fingerprinting', {})

        self.active_enabled = fp_config.get('active_polling', True)
        self.mdns_enabled = fp_config.get('mdns', True) and DNSPYTHON_AVAILABLE
        self.ssdp_enabled = fp_config.get('ssdp', True)
        self.netbios_enabled = fp_config.get('netbios', True)
        self.llmnr_enabled = fp_config.get('llmnr', True) and DNSPYTHON_AVAILABLE
        self.snmp_enabled = fp_config.get('snmp', True)
        self.snmp_community = fp_config.get('snmp_community', 'public')
        self.probe_timeout = float(fp_config.get('probe_timeout', 1.0))
        self.max_parallel = int(fp_config.get('max_parallel', 8))

        if not DNSPYTHON_AVAILABLE:
            logger.warning("dnspython not available - mDNS/LLMNR probes disabled")

    # ---------- DNS-wire helpers (mDNS / LLMNR) ----------

    def _dns_query(self, qname: str, rdtype: str, server: str, port: int) -> Optional['dns.message.Message']:
        """One-shot DNS-format query over UDP; returns parsed reply or None.

        Raw sockets instead of dns.query.udp: mDNS replies often carry
        id=0 instead of echoing the query id, which dns.query rejects.
        """
        try:
            query = dns.message.make_query(qname, rdtype)
            query.flags = 0  # mDNS/LLMNR: no RD
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.probe_timeout)
            try:
                sock.sendto(query.to_wire(), (server, port))
                data, _ = sock.recvfrom(9000)
                return dns.message.from_wire(data, ignore_trailing=True)
            finally:
                sock.close()
        except (socket.timeout, OSError):
            return None
        except Exception as e:
            logger.debug(f"DNS-format query to {server}:{port} failed: {e}")
            return None

    def probe_mdns(self, ip: str) -> Dict:
        """Query a device's mDNS responder directly (one-shot unicast)."""
        result = {}
        if not self.mdns_enabled:
            return result

        # Reverse PTR -> hostname.local
        try:
            reverse_name = str(dns.reversename.from_address(ip))
        except Exception:
            return result
        reply = self._dns_query(reverse_name, 'PTR', ip, 5353)
        hostname = None
        if reply:
            for rrset in reply.answer:
                if rrset.rdtype == dns.rdatatype.PTR:
                    hostname = str(rrset[0].target).rstrip('.')
                    break
        if hostname:
            result['hostname'] = hostname

        # Advertised service types
        reply = self._dns_query('_services._dns-sd._udp.local.', 'PTR', ip, 5353)
        if reply:
            services = sorted({
                str(rr.target).rstrip('.').replace('.local', '')
                for rrset in reply.answer if rrset.rdtype == dns.rdatatype.PTR
                for rr in rrset
            })
            if services:
                result['services'] = services

        # Apple _device-info TXT: model=MacBookPro18,3 / Watch6,7 / iPad13,4
        if hostname:
            instance = hostname.replace('.local', '')
            reply = self._dns_query(f'{instance}._device-info._tcp.local.', 'TXT', ip, 5353)
            if reply:
                for rrset in reply.answer + reply.additional:
                    if rrset.rdtype != dns.rdatatype.TXT:
                        continue
                    for rr in rrset:
                        for txt in rr.strings:
                            txt = txt.decode('utf-8', errors='replace')
                            if txt.startswith('model='):
                                result['model'] = txt[len('model='):]
        return result

    # ---------- SSDP ----------

    def probe_ssdp_sweep(self, wait: float = 3.0) -> Dict[str, Dict]:
        """
        One multicast M-SEARCH; collect responses per source IP and enrich
        with the device description XML the LOCATION header points at.
        """
        results: Dict[str, Dict] = {}
        if not self.ssdp_enabled:
            return results

        message = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 2\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        ).encode('ascii')

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(0.5)
            sock.sendto(message, ('239.255.255.250', 1900))
            sock.sendto(message, ('239.255.255.250', 1900))

            deadline = time.time() + wait
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                headers = {}
                for line in data.decode('utf-8', errors='replace').split('\r\n')[1:]:
                    if ':' in line:
                        key, _, value = line.partition(':')
                        headers[key.strip().lower()] = value.strip()
                entry = results.setdefault(addr[0], {})
                if headers.get('server') and 'server' not in entry:
                    entry['server'] = headers['server']
                if headers.get('location') and 'location' not in entry:
                    entry['location'] = headers['location']
            sock.close()
        except OSError as e:
            logger.debug(f"SSDP sweep failed: {e}")
            return results

        # Fetch description XML per device (friendlyName/modelName/manufacturer)
        if REQUESTS_AVAILABLE:
            for ip, entry in results.items():
                location = entry.get('location')
                if not location:
                    continue
                try:
                    response = requests.get(location, timeout=3)
                    root = ElementTree.fromstring(response.content)
                    # Strip XML namespaces for painless findall
                    for element in root.iter():
                        element.tag = element.tag.partition('}')[2] or element.tag
                    device = root.find('device')
                    if device is not None:
                        for xml_field, key in [('friendlyName', 'friendly_name'),
                                               ('modelName', 'model'),
                                               ('manufacturer', 'manufacturer'),
                                               ('deviceType', 'device_type')]:
                            value = device.findtext(xml_field)
                            if value:
                                entry[key] = value.strip()
                except Exception as e:
                    logger.debug(f"SSDP description fetch from {location} failed: {e}")
        return results

    # ---------- NetBIOS ----------

    def probe_netbios(self, ip: str) -> Dict:
        """NetBIOS node status query (NBSTAT '*') - Windows name + workgroup."""
        result = {}
        if not self.netbios_enabled:
            return result

        transaction_id = os.urandom(2)
        # Header: id, flags=0, qdcount=1; question: encoded '*' name, NBSTAT, IN
        packet = (
            transaction_id + b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            + b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'
            + b'\x00\x21\x00\x01'
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.probe_timeout)
            try:
                sock.sendto(packet, (ip, 137))
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()
        except (socket.timeout, OSError):
            return result

        if len(data) < 57 or data[:2] != transaction_id:
            return result
        try:
            # Skip header(12) + name(34) + type/class/ttl/rdlength(10)
            offset = 56
            num_names = data[offset]
            offset += 1
            for _ in range(num_names):
                if offset + 18 > len(data):
                    break
                raw_name = data[offset:offset + 15]
                suffix = data[offset + 15]
                flags = struct.unpack('>H', data[offset + 16:offset + 18])[0]
                offset += 18
                name = raw_name.decode('ascii', errors='replace').rstrip()
                if suffix == 0x00:
                    if flags & 0x8000:  # group name = workgroup/domain
                        result.setdefault('domain', name)
                    else:
                        result.setdefault('name', name)
        except Exception as e:
            logger.debug(f"NetBIOS parse for {ip} failed: {e}")
        return result

    # ---------- LLMNR ----------

    def probe_llmnr(self, ip: str) -> Dict:
        """LLMNR reverse PTR (UDP 5355) - Windows hostname fallback."""
        result = {}
        if not self.llmnr_enabled:
            return result
        try:
            reverse_name = str(dns.reversename.from_address(ip))
        except Exception:
            return result
        reply = self._dns_query(reverse_name, 'PTR', ip, 5355)
        if reply:
            for rrset in reply.answer:
                if rrset.rdtype == dns.rdatatype.PTR:
                    result['hostname'] = str(rrset[0].target).rstrip('.')
                    break
        return result

    # ---------- SNMP (v2c, minimal BER - no external dependency) ----------

    @staticmethod
    def _ber_encode(tag: int, content: bytes) -> bytes:
        length = len(content)
        if length < 0x80:
            return bytes([tag, length]) + content
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + content

    @classmethod
    def _ber_int(cls, value: int) -> bytes:
        if value == 0:
            return cls._ber_encode(0x02, b'\x00')
        content = value.to_bytes((value.bit_length() + 8) // 8, 'big')
        return cls._ber_encode(0x02, content)

    @classmethod
    def _ber_oid(cls, oid: str) -> bytes:
        parts = [int(p) for p in oid.strip('.').split('.')]
        content = bytes([40 * parts[0] + parts[1]])
        for part in parts[2:]:
            if part < 0x80:
                content += bytes([part])
            else:
                encoded = [part & 0x7F]
                part >>= 7
                while part:
                    encoded.append(0x80 | (part & 0x7F))
                    part >>= 7
                content += bytes(reversed(encoded))
        return cls._ber_encode(0x06, content)

    @staticmethod
    def _ber_decode(data: bytes, offset: int = 0):
        """Decode one TLV; returns (tag, content, next_offset)."""
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        if length & 0x80:
            num_bytes = length & 0x7F
            length = int.from_bytes(data[offset:offset + num_bytes], 'big')
            offset += num_bytes
        return tag, data[offset:offset + length], offset + length

    def probe_snmp(self, ip: str) -> Dict:
        """SNMP v2c GET for sysDescr.0 and sysName.0."""
        result = {}
        if not self.snmp_enabled:
            return result

        oids = {'sysdescr': '1.3.6.1.2.1.1.1.0', 'sysname': '1.3.6.1.2.1.1.5.0'}
        request_id = int.from_bytes(os.urandom(3), 'big')
        varbinds = b''.join(
            self._ber_encode(0x30, self._ber_oid(oid) + self._ber_encode(0x05, b''))
            for oid in oids.values()
        )
        pdu = self._ber_encode(0xA0, (
            self._ber_int(request_id) + self._ber_int(0) + self._ber_int(0)
            + self._ber_encode(0x30, varbinds)
        ))
        message = self._ber_encode(0x30, (
            self._ber_int(1)  # version = SNMPv2c
            + self._ber_encode(0x04, self.snmp_community.encode('ascii'))
            + pdu
        ))

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.probe_timeout)
            try:
                sock.sendto(message, (ip, 161))
                data, _ = sock.recvfrom(8192)
            finally:
                sock.close()
        except (socket.timeout, OSError):
            return result

        try:
            _, msg_content, _ = self._ber_decode(data)             # SEQUENCE
            _, _, offset = self._ber_decode(msg_content)           # version
            _, _, offset = self._ber_decode(msg_content, offset)   # community
            pdu_tag, pdu_content, _ = self._ber_decode(msg_content, offset)
            if pdu_tag != 0xA2:  # GetResponse
                return result
            _, _, offset = self._ber_decode(pdu_content)           # request-id
            _, _, offset = self._ber_decode(pdu_content, offset)   # error-status
            _, _, offset = self._ber_decode(pdu_content, offset)   # error-index
            _, vb_list, _ = self._ber_decode(pdu_content, offset)

            values = []
            offset = 0
            while offset < len(vb_list):
                _, varbind, offset = self._ber_decode(vb_list, offset)
                _, _, value_offset = self._ber_decode(varbind)     # OID
                value_tag, value, _ = self._ber_decode(varbind, value_offset)
                values.append(value.decode('utf-8', errors='replace')
                              if value_tag == 0x04 else None)
            for key, value in zip(oids.keys(), values):
                if value:
                    result[key] = value
        except Exception as e:
            logger.debug(f"SNMP parse for {ip} failed: {e}")
        return result

    # ---------- Orchestration ----------

    def fingerprint_device(self, ip: str, ssdp_data: Dict = None) -> Dict:
        """Run all per-device probes; returns only sections with evidence."""
        fingerprint = {}
        if ssdp_data:
            fingerprint['ssdp'] = ssdp_data
        if not self.active_enabled:
            return fingerprint

        mdns = self.probe_mdns(ip)
        if mdns:
            fingerprint['mdns'] = mdns
        netbios = self.probe_netbios(ip)
        if netbios:
            fingerprint['netbios'] = netbios
        elif not mdns:
            llmnr = self.probe_llmnr(ip)
            if llmnr:
                fingerprint['llmnr'] = llmnr
        snmp = self.probe_snmp(ip)
        if snmp:
            fingerprint['snmp'] = snmp

        if fingerprint:
            fingerprint['scanned_at'] = datetime.now().isoformat()
        return fingerprint

    def scan(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """
        Fingerprint a list of IPs: one SSDP multicast sweep, then parallel
        per-device probes. Returns {ip: fingerprint} for IPs with evidence.
        """
        # Normalize '10.0.0.5/32' (inet::text) to '10.0.0.5'
        ips = [ip.split('/')[0] for ip in ip_addresses if ip]

        ssdp_results = self.probe_ssdp_sweep() if self.active_enabled else {}

        results: Dict[str, Dict] = {}
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            futures = {
                ip: pool.submit(self.fingerprint_device, ip, ssdp_results.get(ip))
                for ip in ips
            }
            for ip, future in futures.items():
                try:
                    fingerprint = future.result()
                    if fingerprint:
                        results[ip] = fingerprint
                except Exception as e:
                    logger.debug(f"Fingerprint scan of {ip} failed: {e}")

        logger.info(
            f"Fingerprint scan: {len(results)}/{len(ips)} devices returned evidence "
            f"(ssdp: {len(ssdp_results)})"
        )
        return results
