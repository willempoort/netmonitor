# SPDX-License-Identifier: AGPL-3.0-only
"""Tests voor detectieregels uit de database (rule_engine.py)."""
import time

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

import rule_engine as re_mod
from rule_engine import RuleEngine, RuleValidationError, validate_rule, validate_match

pytestmark = pytest.mark.unit

INTERNAL = '10.100.0.50'
EXTERNAL = '93.184.216.34'


def rule(**kw):
    base = {'id': kw.pop('id', 1), 'name': kw.pop('name', 'Test'), 'severity': 'HIGH'}
    base.update(kw)
    return base


def engine(*rules, classes=None):
    e = RuleEngine()
    e.load(list(rules), classes or {})
    return e


def dns_query(src, qname, qtype='A'):
    return IP(src=src, dst='10.100.0.1') / UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))


class TestValidation:
    def test_unknown_field_rejected(self):
        with pytest.raises(RuleValidationError, match='onbekende velden'):
            validate_match({'dst_port': '80', 'exec': 'rm -rf /'})

    def test_too_broad_rejected(self):
        with pytest.raises(RuleValidationError, match='te breed'):
            validate_match({'protocol': 'tcp', 'direction': 'outbound'})

    def test_nested_quantifier_rejected(self):
        with pytest.raises(RuleValidationError, match='ReDoS'):
            validate_match({'payload_regex': '(a+)+b'})

    def test_backreference_rejected(self):
        with pytest.raises(RuleValidationError, match='backreference'):
            validate_match({'payload_regex': r'(a)\1'})

    def test_mixed_kinds_rejected(self):
        with pytest.raises(RuleValidationError, match='tegelijk'):
            validate_match({'dns_qtype': ['TXT'], 'tls_sni_suffix': ['x.com']})

    def test_port_spec_normalised(self):
        assert validate_match({'dst_port': [80, '8000-8010']})['dst_port'] == '80,8000-8010'

    def test_bad_cve(self):
        with pytest.raises(RuleValidationError, match='cve'):
            validate_rule(rule(cve='2026-1234', match={'dst_port': '80'}))

    def test_rule_key_derived_from_name(self):
        assert validate_rule(rule(name='Plex Exploit!', match={'dst_port': '32400'}))['rule_key'] == 'plex-exploit'

    def test_builtins_valid(self):
        for b in re_mod.BUILTIN_RULES:
            validate_rule(b)

    def test_invalid_rule_skipped_on_load(self):
        e = RuleEngine()
        n = e.load([rule(id=1, match={'dst_port': '80'}), rule(id=2, match={'bogus': 1})])
        assert n == 1 and e.errors and e.errors[0]['id'] == 2


class TestPacketRules:
    def test_port_and_direction(self):
        e = engine(rule(match={'protocol': 'tcp', 'dst_port': '32400', 'direction': 'inbound'}))
        assert e.match(IP(src=EXTERNAL, dst=INTERNAL) / TCP(dport=32400, flags='S'))
        e2 = engine(rule(match={'protocol': 'tcp', 'dst_port': '32400', 'direction': 'inbound'}))
        assert not e2.match(IP(src=INTERNAL, dst=EXTERNAL) / TCP(dport=32400, flags='S'))

    def test_payload_contains_nocase(self):
        e = engine(rule(match={'dst_port': '80', 'payload_contains': ['CMD.EXE']}))
        assert e.match(IP(src=EXTERNAL, dst=INTERNAL) / TCP(dport=80) / Raw(b'GET /?x=cmd.exe HTTP/1.1\r\n\r\n'))

    def test_wireguard_builtin(self):
        wg = next(b for b in re_mod.BUILTIN_RULES if b['rule_key'] == 'builtin.wireguard-handshake-out')
        e = engine(dict(wg, id=7))
        pkt = IP(src=INTERNAL, dst=EXTERNAL) / UDP(sport=50000, dport=51820) / Raw(b'\x01\x00\x00\x00' + b'\x00' * 144)
        threats = e.match(pkt)
        assert threats and threats[0]['type'] == 'VPN_TUNNEL_DETECTED'
        assert threats[0]['metadata']['rule_id'] == 7
        # andere grootte: geen match
        e2 = engine(dict(wg, id=7))
        assert not e2.match(IP(src=INTERNAL, dst=EXTERNAL) / UDP(dport=51820) / Raw(b'\x01\x00\x00\x00' + b'\x00' * 200))

    def test_new_connection_only_syn(self):
        e = engine(rule(match={'dst_port': '443', 'dst_cidr': ['1.1.1.1/32'], 'new_connection': True}))
        assert not e.match(IP(src=INTERNAL, dst='1.1.1.1') / TCP(dport=443, flags='A'))
        assert e.match(IP(src=INTERNAL, dst='1.1.1.1') / TCP(dport=443, flags='S'))

    def test_wide_port_range_goes_generic(self):
        e = engine(rule(match={'protocol': 'tcp', 'dst_port': '1024-65535', 'payload_contains': ['xyz']}))
        assert e.match(IP(src=INTERNAL, dst=EXTERNAL) / TCP(dport=40000) / Raw(b'..xyz..'))

    def test_payload_scan_is_capped(self):
        e = engine(rule(match={'dst_port': '80', 'payload_contains': ['needle']}))
        big = b'a' * (re_mod.MAX_SCAN_BYTES + 10) + b'needle'
        assert not e.match(IP(src=EXTERNAL, dst=INTERNAL) / TCP(dport=80) / Raw(big))


class TestDissectedPackets:
    """Live ontleedt scapy bekende poorten in eigen lagen (geen Raw meer)."""

    def test_payload_on_dissected_dns(self):
        e = engine(rule(match={'protocol': 'udp', 'src_port': '53', 'payload_contains': ['rule-engine-test']}))
        raw = bytes(IP(src='1.1.1.1', dst=INTERNAL) / UDP(sport=53, dport=40000) /
                    DNS(qr=1, qd=DNSQR(qname='probe.rule-engine-test.invalid')))
        pkt = IP(raw)
        assert pkt.haslayer(DNS) and not pkt.haslayer(Raw)
        assert e.match(pkt)

    def test_http_on_port_80_dissected(self):
        from scapy.layers.http import HTTPRequest  # noqa: F401  (activeert de binding op poort 80)
        e = engine(rule(match={'http_uri_contains': ['/cgi-bin/'], 'http_method': ['GET']}))
        raw = bytes(IP(src=EXTERNAL, dst=INTERNAL) / TCP(sport=4444, dport=80, flags='PA') /
                    Raw(b'GET /cgi-bin/luci HTTP/1.1\r\nHost: x\r\n\r\n'))
        pkt = IP(raw)
        assert pkt.haslayer(HTTPRequest)
        assert e.match(pkt)


class TestHttpRules:
    def test_http_on_any_port(self):
        e = engine(rule(match={'http_method': ['POST'], 'http_uri_regex': r'\.\./'}))
        pkt = IP(src=EXTERNAL, dst=INTERNAL) / TCP(dport=32400) / Raw(
            b'POST /:/x/../../etc/passwd HTTP/1.1\r\nHost: nas\r\nUser-Agent: curl/8\r\n\r\n')
        threats = e.match(pkt)
        assert threats and threats[0]['metadata']['http_method'] == 'POST'

    def test_non_http_payload_ignored(self):
        e = engine(rule(match={'http_user_agent_regex': 'curl'}))
        assert not e.match(IP(src=EXTERNAL, dst=INTERNAL) / TCP(dport=80) / Raw(b'\x16\x03\x01curl'))


class TestDnsAndTls:
    def test_txt_threshold(self):
        e = engine(rule(match={'dns_qtype': ['TXT'], 'device_class': ['iot']},
                        threshold_count=3, threshold_window=60), classes={INTERNAL: 'iot'})
        results = [e.match(dns_query(INTERNAL, f'x{i}.example.com', 'TXT')) for i in range(3)]
        assert results[0] == [] and results[1] == [] and results[2]
        assert '3x' in results[2][0]['description']

    def test_device_class_filters(self):
        e = engine(rule(match={'dns_qtype': ['TXT'], 'device_class': ['iot']}), classes={INTERNAL: 'server'})
        assert not e.match(dns_query(INTERNAL, 'mail.example.com', 'TXT'))

    def test_unclassified_device(self):
        e = engine(rule(match={'dns_qname_suffix': ['eth'], 'device_class': ['unclassified']}))
        assert e.match(dns_query(INTERNAL, 'm3rnbvs5d.eth'))

    def test_dns_suffix_is_label_boundary(self):
        e = engine(rule(match={'dns_qname_suffix': ['eth']}))
        assert not e.match(dns_query(INTERNAL, 'www.zeth'))
        assert e.match(dns_query(INTERNAL, 'abc.eth'))

    def test_dns_responses_ignored(self):
        e = engine(rule(match={'dns_qname_suffix': ['eth']}))
        resp = IP(src='10.100.0.1', dst=INTERNAL) / UDP(sport=53, dport=40000) / DNS(
            qr=1, qd=DNSQR(qname='abc.eth'), an=DNSRR(rrname='abc.eth', rdata='1.2.3.4'))
        assert not e.match(resp)

    def test_tls_sni(self):
        e = engine(rule(match={'tls_sni_suffix': ['cloudflare-dns.com'], 'device_class': ['iot']}),
                   classes={INTERNAL: 'iot'})
        pkt = IP(src=INTERNAL, dst='104.16.248.249') / TCP(dport=443)
        meta = {'handshake_type': 'client_hello', 'sni': 'mozilla.cloudflare-dns.com', 'ja3': 'a' * 32}
        threats = e.match(pkt, meta)
        assert threats and threats[0]['metadata']['tls_sni'] == 'mozilla.cloudflare-dns.com'
        assert not engine(rule(match={'tls_sni_suffix': ['cloudflare-dns.com']})).match(pkt, None)


class TestCooldownAndState:
    def test_cooldown_suppresses_repeats(self):
        e = engine(rule(match={'dst_port': '1194'}, cooldown=300))
        pkt = IP(src=INTERNAL, dst=EXTERNAL) / UDP(dport=1194)
        assert e.match(pkt)
        assert not e.match(pkt)

    def test_track_by_pair(self):
        e = engine(rule(match={'dst_port': '1194'}, cooldown=300, track_by='pair'))
        assert e.match(IP(src=INTERNAL, dst=EXTERNAL) / UDP(dport=1194))
        assert e.match(IP(src=INTERNAL, dst='8.8.4.4') / UDP(dport=1194))

    def test_reload_keeps_state_for_existing_rules(self):
        r = rule(match={'dst_port': '1194'}, cooldown=300)
        e = engine(r)
        pkt = IP(src=INTERNAL, dst=EXTERNAL) / UDP(dport=1194)
        assert e.match(pkt)
        e.load([r])
        assert not e.match(pkt)

    def test_disabled_rule_not_loaded(self):
        assert engine(rule(match={'dst_port': '80'}, enabled=False)).rule_count == 0

    def test_version_changes_with_content(self):
        a = re_mod.rules_version([rule(match={'dst_port': '80'})])
        b = re_mod.rules_version([rule(match={'dst_port': '81'})])
        assert a != b


class TestAutoRefresh:
    def test_loader_used(self):
        e = RuleEngine()
        e.start_auto_refresh(lambda: ([rule(match={'dst_port': '80'})], {}), interval=3600)
        try:
            assert e.rule_count == 1
        finally:
            e.stop()

    def test_loader_failure_keeps_rules(self):
        e = engine(rule(match={'dst_port': '80'}))
        def boom():
            raise RuntimeError('db down')
        e.start_auto_refresh(boom, interval=3600)
        try:
            assert e.rule_count == 1
        finally:
            e.stop()


class TestDetectorIntegration:
    def test_detector_runs_rules(self):
        from detector import ThreatDetector
        config = {'thresholds': {}, 'whitelist': [], 'blacklist': [],
                  'internal_networks': ['10.0.0.0/8']}
        d = ThreatDetector(config)
        assert d.rule_engine is not None
        d.rule_engine.load([rule(id=5, alert_type='PLEX_PROBE',
                                 match={'protocol': 'tcp', 'dst_port': '32400', 'direction': 'inbound'})])
        threats = d.analyze_packet(IP(src=EXTERNAL, dst=INTERNAL) / TCP(sport=5555, dport=32400, flags='S'))
        assert any(t['type'] == 'PLEX_PROBE' for t in threats)

    def test_multicast_is_not_outbound(self):
        from detector import ThreatDetector
        d = ThreatDetector({'thresholds': {}, 'whitelist': [], 'blacklist': [],
                            'internal_networks': ['10.0.0.0/8']})
        d.rule_engine.load([rule(match={'protocol': 'udp', 'dst_port': '5353', 'direction': 'outbound'})])
        assert not [t for t in d.analyze_packet(IP(src=INTERNAL, dst='224.0.0.251') / UDP(dport=5353))
                    if t['type'] == 'DETECTION_RULE']
