# SPDX-License-Identifier: AGPL-3.0-only
"""Advanced detectors luisteren naar threat.<naam>.* en thresholds.advanced_threats.*"""
import os

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

import detector as det_mod
from detector import ThreatDetector

pytestmark = pytest.mark.unit

SRC = '10.100.0.50'
DST = '10.100.0.60'


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(det_mod.time, 'time', c)
    return c


def make(threat=None, master=True, cooldown=300, db=None):
    cfg = {'thresholds': {'advanced_threats': {'enabled': master, 'cooldown': cooldown}},
           'whitelist': [], 'blacklist': [], 'internal_networks': ['10.0.0.0/8'],
           'threat': threat or {}}
    return ThreatDetector(cfg, db_manager=db)


def adv(d, pkt):
    return d._detect_advanced_threats(pkt)


def syn(i=0):
    return IP(src=SRC, dst=DST) / TCP(sport=40000 + i, dport=80, flags='S')


def flood(d, clock, n):
    out = []
    for i in range(n):
        out += adv(d, syn(i))
    clock.t += 1.1
    out += adv(d, syn(n))
    return [t for t in out if t['type'] == 'SYN_FLOOD_ATTACK']


def test_master_off_runs_nothing(clock):
    d = make({'syn_flood': {'enabled': True, 'threshold_per_sec': 5}}, master=False)
    assert flood(d, clock, 50) == []


def test_detector_off_runs_nothing(clock):
    d = make({'syn_flood': {'enabled': False, 'threshold_per_sec': 5}})
    assert flood(d, clock, 50) == []


def test_threshold_from_config(clock):
    d = make({'syn_flood': {'enabled': True, 'threshold_per_sec': 5}})
    assert len(flood(d, clock, 10)) == 1          # vroeger vast 100: geen melding
    d2 = make({'syn_flood': {'enabled': True, 'threshold_per_sec': 500}})
    assert flood(d2, clock, 10) == []


def test_string_values_from_db(clock):
    d = make({'syn_flood': {'enabled': 'true', 'threshold_per_sec': '5'}})
    assert len(flood(d, clock, 10)) == 1


def test_cooldown_suppresses_repeat(clock):
    d = make({'syn_flood': {'enabled': True, 'threshold_per_sec': 5}}, cooldown=300)
    assert len(flood(d, clock, 10)) == 1
    assert flood(d, clock, 10) == []
    clock.t += 301
    assert len(flood(d, clock, 10)) == 1


def test_works_without_database(clock):
    d = make({'syn_flood': {'enabled': True, 'threshold_per_sec': 5}}, db=None)
    assert d.db_manager is None
    assert len(flood(d, clock, 10)) == 1


def test_db_detectors_skipped_without_database(clock):
    d = make({'tor': {'enabled': True}, 'phishing': {'enabled': True}})
    assert adv(d, IP(src=SRC, dst='1.2.3.4') / TCP(dport=443, flags='S')) == []


CRED = {'credential_dumping': {'enabled': True, 'indicators_threshold': 2}}


def raw(payload, dport=445):
    return IP(src=SRC, dst=DST) / TCP(sport=50000, dport=dport, flags='PA') / Raw(payload)


def test_credential_dumping_ignores_noise(clock):
    d = make(CRED, cooldown=0)
    noise = [b'same samsung sample', os.urandom(1400), b'GET /sam HTTP/1.1\r\n\r\n',
             b'kernel exploit cve-2026-1234 runas uac', b'lsass']
    for _ in range(50):
        for p in noise:
            assert [t for t in adv(d, raw(p)) if t['type'] == 'CREDENTIAL_DUMPING'] == []


def test_credential_dumping_real_indicators(clock):
    d = make(CRED)
    first = adv(d, raw(b'mimikatz # sekurlsa::logonpasswords'))   # 1 indicator, drempel 2
    assert [t for t in first if t['type'] == 'CREDENTIAL_DUMPING'] == []
    threats = adv(d, raw('reg save HKLM\\SAM C:\\temp\\sam.hiv'.encode()))
    assert [t for t in threats if t['type'] == 'CREDENTIAL_DUMPING']


def test_credential_dumping_utf16_smb(clock):
    d = make(CRED)
    adv(d, raw('\\Windows\\System32\\config\\SAM'.encode('utf-16-le')))
    threats = adv(d, raw('C:\\tools\\mimikatz.exe'.encode('utf-16-le')))
    assert [t for t in threats if t['type'] == 'CREDENTIAL_DUMPING']


def test_counter_does_not_fire_every_packet(clock):
    """Vroeger: na de drempel een CRITICAL bij elk volgend pakket (498.000 in januari)."""
    d = make(CRED, cooldown=0)
    adv(d, raw(b'sekurlsa::logonpasswords'))
    adv(d, raw(b'lsadump::sam'))
    fired = [t for _ in range(100) for t in adv(d, raw(b'harmless smb data'))
             if t['type'] == 'CREDENTIAL_DUMPING']
    assert fired == []


def test_privilege_escalation_ignores_generic_words(clock):
    d = make({'privilege_escalation': {'enabled': True, 'attempts_threshold': 1}}, cooldown=0)
    for p in [b'linux kernel update', b'exploit-db cve-2026-0001', b'uac settings', b'sudo apt update']:
        assert [t for t in adv(d, raw(p, 80)) if t['type'] == 'PRIVILEGE_ESCALATION'] == []
    assert [t for t in adv(d, raw(b'PrintSpoofer.exe -i -c cmd', 445)) if t['type'] == 'PRIVILEGE_ESCALATION']


def test_tracker_expires(clock):
    d = make({'persistence': {'enabled': True, 'mechanisms_threshold': 2, 'time_window': 60}}, cooldown=0)
    adv(d, raw(b'schtasks /create /tn x /tr evil.exe'))
    clock.t += 200                     # > 2 vensters: telling vervalt
    assert [t for t in adv(d, raw(b'sc create evilsvc binPath= x')) if t['type'] == 'PERSISTENCE_MECHANISM'] == []


def test_config_defaults_only_list_implemented_detectors():
    from config_defaults import BEST_PRACTICE_CONFIG, PARAMETER_CATEGORIES
    implemented = {name for name, *_ in ThreatDetector._ADVANCED_DETECTORS}
    assert set(BEST_PRACTICE_CONFIG['threat']) == implemented
    cats = [c.split('.', 1)[1] for c in PARAMETER_CATEGORIES['Advanced Threat Detection'] if c.startswith('threat.')]
    assert set(cats) <= implemented
    for name, *_ in ThreatDetector._ADVANCED_DETECTORS:
        assert hasattr(ThreatDetector, ThreatDetector._ADVANCED_DETECTORS[[n for n, *_ in ThreatDetector._ADVANCED_DETECTORS].index(name)][1])
