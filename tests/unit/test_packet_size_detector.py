# SPDX-License-Identifier: AGPL-3.0-only
"""UNUSUAL_PACKET_SIZE: geen meldingen door TCP-offload, hooguit één per paar per 5 min."""
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

import detector as det_mod
from detector import ThreatDetector

pytestmark = pytest.mark.unit


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(det_mod.time, 'time', c)
    return c


def make():
    return ThreatDetector({'thresholds': {'packet_size': {'enabled': True, 'min_suspicious_size': 1400}},
                           'whitelist': [], 'blacklist': [], 'internal_networks': ['10.0.0.0/8']})


def test_big_tcp_segment_from_offload_ignored(clock):
    d = make()
    pkt = IP(src='104.26.5.15', dst='10.100.0.18') / TCP(sport=443, dport=50000) / Raw(b'x' * 30000)
    assert d._detect_unusual_packet_size(pkt) is None


def test_big_udp_reported_once_per_pair_per_5_min(clock):
    d = make()
    pkt = IP(src='10.100.0.50', dst='8.8.8.8') / UDP(sport=5000, dport=53) / Raw(b'x' * 3000)
    first = d._detect_unusual_packet_size(pkt)
    assert first and first['type'] == 'UNUSUAL_PACKET_SIZE'
    clock.t += 60
    assert d._detect_unusual_packet_size(pkt) is None
    other = IP(src='10.100.0.50', dst='1.1.1.1') / UDP(sport=5000, dport=53) / Raw(b'x' * 3000)
    assert d._detect_unusual_packet_size(other) is not None
    clock.t += 301
    assert d._detect_unusual_packet_size(pkt) is not None


def test_small_udp_ignored(clock):
    pkt = IP(src='10.100.0.50', dst='8.8.8.8') / UDP(sport=5000, dport=53) / Raw(b'x' * 100)
    assert make()._detect_unusual_packet_size(pkt) is None
