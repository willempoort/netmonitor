#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests voor device_discovery.py - traffic stats / port learning

Focus: regressietest voor de ephemeral-port fix in _update_traffic_stats().
Voor deze fix werd de ephemere/dynamische poort van de andere kant van een
verbinding (bv. een client-poort bij reply-verkeer) meegeleerd als was het een
stabiele service-poort van het gemonitorde apparaat zelf.
"""

from collections import defaultdict

import pytest
from scapy.all import IP, TCP, UDP

from device_discovery import DeviceDiscovery


def built(packet):
    """Rondje via bytes() zodat scapy velden als .len daadwerkelijk berekend worden"""
    return packet.__class__(bytes(packet))


def make_discovery() -> DeviceDiscovery:
    """Bouw een DeviceDiscovery instance zonder __init__ (geen db/achtergrondthread nodig)"""
    discovery = DeviceDiscovery.__new__(DeviceDiscovery)
    discovery.traffic_stats = defaultdict(lambda: {
        'ports_seen': set(),
        'protocols_seen': set(),
        'total_bytes': 0,
        'total_packets': 0,
        'first_seen': None,
        'last_seen': None,
        'outbound_ips': set(),
        'inbound_ips': set()
    })
    return discovery


@pytest.mark.unit
class TestUpdateTrafficStatsEphemeralFilter:
    """Ephemere (>32767) poorten mogen niet in ports_seen terechtkomen"""

    def test_outbound_ephemeral_dst_port_not_learned(self):
        """
        Reply-verkeer: het gemonitorde apparaat is 'src' van het pakket, maar
        de dst_port is de dynamische poort van de andere kant (bv. een server
        die antwoordt op een SSH-client). Mag niet als outbound_destination_port
        geleerd worden.
        """
        discovery = make_discovery()
        packet = built(IP(src='192.168.1.10', dst='192.168.1.20') / TCP(sport=22, dport=54321))

        discovery._update_traffic_stats('192.168.1.10', packet, direction='outbound', dst_ip='192.168.1.20')

        assert discovery.traffic_stats['192.168.1.10']['ports_seen'] == set()

    def test_outbound_real_port_still_learned(self):
        """Sanity check: een echte outbound verbinding naar poort 22 moet nog steeds geleerd worden"""
        discovery = make_discovery()
        packet = built(IP(src='192.168.1.10', dst='192.168.1.20') / TCP(sport=54321, dport=22))

        discovery._update_traffic_stats('192.168.1.10', packet, direction='outbound', dst_ip='192.168.1.20')

        assert discovery.traffic_stats['192.168.1.10']['ports_seen'] == {('TCP', 22, 'dst')}

    def test_inbound_ephemeral_src_port_not_learned(self):
        """UDP-variant: ephemere bronpoort van de andere kant mag niet als inbound_source_port geleerd worden"""
        discovery = make_discovery()
        packet = built(IP(src='192.168.1.20', dst='192.168.1.10') / UDP(sport=54321, dport=53))

        discovery._update_traffic_stats('192.168.1.10', packet, direction='inbound', src_ip='192.168.1.20')

        assert discovery.traffic_stats['192.168.1.10']['ports_seen'] == set()
