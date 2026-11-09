#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests voor baseline_detector.py - BaselineDeviationDetector

Focus: regressietest voor de ephemeral-port fix. Voor deze fix registreerde
BASELINE_NEW_PORT ook de dynamische/ephemere bronpoort van de andere kant van
een verbinding (bv. de reply van een interne server terug naar een SSH-client
op diens willekeurige poort), wat bij elke nieuwe sessie een nieuwe, nooit
eerder geziene poort opleverde en dus telkens opnieuw alarm sloeg.
"""

import pytest
from scapy.all import IP, TCP

from baseline_detector import BaselineDeviationDetector


def make_learned_behavior(outbound_ports=None, inbound_ports=None):
    return {
        'observation_period': {'duration_hours': 48},
        'traffic_summary': {'unique_outbound_destinations': 100},
        'typical_destinations': [],
        'ports': {
            'outbound_destination_ports': outbound_ports or [],
            'inbound_source_ports': inbound_ports or [],
            'protocols': [6],
        }
    }


class FakeDB:
    def __init__(self, learned_behavior):
        self._learned = learned_behavior

    def get_device_by_ip(self, ip):
        return {'id': 1, 'learned_behavior': self._learned}


@pytest.mark.unit
class TestBaselineNewPortEphemeralFilter:
    """Ephemere (>32767) poorten mogen geen BASELINE_NEW_PORT opleveren"""

    def test_server_reply_to_client_ephemeral_port_not_flagged(self, base_config):
        """
        Normal case (het gerapporteerde probleem): interne server (192.168.1.10)
        antwoordt een SSH-client (192.168.1.20) op diens dynamische poort 54321.
        Voor de fix werd deze dynamische poort behandeld als een 'nieuwe
        outbound poort' van de server.
        """
        base_config['internal_networks'] = ['192.168.1.0/24']
        db = FakeDB(make_learned_behavior(outbound_ports=[22]))
        detector = BaselineDeviationDetector(base_config, db_manager=db)

        reply_packet = IP(src='192.168.1.10', dst='192.168.1.20') / TCP(sport=22, dport=54321)
        threats = detector.analyze_packet(reply_packet)

        assert [t for t in threats if t['type'] == 'BASELINE_NEW_PORT'] == []

    def test_genuine_new_low_port_still_flagged(self, base_config):
        """Sanity check: een echte nieuwe, niet-ephemere uitgaande poort moet nog steeds worden gedetecteerd"""
        base_config['internal_networks'] = ['192.168.1.0/24']
        db = FakeDB(make_learned_behavior(outbound_ports=[22]))
        detector = BaselineDeviationDetector(base_config, db_manager=db)

        packet = IP(src='192.168.1.10', dst='8.8.8.8') / TCP(sport=54321, dport=443)
        threats = detector.analyze_packet(packet)

        new_port_threats = [t for t in threats if t['type'] == 'BASELINE_NEW_PORT']
        assert len(new_port_threats) == 1
        assert new_port_threats[0]['metadata']['destination_port'] == 443

    def test_inbound_ephemeral_source_port_not_flagged(self, base_config):
        """
        Edge case: een extern systeem verbindt met een interne server vanaf een
        eigen ephemere bronpoort. Die bronpoort is nooit een zinvolle
        'inbound poort' van de gemonitorde server.
        """
        base_config['internal_networks'] = ['192.168.1.0/24']
        db = FakeDB(make_learned_behavior(inbound_ports=[443]))
        detector = BaselineDeviationDetector(base_config, db_manager=db)

        packet = IP(src='203.0.113.5', dst='192.168.1.10') / TCP(sport=51000, dport=443)
        threats = detector.analyze_packet(packet)

        assert [t for t in threats if t['type'] == 'BASELINE_NEW_PORT'] == []


def make_stable_behavior(destinations, protocols=(6, 17)):
    """Apparaat met een klein, stabiel bestemmingenpalet (zoals een VoIP-telefoon)."""
    return {
        'observation_period': {'duration_hours': 48},
        'traffic_summary': {'unique_outbound_destinations': len(destinations)},
        'typical_destinations': list(destinations),
        'ports': {
            'outbound_destination_ports': [5060],
            'inbound_source_ports': [],
            'protocols': list(protocols),
        }
    }


@pytest.mark.unit
class TestBaselineResponsesNotFlagged:
    """
    Regressie: de SOC-server probet apparaten (device_fingerprinter, UDP
    mDNS/NetBIOS/SNMP). Het ICMP "port unreachable"-antwoord van het apparaat
    gaf BASELINE_NEW_DESTINATION "apparaat -> SOC-server (ICMP)".
    """

    def _detector(self, base_config):
        base_config['internal_networks'] = ['10.100.0.0/24']
        db = FakeDB(make_stable_behavior(['10.100.0.1', '10.100.0.5']))
        return BaselineDeviationDetector(base_config, db_manager=db)

    @pytest.mark.parametrize('icmp_type,code', [(3, 3), (0, 0), (11, 0)])
    def test_icmp_responses_not_flagged(self, base_config, icmp_type, code):
        from scapy.all import ICMP, UDP
        detector = self._detector(base_config)
        # ICMP port unreachable bevat de kop van de oorspronkelijke UDP-probe
        packet = (IP(src='10.100.0.161', dst='10.100.0.2') / ICMP(type=icmp_type, code=code)
                  / IP(src='10.100.0.2', dst='10.100.0.161') / UDP(sport=40000, dport=137))
        threats = detector.analyze_packet(packet)
        assert [t['type'] for t in threats if t['type'].startswith('BASELINE_')] == []

    def test_icmp_echo_request_to_new_destination_still_flagged(self, base_config):
        from scapy.all import ICMP
        detector = self._detector(base_config)
        packet = IP(src='10.100.0.161', dst='10.100.0.99') / ICMP(type=8)
        types = [t['type'] for t in detector.analyze_packet(packet)]
        assert 'BASELINE_NEW_DESTINATION' in types

    @pytest.mark.parametrize('flags', ['SA', 'R', 'RA'])
    def test_tcp_synack_and_rst_not_flagged(self, base_config, flags):
        detector = self._detector(base_config)
        packet = IP(src='10.100.0.161', dst='10.100.0.2') / TCP(sport=80, dport=51515, flags=flags)
        threats = detector.analyze_packet(packet)
        assert [t for t in threats if t['type'] == 'BASELINE_NEW_DESTINATION'] == []

    def test_tcp_syn_to_new_destination_still_flagged(self, base_config):
        detector = self._detector(base_config)
        packet = IP(src='10.100.0.161', dst='10.100.0.2') / TCP(sport=51515, dport=443, flags='S')
        types = [t['type'] for t in detector.analyze_packet(packet)]
        assert 'BASELINE_NEW_DESTINATION' in types
