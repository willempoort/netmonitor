#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests voor detector.py - ThreatDetector class

Test coverage:
- Initialisatie en configuratie
- IP parsing en validatie
- Whitelist/blacklist functionaliteit
- Port scan detectie
- Connection flood detectie
- DNS tunneling detectie
- Packet size anomalie detectie
- Threat feed integratie
- Edge cases en error handling
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, ICMP
import ipaddress

from detector import ThreatDetector


# ============================================================================
# INITIALIZATION TESTS
# ============================================================================

@pytest.mark.unit
class TestDetectorInitialization:
    """Test ThreatDetector initialisatie en setup"""

    def test_init_with_basic_config(self, base_config):
        """
        Test: Detector initialiseert correct met basis configuratie
        Edge case: Minimale configuratie zonder optionele components
        """
        detector = ThreatDetector(base_config)

        assert detector.config == base_config
        assert detector.threat_feeds is None
        assert detector.behavior_detector is None
        assert detector.abuseipdb is None
        assert len(detector.config_whitelist) == 0
        assert len(detector.blacklist) == 0

    def test_init_with_all_components(self, base_config, mock_threat_feed_manager,
                                      mock_behavior_detector, mock_abuseipdb_client,
                                      mock_db_manager):
        """
        Test: Detector initialiseert met alle optionele components
        Normal case: Volledige configuratie met threat feeds, behavior detector, etc.
        """
        detector = ThreatDetector(
            base_config,
            threat_feed_manager=mock_threat_feed_manager,
            behavior_detector=mock_behavior_detector,
            abuseipdb_client=mock_abuseipdb_client,
            db_manager=mock_db_manager,
            sensor_id='test-sensor-001'
        )

        assert detector.threat_feeds == mock_threat_feed_manager
        assert detector.behavior_detector == mock_behavior_detector
        assert detector.abuseipdb == mock_abuseipdb_client
        assert detector.db_manager == mock_db_manager
        assert detector.sensor_id == 'test-sensor-001'

    def test_init_with_whitelist_blacklist(self, base_config):
        """
        Test: Detector initialiseert correct met whitelist/blacklist
        Normal case: Configuratie met IP whitelists en blacklists
        """
        base_config['whitelist'] = ['192.168.1.0/24', '10.0.0.1']
        base_config['blacklist'] = ['192.0.2.0/24', '198.51.100.1']

        detector = ThreatDetector(base_config)

        assert len(detector.config_whitelist) == 2
        assert len(detector.blacklist) == 2

    def test_init_with_invalid_ips(self, base_config, caplog):
        """
        Test: Detector handelt ongeldige IPs gracefully af
        Error case: Whitelist bevat ongeldige IP adressen
        """
        base_config['whitelist'] = ['invalid-ip', '192.168.1.0/24', 'not.an.ip']

        detector = ThreatDetector(base_config)

        # Alleen geldige IP moet geparsed zijn
        assert len(detector.config_whitelist) == 1

        # Warnings moeten gelogd zijn
        assert 'Ongeldig IP/CIDR' in caplog.text


# ============================================================================
# IP PARSING AND VALIDATION TESTS
# ============================================================================

@pytest.mark.unit
class TestIPParsing:
    """Test IP parsing en validatie functionaliteit"""

    def test_parse_ip_list_valid_single_ips(self, base_config):
        """
        Test: Parse lijst van enkele IP adressen
        Normal case: Correcte individuele IP adressen
        """
        detector = ThreatDetector(base_config)

        ip_list = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        parsed = detector._parse_ip_list(ip_list)

        assert len(parsed) == 3
        assert all(isinstance(ip, ipaddress.IPv4Network) or isinstance(ip, ipaddress.IPv6Network)
                   for ip in parsed)

    def test_parse_ip_list_with_cidr(self, base_config):
        """
        Test: Parse lijst met CIDR notatie
        Normal case: IP ranges in CIDR formaat
        """
        detector = ThreatDetector(base_config)

        ip_list = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
        parsed = detector._parse_ip_list(ip_list)

        assert len(parsed) == 3
        # Check dat het daadwerkelijk networks zijn
        assert parsed[0].num_addresses == 65536  # /16
        assert parsed[1].num_addresses == 16777216  # /8

    def test_parse_ip_list_mixed_valid_invalid(self, base_config):
        """
        Test: Parse mixed lijst met geldige en ongeldige IPs
        Edge case: Combinatie van correcte en incorrecte IP adressen
        """
        detector = ThreatDetector(base_config)

        ip_list = ['192.168.1.1', 'invalid', '10.0.0.0/24', 'not-an-ip', '172.16.0.1']
        parsed = detector._parse_ip_list(ip_list)

        # Alleen geldige IPs moeten geparsed zijn
        assert len(parsed) == 3

    def test_parse_ip_list_empty(self, base_config):
        """
        Test: Parse lege lijst
        Edge case: Geen IPs in lijst
        """
        detector = ThreatDetector(base_config)

        parsed = detector._parse_ip_list([])

        assert len(parsed) == 0
        assert parsed == []

    def test_parse_ip_list_none(self, base_config):
        """
        Test: Parse None waarde
        Edge case: None wordt doorgegeven in plaats van lijst
        """
        detector = ThreatDetector(base_config)

        parsed = detector._parse_ip_list(None)

        assert len(parsed) == 0
        assert parsed == []

    def test_is_in_list_single_ip_match(self, base_config):
        """
        Test: IP matching in lijst met enkele IPs
        Normal case: Exact IP match
        """
        base_config['whitelist'] = ['192.168.1.100', '10.0.0.50']
        detector = ThreatDetector(base_config)

        assert detector._is_in_list('192.168.1.100', detector.config_whitelist) is True
        assert detector._is_in_list('10.0.0.50', detector.config_whitelist) is True
        assert detector._is_in_list('192.168.1.101', detector.config_whitelist) is False

    def test_is_in_list_cidr_range_match(self, base_config):
        """
        Test: IP matching binnen CIDR range
        Normal case: IP valt binnen netwerk range
        """
        base_config['whitelist'] = ['192.168.1.0/24', '10.0.0.0/16']
        detector = ThreatDetector(base_config)

        # IPs binnen ranges
        assert detector._is_in_list('192.168.1.1', detector.config_whitelist) is True
        assert detector._is_in_list('192.168.1.255', detector.config_whitelist) is True
        assert detector._is_in_list('10.0.50.100', detector.config_whitelist) is True

        # IPs buiten ranges
        assert detector._is_in_list('192.168.2.1', detector.config_whitelist) is False
        assert detector._is_in_list('10.1.0.1', detector.config_whitelist) is False

    def test_is_in_list_invalid_ip_string(self, base_config):
        """
        Test: Ongeldige IP string handlen
        Error case: Niet-IP string wordt gechecked
        """
        base_config['whitelist'] = ['192.168.1.0/24']
        detector = ThreatDetector(base_config)

        # Ongeldige IPs moeten False returnen zonder crash
        assert detector._is_in_list('invalid-ip', detector.config_whitelist) is False
        assert detector._is_in_list('not.an.ip', detector.config_whitelist) is False


# ============================================================================
# WHITELIST/BLACKLIST FUNCTIONALITY TESTS
# ============================================================================

@pytest.mark.unit
class TestWhitelistBlacklist:
    """Test whitelist en blacklist functionaliteit"""

    def test_is_whitelisted_config_only(self, base_config):
        """
        Test: Whitelist check via config (zonder database)
        Normal case: IP whitelisted in config.yaml
        """
        base_config['whitelist'] = ['192.168.1.100', '10.0.0.0/24']
        detector = ThreatDetector(base_config)

        assert detector._is_whitelisted('192.168.1.100') is True
        assert detector._is_whitelisted('10.0.0.50') is True
        assert detector._is_whitelisted('172.16.0.1') is False

    def test_is_whitelisted_with_database(self, base_config, mock_db_manager):
        """
        Test: Whitelist check via database
        Normal case: IP whitelisted in database
        """
        # Setup database mock
        mock_db_manager.check_ip_whitelisted = Mock(return_value=True)

        detector = ThreatDetector(base_config, db_manager=mock_db_manager, sensor_id='test-sensor')

        assert detector._is_whitelisted('192.0.2.100') is True
        mock_db_manager.check_ip_whitelisted.assert_called_once_with('192.0.2.100', sensor_id='test-sensor', direction=None)

    def test_is_whitelisted_database_error(self, base_config, mock_db_manager, caplog):
        """
        Test: Database whitelist check met error
        Error case: Database error tijdens whitelist check
        """
        # Setup database mock om exception te throwen
        mock_db_manager.check_ip_whitelisted = Mock(side_effect=Exception("DB connection error"))

        detector = ThreatDetector(base_config, db_manager=mock_db_manager, sensor_id='test-sensor')

        # Moet False returnen bij database error
        assert detector._is_whitelisted('192.0.2.100') is False

        # Error moet gelogd zijn
        assert 'Error checking database whitelist' in caplog.text

    def test_blacklist_detection(self, base_config):
        """
        Test: Blacklisted IP detectie
        Normal case: Packet van blacklisted IP
        """
        base_config['blacklist'] = ['192.0.2.100', '198.51.100.0/24']
        detector = ThreatDetector(base_config)

        packet = Ether() / IP(src='192.0.2.100', dst='10.0.0.50') / TCP(dport=80)
        threats = detector.analyze_packet(packet)

        assert len(threats) >= 1
        blacklist_threat = next((t for t in threats if t['type'] == 'BLACKLISTED_IP'), None)
        assert blacklist_threat is not None
        assert blacklist_threat['severity'] == 'HIGH'
        assert blacklist_threat['source_ip'] == '192.0.2.100'

    def test_whitelist_prevents_detection(self, base_config):
        """
        Test: Whitelisted IP voorkomt threat detectie
        Normal case: Whitelisted IP genereert geen alerts
        """
        base_config['whitelist'] = ['192.168.1.100']
        detector = ThreatDetector(base_config)

        # Simuleer port scan (zou normaal alert triggeren)
        for port in range(1, 30):
            packet = Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)
            # Whitelisted IP moet geen threats genereren
            assert len(threats) == 0


# ============================================================================
# PORT SCAN DETECTION TESTS
# ============================================================================

@pytest.mark.unit
class TestPortScanDetection:
    """Test port scan detectie functionaliteit"""

    def test_port_scan_detection_triggers(self, base_config):
        """
        Test: Port scan wordt gedetecteerd bij threshold
        Normal case: > 20 unique poorten binnen 60 seconden
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        threats_found = []
        # Scan 25 poorten (threshold is 20)
        for port in range(1, 26):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)
            threats_found.extend(threats)

        # Port scan alert moet getriggered zijn
        port_scan_threats = [t for t in threats_found if t.get('type') == 'PORT_SCAN']
        assert len(port_scan_threats) > 0

        threat = port_scan_threats[0]
        assert threat['severity'] in ['MEDIUM', 'HIGH']
        assert threat['source_ip'] == src_ip

    def test_port_scan_below_threshold(self, base_config):
        """
        Test: Port scan onder threshold triggert niet
        Edge case: Minder dan 20 unique poorten
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        threats_found = []
        # Scan alleen 10 poorten (onder threshold)
        for port in range(1, 11):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)
            threats_found.extend(threats)

        # Geen port scan alert
        port_scan_threats = [t for t in threats_found if t.get('type') == 'PORT_SCAN']
        assert len(port_scan_threats) == 0

    def test_port_scan_multiple_sources(self, base_config):
        """
        Test: Verschillende source IPs worden apart getracked
        Normal case: Meerdere scanners tegelijkertijd
        """
        detector = ThreatDetector(base_config)

        dst_ip = '10.0.0.50'

        # Scanner 1 - scant 25 poorten
        for port in range(1, 26):
            packet = Ether() / IP(src='192.168.1.100', dst=dst_ip) / TCP(dport=port, flags='S')
            detector.analyze_packet(packet)

        # Scanner 2 - scant 10 poorten (onder threshold)
        for port in range(1, 11):
            packet = Ether() / IP(src='192.168.1.101', dst=dst_ip) / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)

        # Scanner 2 zou geen alert moeten genereren (onder threshold)
        port_scan_threats = [t for t in threats if t.get('type') == 'PORT_SCAN']
        assert len(port_scan_threats) == 0

    def test_port_scan_disabled_in_config(self, base_config):
        """
        Test: Port scan detectie uitgeschakeld in config
        Edge case: Port scan detection disabled
        """
        base_config['thresholds']['port_scan']['enabled'] = False
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        threats_found = []
        # Scan 30 poorten
        for port in range(1, 31):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)
            threats_found.extend(threats)

        # Geen port scan alerts (disabled)
        port_scan_threats = [t for t in threats_found if t.get('type') == 'PORT_SCAN']
        assert len(port_scan_threats) == 0


# ============================================================================
# CONNECTION FLOOD DETECTION TESTS
# ============================================================================

@pytest.mark.unit
class TestConnectionFloodDetection:
    """Test connection flood detectie"""

    def test_connection_flood_triggers(self, base_config):
        """
        Test: Connection flood wordt gedetecteerd
        Normal case: > 100 connections/sec binnen 10 seconden
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        # Threshold: 100 conn/sec * 10 sec = 1000 connections
        threshold = base_config['thresholds']['connection_flood']['connections_per_second'] * \
                    base_config['thresholds']['connection_flood']['time_window']

        threats_found = []
        # Stuur meer dan threshold SYN packets
        for i in range(int(threshold) + 100):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=80, flags='S')
            threats = detector.analyze_packet(packet)
            threats_found.extend(threats)

        # Connection flood moet gedetecteerd zijn
        flood_threats = [t for t in threats_found if t.get('type') == 'CONNECTION_FLOOD']
        assert len(flood_threats) > 0

    def test_connection_flood_below_threshold(self, base_config):
        """
        Test: Connection flood onder threshold
        Edge case: Aantal connecties onder threshold
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        threats_found = []
        # Stuur slechts 50 SYN packets (onder threshold)
        for i in range(50):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=80, flags='S')
            threats = detector.analyze_packet(packet)
            threats_found.extend(threats)

        # Geen connection flood alert
        flood_threats = [t for t in threats_found if t.get('type') == 'CONNECTION_FLOOD']
        assert len(flood_threats) == 0


# ============================================================================
# DNS TUNNELING DETECTION TESTS
# ============================================================================

@pytest.mark.unit
class TestDNSTunnelingDetection:
    """Test DNS tunneling detectie"""

    def test_dns_tunnel_long_query_detection(self, base_config):
        """
        Test: DNS tunneling detectie via lange query names
        Normal case: DNS query met verdacht lange naam
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '8.8.8.8'

        # Maak verdacht lange DNS query (> 50 chars threshold)
        long_query = 'a' * 100 + '.example.com'
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(dport=53) / \
                 DNS(rd=1, qd=DNSQR(qname=long_query))

        threats = detector.analyze_packet(packet)

        # DNS tunneling moet gedetecteerd zijn
        dns_threats = [t for t in threats if 'DNS' in t.get('type', '')]
        assert len(dns_threats) > 0

    def test_dns_tunnel_normal_query(self, base_config):
        """
        Test: Normale DNS queries triggeren geen alert
        Normal case: Legitieme DNS query
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '8.8.8.8'

        # Normale DNS query
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(dport=53) / \
                 DNS(rd=1, qd=DNSQR(qname='www.google.com'))

        threats = detector.analyze_packet(packet)

        # Geen DNS tunneling alert
        dns_threats = [t for t in threats if 'DNS_TUNNEL' in t.get('type', '')]
        assert len(dns_threats) == 0


# ============================================================================
# UNUSUAL PACKET SIZE DETECTION TESTS
# ============================================================================

@pytest.mark.unit
class TestUnusualPacketSize:
    """Test packet size anomalie detectie"""

    def test_large_packet_detection(self, base_config):
        """
        Test: Grote packets worden gedetecteerd
        Normal case: Packet groter dan max_size (1500 bytes)
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        # Maak groot packet (> 1500 bytes)
        large_payload = 'X' * 2000
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=80) / large_payload

        threats = detector.analyze_packet(packet)

        # Packet size alert moet getriggered zijn
        size_threats = [t for t in threats if 'PACKET' in t.get('type', '') or 'SIZE' in t.get('type', '')]
        assert len(size_threats) > 0

    def test_normal_packet_size(self, base_config):
        """
        Test: Normale packet sizes triggeren niet
        Normal case: Standaard packet size
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        # Normaal klein packet
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=80)

        threats = detector.analyze_packet(packet)

        # Geen packet size alerts
        size_threats = [t for t in threats if 'PACKET_SIZE' in t.get('type', '')]
        assert len(size_threats) == 0


# ============================================================================
# THREAT FEED INTEGRATION TESTS
# ============================================================================

@pytest.mark.unit
class TestThreatFeedIntegration:
    """Test integratie met threat feeds"""

    def test_threat_feed_malicious_source_ip(self, base_config, mock_threat_feed_manager):
        """
        Test: Malicious source IP detectie via threat feeds
        Normal case: Source IP in threat feed
        """
        # Setup threat feed mock
        mock_threat_feed_manager.is_malicious_ip = Mock(return_value=(
            True,
            {'feed': 'feodotracker', 'type': 'C2', 'malware': 'Emotet'}
        ))

        detector = ThreatDetector(base_config, threat_feed_manager=mock_threat_feed_manager)

        packet = Ether() / IP(src='192.0.2.100', dst='10.0.0.50') / TCP(dport=80)
        threats = detector.analyze_packet(packet)

        # Threat feed match moet gevonden zijn
        feed_threats = [t for t in threats if t.get('type') == 'THREAT_FEED_MATCH']
        assert len(feed_threats) > 0
        assert feed_threats[0]['severity'] == 'HIGH'
        assert 'feodotracker' in str(feed_threats[0])

    def test_threat_feed_c2_communication(self, base_config, mock_threat_feed_manager):
        """
        Test: C2 communicatie detectie (malicious destination IP)
        Normal case: Internal host verbindt met C2 server
        """
        # Setup threat feed mock - alleen destination IP is malicious
        def mock_is_malicious(ip):
            if ip == '198.51.100.50':  # Destination IP
                return (True, {'feed': 'threatfox', 'malware': 'Qakbot', 'type': 'C2'})
            return (False, None)

        mock_threat_feed_manager.is_malicious_ip = Mock(side_effect=mock_is_malicious)

        detector = ThreatDetector(base_config, threat_feed_manager=mock_threat_feed_manager)

        packet = Ether() / IP(src='10.0.0.100', dst='198.51.100.50') / TCP(dport=443)
        threats = detector.analyze_packet(packet)

        # C2 communication moet gedetecteerd zijn
        c2_threats = [t for t in threats if t.get('type') == 'C2_COMMUNICATION']
        assert len(c2_threats) > 0
        assert c2_threats[0]['severity'] == 'CRITICAL'
        assert 'Qakbot' in c2_threats[0]['description']

    def test_threat_feed_no_match(self, base_config, mock_threat_feed_manager):
        """
        Test: Geen threat feed match voor clean IP
        Normal case: IP niet in threat feeds
        """
        # Setup threat feed mock - geen matches
        mock_threat_feed_manager.is_malicious_ip = Mock(return_value=(False, None))

        detector = ThreatDetector(base_config, threat_feed_manager=mock_threat_feed_manager)

        packet = Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=80)
        threats = detector.analyze_packet(packet)

        # Geen threat feed matches
        feed_threats = [t for t in threats if 'THREAT_FEED' in t.get('type', '') or 'C2' in t.get('type', '')]
        assert len(feed_threats) == 0


# ============================================================================
# EDGE CASES AND ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.unit
class TestEdgeCasesAndErrors:
    """Test edge cases en error handling"""

    def test_analyze_packet_without_ip_layer(self, base_config):
        """
        Test: Packet zonder IP layer
        Edge case: Non-IP traffic (bijv. ARP)
        """
        detector = ThreatDetector(base_config)

        # Ethernet-only packet (geen IP layer)
        packet = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')

        threats = detector.analyze_packet(packet)

        # Geen threats voor non-IP packets
        assert len(threats) == 0

    def test_get_threshold_with_missing_key(self, base_config):
        """
        Test: Threshold ophalen met niet-bestaande key
        Error case: Config key bestaat niet
        """
        detector = ThreatDetector(base_config)

        # Haal niet-bestaande threshold op met default
        value = detector._get_threshold('non_existent', 'key', default=42)
        assert value == 42

        # Zonder default moet None returnen
        value = detector._get_threshold('non_existent', 'key')
        assert value is None

    def test_detector_with_empty_config(self):
        """
        Test: Detector met lege/minimale config
        Edge case: Minimale configuratie
        """
        empty_config = {
            'thresholds': {},
            'whitelist': [],
            'blacklist': []
        }

        detector = ThreatDetector(empty_config)

        # Moet geen crash geven
        packet = Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=80)
        threats = detector.analyze_packet(packet)

        # Moet zonder errors werken (eventueel geen/weinig threats)
        assert isinstance(threats, list)

    def test_detector_tracking_structures_initialized(self, base_config):
        """
        Test: Alle tracking data structures zijn correct geïnitialiseerd
        Normal case: Interne state na initialisatie
        """
        detector = ThreatDetector(base_config)

        # Check dat tracking dicts bestaan
        assert hasattr(detector, 'port_scan_tracker')
        assert hasattr(detector, 'connection_tracker')
        assert hasattr(detector, 'dns_tracker')
        assert hasattr(detector, 'brute_force_tracker')

        # Moet lege dicts zijn bij start
        assert len(detector.port_scan_tracker) == 0
        assert len(detector.connection_tracker) == 0


# ============================================================================
# INTEGRATION-STYLE TESTS (within detector)
# ============================================================================

@pytest.mark.unit
class TestDetectorIntegration:
    """Test detector met meerdere threat types tegelijk"""

    def test_multiple_threats_same_packet(self, base_config, mock_threat_feed_manager):
        """
        Test: Packet triggert meerdere threat types tegelijk
        Integration case: Blacklisted IP + threat feed + large packet
        """
        base_config['blacklist'] = ['192.0.2.100']

        # Setup threat feed
        mock_threat_feed_manager.is_malicious_ip = Mock(return_value=(
            True,
            {'feed': 'feodotracker', 'type': 'C2', 'malware': 'Emotet'}
        ))

        detector = ThreatDetector(base_config, threat_feed_manager=mock_threat_feed_manager)

        # Packet van blacklisted IP, in threat feed, met grote payload
        large_payload = 'X' * 2000
        packet = Ether() / IP(src='192.0.2.100', dst='10.0.0.50') / TCP(dport=80) / large_payload

        threats = detector.analyze_packet(packet)

        # Moet meerdere threat types detecteren
        assert len(threats) >= 2  # Minimaal blacklist + threat feed (packet size mogelijk ook)

        threat_types = [t['type'] for t in threats]
        assert 'BLACKLISTED_IP' in threat_types
        assert 'THREAT_FEED_MATCH' in threat_types

    def test_sequential_packet_analysis(self, base_config):
        """
        Test: Sequentiële packet analyse met state tracking
        Integration case: Port scan opbouw over tijd
        """
        detector = ThreatDetector(base_config)

        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        # Eerst 10 poorten scannen (geen alert)
        for port in range(1, 11):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)
            assert len([t for t in threats if t.get('type') == 'PORT_SCAN']) == 0

        # Dan nog 15 poorten (totaal 25, moet alert triggeren)
        for port in range(11, 26):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)

        # Nu moet port scan gedetecteerd zijn
        port_scan_threats = [t for t in threats if t.get('type') == 'PORT_SCAN']
        assert len(port_scan_threats) > 0
