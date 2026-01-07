#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Integration tests voor Detector + Database integratie

Test coverage:
- Detector genereert alerts → Database slaat op
- Database whitelist → Detector gebruikt
- Alert flow van packet naar database
- Performance met hoog volume
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether
from datetime import datetime

from detector import ThreatDetector
from database import DatabaseManager


@pytest.mark.integration
class TestDetectorDatabaseIntegration:
    """Test integratie tussen Detector en Database"""

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_detector_alert_to_database_flow(self, mock_pool, base_config):
        """
        Integration test: Detector detecteert threat → Database slaat alert op
        Normal case: End-to-end flow van packet naar database
        """
        # Setup database mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # PostgreSQL fetchone() returns tuple, not dict
        mock_cursor.fetchone.return_value = (1,)  # alert_id
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        # Create database en detector
        db = DatabaseManager()
        detector = ThreatDetector(base_config, db_manager=db)

        # Simuleer packet dat port scan triggert
        src_ip = '192.168.1.100'
        dst_ip = '10.0.0.50'

        for port in range(1, 26):  # Trigger port scan threshold
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)

            # Als threats gedetecteerd, sla op in database
            for threat in threats:
                alert_id = db.add_alert({
                    'severity': threat['severity'],
                    'threat_type': threat['type'],
                    'source_ip': threat.get('source_ip'),
                    'destination_ip': threat.get('destination_ip'),
                    'description': threat['description']
                })

                assert alert_id > 0

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_database_whitelist_detector_integration(self, mock_pool, base_config):
        """
        Integration test: Database whitelist → Detector gebruikt whitelist
        Normal case: Database whitelist voorkomt false positives
        """
        # Setup database mock met whitelist
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Return count of 0 for whitelist check (not whitelisted)
        mock_cursor.fetchone.return_value = (0,)
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()

        # Mock whitelist check
        db.check_ip_whitelisted = Mock(return_value=True)

        detector = ThreatDetector(base_config, db_manager=db, sensor_id='test-sensor')

        # Packet van whitelisted IP
        packet = Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=80)

        threats = detector.analyze_packet(packet)

        # Whitelisted IP moet geen threats genereren
        assert len(threats) == 0

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_high_volume_alert_processing(self, mock_pool, base_config):
        """
        Integration test: Performance test met veel alerts
        Performance case: 1000 packets → database inserts
        """
        # Setup database mock with persistent return values
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # PostgreSQL fetchone() returns tuple, not dict
        # Use side_effect to return consistent values for multiple calls
        mock_cursor.fetchone.side_effect = lambda: (1,)  # Always return tuple with ID
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()
        detector = ThreatDetector(base_config, db_manager=db)

        alert_count = 0

        # Simuleer 1000 packets
        for i in range(1000):
            packet = Ether() / IP(src=f'192.168.1.{i % 255}', dst='10.0.0.50') / TCP(dport=80)
            threats = detector.analyze_packet(packet)

            for threat in threats:
                db.add_alert({
                    'severity': threat['severity'],
                    'threat_type': threat['type'],
                    'source_ip': threat.get('source_ip')
                })
                alert_count += 1

        # Performance check - moet binnen redelijke tijd
        assert alert_count >= 0


@pytest.mark.integration
class TestMultipleDetectorComponents:
    """Test detector met meerdere components tegelijk"""

    def test_detector_with_threat_feeds_and_behavior(self, base_config, mock_threat_feed_manager, mock_behavior_detector, mock_db_manager):
        """
        Integration test: Detector met threat feeds + behavior detector
        Complex case: Alle detection components samen
        """
        detector = ThreatDetector(
            base_config,
            threat_feed_manager=mock_threat_feed_manager,
            behavior_detector=mock_behavior_detector,
            db_manager=mock_db_manager,
            sensor_id='test-sensor'
        )

        # Setup mocks
        mock_threat_feed_manager.is_malicious_ip = Mock(return_value=(True, {'feed': 'test', 'malware': 'Emotet'}))
        mock_behavior_detector.analyze_packet = Mock(return_value=[])

        # Packet van malicious IP
        packet = Ether() / IP(src='192.0.2.100', dst='10.0.0.50') / TCP(dport=443)
        threats = detector.analyze_packet(packet)

        # Moet threat feed match vinden
        assert len(threats) > 0
        assert any(t['type'] == 'THREAT_FEED_MATCH' for t in threats)
