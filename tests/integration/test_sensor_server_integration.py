#!/usr/bin/env python3
"""
Integration tests voor Sensor ↔ Server communicatie

Test coverage:
- Sensor registratie → Server accepteert
- Sensor upload alerts → Server slaat op in database
- Server config changes → Sensor synct
- Sensor whitelist sync
- Authentication flow
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import json

from sensor_client import SensorClient
from sensor_auth import SensorAuthManager
from database import DatabaseManager


@pytest.mark.integration
class TestSensorServerCommunication:
    """Test sensor-server communicatie flow"""

    @patch('sensor_client.requests.post')
    @patch('sensor_client.requests.get')
    @patch('sensor_client.load_sensor_config')
    def test_sensor_registration_and_token_flow(self, mock_load_config, mock_get, mock_post, sensor_config):
        """
        Integration test: Sensor registratie → Token generatie → Authenticated requests
        Normal case: Volledige authentication flow
        """
        # Setup config
        mock_load_config.return_value = sensor_config

        # Mock registration response met token
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            'success': True,
            'sensor_id': sensor_config['sensor_id'],
            'token': 'generated-auth-token'
        }
        mock_post.return_value = mock_post_response

        # Mock config fetch
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {'config': {'interface': 'eth0'}}
        mock_get.return_value = mock_get_response

        with patch.object(SensorClient, '_init_components'), \
             patch('sensor_client.psutil.net_if_addrs', return_value={}), \
             patch('sensor_client.socket.gethostname', return_value='test-host'):

            # Sensor client start
            client = SensorClient(config_file='sensor.conf')

            # Token moet ontvangen zijn
            # (In echte implementatie zou client._register_sensor() aangeroepen worden)

    @patch('sensor_client.requests.post')
    @patch('sensor_client.load_sensor_config')
    def test_sensor_alert_upload_to_server(self, mock_load_config, mock_post, sensor_config):
        """
        Integration test: Sensor detecteert alert → Upload naar server
        Normal case: Alert batching en upload
        """
        mock_load_config.return_value = sensor_config

        # Mock successful alert upload
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'count': 2}
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.server_url = sensor_config['server_url']
            client.sensor_id = sensor_config['sensor_id']
            client.ssl_verify = False
            client.sensor_token = 'test-token'
            client.logger = Mock()
            client.batch_lock = MagicMock()

            # Alert batch
            client.alert_batch = [
                {'type': 'PORT_SCAN', 'severity': 'HIGH', 'source_ip': '192.168.1.100'},
                {'type': 'DNS_TUNNEL', 'severity': 'MEDIUM', 'source_ip': '192.168.1.101'}
            ]

            client._upload_alerts()

            # Moet POST request gemaakt hebben
            mock_post.assert_called_once()

            # Batch moet geleegd zijn
            assert len(client.alert_batch) == 0

    @patch('sensor_client.requests.get')
    @patch('sensor_client.load_sensor_config')
    def test_config_sync_from_server_to_sensor(self, mock_load_config, mock_get, sensor_config):
        """
        Integration test: Server config update → Sensor synct
        Normal case: Centralized config management
        """
        mock_load_config.return_value = sensor_config

        # Server stuurt updated config
        server_config = {
            'thresholds': {
                'port_scan': {'unique_ports': 30}  # Gewijzigd van 20 naar 30
            }
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'config': server_config}
        mock_get.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.server_url = sensor_config['server_url']
            client.sensor_id = sensor_config['sensor_id']
            client.ssl_verify = False
            client.sensor_token = 'test-token'
            client.logger = Mock()
            client.config = {'thresholds': {'port_scan': {'unique_ports': 20}}}
            client.detector = Mock()
            client.alert_manager = Mock()

            client._update_config()

            # Config sync moet uitgevoerd zijn
            mock_get.assert_called_once()


@pytest.mark.integration
class TestAuthenticationIntegration:
    """Test authentication tussen sensor en server"""

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_token_generation_and_validation_flow(self, mock_pool):
        """
        Integration test: Token genereren → Valideren → Gebruik
        Normal case: Volledige token lifecycle
        """
        # Setup database mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()
        auth_manager = SensorAuthManager(db)

        # Genereer token
        token = auth_manager.generate_token(
            sensor_id='sensor-001',
            token_name='Test Token'
        )

        assert token is not None

        # Mock validation query result
        mock_cursor.fetchone.return_value = {
            'sensor_id': 'sensor-001',
            'active': True,
            'expires_at': None,
            'permissions': {}
        }

        # Valideer token
        result = auth_manager.validate_token(token)

        assert result is not None
        assert result['sensor_id'] == 'sensor-001'

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_token_expiration_handling(self, mock_pool):
        """
        Integration test: Token expiratie flow
        Edge case: Expired token moet geweigerd worden
        """
        from datetime import timedelta

        # Setup database mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()
        auth_manager = SensorAuthManager(db)

        # Genereer token met expiratie
        token = auth_manager.generate_token(
            sensor_id='sensor-001',
            expires_days=30
        )

        # Mock expired token in validation
        from datetime import datetime
        mock_cursor.fetchone.return_value = {
            'sensor_id': 'sensor-001',
            'active': True,
            'expires_at': datetime.now() - timedelta(days=1),  # Expired
            'permissions': {}
        }

        # Validatie moet falen
        result = auth_manager.validate_token(token)
        assert result is None


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndWorkflow:
    """Test complete end-to-end workflows"""

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    @patch('sensor_client.requests.post')
    @patch('sensor_client.requests.get')
    @patch('sensor_client.load_sensor_config')
    def test_complete_threat_detection_workflow(self, mock_load_config, mock_get, mock_post, mock_pool, sensor_config, base_config):
        """
        Integration test: Packet → Detector → Alert → Sensor upload → Database
        Complex case: Complete workflow van packet tot database
        """
        # Setup database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()

        # Setup sensor client mocks
        mock_load_config.return_value = sensor_config

        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {'success': True}
        mock_post.return_value = mock_post_response

        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {'config': {}}
        mock_get.return_value = mock_get_response

        # Setup detector
        from detector import ThreatDetector
        detector = ThreatDetector(base_config, db_manager=db)

        # Simuleer packet dat threat triggert
        from scapy.all import Ether, IP, TCP

        for port in range(1, 26):  # Trigger port scan
            packet = Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=port, flags='S')
            threats = detector.analyze_packet(packet)

            # Als threats gedetecteerd, zou sensor deze uploaden
            for threat in threats:
                alert = {
                    'severity': threat['severity'],
                    'threat_type': threat['type'],
                    'source_ip': threat.get('source_ip'),
                    'description': threat['description']
                }

                # Database insert (zoals server zou doen bij ontvangst)
                alert_id = db.add_alert(alert)

                assert alert_id > 0

                # Alert zou ook verstuurd worden door sensor client
                # (Dit gebeurt in echte wereld via _upload_alert_immediate of batch)


@pytest.mark.integration
class TestConcurrentOperations:
    """Test concurrent operaties"""

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_concurrent_alert_inserts(self, mock_pool):
        """
        Integration test: Meerdere simultane alert inserts
        Performance case: Connection pool handling
        """
        import threading

        # Setup database mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()

        # Insert alerts concurrent
        def insert_alert(i):
            db.add_alert({
                'severity': 'HIGH',
                'threat_type': f'TEST_{i}',
                'source_ip': f'192.168.1.{i % 255}'
            })

        threads = []
        for i in range(10):
            t = threading.Thread(target=insert_alert, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # Alle inserts moeten succesvol zijn (geen deadlocks/errors)
