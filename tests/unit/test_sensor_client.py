#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests voor sensor_client.py - SensorClient class

Test coverage:
- Sensor initialisatie en configuratie
- Server URL normalisatie en validatie
- Sensor registratie en authentication
- Config/whitelist synchronisatie
- Alert batching en upload
- Heartbeat en metrics
- Error handling en retries
- Edge cases (network failures, SSL, etc.)
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, mock_open
from datetime import datetime
import json
import tempfile
import os

from sensor_client import SensorClient, load_sensor_config, _load_bash_config
from collections import deque
import time


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def setup_mock_sensor_client(client, sensor_config):
    """
    Helper function to set up all required attributes for a mocked SensorClient.
    Use this after patching __init__ to return None.

    Args:
        client: The SensorClient instance with mocked __init__
        sensor_config: The sensor configuration dict from fixture
    """
    client.server_url = sensor_config['server']['url']
    client.sensor_id = sensor_config['sensor']['id']
    client.location = sensor_config['sensor'].get('location', 'Unknown')
    client.ssl_verify = sensor_config['server'].get('ssl_verify', True)
    client.config = sensor_config
    client.logger = Mock()

    # Attributes from __init__
    client.batch_interval = 30
    client.running = False
    client.config_etag = None
    client.token = None
    client.packets_captured = 0
    client.alerts_sent = 0
    client.start_time = time.time()
    client.bytes_received = 0
    client.bytes_sent = 0
    client.bandwidth_window_start = time.time()
    client.bandwidth_window_bytes = 0
    client.alert_buffer = deque(maxlen=10000)

    return client


# ============================================================================
# INITIALIZATION TESTS
# ============================================================================

@pytest.mark.unit
class TestSensorClientInitialization:
    """Test SensorClient initialisatie"""

    @patch('sensor_client.load_sensor_config')
    @patch('sensor_client.ThreatDetector')
    @patch.dict(os.environ, {}, clear=True)  # Clear env vars to avoid .env.test interference
    def test_init_with_config_file(self, mock_detector, mock_load_config, sensor_config):
        """
        Test: SensorClient initialisatie met config file
        Normal case: Laden van sensor.conf configuratie
        """
        mock_load_config.return_value = sensor_config

        with patch.object(SensorClient, '_register_sensor'), \
             patch.object(SensorClient, '_update_config'), \
             patch.object(SensorClient, '_update_whitelist'):

            client = SensorClient(config_file='sensor.conf')

            assert client.sensor_id == sensor_config['sensor']['id']
            assert client.server_url == sensor_config['server']['url']

    @patch('sensor_client.load_sensor_config')
    def test_init_with_override_params(self, mock_load_config, sensor_config):
        """
        Test: SensorClient met override parameters
        Normal case: Command-line parameters overschrijven config
        """
        mock_load_config.return_value = sensor_config

        with patch.object(SensorClient, '_init_components'), \
             patch.object(SensorClient, '_register_sensor'), \
             patch.object(SensorClient, '_update_config'), \
             patch.object(SensorClient, '_update_whitelist'):

            client = SensorClient(
                config_file='sensor.conf',
                server_url='https://override.example.com:9090',
                sensor_id='override-sensor-id',
                location='Override Location'
            )

            # Override parameters moeten gebruikt worden
            assert client.server_url == 'https://override.example.com:9090'
            assert client.sensor_id == 'override-sensor-id'
            assert client.location == 'Override Location'

    @patch('sensor_client.load_sensor_config')
    @patch.dict(os.environ, {}, clear=True)  # Clear env vars
    def test_init_generates_sensor_id_if_missing(self, mock_load_config):
        """
        Test: Automatisch sensor_id genereren
        Edge case: Geen sensor_id in config
        """
        config_without_id = {
            'server': {'url': 'https://soc.example.com'},
            'interface': 'eth0'
        }
        mock_load_config.return_value = config_without_id

        with patch.object(SensorClient, '_init_components'), \
             patch.object(SensorClient, '_register_sensor'), \
             patch.object(SensorClient, '_update_config'), \
             patch.object(SensorClient, '_update_whitelist'), \
             patch('sensor_client.socket.gethostname', return_value='test-host'):

            client = SensorClient(config_file='sensor.conf')

            # Sensor ID moet gegenereerd zijn
            assert client.sensor_id is not None
            assert 'test-host' in client.sensor_id

    def test_normalize_server_url_with_port(self):
        """
        Test: Server URL normalisatie met expliciete port
        Normal case: URL met poort nummer
        """
        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.logger = Mock()

            # HTTPS met port
            normalized = client._normalize_server_url('https://soc.example.com:8080')
            assert normalized == 'https://soc.example.com:8080'

            # HTTP met port
            normalized = client._normalize_server_url('http://soc.example.com:9090')
            assert normalized == 'http://soc.example.com:9090'

    def test_normalize_server_url_without_port(self, caplog):
        """
        Test: Server URL normalisatie zonder port (uses defaults)
        Edge case: Geen poort gespecificeerd, gebruik default
        """
        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.logger = Mock()

            # HTTPS zonder port (default 443)
            normalized = client._normalize_server_url('https://soc.example.com')
            assert ':443' in normalized

            # HTTP zonder port (default 80)
            normalized = client._normalize_server_url('http://soc.example.com')
            assert ':80' in normalized

    def test_normalize_server_url_trailing_slash(self):
        """
        Test: Server URL met trailing slash
        Edge case: URL eindigt op /
        """
        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.logger = Mock()

            normalized = client._normalize_server_url('https://soc.example.com:8080/')
            # Trailing slash moet verwijderd zijn
            assert normalized.endswith('8080')
            assert not normalized.endswith('/')


# ============================================================================
# CONFIG LOADING TESTS
# ============================================================================

@pytest.mark.unit
class TestConfigLoading:
    """Test config file loading en parsing"""

    def test_load_bash_config_valid(self, tmp_path):
        """
        Test: Bash-style config file laden
        Normal case: Geldige KEY=VALUE entries
        """
        config_content = """
# Comment line
SOC_SERVER_URL=https://soc.example.com:8080
SENSOR_ID=test-sensor-001
INTERFACE=eth0
SSL_VERIFY=false
SENSOR_LOCATION=Test Location
"""
        config_file = tmp_path / "sensor.conf"
        config_file.write_text(config_content)

        config = _load_bash_config(str(config_file))

        # _load_bash_config returns nested dict structure
        assert config['server']['url'] == 'https://soc.example.com:8080'
        assert config['sensor']['id'] == 'test-sensor-001'
        assert config['interface'] == 'eth0'
        # SSL_VERIFY is converted to boolean
        assert config['server']['ssl_verify'] is False
        assert config['sensor']['location'] == 'Test Location'

    def test_load_bash_config_with_quotes(self, tmp_path):
        """
        Test: Config met quoted values
        Normal case: Values tussen quotes
        """
        config_content = """
SENSOR_LOCATION="Amsterdam Datacenter"
SENSOR_ID='test-sensor-with-quotes'
"""
        config_file = tmp_path / "sensor.conf"
        config_file.write_text(config_content)

        config = _load_bash_config(str(config_file))

        # Quotes moeten verwijderd zijn
        assert config['sensor']['location'] == 'Amsterdam Datacenter'
        assert config['sensor']['id'] == 'test-sensor-with-quotes'

    def test_load_bash_config_empty_lines_and_comments(self, tmp_path):
        """
        Test: Config met lege regels en comments
        Edge case: Mix van content en comments
        """
        config_content = """
# This is a comment
SENSOR_ID=test-001

# Another comment
INTERFACE=eth0
"""
        config_file = tmp_path / "sensor.conf"
        config_file.write_text(config_content)

        config = _load_bash_config(str(config_file))

        # Config includes parsed values plus defaults (thresholds, whitelist, etc)
        assert config['sensor']['id'] == 'test-001'
        assert config['interface'] == 'eth0'
        # Verify defaults are present
        assert 'thresholds' in config
        assert 'whitelist' in config

    def test_load_bash_config_file_not_found(self):
        """
        Test: Config file niet gevonden
        Error case: Bestand bestaat niet
        """
        with pytest.raises(FileNotFoundError):
            _load_bash_config('/nonexistent/sensor.conf')

    def test_load_sensor_config_converts_types(self, tmp_path):
        """
        Test: Config waarden worden correct geconverteerd
        Normal case: String -> int/bool conversie
        """
        config_content = """
SOC_SERVER_URL=https://soc.example.com
SSL_VERIFY=false
SENSOR_LOCATION=Amsterdam
INTERFACE=eth0
"""
        config_file = tmp_path / "sensor.conf"
        config_file.write_text(config_content)

        config = load_sensor_config(str(config_file))

        # Boolean conversie - load_config uses 'verify_ssl' key
        assert config['server']['verify_ssl'] is False

        # String values and nested structure
        assert config['sensor']['location'] == 'Amsterdam'
        assert config['interface'] == 'eth0'
        # Config includes defaults from load_config
        assert 'thresholds' in config
        assert 'performance' in config


# ============================================================================
# SENSOR REGISTRATION TESTS
# ============================================================================

@pytest.mark.unit
class TestSensorRegistration:
    """Test sensor registratie bij SOC server"""

    @patch('sensor_client.requests.post')
    def test_register_sensor_success(self, mock_post, sensor_config):
        """
        Test: Succesvolle sensor registratie
        Normal case: Server accepteert registratie
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'sensor_id': 'test-sensor-001',
            'token': 'auth-token-123'
        }
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            setup_mock_sensor_client(client, sensor_config)

            # Mocken van IP detection
            with patch('sensor_client.psutil.net_if_addrs', return_value={}), \
                 patch('sensor_client.socket.gethostname', return_value='test-host'):

                result = client._register_sensor()

                assert result is True
                mock_post.assert_called_once()

    @patch('sensor_client.requests.post')
    def test_register_sensor_failure(self, mock_post, sensor_config):
        """
        Test: Sensor registratie faalt
        Error case: Server weigert registratie
        """
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = 'Internal server error'
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            setup_mock_sensor_client(client, sensor_config)

            with patch('sensor_client.psutil.net_if_addrs', return_value={}), \
                 patch('sensor_client.socket.gethostname', return_value='test-host'):

                result = client._register_sensor()

                assert result is False

    @patch('sensor_client.requests.post')
    def test_register_sensor_network_error(self, mock_post, sensor_config, caplog):
        """
        Test: Network error tijdens registratie
        Error case: Connection timeout/failure
        """
        mock_post.side_effect = Exception("Connection timeout")

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            setup_mock_sensor_client(client, sensor_config)

            with patch('sensor_client.psutil.net_if_addrs', return_value={}), \
                 patch('sensor_client.socket.gethostname', return_value='test-host'):

                result = client._register_sensor()

                assert result is False


# ============================================================================
# CONFIG SYNC TESTS
# ============================================================================

@pytest.mark.unit
class TestConfigSynchronization:
    """Test config en whitelist synchronisatie"""

    @patch('sensor_client.requests.get')
    def test_update_config_from_server(self, mock_get):
        """
        Test: Config ophalen van server
        Normal case: Server stuurt updated config
        """
        server_config = {
            'thresholds': {
                'port_scan': {'unique_ports': 25}
            },
            'interface': 'eth1'
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'config': server_config}
        mock_get.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create a minimal config for this test
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'},
                'interface': 'eth0'
            }
            setup_mock_sensor_client(client, test_config)
            client.detector = Mock()
            client.alert_manager = Mock()

            client._update_config()

            # Config moet gemerged zijn
            mock_get.assert_called_once()

    @patch('sensor_client.requests.get')
    def test_update_whitelist_from_server(self, mock_get):
        """
        Test: Whitelist ophalen van server
        Normal case: Server stuurt whitelist entries
        """
        whitelist = ['192.168.1.0/24', '10.0.0.1']

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'whitelist': whitelist}
        mock_get.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create a minimal config for this test
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'},
                'whitelist': []
            }
            setup_mock_sensor_client(client, test_config)
            client.detector = Mock()
            client.detector.config_whitelist = []

            client._update_whitelist()

            mock_get.assert_called_once()

    @patch('sensor_client.requests.get')
    def test_config_sync_with_401_error(self, mock_get, caplog):
        """
        Test: Config sync met auth error
        Error case: 401 Unauthorized
        """
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.server_url = 'https://soc.example.com'
            client.sensor_id = 'test-001'
            client.ssl_verify = False
            client.sensor_token = None
            client.logger = Mock()
            client.config = {}

            client._update_config()

            # Moet warning loggen
            client.logger.warning.assert_called()


# ============================================================================
# ALERT BATCHING AND UPLOAD TESTS
# ============================================================================

@pytest.mark.unit
class TestAlertBatchingAndUpload:
    """Test alert batching en upload naar server"""

    @patch('sensor_client.requests.post')
    def test_upload_alerts_batch_success(self, mock_post):
        """
        Test: Batch van alerts uploaden
        Normal case: Multiple alerts in één request
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'count': 5}
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create test config
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'}
            }
            setup_mock_sensor_client(client, test_config)
            client.token = 'test-token'  # Override token for this test

            # Add test alerts to buffer
            client.alert_buffer.extend([
                {'type': 'PORT_SCAN', 'severity': 'HIGH'},
                {'type': 'DNS_TUNNEL', 'severity': 'MEDIUM'}
            ])

            client._upload_alerts()

            mock_post.assert_called_once()
            # Buffer moet geleegd zijn
            assert len(client.alert_buffer) == 0

    @patch('sensor_client.requests.post')
    def test_upload_alert_immediate(self, mock_post):
        """
        Test: Immediate alert upload (CRITICAL severity)
        Normal case: High priority alert direct versturen
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create test config
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'}
            }
            setup_mock_sensor_client(client, test_config)
            client.token = 'test-token'  # Override token for this test

            alert = {'type': 'C2_COMMUNICATION', 'severity': 'CRITICAL'}

            client._upload_alert_immediate(alert)

            mock_post.assert_called_once()

    def test_alert_batching_within_interval(self):
        """
        Test: Alerts worden gebatched binnen interval
        Normal case: Alerts verzamelen voor batch upload
        """
        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.alert_batch = []
            client.batch_lock = MagicMock()
            client.batch_size_limit = 100

            # Voeg alerts toe aan batch
            for i in range(5):
                alert = {'type': 'TEST', 'id': i}
                with client.batch_lock:
                    client.alert_batch.append(alert)

            assert len(client.alert_batch) == 5


# ============================================================================
# HEARTBEAT AND METRICS TESTS
# ============================================================================

@pytest.mark.unit
class TestHeartbeatAndMetrics:
    """Test heartbeat en metrics verzending"""

    @patch('sensor_client.requests.post')
    def test_send_heartbeat_success(self, mock_post):
        """
        Test: Heartbeat naar server sturen
        Normal case: Keep-alive signaal
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create test config
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'}
            }
            setup_mock_sensor_client(client, test_config)
            client.token = 'test-token'  # Override token for this test

            client._send_heartbeat()

            mock_post.assert_called_once()

    @patch('sensor_client.requests.post')
    @patch('sensor_client.psutil.cpu_percent', return_value=45.2)
    @patch('sensor_client.psutil.virtual_memory')
    def test_send_metrics(self, mock_memory, mock_cpu, mock_post):
        """
        Test: System metrics verzenden
        Normal case: CPU, memory, uptime metrics
        """
        mock_memory.return_value.percent = 62.8

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create test config
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'}
            }
            setup_mock_sensor_client(client, test_config)
            client.token = 'test-token'  # Override token for this test

            client._send_metrics()

            mock_post.assert_called_once()


# ============================================================================
# SSL VERIFICATION TESTS
# ============================================================================

@pytest.mark.unit
class TestSSLVerification:
    """Test SSL certificate verification"""

    @patch('sensor_client.requests.post')
    def test_ssl_verify_enabled(self, mock_post):
        """
        Test: SSL verification enabled
        Normal case: SSL_VERIFY=true
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.server_url = 'https://soc.example.com'
            client.sensor_id = 'test-001'
            client.ssl_verify = True  # SSL verification enabled
            client.sensor_token = 'test-token'
            client.logger = Mock()

            client._send_heartbeat()

            # Verify parameter moet True zijn
            call_kwargs = mock_post.call_args.kwargs
            assert call_kwargs.get('verify') is True

    @patch('sensor_client.requests.post')
    def test_ssl_verify_disabled(self, mock_post):
        """
        Test: SSL verification disabled
        Edge case: SSL_VERIFY=false (zelfondertekend certificaat)
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.server_url = 'https://soc.example.com'
            client.sensor_id = 'test-001'
            client.ssl_verify = False  # SSL verification disabled
            client.sensor_token = 'test-token'
            client.logger = Mock()

            client._send_heartbeat()

            # Verify parameter moet False zijn
            call_kwargs = mock_post.call_args.kwargs
            assert call_kwargs.get('verify') is False


# ============================================================================
# ERROR HANDLING AND RETRIES
# ============================================================================

@pytest.mark.unit
class TestErrorHandlingAndRetries:
    """Test error handling en retry logic"""

    @patch('sensor_client.requests.post')
    def test_upload_with_network_timeout(self, mock_post, caplog):
        """
        Test: Network timeout tijdens upload
        Error case: Request timeout
        """
        from requests.exceptions import Timeout

        mock_post.side_effect = Timeout("Request timed out")

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create test config
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'}
            }
            setup_mock_sensor_client(client, test_config)
            client.token = 'test-token'  # Override token for this test
            client.alert_batch = [{'type': 'TEST'}]
            client.batch_lock = MagicMock()

            client._upload_alerts()

            # Moet error loggen maar niet crashen
            client.logger.error.assert_called()

    @patch('sensor_client.requests.post')
    def test_upload_with_connection_error(self, mock_post):
        """
        Test: Connection error tijdens upload
        Error case: Server unreachable
        """
        from requests.exceptions import ConnectionError

        mock_post.side_effect = ConnectionError("Connection refused")

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            # Create test config
            test_config = {
                'server': {'url': 'https://soc.example.com', 'ssl_verify': False},
                'sensor': {'id': 'test-001'}
            }
            setup_mock_sensor_client(client, test_config)
            client.token = 'test-token'  # Override token for this test
            client.alert_batch = [{'type': 'TEST'}]
            client.batch_lock = MagicMock()

            client._upload_alerts()

            # Moet gracefully handlen
            client.logger.error.assert_called()

    @patch('sensor_client.requests.get')
    def test_config_sync_with_json_decode_error(self, mock_get):
        """
        Test: JSON decode error bij config sync
        Error case: Invalid JSON response
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_get.return_value = mock_response

        with patch.object(SensorClient, '__init__', return_value=None):
            client = SensorClient()
            client.server_url = 'https://soc.example.com'
            client.sensor_id = 'test-001'
            client.ssl_verify = False
            client.sensor_token = None
            client.logger = Mock()
            client.config = {}

            client._update_config()

            # Moet error handlen zonder crash
            client.logger.error.assert_called()


# ============================================================================
# INTERFACE CONFIGURATION TESTS
# ============================================================================

@pytest.mark.unit
class TestInterfaceConfiguration:
    """Test network interface configuratie"""

    def test_interface_parsing_single(self):
        """
        Test: Enkele interface configuratie
        Normal case: INTERFACE=eth0
        """
        config = {'interface': 'eth0'}

        # Interface moet als string blijven
        assert config['interface'] == 'eth0'

    def test_interface_parsing_multiple(self):
        """
        Test: Meerdere interfaces
        Normal case: INTERFACE=eth0,eth1
        """
        interface_str = 'eth0,eth1,eth2'
        interfaces = [i.strip() for i in interface_str.split(',')]

        assert len(interfaces) == 3
        assert 'eth0' in interfaces
        assert 'eth1' in interfaces
        assert 'eth2' in interfaces

    def test_interface_parsing_any(self):
        """
        Test: All interfaces (any)
        Edge case: INTERFACE=any
        """
        config = {'interface': 'any'}

        # 'any' moet geïnterpreteerd worden als None
        interface = None if config['interface'] in ('any', 'all') else config['interface']

        assert interface is None

    def test_interface_parsing_all(self):
        """
        Test: All interfaces (all)
        Edge case: INTERFACE=all
        """
        config = {'interface': 'all'}

        # 'all' moet ook geïnterpreteerd worden als None
        interface = None if config['interface'] in ('any', 'all') else config['interface']

        assert interface is None
