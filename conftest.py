#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Pytest configuratie en shared fixtures voor NetMonitor SOC testing

Dit bestand bevat:
- Shared fixtures die door alle tests gebruikt kunnen worden
- Mock objecten voor database, network, en externe dependencies
- Test configuraties en helpers
"""

import pytest
import os
import sys
import tempfile
import yaml
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any

# Voeg project root toe aan Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ============================================================================
# CONFIGURATIE FIXTURES
# ============================================================================

@pytest.fixture
def base_config() -> Dict[str, Any]:
    """
    Basis configuratie voor tests

    Returns:
        Dict met standaard NetMonitor configuratie
    """
    return {
        'interface': 'eth0',
        'monitor_mode': False,
        'log_level': 'INFO',
        'thresholds': {
            'port_scan': {
                'unique_ports': 20,
                'time_window': 60
            },
            'connection_flood': {
                'connections_per_second': 100,
                'time_window': 10
            },
            'unusual_packet_size': {
                'min_size': 1,
                'max_size': 1500
            },
            'dns_tunnel': {
                'max_query_length': 50,
                'queries_per_minute': 30
            },
            'brute_force': {
                'failed_attempts': 5,
                'time_window': 300
            }
        },
        'blacklist': [],
        'whitelist': [],
        'alerts': {
            'console': True,
            'file': False,
            'syslog': False,
            'file_path': '/tmp/test_alerts.log'
        },
        'database': {
            'host': 'localhost',
            'port': 5432,
            'database': 'netmonitor_test',
            'user': 'test_user',
            'password': 'test_password'
        },
        'threat_feeds': {
            'enabled': False,
            'feeds': []
        },
        'logging': {
            'file': '/tmp/netmonitor_test.log',
            'level': 'INFO',
            'console': True
        }
    }


@pytest.fixture
def config_file(base_config, tmp_path) -> Path:
    """
    Creëer tijdelijke config file voor tests

    Args:
        base_config: Basis configuratie fixture
        tmp_path: Pytest tmp_path fixture

    Returns:
        Path naar tijdelijke config.yaml
    """
    config_path = tmp_path / "config.yaml"
    with open(config_path, 'w') as f:
        yaml.dump(base_config, f)
    return config_path


@pytest.fixture
def sensor_config() -> Dict[str, Any]:
    """
    Sensor-specifieke configuratie

    Returns:
        Dict met sensor configuratie
    """
    return {
        'sensor_id': 'test-sensor-001',
        'location': 'Test Location',
        'server_url': 'https://soc.example.com:8080',
        'ssl_verify': False,
        'interface': 'eth0',
        'batch_interval': 30,
        'heartbeat_interval': 60
    }


# ============================================================================
# DATABASE FIXTURES
# ============================================================================

@pytest.fixture
def mock_db_connection():
    """
    Mock PostgreSQL database connectie

    Returns:
        Mock database connection object
    """
    conn = MagicMock()
    cursor = MagicMock()

    # Setup cursor mock
    cursor.fetchone.return_value = None
    cursor.fetchall.return_value = []
    cursor.rowcount = 0

    conn.cursor.return_value.__enter__.return_value = cursor
    conn.cursor.return_value.__exit__.return_value = None

    return conn


@pytest.fixture
def mock_db_manager(mock_db_connection):
    """
    Mock DatabaseManager voor tests zonder echte database

    Returns:
        Mock DatabaseManager object
    """
    from database import DatabaseManager

    with patch('database.psycopg2.pool.ThreadedConnectionPool'):
        db = DatabaseManager(
            host='localhost',
            database='test_db',
            user='test_user',
            password='test_pass'
        )

        # Override connection methods
        db._get_connection = MagicMock(return_value=mock_db_connection)
        db._return_connection = MagicMock()

        # Mock belangrijke methoden
        db.add_alert = MagicMock(return_value=1)
        db.get_recent_alerts = MagicMock(return_value=[])
        db.add_traffic_metrics = MagicMock()
        db.register_sensor = MagicMock(return_value=True)

        return db


# ============================================================================
# NETWORK/PACKET FIXTURES
# ============================================================================

@pytest.fixture
def mock_packet():
    """
    Mock Scapy packet voor testing

    Returns:
        Mock packet object met IP/TCP layers
    """
    packet = MagicMock()

    # IP layer
    packet.haslayer.return_value = True
    packet.__getitem__.return_value.src = '192.168.1.100'
    packet.__getitem__.return_value.dst = '10.0.0.50'

    # TCP layer
    packet.__getitem__.return_value.sport = 12345
    packet.__getitem__.return_value.dport = 80
    packet.__getitem__.return_value.flags = 'S'

    # Packet metadata
    packet.time = 1234567890.0
    packet.__len__.return_value = 60

    return packet


@pytest.fixture
def sample_packets():
    """
    Genereer sample packets voor verschillende scenario's

    Returns:
        Dict met verschillende packet types
    """
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether

    return {
        'tcp_syn': Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=80, flags='S'),
        'tcp_ack': Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=80, flags='A'),
        'udp': Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / UDP(dport=53),
        'dns_query': Ether() / IP(src='192.168.1.100', dst='8.8.8.8') / UDP(dport=53) /
                     DNS(rd=1, qd=DNSQR(qname='example.com')),
        'large_packet': Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=80) / ('X' * 2000),
    }


# ============================================================================
# DETECTOR FIXTURES
# ============================================================================

@pytest.fixture
def mock_threat_feed_manager():
    """
    Mock ThreatFeedManager voor testing zonder echte feeds

    Returns:
        Mock ThreatFeedManager object
    """
    manager = MagicMock()
    manager.is_malicious_ip.return_value = (False, None, None)
    manager.is_malicious_domain.return_value = False
    manager.load_feeds.return_value = {}
    return manager


@pytest.fixture
def mock_behavior_detector():
    """
    Mock BehaviorDetector voor testing

    Returns:
        Mock BehaviorDetector object
    """
    detector = MagicMock()
    detector.analyze_behavior.return_value = []
    return detector


@pytest.fixture
def mock_abuseipdb_client():
    """
    Mock AbuseIPDB client voor testing zonder API calls

    Returns:
        Mock AbuseIPDBClient object
    """
    client = MagicMock()
    client.check_ip.return_value = {
        'is_malicious': False,
        'abuse_score': 0,
        'country': 'NL'
    }
    return client


# ============================================================================
# SENSOR/AUTH FIXTURES
# ============================================================================

@pytest.fixture
def mock_sensor_auth(mock_db_manager):
    """
    Mock SensorAuthManager voor testing

    Returns:
        Mock SensorAuthManager object
    """
    from sensor_auth import SensorAuthManager

    auth = SensorAuthManager(mock_db_manager)
    auth.generate_token = MagicMock(return_value='test-token-123')
    auth.validate_token = MagicMock(return_value={
        'sensor_id': 'test-sensor-001',
        'permissions': {}
    })
    auth.revoke_token = MagicMock(return_value=True)

    return auth


@pytest.fixture
def mock_requests():
    """
    Mock requests library voor HTTP tests zonder echte network calls

    Yields:
        Mock requests module
    """
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('requests.put') as mock_put:

        # Setup default responses
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True}
        mock_response.text = '{"success": true}'

        mock_get.return_value = mock_response
        mock_post.return_value = mock_response
        mock_put.return_value = mock_response

        yield {
            'get': mock_get,
            'post': mock_post,
            'put': mock_put,
            'response': mock_response
        }


# ============================================================================
# FLASK APP FIXTURES
# ============================================================================

@pytest.fixture
def flask_app(base_config, mock_db_manager):
    """
    Flask test client voor web_dashboard testing

    Returns:
        Flask test client
    """
    from web_dashboard import init_dashboard

    with patch('web_dashboard.DatabaseManager', return_value=mock_db_manager):
        app, _, _ = init_dashboard()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False

        return app.test_client()


# ============================================================================
# UTILITY FIXTURES
# ============================================================================

@pytest.fixture
def temp_log_file(tmp_path) -> Path:
    """
    Tijdelijke log file voor testing

    Returns:
        Path naar tijdelijk log bestand
    """
    log_file = tmp_path / "test.log"
    return log_file


@pytest.fixture
def cleanup_temp_files():
    """
    Cleanup fixture die na test tijdelijke bestanden opruimt

    Yields:
        Lijst waar temp files aan toegevoegd kunnen worden
    """
    temp_files = []

    yield temp_files

    # Cleanup
    for filepath in temp_files:
        if os.path.exists(filepath):
            os.remove(filepath)


# ============================================================================
# PYTEST HOOKS
# ============================================================================

def pytest_configure(config):
    """
    Pytest configuratie hook - uitgevoerd voor tests starten
    """
    # Zet test environment variabelen
    os.environ['NETMONITOR_TESTING'] = '1'
    os.environ['NETMONITOR_LOG_LEVEL'] = 'DEBUG'

    # Maak logs directory
    logs_dir = Path(__file__).parent / 'tests' / 'logs'
    logs_dir.mkdir(parents=True, exist_ok=True)


def pytest_unconfigure(config):
    """
    Pytest cleanup hook - uitgevoerd na alle tests
    """
    # Cleanup test environment variabelen
    os.environ.pop('NETMONITOR_TESTING', None)
    os.environ.pop('NETMONITOR_LOG_LEVEL', None)
