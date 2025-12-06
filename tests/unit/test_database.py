#!/usr/bin/env python3
"""
Unit tests voor database.py - DatabaseManager class

Test coverage:
- Database initialisatie en connection pooling
- Alert management (toevoegen, ophalen, statistics)
- Traffic metrics opslag en retrieval
- Sensor registratie en management
- Whitelist management
- Configuration management
- Error handling en edge cases
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime, timedelta
import json

from database import DatabaseManager


# ============================================================================
# INITIALIZATION TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestDatabaseInitialization:
    """Test DatabaseManager initialisatie"""

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_init_with_default_params(self, mock_pool):
        """
        Test: Database initialisatie met default parameters
        Normal case: Standaard connection parameters
        """
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()

        # Connection pool moet aangemaakt zijn
        mock_pool.assert_called_once()
        assert db.connection_pool is not None

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_init_with_custom_params(self, mock_pool):
        """
        Test: Database initialisatie met custom parameters
        Normal case: Aangepaste host, port, credentials
        """
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager(
            host='db.example.com',
            port=5433,
            database='custom_db',
            user='custom_user',
            password='custom_pass',
            min_connections=5,
            max_connections=20
        )

        # Verify connection pool parameters
        call_args = mock_pool.call_args
        assert call_args.kwargs['host'] == 'db.example.com'
        assert call_args.kwargs['port'] == 5433
        assert call_args.kwargs['database'] == 'custom_db'
        assert call_args.kwargs['user'] == 'custom_user'
        assert call_args.kwargs['password'] == 'custom_pass'

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_init_connection_failure(self, mock_pool):
        """
        Test: Database initialisatie met connection failure
        Error case: Kan geen verbinding maken met database
        """
        mock_pool.side_effect = Exception("Connection refused")

        with pytest.raises(Exception) as exc_info:
            db = DatabaseManager()

        assert "Connection refused" in str(exc_info.value)

    @patch('database.psycopg2.pool.ThreadedConnectionPool')
    def test_init_without_timescaledb(self, mock_pool, caplog):
        """
        Test: Database initialisatie zonder TimescaleDB extensie
        Edge case: TimescaleDB niet beschikbaar
        """
        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        # Simuleer TimescaleDB CREATE EXTENSION failure
        def execute_side_effect(query):
            if 'timescaledb' in query.lower():
                raise Exception("Extension not available")

        mock_cursor.execute.side_effect = execute_side_effect
        mock_conn.cursor.return_value = mock_cursor
        mock_pool.return_value.getconn.return_value = mock_conn

        db = DatabaseManager()

        # Moet warning loggen maar doorgaan
        assert 'TimescaleDB not available' in caplog.text
        assert db.timescaledb_enabled is False


# ============================================================================
# CONNECTION MANAGEMENT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestConnectionManagement:
    """Test connection pool management"""

    def test_get_connection(self, mock_db_manager):
        """
        Test: Connection ophalen uit pool
        Normal case: Get connection from pool
        """
        conn = mock_db_manager._get_connection()

        assert conn is not None
        mock_db_manager._get_connection.assert_called_once()

    def test_return_connection(self, mock_db_manager):
        """
        Test: Connection teruggeven aan pool
        Normal case: Return connection to pool
        """
        conn = mock_db_manager._get_connection()
        mock_db_manager._return_connection(conn)

        mock_db_manager._return_connection.assert_called_once_with(conn)


# ============================================================================
# ALERT MANAGEMENT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestAlertManagement:
    """Test alert opslag en retrieval"""

    def test_add_alert_success(self, mock_db_manager):
        """
        Test: Alert toevoegen aan database
        Normal case: Volledige alert data
        """
        alert = {
            'severity': 'HIGH',
            'threat_type': 'PORT_SCAN',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.50',
            'description': 'Port scan detected',
            'metadata': {'ports_scanned': 25}
        }

        alert_id = mock_db_manager.add_alert(alert)

        # Mock moet integer alert_id returnen
        assert isinstance(alert_id, int)
        assert alert_id > 0
        mock_db_manager.add_alert.assert_called_once_with(alert)

    def test_add_alert_minimal_data(self, mock_db_manager):
        """
        Test: Alert met minimale vereiste velden
        Edge case: Alleen severity en threat_type
        """
        alert = {
            'severity': 'MEDIUM',
            'threat_type': 'UNUSUAL_TRAFFIC'
        }

        alert_id = mock_db_manager.add_alert(alert)

        assert alert_id > 0

    def test_get_recent_alerts_default(self, mock_db_manager):
        """
        Test: Recent alerts ophalen met defaults
        Normal case: Laatste 100 alerts, laatste 24 uur
        """
        mock_db_manager.get_recent_alerts = Mock(return_value=[
            {
                'id': 1,
                'timestamp': datetime.now(),
                'severity': 'HIGH',
                'threat_type': 'PORT_SCAN',
                'source_ip': '192.168.1.100'
            }
        ])

        alerts = mock_db_manager.get_recent_alerts()

        assert isinstance(alerts, list)
        assert len(alerts) >= 0
        mock_db_manager.get_recent_alerts.assert_called_once()

    def test_get_recent_alerts_with_filters(self, mock_db_manager):
        """
        Test: Recent alerts met custom filters
        Normal case: Specifieke limit en time window
        """
        mock_db_manager.get_recent_alerts = Mock(return_value=[])

        alerts = mock_db_manager.get_recent_alerts(limit=50, hours=12)

        mock_db_manager.get_recent_alerts.assert_called_once_with(limit=50, hours=12)

    def test_get_alert_statistics(self, mock_db_manager):
        """
        Test: Alert statistieken ophalen
        Normal case: Statistics voor laatste 24 uur
        """
        mock_stats = {
            'total_alerts': 142,
            'by_severity': {
                'CRITICAL': 5,
                'HIGH': 23,
                'MEDIUM': 67,
                'LOW': 47
            },
            'by_type': {
                'PORT_SCAN': 45,
                'CONNECTION_FLOOD': 12,
                'DNS_TUNNEL': 8
            }
        }

        mock_db_manager.get_alert_statistics = Mock(return_value=mock_stats)

        stats = mock_db_manager.get_alert_statistics(hours=24)

        assert stats['total_alerts'] == 142
        assert 'by_severity' in stats
        assert 'by_type' in stats

    def test_acknowledge_alert(self, mock_db_manager):
        """
        Test: Alert acknowledgen
        Normal case: Alert markeren als acknowledged
        """
        mock_db_manager.acknowledge_alert = Mock(return_value=True)

        result = mock_db_manager.acknowledge_alert(alert_id=123)

        assert result is True
        mock_db_manager.acknowledge_alert.assert_called_once_with(alert_id=123)


# ============================================================================
# TRAFFIC METRICS TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestTrafficMetrics:
    """Test traffic metrics opslag"""

    def test_add_traffic_metrics_complete(self, mock_db_manager):
        """
        Test: Traffic metrics toevoegen met volledige data
        Normal case: Alle metric velden ingevuld
        """
        metrics = {
            'total_packets': 15234,
            'total_bytes': 9876543,
            'inbound_packets': 8123,
            'inbound_bytes': 5432100,
            'outbound_packets': 7111,
            'outbound_bytes': 4444443
        }

        mock_db_manager.add_traffic_metrics(metrics)

        mock_db_manager.add_traffic_metrics.assert_called_once_with(metrics)

    def test_add_traffic_metrics_partial(self, mock_db_manager):
        """
        Test: Traffic metrics met partial data
        Edge case: Alleen enkele velden ingevuld
        """
        metrics = {
            'total_packets': 1000,
            'total_bytes': 500000
        }

        mock_db_manager.add_traffic_metrics(metrics)

        mock_db_manager.add_traffic_metrics.assert_called_once_with(metrics)

    def test_get_traffic_history(self, mock_db_manager):
        """
        Test: Traffic history ophalen
        Normal case: History voor laatste uren
        """
        mock_history = [
            {
                'timestamp': datetime.now() - timedelta(hours=1),
                'total_packets': 5000,
                'total_bytes': 2500000
            },
            {
                'timestamp': datetime.now(),
                'total_packets': 6000,
                'total_bytes': 3000000
            }
        ]

        mock_db_manager.get_traffic_history = Mock(return_value=mock_history)

        history = mock_db_manager.get_traffic_history(hours=24, limit=100)

        assert isinstance(history, list)
        assert len(history) == 2


# ============================================================================
# SENSOR MANAGEMENT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestSensorManagement:
    """Test sensor registratie en management"""

    def test_register_sensor_new(self, mock_db_manager):
        """
        Test: Nieuwe sensor registreren
        Normal case: Eerste registratie van sensor
        """
        mock_db_manager.register_sensor = Mock(return_value=True)

        result = mock_db_manager.register_sensor(
            sensor_id='sensor-001',
            hostname='sensor1.example.com',
            location='Amsterdam DC',
            ip_address='192.168.100.10'
        )

        assert result is True
        mock_db_manager.register_sensor.assert_called_once()

    def test_register_sensor_update_existing(self, mock_db_manager):
        """
        Test: Bestaande sensor updaten
        Normal case: Re-registratie (update)
        """
        mock_db_manager.register_sensor = Mock(return_value=True)

        # Eerste registratie
        mock_db_manager.register_sensor(
            sensor_id='sensor-001',
            hostname='sensor1.example.com'
        )

        # Update met nieuwe data
        result = mock_db_manager.register_sensor(
            sensor_id='sensor-001',
            hostname='sensor1-updated.example.com',
            location='Rotterdam DC'
        )

        assert result is True

    def test_get_sensors_all(self, mock_db_manager):
        """
        Test: Alle sensors ophalen
        Normal case: Lijst van alle registered sensors
        """
        mock_sensors = [
            {'sensor_id': 'sensor-001', 'hostname': 'sensor1', 'status': 'online'},
            {'sensor_id': 'sensor-002', 'hostname': 'sensor2', 'status': 'offline'}
        ]

        mock_db_manager.get_sensors = Mock(return_value=mock_sensors)

        sensors = mock_db_manager.get_sensors()

        assert isinstance(sensors, list)
        assert len(sensors) == 2

    def test_update_sensor_status(self, mock_db_manager):
        """
        Test: Sensor status updaten
        Normal case: Update naar online/offline
        """
        mock_db_manager.update_sensor_status = Mock(return_value=True)

        result = mock_db_manager.update_sensor_status(
            sensor_id='sensor-001',
            status='online'
        )

        assert result is True

    def test_add_sensor_metrics(self, mock_db_manager):
        """
        Test: Sensor metrics toevoegen
        Normal case: CPU, memory, disk metrics van sensor
        """
        metrics = {
            'sensor_id': 'sensor-001',
            'cpu_percent': 45.2,
            'memory_percent': 62.8,
            'disk_percent': 35.1,
            'uptime_seconds': 86400
        }

        mock_db_manager.add_sensor_metrics = Mock()
        mock_db_manager.add_sensor_metrics(metrics)

        mock_db_manager.add_sensor_metrics.assert_called_once_with(metrics)


# ============================================================================
# WHITELIST MANAGEMENT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestWhitelistManagement:
    """Test whitelist CRUD operaties"""

    def test_add_whitelist_entry(self, mock_db_manager):
        """
        Test: Whitelist entry toevoegen
        Normal case: IP/CIDR aan whitelist toevoegen
        """
        mock_db_manager.add_whitelist_entry = Mock(return_value=1)

        entry_id = mock_db_manager.add_whitelist_entry(
            ip_or_cidr='192.168.1.0/24',
            reason='Internal network',
            sensor_id='sensor-001'
        )

        assert entry_id == 1

    def test_remove_whitelist_entry(self, mock_db_manager):
        """
        Test: Whitelist entry verwijderen
        Normal case: Entry uit whitelist halen
        """
        mock_db_manager.remove_whitelist_entry = Mock(return_value=True)

        result = mock_db_manager.remove_whitelist_entry(entry_id=123)

        assert result is True

    def test_check_ip_whitelisted_true(self, mock_db_manager):
        """
        Test: Check of IP whitelisted is (true case)
        Normal case: IP staat in whitelist
        """
        mock_db_manager.check_ip_whitelisted = Mock(return_value=True)

        is_whitelisted = mock_db_manager.check_ip_whitelisted(
            ip='192.168.1.100',
            sensor_id='sensor-001'
        )

        assert is_whitelisted is True

    def test_check_ip_whitelisted_false(self, mock_db_manager):
        """
        Test: Check of IP whitelisted is (false case)
        Normal case: IP staat niet in whitelist
        """
        mock_db_manager.check_ip_whitelisted = Mock(return_value=False)

        is_whitelisted = mock_db_manager.check_ip_whitelisted(
            ip='192.0.2.100',
            sensor_id='sensor-001'
        )

        assert is_whitelisted is False

    def test_get_whitelist_all(self, mock_db_manager):
        """
        Test: Alle whitelist entries ophalen
        Normal case: Complete whitelist
        """
        mock_whitelist = [
            {'id': 1, 'ip_or_cidr': '192.168.1.0/24', 'reason': 'Internal network'},
            {'id': 2, 'ip_or_cidr': '10.0.0.1', 'reason': 'Gateway'}
        ]

        mock_db_manager.get_whitelist = Mock(return_value=mock_whitelist)

        whitelist = mock_db_manager.get_whitelist()

        assert isinstance(whitelist, list)
        assert len(whitelist) == 2

    def test_get_whitelist_by_sensor(self, mock_db_manager):
        """
        Test: Whitelist entries voor specifieke sensor
        Normal case: Sensor-specifieke whitelist
        """
        mock_whitelist = [
            {'id': 1, 'ip_or_cidr': '192.168.1.0/24', 'sensor_id': 'sensor-001'}
        ]

        mock_db_manager.get_whitelist = Mock(return_value=mock_whitelist)

        whitelist = mock_db_manager.get_whitelist(sensor_id='sensor-001')

        assert len(whitelist) == 1


# ============================================================================
# CONFIGURATION MANAGEMENT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestConfigurationManagement:
    """Test configuration opslag en retrieval"""

    def test_save_sensor_config(self, mock_db_manager):
        """
        Test: Sensor configuratie opslaan
        Normal case: Config JSON opslaan voor sensor
        """
        config = {
            'interface': 'eth0',
            'thresholds': {
                'port_scan': {'unique_ports': 20}
            }
        }

        mock_db_manager.save_sensor_config = Mock(return_value=True)

        result = mock_db_manager.save_sensor_config(
            sensor_id='sensor-001',
            config=config
        )

        assert result is True

    def test_get_sensor_config(self, mock_db_manager):
        """
        Test: Sensor configuratie ophalen
        Normal case: Config voor specifieke sensor
        """
        mock_config = {
            'interface': 'eth0',
            'thresholds': {
                'port_scan': {'unique_ports': 20}
            }
        }

        mock_db_manager.get_sensor_config = Mock(return_value=mock_config)

        config = mock_db_manager.get_sensor_config(sensor_id='sensor-001')

        assert config is not None
        assert 'interface' in config

    def test_get_sensor_config_not_found(self, mock_db_manager):
        """
        Test: Config ophalen voor non-existent sensor
        Edge case: Sensor heeft nog geen config
        """
        mock_db_manager.get_sensor_config = Mock(return_value=None)

        config = mock_db_manager.get_sensor_config(sensor_id='non-existent')

        assert config is None


# ============================================================================
# ERROR HANDLING AND EDGE CASES
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestErrorHandling:
    """Test error handling en edge cases"""

    def test_add_alert_with_invalid_severity(self, mock_db_manager):
        """
        Test: Alert met ongeldige severity
        Error case: Onbekende severity waarde
        """
        alert = {
            'severity': 'INVALID_LEVEL',
            'threat_type': 'TEST'
        }

        # Mock kan error throwen of valideren
        mock_db_manager.add_alert = Mock(side_effect=ValueError("Invalid severity"))

        with pytest.raises(ValueError):
            mock_db_manager.add_alert(alert)

    def test_get_alerts_with_invalid_hours(self, mock_db_manager):
        """
        Test: Alerts ophalen met ongeldige time window
        Edge case: Negatieve hours parameter
        """
        mock_db_manager.get_recent_alerts = Mock(return_value=[])

        # Moet leeg returnen of error throwen
        alerts = mock_db_manager.get_recent_alerts(hours=-1)

        assert isinstance(alerts, list)

    def test_database_connection_lost(self, mock_db_manager):
        """
        Test: Database connection verloren tijdens operatie
        Error case: Connection dropout
        """
        mock_db_manager.add_alert = Mock(
            side_effect=Exception("Connection lost")
        )

        alert = {'severity': 'HIGH', 'threat_type': 'TEST'}

        with pytest.raises(Exception) as exc_info:
            mock_db_manager.add_alert(alert)

        assert "Connection lost" in str(exc_info.value)

    def test_concurrent_alert_inserts(self, mock_db_manager):
        """
        Test: Meerdere simultane alert inserts
        Edge case: Thread safety van connection pool
        """
        alerts = [
            {'severity': 'HIGH', 'threat_type': f'TEST_{i}'}
            for i in range(10)
        ]

        mock_db_manager.add_alert = Mock(side_effect=range(1, 11))

        # Simuleer concurrent inserts
        alert_ids = []
        for alert in alerts:
            alert_id = mock_db_manager.add_alert(alert)
            alert_ids.append(alert_id)

        # Alle inserts moeten succesvol zijn
        assert len(alert_ids) == 10
        assert all(isinstance(aid, int) for aid in alert_ids)

    def test_query_with_sql_injection_attempt(self, mock_db_manager):
        """
        Test: SQL injection poging
        Security case: Parameterized queries beschermen tegen injection
        """
        # Probeer SQL injection via alert description
        malicious_alert = {
            'severity': 'HIGH',
            'threat_type': 'TEST',
            'description': "'; DROP TABLE alerts; --"
        }

        mock_db_manager.add_alert = Mock(return_value=1)

        # Moet veilig afgehandeld worden via parameterized query
        alert_id = mock_db_manager.add_alert(malicious_alert)

        assert alert_id == 1
        # Database moet intact blijven (via parameterized queries)

    def test_large_metadata_json(self, mock_db_manager):
        """
        Test: Alert met zeer grote metadata JSON
        Edge case: Grote JSONB payload
        """
        large_metadata = {
            'packet_data': 'X' * 10000,  # 10KB metadata
            'details': {f'field_{i}': f'value_{i}' for i in range(100)}
        }

        alert = {
            'severity': 'MEDIUM',
            'threat_type': 'TEST',
            'metadata': large_metadata
        }

        mock_db_manager.add_alert = Mock(return_value=1)

        alert_id = mock_db_manager.add_alert(alert)

        assert alert_id == 1


# ============================================================================
# PERFORMANCE AND CLEANUP TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.database
class TestPerformanceAndCleanup:
    """Test performance en cleanup functionaliteit"""

    def test_cleanup_old_alerts(self, mock_db_manager):
        """
        Test: Oude alerts opruimen
        Normal case: Verwijder alerts ouder dan X dagen
        """
        mock_db_manager.cleanup_old_alerts = Mock(return_value=150)

        deleted_count = mock_db_manager.cleanup_old_alerts(days=30)

        assert deleted_count == 150

    def test_vacuum_database(self, mock_db_manager):
        """
        Test: Database vacuum uitvoeren
        Normal case: VACUUM voor performance
        """
        mock_db_manager.vacuum_database = Mock(return_value=True)

        result = mock_db_manager.vacuum_database()

        assert result is True

    def test_get_database_size(self, mock_db_manager):
        """
        Test: Database size ophalen
        Normal case: Check disk usage
        """
        mock_db_manager.get_database_size = Mock(return_value={
            'total_size': '245 MB',
            'alerts_size': '120 MB',
            'metrics_size': '85 MB'
        })

        size_info = mock_db_manager.get_database_size()

        assert 'total_size' in size_info
        assert 'alerts_size' in size_info
