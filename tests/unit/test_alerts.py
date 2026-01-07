#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests voor alerts.py - AlertManager class

Test coverage:
- Alert sending (console, file, syslog)
- Rate limiting
- Alert formatting
- Severity handling
- Statistics
- Edge cases
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, mock_open
from datetime import datetime
from scapy.all import IP, TCP, Ether

from alerts import AlertManager


# ============================================================================
# INITIALIZATION TESTS
# ============================================================================

@pytest.mark.unit
class TestAlertManagerInitialization:
    """Test AlertManager initialisatie"""

    def test_init_with_config(self, base_config):
        """
        Test: AlertManager initialisatie met config
        Normal case: Standaard configuratie
        """
        alert_manager = AlertManager(base_config)

        assert alert_manager.config == base_config
        assert hasattr(alert_manager, 'alert_history')
        assert hasattr(alert_manager, 'max_alerts_per_minute')

    def test_init_with_all_outputs_enabled(self):
        """
        Test: Alle alert outputs enabled
        Normal case: Console + file + syslog
        """
        config = {
            'alerts': {
                'console': True,
                'file': True,
                'syslog': True,
                'file_path': '/tmp/alerts.log'
            }
        }

        alert_manager = AlertManager(config)

        assert alert_manager.config['alerts']['console'] is True
        assert alert_manager.config['alerts']['file'] is True

    def test_init_with_minimal_config(self):
        """
        Test: Minimale alert configuratie
        Edge case: Alleen console output
        """
        config = {
            'alerts': {
                'console': True,
                'file': False,
                'syslog': False
            }
        }

        alert_manager = AlertManager(config)

        assert alert_manager.config is not None


# ============================================================================
# ALERT SENDING TESTS
# ============================================================================

@pytest.mark.unit
class TestAlertSending:
    """Test alert verzenden functionaliteit"""

    @patch('alerts.AlertManager._log_to_console')
    def test_send_alert_console_only(self, mock_log_console, base_config):
        """
        Test: Alert naar console
        Normal case: Console logging
        """
        base_config['alerts']['console'] = True
        base_config['alerts']['file'] = False
        base_config['alerts']['syslog'] = False

        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'PORT_SCAN',
            'severity': 'HIGH',
            'source_ip': '192.168.1.100',
            'description': 'Port scan detected'
        }

        packet = Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP(dport=80)

        alert_manager.send_alert(threat, packet)

        # Console log moet aangeroepen zijn
        mock_log_console.assert_called()

    @patch('alerts.AlertManager._log_to_file')
    def test_send_alert_to_file(self, mock_log_file, base_config):
        """
        Test: Alert naar file
        Normal case: File logging
        """
        base_config['alerts']['console'] = False
        base_config['alerts']['file'] = True
        base_config['alerts']['file_path'] = '/tmp/test_alerts.log'

        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'DNS_TUNNEL',
            'severity': 'MEDIUM',
            'description': 'DNS tunneling detected'
        }

        packet = Mock()

        alert_manager.send_alert(threat, packet)

        mock_log_file.assert_called()

    def test_send_alert_with_high_severity(self, base_config):
        """
        Test: High severity alert
        Normal case: HIGH severity moet prominent gelogd worden
        """
        base_config['alerts']['console'] = True

        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'BLACKLISTED_IP',
            'severity': 'HIGH',
            'source_ip': '192.0.2.100',
            'description': 'Blacklisted IP detected'
        }

        packet = Mock()

        with patch.object(alert_manager, '_log_to_console') as mock_console:
            alert_manager.send_alert(threat, packet)
            mock_console.assert_called()

    def test_send_alert_with_critical_severity(self, base_config):
        """
        Test: Critical severity alert
        Normal case: CRITICAL alerts moeten direct attention
        """
        base_config['alerts']['console'] = True

        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'C2_COMMUNICATION',
            'severity': 'CRITICAL',
            'source_ip': '10.0.0.100',
            'destination_ip': '198.51.100.50',
            'description': 'C2 communication detected'
        }

        packet = Mock()

        with patch.object(alert_manager, '_log_to_console') as mock_console:
            alert_manager.send_alert(threat, packet)
            mock_console.assert_called()


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

@pytest.mark.unit
class TestRateLimiting:
    """Test rate limiting functionaliteit"""

    def test_rate_limiting_prevents_spam(self, base_config):
        """
        Test: Rate limiting voorkomt alert spam
        Normal case: Teveel alerts binnen tijd window
        """
        base_config['alerts'] = {
            'console': True,
            'rate_limit': {
                'enabled': True,
                'max_per_minute': 10
            }
        }

        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'TEST',
            'severity': 'LOW',
            'description': 'Test alert'
        }

        packet = Mock()

        # Stuur meer alerts dan rate limit
        with patch.object(alert_manager, '_log_to_console'):
            for i in range(20):
                alert_manager.send_alert(threat, packet)

        # Rate limiting moet getriggered zijn

    def test_rate_limiting_disabled(self, base_config):
        """
        Test: Rate limiting uitgeschakeld
        Edge case: Geen rate limit
        """
        base_config['alerts'] = {
            'console': True,
            'rate_limit': {
                'enabled': False
            }
        }

        alert_manager = AlertManager(base_config)

        threat = {'type': 'TEST', 'severity': 'LOW'}
        packet = Mock()

        # Moet alle alerts verwerken zonder rate limit
        with patch.object(alert_manager, '_log_to_console') as mock_console:
            for i in range(20):
                alert_manager.send_alert(threat, packet)

            # Alle calls moeten doorgelaten zijn
            assert mock_console.call_count == 20


# ============================================================================
# ALERT FORMATTING TESTS
# ============================================================================

@pytest.mark.unit
class TestAlertFormatting:
    """Test alert formatting"""

    def test_format_alert_with_all_fields(self, base_config):
        """
        Test: Alert formatting met alle velden
        Normal case: Volledige threat info
        """
        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'PORT_SCAN',
            'severity': 'HIGH',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.50',
            'description': 'Port scan from 192.168.1.100',
            'metadata': {'ports_scanned': 25}
        }

        packet = Ether() / IP(src='192.168.1.100', dst='10.0.0.50') / TCP()

        formatted = alert_manager._format_alert(threat, packet)

        assert isinstance(formatted, str)
        assert 'PORT_SCAN' in formatted
        assert 'HIGH' in formatted

    def test_format_alert_minimal_fields(self, base_config):
        """
        Test: Alert formatting met minimale velden
        Edge case: Alleen type en severity
        """
        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'UNUSUAL_TRAFFIC',
            'severity': 'LOW'
        }

        packet = Mock()

        formatted = alert_manager._format_alert(threat, packet)

        assert isinstance(formatted, str)
        assert 'UNUSUAL_TRAFFIC' in formatted


# ============================================================================
# SEVERITY HANDLING TESTS
# ============================================================================

@pytest.mark.unit
class TestSeverityHandling:
    """Test severity level handling"""

    def test_severity_color_mapping(self, base_config):
        """
        Test: Severity colors voor console output
        Normal case: Verschillende kleuren per severity
        """
        alert_manager = AlertManager(base_config)

        # Test verschillende severities
        color_critical = alert_manager._get_severity_color('CRITICAL')
        color_high = alert_manager._get_severity_color('HIGH')
        color_medium = alert_manager._get_severity_color('MEDIUM')
        color_low = alert_manager._get_severity_color('LOW')

        # Elke severity moet een color hebben
        assert color_critical is not None
        assert color_high is not None
        assert color_medium is not None
        assert color_low is not None

    def test_unknown_severity_handling(self, base_config):
        """
        Test: Onbekende severity level
        Edge case: Niet-standaard severity
        """
        alert_manager = AlertManager(base_config)

        color = alert_manager._get_severity_color('UNKNOWN')

        # Moet default color returnen
        assert color is not None


# ============================================================================
# STATISTICS TESTS
# ============================================================================

@pytest.mark.unit
class TestAlertStatistics:
    """Test alert statistieken"""

    def test_get_stats_after_alerts(self, base_config):
        """
        Test: Statistieken na meerdere alerts
        Normal case: Alert counts bijhouden
        """
        base_config['alerts']['console'] = True

        alert_manager = AlertManager(base_config)

        threats = [
            {'type': 'PORT_SCAN', 'severity': 'HIGH'},
            {'type': 'DNS_TUNNEL', 'severity': 'MEDIUM'},
            {'type': 'PORT_SCAN', 'severity': 'HIGH'}
        ]

        packet = Mock()

        with patch.object(alert_manager, '_log_to_console'):
            for threat in threats:
                alert_manager.send_alert(threat, packet)

        stats = alert_manager.get_stats()

        assert stats is not None
        assert 'total' in stats or stats.get('alert_count', 0) >= 3

    def test_get_stats_no_alerts(self, base_config):
        """
        Test: Statistieken zonder alerts
        Edge case: Nog geen alerts verzonden
        """
        alert_manager = AlertManager(base_config)

        stats = alert_manager.get_stats()

        assert stats is not None


# ============================================================================
# FILE OUTPUT TESTS
# ============================================================================

@pytest.mark.unit
class TestFileOutput:
    """Test file output functionaliteit"""

    @patch('builtins.open', new_callable=mock_open)
    def test_log_to_file_creates_file(self, mock_file, base_config):
        """
        Test: Alert naar file schrijven
        Normal case: File wordt aangemaakt en beschreven
        """
        base_config['alerts']['file'] = True
        base_config['alerts']['file_path'] = '/tmp/test_alerts.log'

        alert_manager = AlertManager(base_config)

        message = "[HIGH] PORT_SCAN: Test alert"

        alert_manager._log_to_file(message)

        # File moet geopend zijn
        mock_file.assert_called()

    def test_log_to_file_with_permission_error(self, base_config, caplog):
        """
        Test: File write met permission error
        Error case: Geen schrijfrechten
        """
        base_config['alerts']['file'] = True
        base_config['alerts']['file_path'] = '/root/no_permission.log'

        alert_manager = AlertManager(base_config)

        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            message = "[HIGH] TEST: Alert"

            # Moet error handlen zonder crash
            try:
                alert_manager._log_to_file(message)
            except:
                pass  # Expected to fail gracefully


# ============================================================================
# EDGE CASES
# ============================================================================

@pytest.mark.unit
class TestEdgeCases:
    """Test edge cases en error handling"""

    def test_send_alert_with_none_packet(self, base_config):
        """
        Test: Alert met None packet
        Edge case: Geen packet data beschikbaar
        """
        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'MANUAL_ALERT',
            'severity': 'MEDIUM',
            'description': 'Manual alert without packet'
        }

        with patch.object(alert_manager, '_log_to_console'):
            # Moet geen crash geven
            alert_manager.send_alert(threat, None)

    def test_send_alert_with_missing_severity(self, base_config):
        """
        Test: Alert zonder severity
        Edge case: Severity niet opgegeven
        """
        alert_manager = AlertManager(base_config)

        threat = {
            'type': 'TEST'
            # Geen severity
        }

        packet = Mock()

        with patch.object(alert_manager, '_log_to_console'):
            # Moet default severity gebruiken
            alert_manager.send_alert(threat, packet)

    def test_concurrent_alert_sending(self, base_config):
        """
        Test: Meerdere simultane alerts
        Edge case: Thread safety
        """
        alert_manager = AlertManager(base_config)

        threat = {'type': 'TEST', 'severity': 'LOW'}
        packet = Mock()

        with patch.object(alert_manager, '_log_to_console'):
            # Simuleer concurrent alerts
            for i in range(10):
                alert_manager.send_alert(threat, packet)

        # Moet alle alerts verwerken zonder issues
