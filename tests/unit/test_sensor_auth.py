#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Unit tests voor sensor_auth.py - SensorAuthManager class

Test coverage:
- Token generatie en validatie
- Token expiratie handling
- Permission management
- Token revocation
- Cleanup van expired tokens
- Edge cases en security
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
import secrets

from sensor_auth import SensorAuthManager


# ============================================================================
# TOKEN GENERATION TESTS
# ============================================================================

@pytest.mark.unit
class TestTokenGeneration:
    """Test token generatie functionaliteit"""

    def test_generate_token_default_params(self, mock_db_manager):
        """
        Test: Token genereren met default parameters
        Normal case: Standaard token zonder expiratie
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        # Mock database insert
        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        token = auth_manager.generate_token(sensor_id='sensor-001')

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20  # Should be reasonably long

    def test_generate_token_with_expiration(self, mock_db_manager):
        """
        Test: Token met expiratie datum
        Normal case: Token expires in X dagen
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        token = auth_manager.generate_token(
            sensor_id='sensor-001',
            expires_days=30
        )

        assert token is not None

    def test_generate_token_with_name(self, mock_db_manager):
        """
        Test: Named token voor identificatie
        Normal case: Token met beschrijvende naam
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        token = auth_manager.generate_token(
            sensor_id='sensor-001',
            token_name='Production Token'
        )

        assert token is not None

    def test_generate_token_with_permissions(self, mock_db_manager):
        """
        Test: Token met specifieke permissions
        Normal case: Limited permission token
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        permissions = {
            'can_upload_alerts': True,
            'can_modify_config': False
        }

        token = auth_manager.generate_token(
            sensor_id='sensor-001',
            permissions=permissions
        )

        assert token is not None

    def test_generate_multiple_unique_tokens(self, mock_db_manager):
        """
        Test: Meerdere tokens moeten uniek zijn
        Security case: Geen duplicate tokens
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        tokens = set()
        for i in range(10):
            token = auth_manager.generate_token(sensor_id=f'sensor-{i:03d}')
            tokens.add(token)

        # Alle tokens moeten uniek zijn
        assert len(tokens) == 10


# ============================================================================
# TOKEN VALIDATION TESTS
# ============================================================================

@pytest.mark.unit
class TestTokenValidation:
    """Test token validatie functionaliteit"""

    def test_validate_token_valid_active(self, mock_db_manager):
        """
        Test: Validatie van actieve, geldige token
        Normal case: Token is active en niet expired
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        # Mock database query result - validate_token expects tuple of 8 values
        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Return tuple: (token_id, sensor_id, token_name, permissions, expires_at, hostname, location, status)
        mock_cursor.fetchone.return_value = (
            1,                                      # token_id
            'sensor-001',                           # sensor_id
            'Test Token',                           # token_name
            {'alerts': True, 'metrics': True},      # permissions (dict)
            datetime.now() + timedelta(days=30),    # expires_at
            'test-host',                            # hostname
            'test-location',                        # location
            'online'                                # status
        )
        mock_cursor.rowcount = 1
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn
        mock_db_manager._return_connection = Mock()

        result = auth_manager.validate_token('valid-token-123')

        assert result is not None
        assert result['sensor_id'] == 'sensor-001'

    def test_validate_token_expired(self, mock_db_manager):
        """
        Test: Validatie van expired token
        Edge case: Token is verlopen
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        # Mock database query result - expired token (tuple format)
        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Return tuple: (token_id, sensor_id, token_name, permissions, expires_at, hostname, location, status)
        mock_cursor.fetchone.return_value = (
            1,                                      # token_id
            'sensor-001',                           # sensor_id
            'Test Token',                           # token_name
            {'alerts': True},                       # permissions
            datetime.now() - timedelta(days=1),     # expires_at (expired)
            'test-host',                            # hostname
            'test-location',                        # location
            'online'                                # status
        )
        mock_cursor.rowcount = 1
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn
        mock_db_manager._return_connection = Mock()

        result = auth_manager.validate_token('expired-token')

        # Expired token moet None returnen
        assert result is None

    def test_validate_token_inactive(self, mock_db_manager):
        """
        Test: Validatie van inactieve token
        Edge case: Token is gerevoked (query retourneert geen resultaten)
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        # Mock database query result - inactive token returns None (filtered by WHERE is_active = TRUE)
        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None  # No result for inactive tokens
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn
        mock_db_manager._return_connection = Mock()

        result = auth_manager.validate_token('inactive-token')

        assert result is None

    def test_validate_token_not_found(self, mock_db_manager):
        """
        Test: Validatie van niet-bestaande token
        Error case: Token bestaat niet in database
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        # Mock database query result - no token found
        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        result = auth_manager.validate_token('nonexistent-token')

        assert result is None

    def test_validate_token_with_permission_check(self, mock_db_manager):
        """
        Test: Token validatie met permission check
        Normal case: Check specifieke permission
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        # Test 1: Check permission that exists and is True
        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Return tuple: (token_id, sensor_id, token_name, permissions, expires_at, hostname, location, status)
        mock_cursor.fetchone.return_value = (
            1,                                      # token_id
            'sensor-001',                           # sensor_id
            'Test Token',                           # token_name
            {'can_upload_alerts': True, 'can_modify_config': False},  # permissions
            None,                                   # expires_at
            'test-host',                            # hostname
            'test-location',                        # location
            'online'                                # status
        )
        mock_cursor.rowcount = 1
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn
        mock_db_manager._return_connection = Mock()

        result = auth_manager.validate_token('token', required_permission='can_upload_alerts')
        assert result is not None

        # Test 2: Check permission that is False
        mock_cursor.fetchone.return_value = (
            1, 'sensor-001', 'Test Token',
            {'can_upload_alerts': True, 'can_modify_config': False},
            None, 'test-host', 'test-location', 'online'
        )
        result = auth_manager.validate_token('token', required_permission='can_modify_config')
        assert result is None

        # Test 3: Check permission that doesn't exist
        mock_cursor.fetchone.return_value = (
            1, 'sensor-001', 'Test Token',
            {'can_upload_alerts': True, 'can_modify_config': False},
            None, 'test-host', 'test-location', 'online'
        )
        result = auth_manager.validate_token('token', required_permission='nonexistent_permission')
        assert result is None


# ============================================================================
# TOKEN REVOCATION TESTS
# ============================================================================

@pytest.mark.unit
class TestTokenRevocation:
    """Test token revocation functionaliteit"""

    def test_revoke_token_success(self, mock_db_manager):
        """
        Test: Token revoken
        Normal case: Active token wordt inactief gemaakt
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 1  # 1 row affected
        # revoke_token calls conn.cursor() directly (not as context manager)
        mock_conn.cursor.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn
        mock_db_manager._return_connection = Mock()

        result = auth_manager.revoke_token(token_id=123)

        assert result is True

    def test_revoke_token_not_found(self, mock_db_manager):
        """
        Test: Revoke non-existent token
        Error case: Token ID bestaat niet
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 0  # No rows affected
        # revoke_token calls conn.cursor() directly (not as context manager)
        mock_conn.cursor.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn
        mock_db_manager._return_connection = Mock()

        result = auth_manager.revoke_token(token_id=999)

        assert result is False


# ============================================================================
# TOKEN LISTING TESTS
# ============================================================================

@pytest.mark.unit
class TestTokenListing:
    """Test token listing functionaliteit"""

    def test_list_all_active_tokens(self, mock_db_manager):
        """
        Test: Alle actieve tokens ophalen
        Normal case: Lijst van active tokens
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_tokens = [
            {'id': 1, 'sensor_id': 'sensor-001', 'token_name': 'Token 1', 'active': True},
            {'id': 2, 'sensor_id': 'sensor-002', 'token_name': 'Token 2', 'active': True}
        ]

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = mock_tokens
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        tokens = auth_manager.list_tokens()

        assert isinstance(tokens, list)
        assert len(tokens) == 2

    def test_list_tokens_for_specific_sensor(self, mock_db_manager):
        """
        Test: Tokens voor specifieke sensor
        Normal case: Filter op sensor_id
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_tokens = [
            {'id': 1, 'sensor_id': 'sensor-001', 'token_name': 'Token 1'}
        ]

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = mock_tokens
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        tokens = auth_manager.list_tokens(sensor_id='sensor-001')

        assert len(tokens) == 1
        assert tokens[0]['sensor_id'] == 'sensor-001'

    def test_list_tokens_include_inactive(self, mock_db_manager):
        """
        Test: Lijst inclusief inactive tokens
        Edge case: Ook revoked tokens tonen
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_tokens = [
            {'id': 1, 'active': True},
            {'id': 2, 'active': False}
        ]

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = mock_tokens
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        tokens = auth_manager.list_tokens(include_inactive=True)

        assert len(tokens) == 2


# ============================================================================
# CLEANUP TESTS
# ============================================================================

@pytest.mark.unit
class TestTokenCleanup:
    """Test cleanup van expired tokens"""

    def test_cleanup_expired_tokens(self, mock_db_manager):
        """
        Test: Expired tokens verwijderen
        Normal case: Oude tokens opruimen
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 15  # 15 tokens verwijderd
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        deleted_count = auth_manager.cleanup_expired_tokens()

        assert deleted_count == 15

    def test_cleanup_no_expired_tokens(self, mock_db_manager):
        """
        Test: Cleanup zonder expired tokens
        Edge case: Geen tokens om te verwijderen
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 0  # Geen tokens verwijderd
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        deleted_count = auth_manager.cleanup_expired_tokens()

        assert deleted_count == 0


# ============================================================================
# SECURITY TESTS
# ============================================================================

@pytest.mark.unit
class TestSecurityAspects:
    """Test security aspecten van token management"""

    def test_token_minimum_length(self, mock_db_manager):
        """
        Test: Tokens hebben minimale lengte voor security
        Security case: Tokens moeten lang genoeg zijn
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        token = auth_manager.generate_token(sensor_id='sensor-001')

        # Token moet minstens 32 characters zijn voor voldoende entropy
        assert len(token) >= 32

    def test_token_uniqueness_across_sensors(self, mock_db_manager):
        """
        Test: Tokens zijn uniek across verschillende sensors
        Security case: Geen token reuse tussen sensors
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        mock_db_manager._get_connection = Mock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {'id': 1}
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_db_manager._get_connection.return_value = mock_conn

        token1 = auth_manager.generate_token(sensor_id='sensor-001')
        token2 = auth_manager.generate_token(sensor_id='sensor-002')

        assert token1 != token2

    def test_validate_empty_token(self, mock_db_manager):
        """
        Test: Validatie van lege token
        Security case: Empty/None token moet rejected worden
        """
        auth_manager = SensorAuthManager(mock_db_manager)

        result = auth_manager.validate_token('')
        assert result is None

        result = auth_manager.validate_token(None)
        assert result is None
