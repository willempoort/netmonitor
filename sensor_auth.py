# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Sensor Authentication Module
Token-based authentication for remote sensors
"""

import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any


class SensorAuthManager:
    """Manage sensor authentication tokens"""

    def __init__(self, db_manager):
        """
        Initialize sensor auth manager

        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.SensorAuth')

    def generate_token(self, sensor_id: str, token_name: Optional[str] = None,
                       expires_days: Optional[int] = None,
                       permissions: Optional[Dict] = None) -> str:
        """
        Generate a new authentication token for a sensor

        Args:
            sensor_id: Unique sensor identifier
            token_name: Optional name/description for the token
            expires_days: Optional expiration in days (None = never expires)
            permissions: Optional permissions dict (default: full access)

        Returns:
            str: The generated token (plaintext - only shown once!)
        """
        # Generate secure random token
        token = secrets.token_urlsafe(32)  # 256 bits of entropy

        # Hash token for storage (SHA-256)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Calculate expiration
        expires_at = None
        if expires_days:
            expires_at = datetime.now() + timedelta(days=expires_days)

        # Default permissions
        if permissions is None:
            permissions = {
                'alerts': True,
                'metrics': True,
                'commands': False  # Commands require explicit permission
            }

        # Store in database
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()

            # Convert permissions dict to JSON string for PostgreSQL
            import json
            permissions_json = json.dumps(permissions)

            cursor.execute('''
                INSERT INTO sensor_tokens (sensor_id, token_hash, token_name, expires_at, permissions)
                VALUES (%s, %s, %s, %s, %s::jsonb)
                RETURNING id
            ''', (sensor_id, token_hash, token_name, expires_at, permissions_json))

            token_id = cursor.fetchone()[0]
            conn.commit()

            self.logger.info(f"Generated token for sensor {sensor_id} (ID: {token_id})")

            return token  # Return plaintext token (only time it's available!)

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error generating token: {e}")
            raise
        finally:
            self.db._return_connection(conn)

    def validate_token(self, token: str, required_permission: str = None) -> Optional[Dict[str, Any]]:
        """
        Validate a sensor token

        Args:
            token: The token to validate
            required_permission: Optional specific permission required (e.g., 'alerts', 'commands')

        Returns:
            Dict with sensor details if valid, None otherwise
        """
        # Hash the provided token
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()

            # Look up token
            cursor.execute('''
                SELECT
                    st.id,
                    st.sensor_id,
                    st.token_name,
                    st.permissions,
                    st.expires_at,
                    s.hostname,
                    s.location,
                    s.status
                FROM sensor_tokens st
                JOIN sensors s ON st.sensor_id = s.sensor_id
                WHERE st.token_hash = %s
                  AND st.is_active = TRUE
            ''', (token_hash,))

            result = cursor.fetchone()

            if not result:
                self.logger.warning(f"Invalid token attempted")
                return None

            token_id, sensor_id, token_name, permissions, expires_at, hostname, location, status = result

            # Check expiration
            if expires_at and datetime.now() > expires_at:
                self.logger.warning(f"Expired token used for sensor {sensor_id}")
                return None

            # Check specific permission if requested
            if required_permission:
                if not permissions.get(required_permission, False):
                    self.logger.warning(f"Sensor {sensor_id} lacks permission: {required_permission}")
                    return None

            # Update last_used timestamp
            cursor.execute('''
                UPDATE sensor_tokens
                SET last_used = NOW()
                WHERE id = %s
            ''', (token_id,))
            conn.commit()

            # Return sensor details
            return {
                'token_id': token_id,
                'sensor_id': sensor_id,
                'token_name': token_name,
                'hostname': hostname,
                'location': location,
                'status': status,
                'permissions': permissions
            }

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error validating token: {e}")
            return None
        finally:
            self.db._return_connection(conn)

    def revoke_token(self, token_id: int) -> bool:
        """
        Revoke a token (mark as inactive)

        Args:
            token_id: The token ID to revoke

        Returns:
            bool: True if revoked, False otherwise
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sensor_tokens
                SET is_active = FALSE
                WHERE id = %s
            ''', (token_id,))

            conn.commit()
            self.logger.info(f"Revoked token ID {token_id}")
            return cursor.rowcount > 0

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error revoking token: {e}")
            return False
        finally:
            self.db._return_connection(conn)

    def list_tokens(self, sensor_id: Optional[str] = None, include_inactive: bool = False) -> list:
        """
        List all tokens (optionally filtered by sensor)

        Args:
            sensor_id: Optional sensor ID to filter by
            include_inactive: Include revoked tokens

        Returns:
            List of token metadata (no token hashes!)
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()

            query = '''
                SELECT
                    st.id,
                    st.sensor_id,
                    st.token_name,
                    st.created_at,
                    st.last_used,
                    st.expires_at,
                    st.is_active,
                    st.permissions,
                    s.hostname,
                    s.location
                FROM sensor_tokens st
                JOIN sensors s ON st.sensor_id = s.sensor_id
                WHERE 1=1
            '''
            params = []

            if sensor_id:
                query += ' AND st.sensor_id = %s'
                params.append(sensor_id)

            if not include_inactive:
                query += ' AND st.is_active = TRUE'

            query += ' ORDER BY st.created_at DESC'

            cursor.execute(query, params)

            tokens = []
            for row in cursor.fetchall():
                tokens.append({
                    'id': row[0],
                    'sensor_id': row[1],
                    'token_name': row[2],
                    'created_at': row[3].isoformat() if row[3] else None,
                    'last_used': row[4].isoformat() if row[4] else None,
                    'expires_at': row[5].isoformat() if row[5] else None,
                    'is_active': row[6],
                    'permissions': row[7],
                    'hostname': row[8],
                    'location': row[9]
                })

            return tokens

        finally:
            self.db._return_connection(conn)

    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens (mark as inactive)

        Returns:
            int: Number of tokens cleaned up
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sensor_tokens
                SET is_active = FALSE
                WHERE expires_at < NOW()
                  AND is_active = TRUE
            ''')

            conn.commit()
            count = cursor.rowcount

            if count > 0:
                self.logger.info(f"Cleaned up {count} expired tokens")

            return count

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error cleaning expired tokens: {e}")
            return 0
        finally:
            self.db._return_connection(conn)
