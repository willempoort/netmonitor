# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Sensor Authentication Module
Token-based authentication for remote sensors
"""

import secrets
import hashlib
import logging
import json
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any


# Aanmelden (enrollment) van nieuwe sensors
SENSOR_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
# Paden onder /api/sensors/ die geen sensor-ID mogen zijn
RESERVED_SENSOR_IDS = {'register', 'enroll', 'enrollments', 'tokens'}
MAX_PENDING_ENROLLMENTS = 50
PENDING_ENROLLMENT_TTL_DAYS = 7
DEFAULT_ENROLLED_PERMISSIONS = {'alerts': True, 'metrics': True, 'commands': True}


def token_fingerprint(token: str) -> str:
    """
    Korte, leesbare vingerafdruk van een token (eerste 16 hex-tekens van de
    SHA-256). De sensor logt dezelfde waarde, zodat de beheerder bij het
    goedkeuren kan controleren dat het verzoek van de juiste machine komt.
    """
    digest = hashlib.sha256(token.encode()).hexdigest()[:16]
    return '-'.join(digest[i:i + 4] for i in range(0, 16, 4))


def _hash_fingerprint(token_hash: str) -> str:
    digest = token_hash[:16]
    return '-'.join(digest[i:i + 4] for i in range(0, 16, 4))


class EnrollmentError(Exception):
    """Aanmeldverzoek geweigerd; code is een korte machine-leesbare reden."""

    def __init__(self, code: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


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
        # Check for None or empty token
        if not token:
            self.logger.warning("Empty or None token provided")
            return None

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

            # Deserialize permissions if it's a JSON string
            if isinstance(permissions, str):
                try:
                    permissions = json.loads(permissions)
                except json.JSONDecodeError:
                    permissions = {}
            elif permissions is None:
                permissions = {}

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

    # ------------------------------------------------------------------
    # Aanmelden (enrollment): sensor vraagt zelf een token aan, een admin
    # keurt het verzoek goed in het dashboard. Pas dan komt het token in
    # sensor_tokens en accepteert validate_token() het.
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_text(value, max_len):
        if value is None:
            return None
        value = str(value).strip()
        return value[:max_len] or None

    def _expire_stale_enrollments(self, cursor):
        cursor.execute('''
            UPDATE sensor_enrollments
            SET status = 'expired', decided_at = NOW(), decided_by = 'system'
            WHERE status = 'pending'
              AND requested_at < NOW() - make_interval(days => %s)
        ''', (PENDING_ENROLLMENT_TTL_DAYS,))

    def request_enrollment(self, sensor_id, hostname=None, location=None,
                           ip_address=None, version=None) -> Dict[str, Any]:
        """
        Maak een aanmeldverzoek aan. Geeft het (nog niet geldige) token één keer
        terug. Raises EnrollmentError bij een ongeldig of geweigerd verzoek.
        """
        if not isinstance(sensor_id, str) or not SENSOR_ID_RE.match(sensor_id) \
                or sensor_id.lower() in RESERVED_SENSOR_IDS:
            raise EnrollmentError('invalid_sensor_id',
                                  'sensor_id: 1-64 tekens, letters/cijfers/.-_', 400)

        hostname = self._clean_text(hostname, 255)
        location = self._clean_text(location, 255)
        version = self._clean_text(version, 64)

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            self._expire_stale_enrollments(cursor)

            cursor.execute("SELECT COUNT(*) FROM sensor_enrollments WHERE status = 'pending'")
            if cursor.fetchone()[0] >= MAX_PENDING_ENROLLMENTS:
                conn.commit()
                raise EnrollmentError('too_many_pending',
                                      'Te veel openstaande aanmeldverzoeken', 429)

            cursor.execute(
                "SELECT 1 FROM sensor_enrollments WHERE sensor_id = %s AND status = 'pending'",
                (sensor_id,))
            if cursor.fetchone():
                conn.commit()
                raise EnrollmentError(
                    'already_pending',
                    'Er staat al een aanmeldverzoek open voor deze sensor. '
                    'Wijs het oude verzoek af in het dashboard en probeer opnieuw.', 409)

            cursor.execute('''
                INSERT INTO sensor_enrollments
                    (sensor_id, hostname, location, ip_address, version, token_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (sensor_id, hostname, location, ip_address, version, token_hash))
            enrollment_id = cursor.fetchone()[0]
            conn.commit()
        except EnrollmentError:
            raise
        except Exception as e:
            conn.rollback()
            # Gelijktijdig verzoek voor dezelfde sensor -> unieke index
            if 'idx_sensor_enrollments_one_pending' in str(e):
                raise EnrollmentError('already_pending',
                                      'Er staat al een aanmeldverzoek open voor deze sensor.', 409)
            self.logger.error(f"Error creating enrollment for {sensor_id}: {e}")
            raise
        finally:
            self.db._return_connection(conn)

        fingerprint = token_fingerprint(token)
        self.logger.warning(
            f"Nieuw aanmeldverzoek #{enrollment_id} van sensor {sensor_id} "
            f"({hostname}, {ip_address}), vingerafdruk {fingerprint} - keur goed in het dashboard"
        )
        return {'id': enrollment_id, 'token': token, 'fingerprint': fingerprint, 'status': 'pending'}

    def get_enrollment_status(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Status van het aanmeldverzoek bij dit token: pending, approved,
        rejected, expired of revoked (goedgekeurd maar token ingetrokken).
        None als het token onbekend is.
        """
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            self._expire_stale_enrollments(cursor)
            cursor.execute('''
                SELECT e.id, e.sensor_id, e.status, st.is_active
                FROM sensor_enrollments e
                LEFT JOIN sensor_tokens st ON st.id = e.token_id
                WHERE e.token_hash = %s
            ''', (token_hash,))
            row = cursor.fetchone()
            if row:
                cursor.execute('UPDATE sensor_enrollments SET last_poll = NOW() WHERE id = %s', (row[0],))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.db._return_connection(conn)

        if not row:
            return None
        enrollment_id, sensor_id, status, token_active = row
        if status == 'approved' and not token_active:
            status = 'revoked'
        return {'id': enrollment_id, 'sensor_id': sensor_id, 'status': status}

    def list_enrollments(self, status: Optional[str] = 'pending') -> list:
        """Aanmeldverzoeken, met info over een eventueel al bestaande sensor."""
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            self._expire_stale_enrollments(cursor)
            conn.commit()
            query = '''
                SELECT e.id, e.sensor_id, e.hostname, e.location, host(e.ip_address),
                       e.version, e.token_hash, e.status, e.requested_at, e.last_poll,
                       e.decided_at, e.decided_by,
                       s.sensor_id IS NOT NULL AS existing,
                       host(s.ip_address), s.hostname, s.last_seen,
                       (SELECT COUNT(*) FROM sensor_tokens t
                         WHERE t.sensor_id = e.sensor_id AND t.is_active) AS active_tokens
                FROM sensor_enrollments e
                LEFT JOIN sensors s ON s.sensor_id = e.sensor_id
            '''
            params = []
            if status:
                query += ' WHERE e.status = %s'
                params.append(status)
            query += ' ORDER BY e.requested_at DESC LIMIT 200'
            cursor.execute(query, params)
            rows = cursor.fetchall()
        finally:
            self.db._return_connection(conn)

        def iso(v):
            return v.isoformat() if v else None

        return [{
            'id': r[0], 'sensor_id': r[1], 'hostname': r[2], 'location': r[3],
            'ip_address': r[4], 'version': r[5], 'fingerprint': _hash_fingerprint(r[6]),
            'status': r[7], 'requested_at': iso(r[8]), 'last_poll': iso(r[9]),
            'decided_at': iso(r[10]), 'decided_by': r[11],
            'existing_sensor': bool(r[12]),
            'existing_ip': r[13], 'existing_hostname': r[14], 'existing_last_seen': iso(r[15]),
            'existing_active_tokens': r[16],
        } for r in rows]

    def approve_enrollment(self, enrollment_id: int, approved_by: str,
                           allow_commands: bool = True) -> Optional[Dict[str, Any]]:
        """
        Keur een openstaand verzoek goed: maakt zo nodig de sensor-rij aan en
        zet het token in sensor_tokens. None als het verzoek niet (meer) open staat.
        """
        permissions = dict(DEFAULT_ENROLLED_PERMISSIONS, commands=bool(allow_commands))
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            self._expire_stale_enrollments(cursor)
            cursor.execute('''
                SELECT sensor_id, hostname, location, ip_address, version, token_hash
                FROM sensor_enrollments
                WHERE id = %s AND status = 'pending'
                FOR UPDATE
            ''', (enrollment_id,))
            row = cursor.fetchone()
            if not row:
                conn.commit()
                return None
            sensor_id, hostname, location, ip_address, version, token_hash = row

            # Nieuwe sensor aanmaken; een bestaande sensor laten we ongemoeid
            # (de eerstvolgende /register werkt hostname/IP/versie bij).
            cursor.execute('''
                INSERT INTO sensors (sensor_id, hostname, location, ip_address, version, status)
                VALUES (%s, %s, %s, %s, %s, 'offline')
                ON CONFLICT (sensor_id) DO NOTHING
            ''', (sensor_id, hostname or sensor_id, location, ip_address, version))

            cursor.execute('''
                INSERT INTO sensor_tokens (sensor_id, token_hash, token_name, permissions)
                VALUES (%s, %s, %s, %s::jsonb)
                RETURNING id
            ''', (sensor_id, token_hash,
                  f"enrolled #{enrollment_id} (approved by {approved_by})",
                  json.dumps(permissions)))
            token_id = cursor.fetchone()[0]

            cursor.execute('''
                UPDATE sensor_enrollments
                SET status = 'approved', decided_at = NOW(), decided_by = %s, token_id = %s
                WHERE id = %s
            ''', (approved_by, token_id, enrollment_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error approving enrollment #{enrollment_id}: {e}")
            raise
        finally:
            self.db._return_connection(conn)

        self.logger.warning(
            f"Aanmeldverzoek #{enrollment_id} voor sensor {sensor_id} goedgekeurd door {approved_by} "
            f"(token #{token_id}, commands={permissions['commands']})"
        )
        return {'id': enrollment_id, 'sensor_id': sensor_id, 'token_id': token_id,
                'permissions': permissions}

    def reject_enrollment(self, enrollment_id: int, rejected_by: str) -> Optional[str]:
        """Wijs een openstaand verzoek af. Geeft het sensor_id terug, of None."""
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sensor_enrollments
                SET status = 'rejected', decided_at = NOW(), decided_by = %s
                WHERE id = %s AND status = 'pending'
                RETURNING sensor_id
            ''', (rejected_by, enrollment_id))
            row = cursor.fetchone()
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.db._return_connection(conn)

        if row:
            self.logger.warning(f"Aanmeldverzoek #{enrollment_id} voor sensor {row[0]} afgewezen door {rejected_by}")
            return row[0]
        return None
