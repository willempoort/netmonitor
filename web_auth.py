#!/usr/bin/env python3
"""
Web Authentication Module
User management with password hashing and 2FA support
"""

import secrets
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
import qrcode
import io
import base64


class WebUser:
    """User model for Flask-Login"""

    def __init__(self, user_data: Dict[str, Any]):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data.get('email')
        self.role = user_data['role']
        self.totp_enabled = user_data.get('totp_enabled', False)
        self.totp_secret = user_data.get('totp_secret')
        self.created_at = user_data.get('created_at')
        self.last_login = user_data.get('last_login')
        self.is_active = user_data.get('is_active', True)

    @property
    def is_authenticated(self):
        """Required by Flask-Login"""
        return True

    @property
    def is_anonymous(self):
        """Required by Flask-Login"""
        return False

    def get_id(self):
        """Required by Flask-Login"""
        return str(self.id)

    def __repr__(self):
        """String representation - NEVER include totp_secret for security!"""
        return f"<WebUser(id={self.id}, username='{self.username}', role='{self.role}', 2fa={'enabled' if self.totp_enabled else 'disabled'})>"

    def __str__(self):
        """String representation - NEVER include totp_secret for security!"""
        return f"User: {self.username} ({self.role})"

    def to_dict(self):
        """Convert to dictionary for JSON responses - NEVER include totp_secret!"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'totp_enabled': self.totp_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class WebAuthManager:
    """Manages web user authentication with 2FA support"""

    def __init__(self, db_manager):
        """
        Initialize web auth manager

        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.WebAuth')
        self.ph = PasswordHasher()  # Argon2 password hasher

        # Rate limiting cache: {username: [timestamp1, timestamp2, ...]}
        self.rate_limit_cache = {}

    def create_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        role: str = 'operator',
        created_by: Optional[str] = None,
        enable_2fa: bool = False
    ) -> Optional[WebUser]:
        """
        Create a new web user

        Args:
            username: Unique username
            password: Plain text password (will be hashed)
            email: Optional email address
            role: User role (admin, operator, viewer)
            created_by: Username of creator
            enable_2fa: Automatically enable 2FA with generated secret

        Returns:
            WebUser object if successful, None otherwise
        """
        # Validate inputs
        if not username or not password:
            self.logger.error("Username and password are required")
            return None

        if role not in ['admin', 'operator', 'viewer']:
            self.logger.error(f"Invalid role: {role}")
            return None

        # Validate password strength
        if len(password) < 12:
            self.logger.error("Password must be at least 12 characters")
            return None

        # Hash password with Argon2
        password_hash = self.ph.hash(password)

        # Generate TOTP secret if 2FA is enabled
        totp_secret = None
        if enable_2fa:
            totp_secret = pyotp.random_base32()

        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO web_users (username, password_hash, email, role, totp_secret, totp_enabled, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, username, email, role, totp_secret, totp_enabled, created_at, is_active
            ''', (username, password_hash, email, role, totp_secret, enable_2fa, created_by))

            result = cursor.fetchone()
            conn.commit()

            user_data = {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3],
                'totp_secret': result[4],
                'totp_enabled': result[5],
                'created_at': result[6],
                'is_active': result[7]
            }

            self.logger.info(f"Created user: {username} (role: {role}, 2FA: {enable_2fa})")
            self.audit_log(user_data['id'], 'user_created', None, created_by, {'role': role, '2fa_enabled': enable_2fa})

            return WebUser(user_data)

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating user: {e}")
            return None
        finally:
            self.db._return_connection(conn)

    def authenticate(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[WebUser]:
        """
        Authenticate user with username and password

        Args:
            username: Username
            password: Plain text password
            ip_address: Client IP address (for audit log)
            user_agent: Client user agent (for audit log)

        Returns:
            WebUser object if credentials are valid, None otherwise
        """
        # Check rate limiting
        if not self._check_rate_limit(username):
            self.logger.warning(f"Rate limit exceeded for user: {username}")
            self.audit_log(None, 'login_rate_limited', ip_address, username, {'user_agent': user_agent})
            return None

        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, password_hash, email, role, totp_secret, totp_enabled,
                       created_at, last_login, is_active, locked_until, failed_login_attempts
                FROM web_users
                WHERE username = %s AND is_active = TRUE
            ''', (username,))

            result = cursor.fetchone()

            if not result:
                self.logger.warning(f"Login failed: user not found: {username}")
                self.audit_log(None, 'login_failed', ip_address, username, {'reason': 'user_not_found', 'user_agent': user_agent})
                return None

            user_id, username, password_hash, email, role, totp_secret, totp_enabled, \
                created_at, last_login, is_active, locked_until, failed_attempts = result

            # Check if account is locked
            if locked_until and locked_until > datetime.now():
                self.logger.warning(f"Login failed: account locked: {username} (until {locked_until})")
                self.audit_log(user_id, 'login_failed', ip_address, username, {'reason': 'account_locked', 'user_agent': user_agent})
                return None

            # Verify password
            try:
                self.ph.verify(password_hash, password)

                # Password is valid - check if needs rehashing (Argon2 auto-rehash)
                if self.ph.check_needs_rehash(password_hash):
                    new_hash = self.ph.hash(password)
                    cursor.execute('''
                        UPDATE web_users SET password_hash = %s WHERE id = %s
                    ''', (new_hash, user_id))
                    self.logger.info(f"Rehashed password for user: {username}")

                # Reset failed login attempts on successful password verification
                cursor.execute('''
                    UPDATE web_users
                    SET failed_login_attempts = 0, locked_until = NULL
                    WHERE id = %s
                ''', (user_id,))
                conn.commit()

                # Log successful password verification (not full login if 2FA required)
                event_type = 'login_password_verified' if totp_enabled else 'login_success'
                self.audit_log(user_id, event_type, ip_address, username, {'user_agent': user_agent})

                # Update last_login only if 2FA is not required (otherwise update after 2FA)
                if not totp_enabled:
                    cursor.execute('''
                        UPDATE web_users SET last_login = NOW() WHERE id = %s
                    ''', (user_id,))
                    conn.commit()

                user_data = {
                    'id': user_id,
                    'username': username,
                    'email': email,
                    'role': role,
                    'totp_secret': totp_secret,
                    'totp_enabled': totp_enabled,
                    'created_at': created_at,
                    'last_login': last_login,
                    'is_active': is_active
                }

                return WebUser(user_data)

            except VerifyMismatchError:
                # Password verification failed
                failed_attempts += 1

                # Lock account after 5 failed attempts for 15 minutes
                locked_until_time = None
                if failed_attempts >= 5:
                    locked_until_time = datetime.now() + timedelta(minutes=15)
                    self.logger.warning(f"Account locked after {failed_attempts} failed attempts: {username}")

                cursor.execute('''
                    UPDATE web_users
                    SET failed_login_attempts = %s, locked_until = %s
                    WHERE id = %s
                ''', (failed_attempts, locked_until_time, user_id))
                conn.commit()

                self.logger.warning(f"Login failed: invalid password: {username} (attempt {failed_attempts})")
                self.audit_log(user_id, 'login_failed', ip_address, username, {
                    'reason': 'invalid_password',
                    'failed_attempts': failed_attempts,
                    'user_agent': user_agent
                })

                return None

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error authenticating user: {e}")
            return None
        finally:
            self.db._return_connection(conn)

    def verify_2fa(
        self,
        user: WebUser,
        code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        is_backup_code: bool = False
    ) -> bool:
        """
        Verify 2FA code (TOTP or backup code)

        Args:
            user: WebUser object
            code: 6-digit TOTP code or backup code
            ip_address: Client IP address
            user_agent: Client user agent
            is_backup_code: If True, treat as backup code

        Returns:
            True if code is valid, False otherwise
        """
        if not user.totp_enabled or not user.totp_secret:
            self.logger.warning(f"2FA verification attempted but 2FA not enabled: {user.username}")
            return False

        # Try backup code first if specified or if code is too long for TOTP
        if is_backup_code or len(code) > 6:
            if self._verify_backup_code(user, code):
                self.logger.info(f"2FA backup code verified: {user.username}")
                self.audit_log(user.id, '2fa_backup_code_used', ip_address, user.username, {'user_agent': user_agent})
                self._update_last_login(user.id)
                return True
            else:
                self.logger.warning(f"2FA backup code invalid: {user.username}")
                self.audit_log(user.id, '2fa_failed', ip_address, user.username, {'reason': 'invalid_backup_code', 'user_agent': user_agent})
                return False

        # Verify TOTP code
        totp = pyotp.TOTP(user.totp_secret)

        # Allow 1 time window before and after (90 seconds total window)
        if totp.verify(code, valid_window=1):
            self.logger.info(f"2FA verified: {user.username}")
            self.audit_log(user.id, 'login_success', ip_address, user.username, {'2fa': True, 'user_agent': user_agent})
            self._update_last_login(user.id)
            return True
        else:
            self.logger.warning(f"2FA failed: {user.username}")
            self.audit_log(user.id, '2fa_failed', ip_address, user.username, {'reason': 'invalid_totp', 'user_agent': user_agent})
            return False

    def setup_2fa(self, user_id: int, app_name: str = "NetMonitor") -> Optional[Dict[str, Any]]:
        """
        Setup 2FA for a user (generate secret and QR code)

        Args:
            user_id: User ID
            app_name: Application name for TOTP URI

        Returns:
            Dict with secret, qr_code (base64 PNG), and backup_codes
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()

            # Get user
            cursor.execute('SELECT username FROM web_users WHERE id = %s', (user_id,))
            result = cursor.fetchone()
            if not result:
                return None

            username = result[0]

            # Generate TOTP secret
            totp_secret = pyotp.random_base32()

            # Generate backup codes (10 codes)
            backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
            backup_codes_hashed = [self.ph.hash(code) for code in backup_codes]

            # Update user
            cursor.execute('''
                UPDATE web_users
                SET totp_secret = %s, totp_enabled = TRUE, backup_codes = %s
                WHERE id = %s
            ''', (totp_secret, backup_codes_hashed, user_id))
            conn.commit()

            # Generate QR code
            totp = pyotp.TOTP(totp_secret)
            provisioning_uri = totp.provisioning_uri(name=username, issuer_name=app_name)

            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to base64
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

            self.logger.info(f"2FA setup completed for user: {username}")
            self.audit_log(user_id, '2fa_enabled', None, username)

            return {
                'secret': totp_secret,
                'qr_code': qr_code_base64,
                'backup_codes': backup_codes,  # Only returned once!
                'provisioning_uri': provisioning_uri
            }

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error setting up 2FA: {e}")
            return None
        finally:
            self.db._return_connection(conn)

    def disable_2fa(self, user_id: int) -> bool:
        """
        Disable 2FA for a user

        Args:
            user_id: User ID

        Returns:
            True if successful, False otherwise
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE web_users
                SET totp_enabled = FALSE, totp_secret = NULL, backup_codes = NULL
                WHERE id = %s
            ''', (user_id,))
            conn.commit()

            self.logger.info(f"2FA disabled for user ID: {user_id}")
            self.audit_log(user_id, '2fa_disabled', None, None)

            return cursor.rowcount > 0

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error disabling 2FA: {e}")
            return False
        finally:
            self.db._return_connection(conn)

    def get_user_by_id(self, user_id: int) -> Optional[WebUser]:
        """
        Get user by ID

        Args:
            user_id: User ID

        Returns:
            WebUser object if found, None otherwise
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, role, totp_secret, totp_enabled, created_at, last_login, is_active
                FROM web_users
                WHERE id = %s AND is_active = TRUE
            ''', (user_id,))

            result = cursor.fetchone()

            if not result:
                return None

            user_data = {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3],
                'totp_secret': result[4],
                'totp_enabled': result[5],
                'created_at': result[6],
                'last_login': result[7],
                'is_active': result[8]
            }

            return WebUser(user_data)

        finally:
            self.db._return_connection(conn)

    def get_user_by_username(self, username: str) -> Optional[WebUser]:
        """
        Get user by username

        Args:
            username: Username

        Returns:
            WebUser object if found, None otherwise
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, role, totp_secret, totp_enabled, created_at, last_login, is_active
                FROM web_users
                WHERE username = %s AND is_active = TRUE
            ''', (username,))

            result = cursor.fetchone()

            if not result:
                return None

            user_data = {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3],
                'totp_secret': result[4],
                'totp_enabled': result[5],
                'created_at': result[6],
                'last_login': result[7],
                'is_active': result[8]
            }

            return WebUser(user_data)

        finally:
            self.db._return_connection(conn)

    def list_users(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """
        List all users

        Args:
            include_inactive: Include inactive users

        Returns:
            List of user dicts
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()

            query = '''
                SELECT id, username, email, role, totp_enabled, created_at, last_login, is_active, created_by
                FROM web_users
            '''

            if not include_inactive:
                query += ' WHERE is_active = TRUE'

            query += ' ORDER BY created_at DESC'

            cursor.execute(query)

            users = []
            for row in cursor.fetchall():
                users.append({
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'role': row[3],
                    'totp_enabled': row[4],
                    'created_at': row[5].isoformat() if row[5] else None,
                    'last_login': row[6].isoformat() if row[6] else None,
                    'is_active': row[7],
                    'created_by': row[8]
                })

            return users

        finally:
            self.db._return_connection(conn)

    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """
        Change user password

        Args:
            user_id: User ID
            old_password: Current password
            new_password: New password

        Returns:
            True if successful, False otherwise
        """
        if len(new_password) < 12:
            self.logger.error("New password must be at least 12 characters")
            return False

        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()

            # Get current password hash
            cursor.execute('SELECT password_hash, username FROM web_users WHERE id = %s', (user_id,))
            result = cursor.fetchone()

            if not result:
                return False

            current_hash, username = result

            # Verify old password
            try:
                self.ph.verify(current_hash, old_password)
            except VerifyMismatchError:
                self.logger.warning(f"Password change failed: incorrect old password: {username}")
                self.audit_log(user_id, 'password_change_failed', None, username, {'reason': 'incorrect_old_password'})
                return False

            # Hash new password
            new_hash = self.ph.hash(new_password)

            # Update password
            cursor.execute('''
                UPDATE web_users SET password_hash = %s WHERE id = %s
            ''', (new_hash, user_id))
            conn.commit()

            self.logger.info(f"Password changed for user: {username}")
            self.audit_log(user_id, 'password_changed', None, username)

            return True

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error changing password: {e}")
            return False
        finally:
            self.db._return_connection(conn)

    def deactivate_user(self, user_id: int, deactivated_by: Optional[str] = None) -> bool:
        """
        Deactivate a user

        Args:
            user_id: User ID to deactivate
            deactivated_by: Username of admin performing action

        Returns:
            True if successful, False otherwise
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE web_users SET is_active = FALSE WHERE id = %s
            ''', (user_id,))
            conn.commit()

            self.logger.info(f"User deactivated: ID {user_id} by {deactivated_by}")
            self.audit_log(user_id, 'user_deactivated', None, deactivated_by)

            return cursor.rowcount > 0

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deactivating user: {e}")
            return False
        finally:
            self.db._return_connection(conn)

    def audit_log(
        self,
        user_id: Optional[int],
        event_type: str,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        details: Optional[Dict] = None
    ):
        """
        Log security event to audit trail

        Args:
            user_id: User ID (can be None for failed logins)
            event_type: Type of event
            ip_address: Client IP address
            username: Username (for events where user_id is not available)
            details: Additional details as JSON
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO web_user_audit (user_id, username, event_type, ip_address, details)
                VALUES (%s, %s, %s, %s, %s)
            ''', (user_id, username, event_type, ip_address, details))
            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error logging audit event: {e}")
        finally:
            self.db._return_connection(conn)

    def _check_rate_limit(self, username: str) -> bool:
        """
        Check rate limiting for login attempts

        Args:
            username: Username to check

        Returns:
            True if within limits, False if exceeded
        """
        now = datetime.now()

        # Clean old entries
        if username in self.rate_limit_cache:
            self.rate_limit_cache[username] = [
                ts for ts in self.rate_limit_cache[username]
                if ts > now - timedelta(minutes=15)
            ]
        else:
            self.rate_limit_cache[username] = []

        # Check limit (max 5 attempts per 15 minutes)
        if len(self.rate_limit_cache[username]) >= 5:
            return False

        # Add to cache
        self.rate_limit_cache[username].append(now)
        return True

    def _verify_backup_code(self, user: WebUser, code: str) -> bool:
        """
        Verify and consume a backup code

        Args:
            user: WebUser object
            code: Backup code to verify

        Returns:
            True if valid and consumed, False otherwise
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()

            # Get backup codes
            cursor.execute('SELECT backup_codes FROM web_users WHERE id = %s', (user.id,))
            result = cursor.fetchone()

            if not result or not result[0]:
                return False

            backup_codes = result[0]

            # Check each backup code
            for i, hashed_code in enumerate(backup_codes):
                try:
                    self.ph.verify(hashed_code, code)

                    # Code is valid - remove it from array
                    backup_codes.pop(i)

                    cursor.execute('''
                        UPDATE web_users SET backup_codes = %s WHERE id = %s
                    ''', (backup_codes, user.id))
                    conn.commit()

                    return True

                except VerifyMismatchError:
                    continue

            return False

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error verifying backup code: {e}")
            return False
        finally:
            self.db._return_connection(conn)

    def _update_last_login(self, user_id: int):
        """Update last_login timestamp"""
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE web_users SET last_login = NOW() WHERE id = %s', (user_id,))
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating last_login: {e}")
        finally:
            self.db._return_connection(conn)
