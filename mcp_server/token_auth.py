#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Token Authentication Module for MCP HTTP API

Handles API token validation, rate limiting, and usage tracking.
"""

import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from collections import defaultdict
import psycopg2
import psycopg2.extras
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger('NetMonitor.MCP.TokenAuth')

# Security scheme
security = HTTPBearer()


class TokenAuthManager:
    """Manages API token authentication and rate limiting"""

    def __init__(self, db_config: Dict[str, Any]):
        """
        Initialize token auth manager

        Args:
            db_config: Database configuration dict with host, port, database, user, password
        """
        self.db_config = db_config
        self.conn = None
        self.rate_limit_cache = defaultdict(lambda: {'minute': [], 'hour': [], 'day': []})
        self._connect()

    def _connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(
                host=self.db_config['host'],
                port=self.db_config['port'],
                database=self.db_config['database'],
                user=self.db_config['user'],
                password=self.db_config['password']
            )
            logger.info("Token auth manager connected to database")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def _ensure_connection(self):
        """Ensure database connection is alive"""
        try:
            if self.conn.closed:
                self._connect()
        except Exception:
            self._connect()

    def generate_token(self) -> str:
        """
        Generate a cryptographically secure API token

        Returns:
            64-character hexadecimal token
        """
        return secrets.token_hex(32)  # 32 bytes = 64 hex chars

    def create_token(
        self,
        name: str,
        description: str = "",
        scope: str = "read_only",
        rate_limit_per_minute: Optional[int] = 60,
        rate_limit_per_hour: Optional[int] = 1000,
        rate_limit_per_day: Optional[int] = 10000,
        expires_in_days: Optional[int] = None,
        created_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new API token

        Args:
            name: Human-readable name for the token
            description: Optional description
            scope: Permission level (read_only, read_write, admin)
            rate_limit_per_minute: Max requests per minute (None = unlimited)
            rate_limit_per_hour: Max requests per hour (None = unlimited)
            rate_limit_per_day: Max requests per day (None = unlimited)
            expires_in_days: Token expires after N days (None = no expiration)
            created_by: Username of creator

        Returns:
            Dict with token details including the actual token
        """
        self._ensure_connection()

        token = self.generate_token()
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)

        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            cursor.execute("""
                INSERT INTO mcp_api_tokens
                    (token, name, description, scope, rate_limit_per_minute,
                     rate_limit_per_hour, rate_limit_per_day, expires_at, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, token, name, scope, created_at, expires_at
            """, (token, name, description, scope, rate_limit_per_minute,
                  rate_limit_per_hour, rate_limit_per_day, expires_at, created_by))

            result = cursor.fetchone()
            self.conn.commit()

            logger.info(f"Created API token '{name}' (ID: {result['id']}, scope: {scope})")

            return dict(result)

        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to create token: {e}")
            raise
        finally:
            cursor.close()

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate an API token

        Args:
            token: API token to validate

        Returns:
            Token details dict if valid, None if invalid
        """
        self._ensure_connection()

        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            cursor.execute("""
                SELECT id, token, name, scope, enabled,
                       rate_limit_per_minute, rate_limit_per_hour, rate_limit_per_day,
                       expires_at, last_used_at
                FROM mcp_api_tokens
                WHERE token = %s AND enabled = true
            """, (token,))

            result = cursor.fetchone()

            if not result:
                logger.warning(f"Invalid or disabled token: {token[:16]}...")
                return None

            # Check expiration
            if result['expires_at'] and result['expires_at'] < datetime.now():
                logger.warning(f"Expired token: {result['name']} (expired: {result['expires_at']})")
                return None

            # Update last_used_at
            cursor.execute("""
                UPDATE mcp_api_tokens
                SET last_used_at = NOW(), request_count = request_count + 1
                WHERE id = %s
            """, (result['id'],))
            self.conn.commit()

            return dict(result)

        except Exception as e:
            logger.error(f"Failed to validate token: {e}")
            return None
        finally:
            cursor.close()

    def check_rate_limit(self, token_id: int, token_details: Dict[str, Any]) -> bool:
        """
        Check if request is within rate limits

        Args:
            token_id: Token ID
            token_details: Token details from validate_token()

        Returns:
            True if within limits, False if exceeded
        """
        now = datetime.now()

        # Get rate limits
        limit_minute = token_details.get('rate_limit_per_minute')
        limit_hour = token_details.get('rate_limit_per_hour')
        limit_day = token_details.get('rate_limit_per_day')

        # If no limits, allow
        if not any([limit_minute, limit_hour, limit_day]):
            return True

        # Clean old entries from cache
        cache = self.rate_limit_cache[token_id]
        cache['minute'] = [t for t in cache['minute'] if t > now - timedelta(minutes=1)]
        cache['hour'] = [t for t in cache['hour'] if t > now - timedelta(hours=1)]
        cache['day'] = [t for t in cache['day'] if t > now - timedelta(days=1)]

        # Check limits
        if limit_minute and len(cache['minute']) >= limit_minute:
            logger.warning(f"Rate limit exceeded (minute) for token {token_id}")
            return False

        if limit_hour and len(cache['hour']) >= limit_hour:
            logger.warning(f"Rate limit exceeded (hour) for token {token_id}")
            return False

        if limit_day and len(cache['day']) >= limit_day:
            logger.warning(f"Rate limit exceeded (day) for token {token_id}")
            return False

        # Add to cache
        cache['minute'].append(now)
        cache['hour'].append(now)
        cache['day'].append(now)

        return True

    def log_request(
        self,
        token_id: int,
        endpoint: str,
        method: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status_code: Optional[int] = None,
        response_time_ms: Optional[int] = None,
        error_message: Optional[str] = None
    ):
        """
        Log API request for audit trail

        Args:
            token_id: Token ID
            endpoint: API endpoint path
            method: HTTP method
            ip_address: Client IP address
            user_agent: Client user agent
            status_code: HTTP response status code
            response_time_ms: Response time in milliseconds
            error_message: Error message if request failed
        """
        self._ensure_connection()

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO mcp_api_token_usage
                    (token_id, endpoint, method, ip_address, user_agent,
                     status_code, response_time_ms, error_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (token_id, endpoint, method, ip_address, user_agent,
                  status_code, response_time_ms, error_message))

            self.conn.commit()

        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to log request: {e}")
        finally:
            cursor.close()

    def get_token_stats(self, token_id: int) -> Dict[str, Any]:
        """
        Get usage statistics for a token

        Args:
            token_id: Token ID

        Returns:
            Dict with usage statistics
        """
        self._ensure_connection()

        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            # Get total requests
            cursor.execute("""
                SELECT
                    COUNT(*) as total_requests,
                    COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour') as requests_last_hour,
                    COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') as requests_last_day,
                    AVG(response_time_ms) as avg_response_time_ms,
                    COUNT(*) FILTER (WHERE status_code >= 400) as error_count
                FROM mcp_api_token_usage
                WHERE token_id = %s
            """, (token_id,))

            stats = cursor.fetchone()

            return dict(stats) if stats else {}

        except Exception as e:
            logger.error(f"Failed to get token stats: {e}")
            return {}
        finally:
            cursor.close()

    def list_tokens(self, include_disabled: bool = False) -> list:
        """
        List all API tokens

        Args:
            include_disabled: Include disabled tokens

        Returns:
            List of token dicts (without actual token values)
        """
        self._ensure_connection()

        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            query = """
                SELECT id, name, description, scope, enabled,
                       rate_limit_per_minute, rate_limit_per_hour, rate_limit_per_day,
                       created_at, created_by, last_used_at, expires_at, request_count
                FROM mcp_api_tokens
            """

            if not include_disabled:
                query += " WHERE enabled = true"

            query += " ORDER BY created_at DESC"

            cursor.execute(query)
            tokens = cursor.fetchall()

            return [dict(t) for t in tokens]

        except Exception as e:
            logger.error(f"Failed to list tokens: {e}")
            return []
        finally:
            cursor.close()

    def revoke_token(self, token_id: int):
        """
        Revoke (disable) an API token

        Args:
            token_id: Token ID to revoke
        """
        self._ensure_connection()

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                UPDATE mcp_api_tokens
                SET enabled = false
                WHERE id = %s
            """, (token_id,))

            self.conn.commit()
            logger.info(f"Revoked token ID {token_id}")

        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to revoke token: {e}")
            raise
        finally:
            cursor.close()


async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    """
    FastAPI dependency to verify API token

    Args:
        credentials: HTTP Bearer token from request

    Returns:
        Token details dict

    Raises:
        HTTPException: If token is invalid or rate limit exceeded
    """
    from fastapi import Request
    from fastapi.requests import Request as FastAPIRequest

    # This will be set by the FastAPI app
    token_manager: TokenAuthManager = getattr(verify_token, 'token_manager', None)

    if not token_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token authentication not initialized"
        )

    token = credentials.credentials

    # Validate token
    token_details = token_manager.validate_token(token)

    if not token_details:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check rate limit
    if not token_manager.check_rate_limit(token_details['id'], token_details):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

    return token_details
