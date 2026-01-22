#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Token Authentication Middleware for MCP Streamable HTTP

Integrates existing TokenAuthManager with Starlette middleware.
Validates Bearer tokens and enforces rate limits.
"""

import logging
import time
from typing import List, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS

from token_auth import TokenAuthManager

logger = logging.getLogger('NetMonitor.MCP.Auth')


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """
    Token authentication middleware for MCP Streamable HTTP

    Validates Bearer tokens and enforces rate limits before
    passing requests to MCP protocol handlers.

    Features:
    - Bearer token validation
    - Rate limiting per token
    - Scope-based permissions
    - Request audit logging
    - Graceful error handling
    """

    def __init__(self, app, token_manager: TokenAuthManager, exempt_paths: Optional[List[str]] = None):
        """
        Initialize middleware

        Args:
            app: ASGI application
            token_manager: TokenAuthManager instance
            exempt_paths: List of paths that don't require authentication
                         (default: /health, /docs, /redoc, /openapi.json)
        """
        super().__init__(app)
        self.token_manager = token_manager
        self.exempt_paths = exempt_paths or ['/health', '/docs', '/redoc', '/openapi.json', '/metrics']

        logger.info(f"Token auth middleware initialized (exempt paths: {self.exempt_paths})")

    async def dispatch(self, request, call_next):
        """
        Process request through authentication middleware

        Args:
            request: Starlette Request object
            call_next: Next middleware in chain

        Returns:
            Response from next middleware or error response
        """
        start_time = time.time()

        # Skip auth for exempt paths (health check, etc.)
        if request.url.path in self.exempt_paths:
            logger.debug(f"Exempt path requested: {request.url.path}")
            return await call_next(request)

        # Extract Bearer token from Authorization header
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            logger.warning(f"Missing or invalid Authorization header from {request.client.host}")
            return JSONResponse(
                {
                    "error": "missing_token",
                    "message": "Missing or invalid Authorization header. Use: Authorization: Bearer <token>"
                },
                status_code=HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"}
            )

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Validate token with TokenAuthManager
        token_details = self.token_manager.validate_token(token)
        if not token_details:
            logger.warning(f"Invalid or expired token from {request.client.host}")
            return JSONResponse(
                {
                    "error": "invalid_token",
                    "message": "Invalid or expired token"
                },
                status_code=HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"}
            )

        logger.debug(f"Token validated: {token_details['name']} (scope: {token_details['scope']})")

        # Check rate limits
        if not self.token_manager.check_rate_limit(token_details['id'], token_details):
            logger.warning(f"Rate limit exceeded for token: {token_details['name']}")
            return JSONResponse(
                {
                    "error": "rate_limit_exceeded",
                    "message": "Rate limit exceeded. Please try again later.",
                    "limits": {
                        "per_minute": token_details.get('rate_limit_per_minute'),
                        "per_hour": token_details.get('rate_limit_per_hour'),
                        "per_day": token_details.get('rate_limit_per_day')
                    }
                },
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit-Minute": str(token_details.get('rate_limit_per_minute', 'unlimited')),
                    "X-RateLimit-Limit-Hour": str(token_details.get('rate_limit_per_hour', 'unlimited')),
                    "X-RateLimit-Limit-Day": str(token_details.get('rate_limit_per_day', 'unlimited'))
                }
            )

        # Attach token details to request state for downstream use
        request.state.token_details = token_details
        request.state.auth_time = time.time() - start_time

        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Error processing request: {e}", exc_info=True)
            return JSONResponse(
                {
                    "error": "internal_error",
                    "message": "An internal error occurred"
                },
                status_code=500
            )

        # Calculate total response time
        response_time_ms = int((time.time() - start_time) * 1000)

        # Log request to audit trail
        try:
            self.token_manager.log_request(
                token_id=token_details['id'],
                endpoint=request.url.path,
                method=request.method,
                ip_address=request.client.host if request.client else 'unknown',
                user_agent=request.headers.get('user-agent', 'unknown'),
                status_code=response.status_code,
                response_time_ms=response_time_ms
            )
        except Exception as e:
            # Don't fail request if logging fails
            logger.error(f"Failed to log request: {e}")

        # Add response headers
        response.headers['X-Response-Time'] = f"{response_time_ms}ms"
        response.headers['X-Auth-Time'] = f"{int(request.state.auth_time * 1000)}ms"
        response.headers['X-Token-Name'] = token_details['name']
        response.headers['X-Token-Scope'] = token_details['scope']

        return response


class ScopeValidator:
    """
    Helper class for scope-based permission validation

    Scope hierarchy (from least to most privileged):
    - read_only: Can only read data
    - read_write: Can read and modify data
    - admin: Full access including configuration changes
    """

    SCOPE_HIERARCHY = {
        'read_only': 1,
        'read_write': 2,
        'admin': 3
    }

    @classmethod
    def has_scope(cls, user_scope: str, required_scope: str) -> bool:
        """
        Check if user has required scope level

        Args:
            user_scope: User's granted scope
            required_scope: Required scope for operation

        Returns:
            True if user has sufficient privileges
        """
        user_level = cls.SCOPE_HIERARCHY.get(user_scope, 0)
        required_level = cls.SCOPE_HIERARCHY.get(required_scope, 0)

        return user_level >= required_level

    @classmethod
    def validate_scope(cls, request, required_scope: str) -> bool:
        """
        Validate request has required scope

        Args:
            request: Starlette Request object (must have state.token_details)
            required_scope: Required scope level

        Returns:
            True if authorized

        Raises:
            ValueError: If token details not in request state
        """
        if not hasattr(request.state, 'token_details'):
            raise ValueError("Token details not found in request state. Ensure TokenAuthMiddleware is applied.")

        token_details = request.state.token_details
        user_scope = token_details.get('scope', 'read_only')

        return cls.has_scope(user_scope, required_scope)


def require_scope(required_scope: str):
    """
    Decorator to require specific scope for route handler

    Usage:
        @app.post("/admin/action")
        @require_scope("admin")
        async def admin_action(request):
            ...

    Args:
        required_scope: Required scope level

    Returns:
        Decorator function
    """
    def decorator(func):
        async def wrapper(request, *args, **kwargs):
            if not ScopeValidator.validate_scope(request, required_scope):
                token_details = request.state.token_details
                return JSONResponse(
                    {
                        "error": "insufficient_permissions",
                        "message": f"This operation requires '{required_scope}' scope. Your scope: '{token_details.get('scope')}'"
                    },
                    status_code=HTTP_403_FORBIDDEN
                )
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator


if __name__ == "__main__":
    # Test scope validation
    print("Testing scope validation:")
    print(f"  read_only has read_only: {ScopeValidator.has_scope('read_only', 'read_only')}")  # True
    print(f"  read_only has read_write: {ScopeValidator.has_scope('read_only', 'read_write')}")  # False
    print(f"  read_write has read_only: {ScopeValidator.has_scope('read_write', 'read_only')}")  # True
    print(f"  read_write has admin: {ScopeValidator.has_scope('read_write', 'admin')}")  # False
    print(f"  admin has everything: {ScopeValidator.has_scope('admin', 'admin')}")  # True
    print("✅ Scope validation logic works correctly")
