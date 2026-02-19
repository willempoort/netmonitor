#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Web Dashboard Server
Real-time security monitoring dashboard
"""

import os
import sys
import time
import logging
import threading
import hashlib
import json
import traceback
from pathlib import Path
from datetime import datetime

# Import eventlet first and monkey patch
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, jsonify, request, session, g, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

# Add current dir to path
sys.path.insert(0, str(Path(__file__).parent))

from config_loader import load_config
from database import DatabaseManager
from sensor_auth import SensorAuthManager
from web_auth import WebAuthManager, WebUser
from functools import wraps


# Initialize Flask app
app = Flask(__name__,
           template_folder='web/templates',
           static_folder='web/static')

# Configure SECRET_KEY from environment or use a development default
# SECURITY: Set FLASK_SECRET_KEY environment variable in production!
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-key-CHANGE-ME-IN-PRODUCTION')

# Session configuration for security
app.config['SESSION_COOKIE_NAME'] = 'netmonitor_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 900  # 15 minuten inactiviteit timeout
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Refresh session on each request
# app.config['SESSION_COOKIE_SECURE'] = True  # Enable in production with HTTPS

# URL routing: Accept both /api/sensors and /api/sensors/
# This makes the app work with or without nginx reverse proxy
app.url_map.strict_slashes = False

CORS(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.session_protection = 'basic'  # Changed from 'strong' to prevent premature session invalidation

INACTIVITY_TIMEOUT = 900  # 15 minuten

@app.before_request
def check_session_timeout():
    """Log gebruiker uit na 15 minuten inactiviteit"""
    if current_user.is_authenticated:
        last_active = session.get('last_active')
        now = time.time()
        if last_active and (now - last_active) > INACTIVITY_TIMEOUT:
            logout_user()
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Session expired due to inactivity'}), 401
            return redirect(url_for('login_page'))
        session['last_active'] = now

# Initialize SocketIO with eventlet for production
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    logger=True,
    engineio_logger=False
)

# Global instances
db = None
config = None
logger = None
sensor_auth = None  # Sensor authentication manager
web_auth = None  # Web user authentication manager

# PCAP statistics cache (to avoid scanning 960k+ files repeatedly)
pcap_stats_cache = None
pcap_stats_cache_time = None
pcap_stats_cache_lock = threading.Lock()
PCAP_STATS_CACHE_TTL = 300  # 5 minutes cache


def init_dashboard(config_file='config.yaml'):
    """Initialize dashboard components"""
    global db, config, logger, sensor_auth, web_auth

    # Load config
    config = load_config(config_file)

    # Configure SECRET_KEY from config if not already set by environment variable
    if 'FLASK_SECRET_KEY' not in os.environ:
        dashboard_config = config.get('dashboard', {})
        if 'secret_key' in dashboard_config:
            app.config['SECRET_KEY'] = dashboard_config['secret_key']
            logger_temp = logging.getLogger('NetMonitor.WebDashboard')
            logger_temp.info("SECRET_KEY loaded from config file")

    # Setup logging - use existing NetMonitor logger hierarchy
    # Don't call basicConfig() as it may add duplicate handlers
    logger = logging.getLogger('NetMonitor.WebDashboard')

    # Only configure if no handlers exist yet (prevents duplicates)
    if not logger.handlers and not logging.getLogger('NetMonitor').handlers:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    # Prevent propagation to root logger to avoid duplicate messages
    # (NetMonitor parent logger already handles output)
    logger.propagate = True  # Keep propagation for parent NetMonitor logger

    # Initialize database
    db_config = config.get('database', {})
    db_type = db_config.get('type', 'postgresql')

    if db_type == 'postgresql':
        pg_config = db_config.get('postgresql', {})
        # Use config value if set, otherwise fall back to environment variable
        db_password = pg_config.get('password') or os.environ.get('DB_PASSWORD', 'netmonitor')
        db = DatabaseManager(
            host=pg_config.get('host') or os.environ.get('DB_HOST', 'localhost'),
            port=pg_config.get('port') or int(os.environ.get('DB_PORT', '5432')),
            database=pg_config.get('database') or os.environ.get('DB_NAME', 'netmonitor'),
            user=pg_config.get('user') or os.environ.get('DB_USER', 'netmonitor'),
            password=db_password,
            min_connections=pg_config.get('min_connections', 2),
            config=config,  # Pass config for retention policies
            max_connections=pg_config.get('max_connections', 10)
        )
        logger.info("Database connected (PostgreSQL + TimescaleDB)")
    else:
        logger.error(f"Unsupported database type: {db_type}")
        raise ValueError(f"Database type '{db_type}' not supported")

    # Initialize sensor authentication manager
    sensor_auth = SensorAuthManager(db)
    logger.info("Sensor authentication manager initialized")

    # Initialize web authentication manager
    web_auth = WebAuthManager(db)
    logger.info("Web authentication manager initialized")

    # Initialize ML classifier (if sklearn is available)
    ml = get_ml_classifier()
    if ml:
        logger.info("ML Classifier initialized and background training started")

    logger.info("Web Dashboard geïnitialiseerd")


# ==================== Flask-Login User Loader ====================

@login_manager.user_loader
def load_user(user_id):
    """User loader for Flask-Login"""
    if web_auth:
        return web_auth.get_user_by_id(int(user_id))
    return None


# ==================== Authentication Decorators ====================

def require_role(*roles):
    """
    Decorator to require specific user role(s)

    Usage:
        @require_role('admin')
        @require_role('admin', 'operator')
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles and current_user.role != 'admin':
                logger.warning(f"Unauthorized access attempt by {current_user.username} (role: {current_user.role})")
                return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_sensor_token(required_permission=None):
    """
    Decorator to require sensor token authentication

    Usage:
        @require_sensor_token()
        @require_sensor_token('alerts')
        @require_sensor_token('commands')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization', '')

            if not auth_header.startswith('Bearer '):
                logger.warning(f"Missing or invalid Authorization header from {request.remote_addr}")
                return jsonify({
                    'success': False,
                    'error': 'Missing or invalid Authorization header. Use: Authorization: Bearer <token>'
                }), 401

            token = auth_header.replace('Bearer ', '').strip()

            # Validate token
            if not sensor_auth:
                logger.error("Sensor auth manager not initialized")
                return jsonify({'success': False, 'error': 'Authentication system not available'}), 500

            sensor_details = sensor_auth.validate_token(token, required_permission)

            if not sensor_details:
                logger.warning(f"Invalid token attempted from {request.remote_addr}")
                return jsonify({'success': False, 'error': 'Invalid or expired token'}), 403

            # Add sensor details to Flask's g object for use in route
            from flask import g
            g.sensor_details = sensor_details

            logger.info(f"Authenticated sensor: {sensor_details['sensor_id']} ({sensor_details['hostname']})")

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def require_sensor_token_or_login():
    """
    Decorator that accepts either sensor token authentication OR Flask-Login session
    Used for endpoints that sensors AND web users need to access (like /api/config)

    Special case: GET requests with sensor_id parameter are allowed without authentication
    This allows newly registered sensors to fetch their config and whitelist without tokens
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for sensor token first
            auth_header = request.headers.get('Authorization', '')

            if auth_header.startswith('Bearer '):
                # Sensor token authentication
                token = auth_header.replace('Bearer ', '').strip()

                if sensor_auth:
                    sensor_details = sensor_auth.validate_token(token, None)

                    if sensor_details:
                        # Valid sensor token - add to g object
                        from flask import g
                        g.sensor_details = sensor_details
                        g.auth_method = 'sensor_token'
                        logger.debug(f"API access via sensor token: {sensor_details['sensor_id']}")
                        return f(*args, **kwargs)

            # Check for Flask-Login session
            if current_user.is_authenticated:
                # Valid web user session
                from flask import g
                g.auth_method = 'web_session'
                logger.debug(f"API access via web session: {current_user.username}")
                return f(*args, **kwargs)

            # Special case: Allow GET requests with sensor_id parameter (for sensor registration flow)
            if request.method == 'GET' and request.args.get('sensor_id'):
                from flask import g
                g.auth_method = 'sensor_registration'
                g.sensor_id = request.args.get('sensor_id')
                logger.debug(f"API access via sensor registration flow: {g.sensor_id}")
                return f(*args, **kwargs)

            # No valid authentication
            logger.warning(f"Unauthorized API access attempt from {request.remote_addr} to {request.path}")
            return jsonify({
                'success': False,
                'error': 'Authentication required (sensor token or web login)'
            }), 401

        return decorated_function
    return decorator


def is_local_request():
    """Check if request is from localhost (for internal API access)"""
    remote_addr = request.remote_addr
    return remote_addr in ('127.0.0.1', '::1', 'localhost')


def local_or_login_required(f):
    """
    Decorator that allows access from localhost without login,
    or requires login for external requests.
    Used for internal API endpoints accessed by MCP server.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_local_request():
            # Local request - allow without authentication
            logger.debug(f"Internal API access from localhost: {request.path}")
            return f(*args, **kwargs)
        elif current_user.is_authenticated:
            # External request with valid session
            return f(*args, **kwargs)
        else:
            # External request without authentication
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
    return decorated_function


# ==================== Authentication Routes ====================

@app.route('/login')
def login_page():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Login API - step 1: username/password authentication"""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400

        # Authenticate user
        user = web_auth.authenticate(
            username,
            password,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials or account locked'}), 401

        # Check if 2FA is enabled
        if user.totp_enabled:
            # 2FA required - don't log in yet
            session['pending_2fa_user_id'] = user.id
            logger.info(f"Password verified for {username}, awaiting 2FA")
            return jsonify({'success': True, 'require_2fa': True})
        else:
            # No 2FA - log in directly
            login_user(user, remember=False)
            session.permanent = True
            logger.info(f"User logged in: {username}")
            return jsonify({'success': True, 'user': user.to_dict()})

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/auth/verify-2fa', methods=['POST'])
def api_verify_2fa():
    """Login API - step 2: 2FA verification"""
    try:
        data = request.json
        code = data.get('code')
        use_backup = data.get('use_backup_code', False)

        if not code:
            return jsonify({'success': False, 'error': '2FA code required'}), 400

        user_id = session.get('pending_2fa_user_id')

        if not user_id:
            return jsonify({'success': False, 'error': 'No pending 2FA verification'}), 400

        user = web_auth.get_user_by_id(user_id)

        if not user:
            session.pop('pending_2fa_user_id', None)
            return jsonify({'success': False, 'error': 'Invalid session'}), 400

        # Verify 2FA code
        if web_auth.verify_2fa(
            user,
            code,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            is_backup_code=use_backup
        ):
            login_user(user, remember=False)
            session.permanent = True
            session.pop('pending_2fa_user_id', None)
            logger.info(f"User logged in with 2FA: {user.username}")
            return jsonify({'success': True, 'user': user.to_dict()})
        else:
            return jsonify({'success': False, 'error': 'Invalid 2FA code'}), 401

    except Exception as e:
        logger.error(f"2FA verification error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    """Logout API"""
    try:
        username = current_user.username
        web_auth.audit_log(current_user.id, 'logout', request.remote_addr, username)
        logout_user()
        logger.info(f"User logged out: {username}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/auth/current-user', methods=['GET'])
@login_required
def api_current_user():
    """Get current logged-in user info"""
    return jsonify({'success': True, 'user': current_user.to_dict()})


@app.route('/api/auth/session-debug', methods=['GET'])
def api_session_debug():
    """Debug endpoint to check session status (NO AUTH REQUIRED)"""
    from flask import session as flask_session

    debug_info = {
        'cookies_received': dict(request.cookies),
        'session_keys': list(flask_session.keys()),
        'is_authenticated': current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else False,
        'user_id': current_user.id if current_user.is_authenticated else None,
        'username': current_user.username if current_user.is_authenticated else None,
    }

    return jsonify(debug_info)


@app.route('/api/auth/setup-2fa', methods=['POST'])
@login_required
def api_setup_2fa():
    """Setup 2FA for current user"""
    try:
        result = web_auth.setup_2fa(current_user.id, app_name="NetMonitor SOC")

        if result:
            logger.info(f"2FA setup initiated for user: {current_user.username}")
            return jsonify({'success': True, **result})
        else:
            return jsonify({'success': False, 'error': 'Failed to setup 2FA'}), 500

    except Exception as e:
        logger.error(f"2FA setup error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/auth/disable-2fa', methods=['POST'])
@login_required
def api_disable_2fa():
    """Disable 2FA for current user"""
    try:
        if web_auth.disable_2fa(current_user.id):
            logger.info(f"2FA disabled for user: {current_user.username}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to disable 2FA'}), 500

    except Exception as e:
        logger.error(f"2FA disable error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change password for current user"""
    try:
        data = request.json
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        if not old_password or not new_password:
            return jsonify({'success': False, 'error': 'Old and new password required'}), 400

        if web_auth.change_password(current_user.id, old_password, new_password):
            logger.info(f"Password changed for user: {current_user.username}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to change password (incorrect old password or weak new password)'}), 400

    except Exception as e:
        logger.error(f"Password change error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


# ==================== User Management Routes (Admin only) ====================

@app.route('/api/users', methods=['GET'])
@require_role('admin')
def api_list_users():
    """List all users (admin only)"""
    try:
        include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
        users = web_auth.list_users(include_inactive=include_inactive)
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/users', methods=['POST'])
@require_role('admin')
def api_create_user():
    """Create new user (admin only)"""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        role = data.get('role', 'operator')
        enable_2fa = data.get('enable_2fa', False)

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400

        user = web_auth.create_user(
            username=username,
            password=password,
            email=email,
            role=role,
            created_by=current_user.username,
            enable_2fa=enable_2fa
        )

        if user:
            logger.info(f"User created: {username} by {current_user.username}")
            return jsonify({'success': True, 'user': user.to_dict()})
        else:
            return jsonify({'success': False, 'error': 'Failed to create user (username exists or invalid data)'}), 400

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_role('admin')
def api_deactivate_user(user_id):
    """Deactivate user (admin only)"""
    try:
        # Prevent self-deactivation
        if user_id == current_user.id:
            return jsonify({'success': False, 'error': 'Cannot deactivate your own account'}), 400

        if web_auth.deactivate_user(user_id, deactivated_by=current_user.username):
            logger.info(f"User deactivated: ID {user_id} by {current_user.username}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to deactivate user'}), 500

    except Exception as e:
        logger.error(f"Error deactivating user: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


# ==================== REST API Endpoints ====================

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template('dashboard.html', user=current_user)

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory(app.static_folder, 'favicon.ico',
                               mimetype='image/vnd.microsoft.icon')


@app.route('/api/status')
def api_status():
    """API status endpoint (public)"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })


@app.route('/api/integrations/status')
@login_required
def api_integrations_status():
    """Get status of all configured integrations (SIEM, Threat Intel)"""
    try:
        # Try to get integration manager from the running monitor
        # If not available, return empty status
        integration_status = {
            'enabled': False,
            'siem': [],
            'threat_intel': [],
            'timestamp': datetime.now().isoformat()
        }

        # Check if integrations are configured
        from config_loader import load_config
        try:
            config = load_config('config.yaml')
            integrations_config = config.get('integrations', {})
            integration_status['enabled'] = integrations_config.get('enabled', False)

            # Build status for configured integrations
            if integration_status['enabled']:
                # SIEM integrations
                siem_config = integrations_config.get('siem', {})
                if siem_config.get('enabled', False):
                    # Syslog
                    syslog_config = siem_config.get('syslog', {})
                    if syslog_config.get('enabled', False):
                        integration_status['siem'].append({
                            'name': 'syslog',
                            'display_name': 'Syslog Output',
                            'enabled': True,
                            'host': syslog_config.get('host', 'localhost'),
                            'port': syslog_config.get('port', 514),
                            'format': syslog_config.get('format', 'cef'),
                            'healthy': None  # Would need connection test
                        })

                    # Wazuh
                    wazuh_config = siem_config.get('wazuh', {})
                    if wazuh_config.get('enabled', False):
                        import os
                        api_url = os.environ.get('WAZUH_API_URL') or wazuh_config.get('api_url', '')
                        integration_status['siem'].append({
                            'name': 'wazuh',
                            'display_name': 'Wazuh SIEM',
                            'enabled': True,
                            'api_url': api_url,
                            'has_credentials': bool(os.environ.get('WAZUH_API_PASSWORD') or wazuh_config.get('api_password')),
                            'healthy': None  # Would need connection test
                        })

                # Threat Intel integrations
                ti_config = integrations_config.get('threat_intel', {})
                if ti_config.get('enabled', False):
                    import os

                    # MISP
                    misp_config = ti_config.get('misp', {})
                    if misp_config.get('enabled', False):
                        url = os.environ.get('MISP_URL') or misp_config.get('url', '')
                        integration_status['threat_intel'].append({
                            'name': 'misp',
                            'display_name': 'MISP',
                            'enabled': True,
                            'url': url,
                            'has_credentials': bool(os.environ.get('MISP_API_KEY') or misp_config.get('api_key')),
                            'healthy': None
                        })

                    # OTX
                    otx_config = ti_config.get('otx', {})
                    if otx_config.get('enabled', False):
                        integration_status['threat_intel'].append({
                            'name': 'otx',
                            'display_name': 'AlienVault OTX',
                            'enabled': True,
                            'has_credentials': bool(os.environ.get('OTX_API_KEY') or otx_config.get('api_key')),
                            'healthy': None
                        })

                    # AbuseIPDB
                    abuseipdb_config = ti_config.get('abuseipdb', {})
                    if abuseipdb_config.get('enabled', False):
                        integration_status['threat_intel'].append({
                            'name': 'abuseipdb',
                            'display_name': 'AbuseIPDB',
                            'enabled': True,
                            'has_credentials': bool(os.environ.get('ABUSEIPDB_API_KEY') or abuseipdb_config.get('api_key')),
                            'healthy': None
                        })

        except Exception as config_error:
            logger.debug(f"Could not load integration config: {config_error}")

        return jsonify({
            'success': True,
            'data': integration_status
        })

    except Exception as e:
        logger.error(f"Error getting integration status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/integrations/test/<integration_name>', methods=['POST'])
@login_required
def api_integration_test(integration_name):
    """Test connection to a specific integration"""
    try:
        from config_loader import load_config
        import os

        config = load_config('config.yaml')
        integrations_config = config.get('integrations', {})

        result = {
            'name': integration_name,
            'success': False,
            'message': 'Unknown integration'
        }

        # Test based on integration type
        if integration_name == 'misp':
            misp_config = integrations_config.get('threat_intel', {}).get('misp', {})
            from integrations.threat_intel.misp_source import MISPSource
            source = MISPSource(misp_config)
            valid, error = source.validate_config()
            if valid:
                healthy = source.health_check()
                result = {
                    'name': 'misp',
                    'success': healthy,
                    'message': 'Connection successful' if healthy else 'Connection failed'
                }
            else:
                result = {'name': 'misp', 'success': False, 'message': error}

        elif integration_name == 'otx':
            otx_config = integrations_config.get('threat_intel', {}).get('otx', {})
            from integrations.threat_intel.otx_source import OTXSource
            source = OTXSource(otx_config)
            valid, error = source.validate_config()
            if valid:
                healthy = source.health_check()
                result = {
                    'name': 'otx',
                    'success': healthy,
                    'message': 'Connection successful' if healthy else 'Connection failed'
                }
            else:
                result = {'name': 'otx', 'success': False, 'message': error}

        elif integration_name == 'abuseipdb':
            abuseipdb_config = integrations_config.get('threat_intel', {}).get('abuseipdb', {})
            from integrations.threat_intel.abuseipdb_source import AbuseIPDBSource
            source = AbuseIPDBSource(abuseipdb_config)
            valid, error = source.validate_config()
            if valid:
                healthy = source.health_check()
                result = {
                    'name': 'abuseipdb',
                    'success': healthy,
                    'message': 'Connection successful' if healthy else 'Connection failed'
                }
            else:
                result = {'name': 'abuseipdb', 'success': False, 'message': error}

        elif integration_name == 'wazuh':
            wazuh_config = integrations_config.get('siem', {}).get('wazuh', {})
            from integrations.siem.wazuh_output import WazuhOutput
            output = WazuhOutput(wazuh_config)
            valid, error = output.validate_config()
            if valid:
                success, message = output.test_connection()
                result = {'name': 'wazuh', 'success': success, 'message': message}
            else:
                result = {'name': 'wazuh', 'success': False, 'message': error}

        return jsonify(result)

    except ImportError as e:
        return jsonify({
            'name': integration_name,
            'success': False,
            'message': f'Integration module not available: {e}'
        })
    except Exception as e:
        logger.error(f"Error testing integration {integration_name}: {e}")
        return jsonify({
            'name': integration_name,
            'success': False,
            'message': str(e)
        }), 500


@app.route('/api/integrations/abuseipdb/stats')
@login_required
def api_abuseipdb_stats():
    """Get AbuseIPDB statistics including cache usage and lookup history"""
    try:
        stats = {
            'success': True,
            'cache': {
                'total_entries': 0,
                'entries_with_score': 0,
                'entries_last_24h': 0,
                'entries_last_7d': 0
            },
            'scores': {
                'critical': 0,  # 80-100
                'high': 0,      # 50-79
                'medium': 0,    # 20-49
                'low': 0,       # 1-19
                'clean': 0      # 0
            },
            'top_malicious': [],
            'recent_lookups': [],
            'api_stats': None
        }

        # Get database stats
        if db:
            conn = db._get_connection()
            cursor = conn.cursor()

            # Total entries and entries with AbuseIPDB score
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    COUNT(abuseipdb_score) as with_score,
                    COUNT(*) FILTER (WHERE last_updated > NOW() - INTERVAL '24 hours') as last_24h,
                    COUNT(*) FILTER (WHERE last_updated > NOW() - INTERVAL '7 days') as last_7d
                FROM threat_intel_ip_cache
            """)
            row = cursor.fetchone()
            if row:
                stats['cache']['total_entries'] = row[0]
                stats['cache']['entries_with_score'] = row[1]
                stats['cache']['entries_last_24h'] = row[2]
                stats['cache']['entries_last_7d'] = row[3]

            # Score distribution
            cursor.execute("""
                SELECT
                    COUNT(*) FILTER (WHERE abuseipdb_score >= 80) as critical,
                    COUNT(*) FILTER (WHERE abuseipdb_score >= 50 AND abuseipdb_score < 80) as high,
                    COUNT(*) FILTER (WHERE abuseipdb_score >= 20 AND abuseipdb_score < 50) as medium,
                    COUNT(*) FILTER (WHERE abuseipdb_score >= 1 AND abuseipdb_score < 20) as low,
                    COUNT(*) FILTER (WHERE abuseipdb_score = 0) as clean
                FROM threat_intel_ip_cache
                WHERE abuseipdb_score IS NOT NULL
            """)
            row = cursor.fetchone()
            if row:
                stats['scores']['critical'] = row[0]
                stats['scores']['high'] = row[1]
                stats['scores']['medium'] = row[2]
                stats['scores']['low'] = row[3]
                stats['scores']['clean'] = row[4]

            # Top malicious IPs
            cursor.execute("""
                SELECT ip_address::text, abuseipdb_score, abuseipdb_reports,
                       threat_level, last_updated
                FROM threat_intel_ip_cache
                WHERE abuseipdb_score IS NOT NULL
                ORDER BY abuseipdb_score DESC, abuseipdb_reports DESC
                LIMIT 10
            """)
            stats['top_malicious'] = [
                {
                    'ip': row[0],
                    'score': row[1],
                    'reports': row[2],
                    'threat_level': row[3],
                    'last_updated': row[4].isoformat() if row[4] else None
                }
                for row in cursor.fetchall()
            ]

            # Recent lookups (entries with abuseipdb_score, ordered by last_updated)
            cursor.execute("""
                SELECT ip_address::text, abuseipdb_score, abuseipdb_reports,
                       threat_level, last_updated
                FROM threat_intel_ip_cache
                WHERE abuseipdb_score IS NOT NULL
                ORDER BY last_updated DESC
                LIMIT 20
            """)
            stats['recent_lookups'] = [
                {
                    'ip': row[0],
                    'score': row[1],
                    'reports': row[2],
                    'threat_level': row[3],
                    'last_updated': row[4].isoformat() if row[4] else None
                }
                for row in cursor.fetchall()
            ]

            # Get API call statistics from abuseipdb_api_stats table
            cursor.execute("""
                SELECT
                    COALESCE(SUM(api_calls), 0) as total_api_calls,
                    COALESCE(SUM(cache_hits), 0) as total_cache_hits,
                    COALESCE(SUM(unique_ips_queried), 0) as total_unique_ips
                FROM abuseipdb_api_stats
            """)
            row = cursor.fetchone()
            if row:
                stats['api_stats'] = {
                    'total_api_calls': row[0],
                    'total_cache_hits': row[1],
                    'total_unique_ips': row[2]
                }

            # Get API calls per day (last 7 days)
            cursor.execute("""
                SELECT date, api_calls, cache_hits, unique_ips_queried
                FROM abuseipdb_api_stats
                WHERE date >= CURRENT_DATE - INTERVAL '7 days'
                ORDER BY date DESC
            """)
            stats['api_daily'] = [
                {
                    'date': row[0].isoformat() if row[0] else None,
                    'api_calls': row[1],
                    'cache_hits': row[2],
                    'unique_ips': row[3]
                }
                for row in cursor.fetchall()
            ]

            # Today's stats
            cursor.execute("""
                SELECT api_calls, cache_hits, unique_ips_queried
                FROM abuseipdb_api_stats
                WHERE date = CURRENT_DATE
            """)
            row = cursor.fetchone()
            if row:
                stats['today'] = {
                    'api_calls': row[0],
                    'cache_hits': row[1],
                    'unique_ips': row[2]
                }
            else:
                stats['today'] = {'api_calls': 0, 'cache_hits': 0, 'unique_ips': 0}

            db._return_connection(conn)

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Error getting AbuseIPDB stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/dashboard')
@login_required
def api_dashboard():
    """Get all dashboard data"""
    try:
        data = db.get_dashboard_data()
        return jsonify({
            'success': True,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts')
@login_required
def api_alerts():
    """Get recent alerts"""
    try:
        limit = int(request.args.get('limit', 100))
        hours = int(request.args.get('hours', 24))

        alerts = db.get_recent_alerts(limit=limit, hours=hours)

        return jsonify({
            'success': True,
            'data': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/stats')
@login_required
def api_alert_stats():
    """Get alert statistics"""
    try:
        hours = int(request.args.get('hours', 24))
        stats = db.get_alert_statistics(hours=hours)

        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        logger.error(f"Error getting alert stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@require_role('admin', 'operator')
def api_acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        success = db.acknowledge_alert(alert_id)

        if success:
            # Broadcast to all connected clients
            socketio.emit('alert_acknowledged', {'alert_id': alert_id})

        return jsonify({
            'success': success,
            'alert_id': alert_id
        })
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/traffic/history')
@login_required
def api_traffic_history():
    """Get traffic history"""
    try:
        hours = int(request.args.get('hours', 24))
        history = db.get_traffic_history(hours=hours)

        return jsonify({
            'success': True,
            'data': history
        })
    except Exception as e:
        logger.error(f"Error getting traffic history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/top-talkers')
@login_required
def api_top_talkers():
    """Get top talkers"""
    try:
        limit = int(request.args.get('limit', 10))
        talkers = db.get_top_talkers(limit=limit)

        return jsonify({
            'success': True,
            'data': talkers
        })
    except Exception as e:
        logger.error(f"Error getting top talkers: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/threat-details/<threat_type>')
def api_threat_details(threat_type):
    """Get detailed information for a specific threat type"""
    try:
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 100))

        details = db.get_threat_type_details(threat_type, hours=hours, limit=limit)

        # Add geolocation for IPs
        from geoip_helper import get_country_for_ips, set_internal_networks

        # Configure internal networks for Local/Private distinction
        internal_nets = config.get('internal_networks', []) if config else []
        if not internal_nets:
            # Try to get from config_defaults
            try:
                from config_defaults import BEST_PRACTICE_CONFIG
                internal_nets = BEST_PRACTICE_CONFIG.get('internal_networks', [])
            except:
                pass

        # Log what networks we're using
        logger.debug(f"GeoIP using internal_networks: {internal_nets}")
        set_internal_networks(internal_nets)

        # Collect all unique IPs (from alerts, top_sources, and top_targets)
        all_ips = set()
        for alert in details.get('alerts', []):
            if alert.get('source_ip'):
                all_ips.add(alert['source_ip'])
            if alert.get('destination_ip'):
                all_ips.add(alert['destination_ip'])

        # Also collect from top_sources and top_targets (may have different format)
        for source in details.get('top_sources', []):
            if source.get('ip'):
                all_ips.add(source['ip'])
        for target in details.get('top_targets', []):
            if target.get('ip'):
                all_ips.add(target['ip'])

        # Get country information
        ip_countries = get_country_for_ips(list(all_ips))

        # Add country info to alerts
        for alert in details.get('alerts', []):
            if alert.get('source_ip'):
                alert['source_country'] = ip_countries.get(alert['source_ip'])
            if alert.get('destination_ip'):
                alert['destination_country'] = ip_countries.get(alert['destination_ip'])

        # Add country info to top sources
        for source in details.get('top_sources', []):
            source['country'] = ip_countries.get(source['ip'])

        # Add country info to top targets
        for target in details.get('top_targets', []):
            target['country'] = ip_countries.get(target['ip'])

        return jsonify({
            'success': True,
            'data': details
        })
    except Exception as e:
        logger.error(f"Error getting threat details for {threat_type}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Sensor API Endpoints ====================

@app.route('/api/sensors/', methods=['GET'])
@login_required
def api_get_sensors():
    """Get all registered sensors"""
    try:
        sensors = db.get_sensors()

        # Filter out SOC server if self-monitoring is disabled
        self_monitor_config = config.get('self_monitor', {})
        self_monitor_enabled = self_monitor_config.get('enabled', True)

        if not self_monitor_enabled:
            # Exclude sensors with 'soc-server' in their sensor_id
            sensors = [s for s in sensors if 'soc-server' not in s.get('sensor_id', '').lower()]

        return jsonify({
            'success': True,
            'data': sensors,
            'count': len(sensors)
        })
    except Exception as e:
        logger.error(f"Error getting sensors: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/register', methods=['POST'])
def api_register_sensor():
    """Register a new sensor or update existing one"""
    try:
        data = request.get_json()

        # Validate required fields
        required = ['sensor_id', 'hostname']
        for field in required:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400

        # Register sensor
        success = db.register_sensor(
            sensor_id=data['sensor_id'],
            hostname=data['hostname'],
            location=data.get('location'),
            ip_address=data.get('ip_address'),
            version=data.get('version'),
            config=data.get('config')
        )

        if success:
            return jsonify({'success': True, 'message': 'Sensor registered'})
        else:
            return jsonify({'success': False, 'error': 'Failed to register sensor'}), 500

    except Exception as e:
        logger.error(f"Error registering sensor: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>', methods=['DELETE'])
@require_role('admin', 'operator')
def api_delete_sensor(sensor_id):
    """Delete a sensor and all its data"""
    try:
        # Prevent deletion of SOC server itself
        self_monitor_config = config.get('self_monitor', {})
        soc_sensor_id = self_monitor_config.get('sensor_id', 'soc-server')

        if sensor_id == soc_sensor_id:
            return jsonify({
                'success': False,
                'error': 'Cannot delete SOC server sensor'
            }), 400

        # Delete sensor using existing deregister_sensor method
        success = db.deregister_sensor(sensor_id)

        if success:
            logger.info(f"Sensor deleted via dashboard: {sensor_id}")
            return jsonify({
                'success': True,
                'message': f'Sensor {sensor_id} deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to delete sensor'
            }), 500

    except Exception as e:
        logger.error(f"Error deleting sensor {sensor_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>/heartbeat', methods=['POST'])
def api_sensor_heartbeat(sensor_id):
    """Update sensor heartbeat"""
    try:
        success = db.update_sensor_heartbeat(sensor_id)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Sensor not found'}), 404
    except Exception as e:
        logger.error(f"Error updating heartbeat: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>/metrics', methods=['POST'])
def api_submit_sensor_metrics(sensor_id):
    """Submit sensor performance metrics"""
    try:
        data = request.get_json()

        # Update heartbeat
        db.update_sensor_heartbeat(sensor_id)

        # Save metrics
        success = db.save_sensor_metrics(
            sensor_id=sensor_id,
            cpu_percent=data.get('cpu_percent'),
            memory_percent=data.get('memory_percent'),
            disk_percent=data.get('disk_percent'),
            uptime_seconds=data.get('uptime_seconds'),
            packets_captured=data.get('packets_captured'),
            alerts_sent=data.get('alerts_sent'),
            network_interface=data.get('network_interface'),
            bandwidth_mbps=data.get('bandwidth_mbps')
        )

        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to save metrics'}), 500

    except Exception as e:
        logger.error(f"Error submitting metrics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>/traffic', methods=['POST'])
def api_submit_sensor_traffic(sensor_id):
    """Submit traffic metrics from remote sensor

    Accepts traffic metrics (packets, bytes, top talkers) from sensors
    for aggregated network-wide traffic visibility.

    Expected JSON format:
    {
        "metrics": {
            "total_packets": 12345,
            "total_bytes": 9876543,
            "inbound_packets": 6789,
            "inbound_bytes": 4567890,
            "outbound_packets": 5556,
            "outbound_bytes": 5308653
        },
        "top_talkers": [
            {
                "ip": "192.168.1.100",
                "hostname": "server.local",
                "packets": 1234,
                "bytes": 567890,
                "direction": "inbound"
            }
        ]
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        # Update heartbeat
        db.update_sensor_heartbeat(sensor_id)

        # Save traffic metrics
        metrics = data.get('metrics')
        if metrics:
            db.add_traffic_metrics(metrics, sensor_id=sensor_id)

        # Save top talkers if provided
        top_talkers = data.get('top_talkers', [])
        if top_talkers and isinstance(top_talkers, list):
            db.update_top_talkers(top_talkers, sensor_id=sensor_id)

        return jsonify({
            'success': True,
            'metrics_saved': bool(metrics),
            'top_talkers_count': len(top_talkers) if top_talkers else 0
        })

    except Exception as e:
        logger.error(f"Error submitting traffic metrics from sensor {sensor_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>/alerts', methods=['POST'])
def api_submit_sensor_alerts(sensor_id):
    """Submit alerts from remote sensor (batch)

    Supports optional PCAP data for forensic evidence (NIS2 compliance).
    PCAP data should be base64 encoded in alert['pcap_data'].

    Alerts are filtered through BehaviorMatcher to suppress expected behavior
    based on device templates before being stored.
    """
    import base64

    try:
        data = request.get_json()

        # Expect array of alerts
        alerts = data.get('alerts', [])
        if not isinstance(alerts, list):
            return jsonify({'success': False, 'error': 'alerts must be an array'}), 400

        # Update heartbeat
        db.update_sensor_heartbeat(sensor_id)

        # Initialize BehaviorMatcher for alert filtering (same as local capture)
        behavior_matcher = None
        try:
            from behavior_matcher import BehaviorMatcher
            behavior_matcher = BehaviorMatcher(db_manager=db)
        except ImportError:
            logger.debug("BehaviorMatcher not available, sensor alerts will not be filtered")
        except Exception as e:
            logger.warning(f"Could not initialize BehaviorMatcher for sensor alerts: {e}")

        # Ensure PCAP directory exists for sensor captures
        pcap_dir = Path('/var/log/netmonitor/pcap/sensors')
        pcap_dir.mkdir(parents=True, exist_ok=True)

        # Process alerts
        success_count = 0
        suppressed_count = 0
        pcap_count = 0
        for alert in alerts:
            # Parse timestamp if provided
            timestamp = None
            if 'timestamp' in alert:
                try:
                    timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                except:
                    pass

            # Handle PCAP data if present (NIS2 forensic evidence)
            pcap_filename = None
            if alert.get('pcap_data'):
                try:
                    pcap_data = base64.b64decode(alert['pcap_data'])
                    # Generate filename: sensor_alerttype_srcip_timestamp.pcap
                    ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
                    src_ip = (alert.get('source_ip') or 'unknown').replace('.', '_')
                    alert_type = (alert.get('threat_type') or 'unknown').lower()
                    pcap_filename = f"{sensor_id}_{alert_type}_{src_ip}_{ts_str}.pcap"
                    pcap_path = pcap_dir / pcap_filename

                    # Write PCAP file
                    with open(pcap_path, 'wb') as f:
                        f.write(pcap_data)

                    pcap_count += 1
                    logger.info(f"Received PCAP from sensor {sensor_id}: {pcap_filename} ({len(pcap_data)} bytes)")
                except Exception as pcap_err:
                    logger.warning(f"Failed to save PCAP from sensor {sensor_id}: {pcap_err}")
                    pcap_filename = None

            # Add PCAP reference to metadata
            metadata = alert.get('metadata') or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except:
                    metadata = {}
            if pcap_filename:
                metadata['pcap_file'] = pcap_filename
                metadata['pcap_source'] = 'sensor'

            # Check if alert should be suppressed based on device templates
            should_suppress = False
            suppression_reason = None
            if behavior_matcher:
                try:
                    threat_for_check = {
                        'source_ip': alert.get('source_ip'),
                        'destination_ip': alert.get('destination_ip'),
                        'type': alert.get('threat_type', 'UNKNOWN'),
                        'severity': alert.get('severity', 'INFO'),
                        'metadata': metadata
                    }
                    should_suppress, suppression_reason = behavior_matcher.should_suppress_alert(threat_for_check)
                except Exception as e:
                    logger.debug(f"Error checking alert suppression: {e}")

            if should_suppress:
                suppressed_count += 1
                logger.debug(f"Suppressed sensor alert from {alert.get('source_ip')}: {suppression_reason}")
                continue  # Skip this alert, don't insert

            success = db.insert_alert_from_sensor(
                sensor_id=sensor_id,
                severity=alert.get('severity', 'INFO'),
                threat_type=alert.get('threat_type', 'UNKNOWN'),
                source_ip=alert.get('source_ip'),
                destination_ip=alert.get('destination_ip'),
                description=alert.get('description', ''),
                metadata=metadata,
                timestamp=timestamp
            )

            if success:
                success_count += 1

                # Broadcast to dashboard
                try:
                    socketio.emit('new_alert', {
                        'severity': alert.get('severity'),
                        'threat_type': alert.get('threat_type'),
                        'source_ip': alert.get('source_ip'),
                        'destination_ip': alert.get('destination_ip'),
                        'description': alert.get('description'),
                        'sensor_id': sensor_id,
                        'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                        'has_pcap': pcap_filename is not None
                    })
                except:
                    pass  # Don't fail if broadcast fails

        # Log suppression statistics if any
        if suppressed_count > 0:
            logger.info(f"Sensor {sensor_id}: {suppressed_count}/{len(alerts)} alerts suppressed by BehaviorMatcher")

        return jsonify({
            'success': True,
            'received': len(alerts),
            'inserted': success_count,
            'suppressed': suppressed_count,
            'pcap_received': pcap_count
        })

    except Exception as e:
        logger.error(f"Error submitting alerts from sensor {sensor_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>', methods=['GET'])
def api_get_sensor(sensor_id):
    """Get specific sensor details"""
    try:
        sensor = db.get_sensor_by_id(sensor_id)
        if sensor:
            return jsonify({'success': True, 'data': sensor})
        else:
            return jsonify({'success': False, 'error': 'Sensor not found'}), 404
    except Exception as e:
        logger.error(f"Error getting sensor: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== Sensor Command Endpoints ====================

@app.route('/api/sensors/<sensor_id>/commands', methods=['POST'])
def api_create_sensor_command(sensor_id):
    """Create a command for a sensor"""
    try:
        data = request.get_json()
        command_type = data.get('command_type')
        parameters = data.get('parameters', {})

        if not command_type:
            return jsonify({'success': False, 'error': 'command_type required'}), 400

        # Verify sensor exists
        sensor = db.get_sensor_by_id(sensor_id)
        if not sensor:
            return jsonify({'success': False, 'error': 'Sensor not found'}), 404

        # Create command
        command_id = db.create_sensor_command(sensor_id, command_type, parameters)

        if command_id:
            logger.info(f"Command {command_type} created for sensor {sensor_id}")
            return jsonify({
                'success': True,
                'command_id': command_id,
                'message': f'Command {command_type} queued for sensor {sensor_id}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to create command'}), 500

    except Exception as e:
        logger.error(f"Error creating command for sensor {sensor_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>/commands', methods=['GET'])
def api_get_sensor_commands(sensor_id):
    """Get pending commands for a sensor (used by sensor for polling)"""
    try:
        commands = db.get_pending_commands(sensor_id)
        return jsonify({'success': True, 'commands': commands})

    except Exception as e:
        logger.error(f"Error getting commands for sensor {sensor_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>/commands/<int:command_id>', methods=['PUT'])
def api_update_command_status(sensor_id, command_id):
    """Update command execution status (used by sensor to report results)"""
    try:
        data = request.get_json()
        status = data.get('status')
        result = data.get('result', {})

        if status not in ['executing', 'completed', 'failed']:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400

        success = db.update_command_status(command_id, status, result)

        if success:
            logger.info(f"Command {command_id} status updated to {status}")
            return jsonify({'success': True, 'message': 'Command status updated'})
        else:
            return jsonify({'success': False, 'error': 'Failed to update command'}), 500

    except Exception as e:
        logger.error(f"Error updating command {command_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensors/<sensor_id>/commands/history', methods=['GET'])
def api_get_command_history(sensor_id):
    """Get command history for a sensor (for dashboard)"""
    try:
        limit = request.args.get('limit', 50, type=int)
        commands = db.get_sensor_command_history(sensor_id, limit)
        return jsonify({'success': True, 'commands': commands})

    except Exception as e:
        logger.error(f"Error getting command history for sensor {sensor_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== Whitelist Management Endpoints ====================

@app.route('/api/whitelist', methods=['GET'])
@require_sensor_token_or_login()
def api_get_whitelist():
    """Get whitelist entries"""
    try:
        scope = request.args.get('scope')
        sensor_id = request.args.get('sensor_id')
        entries = db.get_whitelist(scope=scope, sensor_id=sensor_id)
        return jsonify({'success': True, 'entries': entries})
    except Exception as e:
        logger.error(f"Error getting whitelist: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whitelist', methods=['POST'])
@require_role('admin', 'operator')
def api_add_whitelist():
    """Add whitelist entry

    Request body:
        ip_cidr: Legacy IP address or CIDR range (optional if source_ip/target_ip provided)
        source_ip: Source IP/CIDR filter (optional, NULL = all sources)
        target_ip: Target/destination IP/CIDR filter (optional, NULL = all destinations)
        port_filter: Port filter string, e.g. "80,443,8080-8090" (optional)
        description: Human-readable description
        scope: 'global' or 'sensor'
        sensor_id: Required if scope is 'sensor'
        direction: 'inbound', 'outbound', or 'both' (default: 'both', legacy)
        created_by: User/system identifier
    """
    try:
        data = request.get_json()
        ip_cidr = data.get('ip_cidr')
        source_ip = data.get('source_ip')
        target_ip = data.get('target_ip')
        port_filter = data.get('port_filter')
        description = data.get('description', '')
        scope = data.get('scope', 'global')
        sensor_id = data.get('sensor_id')
        direction = data.get('direction', 'both')
        created_by = data.get('created_by', 'dashboard')

        # Need at least one IP specification
        if not ip_cidr and not source_ip and not target_ip:
            return jsonify({'success': False, 'error': 'At least ip_cidr, source_ip, or target_ip is required'}), 400

        # Validate port_filter format if provided
        if port_filter:
            try:
                from database import DatabaseManager
                DatabaseManager._parse_port_filter(port_filter)
            except ValueError as e:
                return jsonify({'success': False, 'error': f'Invalid port_filter: {e}'}), 400

        # Validate and normalize direction (support both old and new terminology)
        direction_map = {
            'source': 'outbound',
            'destination': 'inbound',
            'inbound': 'inbound',
            'outbound': 'outbound',
            'both': 'both'
        }
        if direction not in direction_map:
            return jsonify({
                'success': False,
                'error': "direction must be 'source', 'destination', or 'both'"
            }), 400
        direction = direction_map[direction]

        entry_id = db.add_whitelist_entry(
            ip_cidr=ip_cidr,
            description=description,
            scope=scope,
            sensor_id=sensor_id,
            direction=direction,
            created_by=created_by,
            source_ip=source_ip,
            target_ip=target_ip,
            port_filter=port_filter
        )

        if entry_id:
            desc_parts = []
            if source_ip:
                desc_parts.append(f'src={source_ip}')
            if target_ip:
                desc_parts.append(f'dst={target_ip}')
            if port_filter:
                desc_parts.append(f'ports={port_filter}')
            if ip_cidr and not source_ip and not target_ip:
                desc_parts.append(f'{ip_cidr} ({direction})')
            return jsonify({
                'success': True,
                'entry_id': entry_id,
                'message': f'Whitelist entry added: {", ".join(desc_parts)}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to add whitelist entry'}), 500

    except Exception as e:
        logger.error(f"Error adding whitelist entry: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whitelist/<int:entry_id>', methods=['DELETE'])
@require_role('admin', 'operator')
def api_delete_whitelist(entry_id):
    """Delete whitelist entry"""
    try:
        success = db.delete_whitelist_entry(entry_id)
        if success:
            return jsonify({'success': True, 'message': 'Whitelist entry deleted'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete entry'}), 500
    except Exception as e:
        logger.error(f"Error deleting whitelist entry: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whitelist/check/<ip_address>', methods=['GET'])
@require_sensor_token_or_login()
def api_check_whitelist(ip_address):
    """Check if IP is whitelisted

    Query parameters:
        sensor_id: Optional sensor ID for sensor-specific rules
        direction: 'source', 'destination', or omit for 'both' only (legacy)
        source_ip: Source IP for combined check (new mode)
        destination_ip: Destination IP for combined check (new mode)
        port: Destination port for combined check (new mode)
    """
    try:
        sensor_id = request.args.get('sensor_id')
        direction = request.args.get('direction')
        source_ip = request.args.get('source_ip')
        destination_ip = request.args.get('destination_ip')
        port_str = request.args.get('port')
        port = int(port_str) if port_str else None

        # New combined mode
        if source_ip or destination_ip:
            is_whitelisted = db.check_ip_whitelisted(
                source_ip=source_ip or ip_address,
                destination_ip=destination_ip or ip_address,
                port=port,
                sensor_id=sensor_id
            )
            return jsonify({
                'success': True,
                'source_ip': source_ip or ip_address,
                'destination_ip': destination_ip or ip_address,
                'port': port,
                'is_whitelisted': is_whitelisted
            })

        # Legacy mode
        valid_directions = ('source', 'destination', 'inbound', 'outbound', 'both')
        if direction and direction not in valid_directions:
            return jsonify({
                'success': False,
                'error': "direction must be 'source', 'destination', or 'both'"
            }), 400

        is_whitelisted = db.check_ip_whitelisted(
            ip_address,
            sensor_id=sensor_id,
            direction=direction
        )
        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'direction': direction or 'both',
            'is_whitelisted': is_whitelisted
        })
    except Exception as e:
        logger.error(f"Error checking whitelist: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Configuration Management Endpoints ====================

@app.route('/api/config', methods=['GET'])
@require_sensor_token_or_login()
def api_get_config():
    """Get configuration for a sensor (merged defaults + global + sensor-specific)

    Supports ETag-based caching:
    - Send If-None-Match header with previous ETag
    - Returns 304 Not Modified if config unchanged
    - Returns 200 OK with ETag header if config changed
    """
    try:
        sensor_id = request.args.get('sensor_id') or None  # Convert empty string to None
        parameter_path = request.args.get('parameter_path') or None
        include_defaults = request.args.get('include_defaults', 'true').lower() == 'true'

        # Get database config (global + sensor-specific)
        db_config = db.get_sensor_config(sensor_id=sensor_id, parameter_path=parameter_path)

        # Merge with defaults if requested (for UI display)
        if include_defaults and not parameter_path:
            from config_defaults import BEST_PRACTICE_CONFIG
            import copy

            def deep_merge(base, override):
                """Deep merge override into base"""
                result = copy.deepcopy(base)
                for key, value in override.items():
                    if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                        result[key] = deep_merge(result[key], value)
                    else:
                        result[key] = value
                return result

            config = deep_merge(BEST_PRACTICE_CONFIG, db_config)
        else:
            config = db_config

        # Generate ETag from config content (MD5 hash of JSON)
        config_json = json.dumps(config, sort_keys=True, default=str)
        etag = hashlib.md5(config_json.encode('utf-8')).hexdigest()

        # Check If-None-Match header (client's cached ETag)
        client_etag = request.headers.get('If-None-Match')
        if client_etag and client_etag.strip('"') == etag:
            # Config unchanged - return 304 Not Modified
            response = app.response_class(status=304)
            response.headers['ETag'] = f'"{etag}"'
            return response

        # Config changed or no cache - return full config with ETag
        response = jsonify({'success': True, 'config': config})
        response.headers['ETag'] = f'"{etag}"'
        response.headers['Cache-Control'] = 'no-cache'  # Must revalidate with server
        return response

    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/parameters', methods=['GET'])
def api_get_config_parameters():
    """Get all configuration parameters with metadata

    Public endpoint for MCP server integration (localhost only).
    Production deployments should firewall this endpoint.
    """
    try:
        sensor_id = request.args.get('sensor_id')
        parameters = db.get_all_config_parameters(sensor_id=sensor_id)
        return jsonify({'success': True, 'parameters': parameters})
    except Exception as e:
        logger.error(f"Error getting config parameters: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/parameter', methods=['PUT'])
@require_role('admin', 'operator')
def api_set_config_parameter():
    """Set a configuration parameter (global or per-sensor)"""
    try:
        data = request.get_json()
        parameter_path = data.get('parameter_path')
        value = data.get('value')
        sensor_id = data.get('sensor_id')  # None = global
        scope = data.get('scope', 'global')
        description = data.get('description')
        updated_by = data.get('updated_by', 'dashboard')

        if not parameter_path or value is None:
            return jsonify({'success': False, 'error': 'parameter_path and value are required'}), 400

        success = db.set_config_parameter(
            parameter_path=parameter_path,
            value=value,
            sensor_id=sensor_id,
            scope=scope,
            description=description,
            updated_by=updated_by
        )

        if success:
            # Broadcast config update to connected clients
            socketio.emit('config_updated', {
                'parameter_path': parameter_path,
                'value': value,
                'sensor_id': sensor_id,
                'scope': scope
            })

            return jsonify({
                'success': True,
                'message': f'Parameter {parameter_path} updated',
                'parameter_path': parameter_path,
                'value': value
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to update parameter'}), 500

    except Exception as e:
        logger.error(f"Error setting config parameter: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/parameter', methods=['DELETE'])
@require_role('admin', 'operator')
def api_delete_config_parameter():
    """Delete a configuration parameter"""
    try:
        parameter_path = request.args.get('parameter_path')
        sensor_id = request.args.get('sensor_id')

        if not parameter_path:
            return jsonify({'success': False, 'error': 'parameter_path is required'}), 400

        success = db.delete_config_parameter(parameter_path=parameter_path, sensor_id=sensor_id)

        if success:
            return jsonify({'success': True, 'message': f'Parameter {parameter_path} deleted'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete parameter'}), 500

    except Exception as e:
        logger.error(f"Error deleting config parameter: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/defaults', methods=['GET'])
@login_required
def api_get_config_defaults():
    """Get best practice default configuration"""
    try:
        from config_defaults import BEST_PRACTICE_CONFIG, PARAMETER_DESCRIPTIONS, PARAMETER_CATEGORIES

        return jsonify({
            'success': True,
            'defaults': BEST_PRACTICE_CONFIG,
            'descriptions': PARAMETER_DESCRIPTIONS,
            'categories': PARAMETER_CATEGORIES
        })
    except Exception as e:
        logger.error(f"Error getting config defaults: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/reset', methods=['POST'])
@require_role('admin')
def api_reset_config():
    """Reset configuration to best practice defaults"""
    try:
        data = request.get_json()
        sensor_id = data.get('sensor_id')  # None = global
        confirm = data.get('confirm', False)

        if not confirm:
            return jsonify({'success': False, 'error': 'Confirmation required'}), 400

        from config_defaults import BEST_PRACTICE_CONFIG, flatten_config

        # Flatten config to parameter paths
        flat_config = flatten_config(BEST_PRACTICE_CONFIG)

        # Set each parameter
        count = 0
        for parameter_path, value in flat_config.items():
            success = db.set_config_parameter(
                parameter_path=parameter_path,
                value=value,
                sensor_id=sensor_id,
                scope='global' if not sensor_id else 'sensor',
                description='Reset to best practice default',
                updated_by='dashboard_reset'
            )
            if success:
                count += 1

        # Broadcast reset event
        socketio.emit('config_reset', {
            'sensor_id': sensor_id,
            'parameters_reset': count
        })

        return jsonify({
            'success': True,
            'message': f'Reset {count} parameters to defaults',
            'parameters_reset': count
        })

    except Exception as e:
        logger.error(f"Error resetting config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Kiosk Mode Routes (Public Access) ====================

@app.route('/kiosk')
def kiosk_view():
    """
    Kiosk mode fullscreen view - Public access for monitoring displays
    No authentication required
    """
    return render_template('kiosk.html')

@app.route('/api/kiosk/metrics')
def api_kiosk_metrics():
    """
    Get aggregated metrics for kiosk display - Public API
    Returns cumulative metrics from ALL sensors
    """
    try:
        # Get aggregated metrics from ALL sensors
        aggregated = db.get_aggregated_metrics()

        # Get sensor status overview
        sensors = db.get_sensors()

        # Calculate average CPU/Memory across all sensors
        total_cpu = 0
        total_memory = 0
        sensor_count = 0

        for sensor in sensors:
            if sensor.get('cpu_percent') is not None:
                total_cpu += sensor['cpu_percent']
                sensor_count += 1
            if sensor.get('memory_percent') is not None:
                total_memory += sensor['memory_percent']

        avg_cpu = round(total_cpu / sensor_count, 1) if sensor_count > 0 else 0
        avg_memory = round(total_memory / sensor_count, 1) if sensor_count > 0 else 0

        # Get disk/storage metrics (from SOC server sensor)
        disk_info = {}
        pcap_info = {}
        db_info = {}

        # Get disk usage (from SOC server)
        try:
            import psutil
            disk = psutil.disk_usage('/')
            disk_used_gb = disk.used / (1024**3)
            disk_total_gb = disk.total / (1024**3)
            disk_info = {
                'disk_percent': disk.percent,
                'disk_used': f"{disk_used_gb:.1f} GB",
                'disk_total': f"{disk_total_gb:.1f} GB"
            }
        except Exception as e:
            logger.error(f"Error getting disk usage: {e}")
            # Fallback to sensor data if available
            soc_sensor = next((s for s in sensors if 'soc-server' in s.get('sensor_id', '')), None)
            disk_info = {
                'disk_percent': soc_sensor.get('disk_percent', 0) if soc_sensor else 0,
                'disk_used': '0 GB',
                'disk_total': '0 GB'
            }

        # Get database storage info
        try:
            # Get database size
            conn = db._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT pg_database_size(current_database())")
            db_size_bytes = cursor.fetchone()[0]
            db_size_mb = db_size_bytes / (1024 * 1024)
            db_size_gb = db_size_bytes / (1024 * 1024 * 1024)

            # Get alert count
            cursor.execute("SELECT COUNT(*) FROM alerts")
            db_alerts_count = cursor.fetchone()[0]

            # Get oldest alert date
            cursor.execute("SELECT MIN(timestamp) FROM alerts")
            oldest_alert = cursor.fetchone()[0]
            data_age_days = 0
            if oldest_alert:
                data_age_days = (datetime.now() - oldest_alert.replace(tzinfo=None)).days

            db._return_connection(conn)

            db_info = {
                'db_size_human': f"{db_size_mb:.0f} MB" if db_size_mb < 1024 else f"{db_size_gb:.1f} GB",
                'db_alerts_count': db_alerts_count,
                'data_age_days': data_age_days
            }
        except Exception as e:
            logger.error(f"Error getting database info: {e}")
            db_info = {
                'db_size_human': '0 MB',
                'db_alerts_count': 0,
                'data_age_days': 0
            }

        # Get PCAP storage info
        try:
            import os
            pcap_dir = '/var/log/netmonitor/pcap'
            if os.path.exists(pcap_dir):
                pcap_files = []
                pcap_size_bytes = 0
                for root, dirs, files in os.walk(pcap_dir):
                    for file in files:
                        if file.endswith('.pcap'):
                            file_path = os.path.join(root, file)
                            pcap_size_bytes += os.path.getsize(file_path)
                            pcap_files.append(file)

                pcap_size_mb = pcap_size_bytes / (1024 * 1024)
                pcap_size_gb = pcap_size_bytes / (1024 * 1024 * 1024)

                pcap_info = {
                    'pcap_file_count': len(pcap_files),
                    'pcap_size_human': f"{pcap_size_mb:.0f} MB" if pcap_size_mb < 1024 else f"{pcap_size_gb:.1f} GB"
                }
            else:
                pcap_info = {
                    'pcap_file_count': 0,
                    'pcap_size_human': '0 MB'
                }
        except Exception as e:
            logger.error(f"Error getting PCAP info: {e}")
            pcap_info = {
                'pcap_file_count': 0,
                'pcap_size_human': '0 MB'
            }

        # Get critical/high alerts (last hour)
        alerts = db.get_recent_alerts(limit=20, hours=1)
        critical_alerts = [a for a in alerts if a['severity'] in ['CRITICAL', 'HIGH']]

        # Get alert statistics for threat breakdown
        stats = db.get_alert_statistics(hours=24)

        # Sensor health counts
        sensor_health = {
            'total': len(sensors),
            'online': len([s for s in sensors if s['computed_status'] == 'online']),
            'warning': len([s for s in sensors if s['computed_status'] == 'warning']),
            'offline': len([s for s in sensors if s['computed_status'] == 'offline'])
        }

        # Merge all metrics
        metrics_dict = {
            'bandwidth_mbps': aggregated.get('bandwidth_mbps', 0),
            'packets_per_sec': aggregated.get('packets_per_sec', 0),
            'alerts_per_min': aggregated.get('alerts_per_min', 0),
            'active_sensors': f"{sensor_health['online']}/{sensor_health['total']}",
            'avg_cpu_percent': avg_cpu,
            'avg_memory_percent': avg_memory,
            **disk_info,
            **db_info,
            **pcap_info,
            'retention_alerts': 365,  # From config
            'retention_metrics': 90    # From config
        }

        return jsonify({
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics_dict,
            'sensor_health': sensor_health,
            'critical_alerts': critical_alerts[:10],  # Max 10 for kiosk
            'top_threats': dict(list(stats.get('by_type', {}).items())[:5]),
            'alert_severity': stats.get('by_severity', {})
        })

    except Exception as e:
        logger.error(f"Error getting kiosk metrics: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'metrics': {
                'bandwidth_mbps': 0,
                'packets_per_sec': 0,
                'alerts_per_min': 0,
                'active_sensors': '0/0',
                'avg_cpu_percent': 0,
                'avg_memory_percent': 0
            }
        }), 500

@app.route('/api/kiosk/sensors')
def api_kiosk_sensors():
    """
    Get detailed sensor status for kiosk sensor view
    Public API - no auth required
    """
    try:
        sensors = db.get_sensors()

        # Format for kiosk display
        formatted_sensors = []
        for sensor in sensors:
            formatted_sensors.append({
                'id': sensor['sensor_id'],
                'name': sensor['hostname'],
                'location': sensor.get('location', 'Unknown'),
                'status': sensor['computed_status'],
                'cpu': sensor.get('cpu_percent', 0),
                'memory': sensor.get('memory_percent', 0),
                'bandwidth': sensor.get('bandwidth_mbps', 0),
                'alerts_24h': sensor.get('alerts_24h', 0),
                'last_seen': sensor.get('last_seen')
            })

        return jsonify({
            'success': True,
            'sensors': formatted_sensors,
            'total': len(formatted_sensors),
            'online': len([s for s in formatted_sensors if s['status'] == 'online'])
        })

    except Exception as e:
        logger.error(f"Error getting kiosk sensors: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/kiosk/traffic')
def api_kiosk_traffic():
    """
    Get network traffic data for last 24 hours for kiosk chart
    Public API - no auth required
    Returns bandwidth in Mbps with peak tracking
    """
    try:
        from datetime import datetime, timedelta

        # Get traffic history from database (last 24 hours, up to 288 points = 5min intervals)
        traffic_data = db.get_traffic_history(hours=24, limit=288)

        # Format data for Chart.js
        labels = []
        bandwidth_in_avg = []
        bandwidth_in_peak = []
        bandwidth_out_avg = []
        bandwidth_out_peak = []

        if traffic_data and len(traffic_data) > 0:
            for record in traffic_data:
                # Format timestamp
                timestamp = record.get('timestamp')
                if timestamp:
                    if isinstance(timestamp, str):
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    else:
                        dt = timestamp
                    labels.append(dt.strftime('%H:%M'))
                else:
                    labels.append('')

                # Use pre-calculated Mbps values from database
                bandwidth_in_avg.append(record.get('inbound_mbps', 0) or 0)
                bandwidth_in_peak.append(record.get('inbound_mbps_peak', 0) or 0)
                bandwidth_out_avg.append(record.get('outbound_mbps', 0) or 0)
                bandwidth_out_peak.append(record.get('outbound_mbps_peak', 0) or 0)

        # If no data, generate empty data points for last 24 hours
        if len(labels) == 0:
            now = datetime.now()
            for i in range(24):
                hour = (now - timedelta(hours=23-i)).strftime('%H:%M')
                labels.append(hour)
                bandwidth_in_avg.append(0)
                bandwidth_in_peak.append(0)
                bandwidth_out_avg.append(0)
                bandwidth_out_peak.append(0)

        return jsonify({
            'success': True,
            'labels': labels,
            'datasets': {
                'bandwidth_in_avg': bandwidth_in_avg,
                'bandwidth_in_peak': bandwidth_in_peak,
                'bandwidth_out_avg': bandwidth_out_avg,
                'bandwidth_out_peak': bandwidth_out_peak
            },
            'unit': 'Mbps',
            'period': '24 hours'
        })

    except Exception as e:
        logger.error(f"Error getting kiosk traffic data: {e}")
        import traceback
        logger.error(traceback.format_exc())

        # Return empty data on error
        now = datetime.now()
        labels = [(now - timedelta(hours=23-i)).strftime('%H:%M') for i in range(24)]
        return jsonify({
            'success': False,
            'error': str(e),
            'labels': labels,
            'datasets': {
                'bandwidth_in_avg': [0] * 24,
                'bandwidth_in_peak': [0] * 24,
                'bandwidth_out_avg': [0] * 24,
                'bandwidth_out_peak': [0] * 24
            },
            'unit': 'Mbps',
            'period': '24 hours'
        }), 500

@app.route('/api/disk-usage')
@login_required
def api_disk_usage():
    """
    Get disk usage and storage metrics for dashboard.

    Performance optimizations:
    - Uses subprocess 'du' and 'find' commands (100x faster than os.walk)
    - Caches PCAP stats for 5 minutes
    - Runs PCAP scan in background if cache is stale
    """
    try:
        import psutil
        import subprocess

        # Get disk usage (fast)
        disk = psutil.disk_usage('/')

        # Get database size and info (fast with indexes)
        conn = db._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT pg_database_size(current_database())")
        db_size_bytes = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts")
        db_alerts_count = cursor.fetchone()[0]

        cursor.execute("SELECT MIN(timestamp) FROM alerts")
        oldest_alert = cursor.fetchone()[0]
        data_age_days = 0
        if oldest_alert:
            data_age_days = (datetime.now() - oldest_alert.replace(tzinfo=None)).days

        db._return_connection(conn)

        # Get PCAP storage info - OPTIMIZED with 5-minute caching
        # With 960k+ PCAP files, scanning takes 10+ seconds
        # Cache dramatically improves dashboard load time
        # CRITICAL: Use lock to prevent multiple workers from scanning simultaneously
        global pcap_stats_cache, pcap_stats_cache_time, pcap_stats_cache_lock

        pcap_size_bytes = 0
        pcap_file_count = 0

        # Lock the entire cache check + populate operation to prevent race conditions
        # This ensures only ONE worker scans while others wait for the cache
        with pcap_stats_cache_lock:
            # Check if cache is fresh
            if pcap_stats_cache and pcap_stats_cache_time:
                cache_age = (datetime.now() - pcap_stats_cache_time).total_seconds()
                if cache_age < PCAP_STATS_CACHE_TTL:
                    # Use cached values (fast path)
                    pcap_size_bytes = pcap_stats_cache.get('size_bytes', 0)
                    pcap_file_count = pcap_stats_cache.get('file_count', 0)
                    logger.debug(f"Using cached PCAP stats (age: {cache_age:.0f}s)")
                    # Early return - skip scanning
                    cache_age = cache_age  # Keep value for later check
                else:
                    cache_age = None  # Cache is stale, need to scan
            else:
                cache_age = None  # No cache yet, need to scan

            # If no cache or cache is stale, scan filesystem (while holding lock)
            # This prevents multiple workers from scanning simultaneously
            if cache_age is None:
                import os
                pcap_dir = '/var/log/netmonitor/pcap'

                if os.path.exists(pcap_dir):
                    logger.info("PCAP cache stale, scanning filesystem (this may take ~10s)...")
                    try:
                        # Use fast 'du' command for total size
                        result = subprocess.run(
                            ['du', '-sb', pcap_dir],
                            capture_output=True,
                            text=True,
                            timeout=20  # 20 second timeout (increased for safety)
                        )
                        if result.returncode == 0:
                            pcap_size_bytes = int(result.stdout.split()[0])

                        # Use fast 'find' with wc for count (avoids loading all filenames)
                        result = subprocess.run(
                            "find /var/log/netmonitor/pcap -name '*.pcap' -type f | wc -l",
                            capture_output=True,
                            text=True,
                            shell=True,
                            timeout=20
                        )
                        if result.returncode == 0:
                            pcap_file_count = int(result.stdout.strip())

                        # Update cache (already holding lock)
                        pcap_stats_cache = {
                            'size_bytes': pcap_size_bytes,
                            'file_count': pcap_file_count
                        }
                        pcap_stats_cache_time = datetime.now()
                        logger.info(f"PCAP stats cached: {pcap_file_count:,} files, {pcap_size_bytes/(1024**3):.2f} GB")

                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as e:
                        logger.warning(f"PCAP stats scan failed: {e}")
                        # Use old cache if available, otherwise 0
                        if pcap_stats_cache:
                            pcap_size_bytes = pcap_stats_cache.get('size_bytes', 0)
                            pcap_file_count = pcap_stats_cache.get('file_count', 0)
                            logger.info("Using stale PCAP cache due to scan failure")

        # Format sizes
        def format_bytes(bytes_val):
            if bytes_val >= 1024**3:
                return f"{bytes_val / (1024**3):.2f} GB"
            elif bytes_val >= 1024**2:
                return f"{bytes_val / (1024**2):.2f} MB"
            elif bytes_val >= 1024:
                return f"{bytes_val / 1024:.2f} KB"
            else:
                return f"{bytes_val} B"

        return jsonify({
            'success': True,
            'data': {
                'system': {
                    'percent_used': disk.percent,
                    'used_human': format_bytes(disk.used),
                    'total_human': format_bytes(disk.total)
                },
                'database': {
                    'size_human': format_bytes(db_size_bytes),
                    'size_bytes': db_size_bytes,
                    'alerts_count': db_alerts_count,
                    'data_age_days': data_age_days
                },
                'pcap': {
                    'size_human': format_bytes(pcap_size_bytes),
                    'size_bytes': pcap_size_bytes,
                    'file_count': pcap_file_count
                },
                'retention': db.get_retention_config()
            }
        })

    except Exception as e:
        logger.error(f"Error getting disk usage: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== Device Classification API ====================

@app.route('/api/devices')
@login_required
def api_get_devices():
    """
    Get all discovered devices
    Query params:
      - sensor_id: Filter by sensor
      - template_id: Filter by assigned template
      - active_only: Only show active devices (default: true)
    """
    try:
        sensor_id = request.args.get('sensor_id')
        template_id = request.args.get('template_id', type=int)
        active_only = request.args.get('active_only', 'true').lower() == 'true'

        devices = db.get_devices(
            sensor_id=sensor_id,
            template_id=template_id,
            include_inactive=not active_only
        )

        return jsonify({
            'success': True,
            'devices': devices,
            'total': len(devices)
        })
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>')
@login_required
def api_get_device(ip_address):
    """Get details for a specific device by IP"""
    try:
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        return jsonify({
            'success': True,
            'device': device
        })
    except Exception as e:
        logger.error(f"Error getting device {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>/template', methods=['PUT'])
@login_required
def api_assign_device_template(ip_address):
    """Assign a template to a device"""
    try:
        data = request.get_json()
        template_id = data.get('template_id')
        confidence = data.get('confidence', 1.0)
        method = data.get('method', 'manual')

        if template_id is None:
            return jsonify({'success': False, 'error': 'template_id is required'}), 400

        # First get the device to get its ID
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        success = db.assign_device_template(
            device_id=device['id'],
            template_id=template_id if template_id != 0 else None,
            confidence=confidence,
            method=method
        )

        if success:
            return jsonify({'success': True, 'message': 'Template assigned successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to assign template'}), 500

    except Exception as e:
        logger.error(f"Error assigning template to {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>/inherit', methods=['POST'])
@login_required
def api_inherit_device_settings(ip_address):
    """
    Inherit settings from another device.

    Useful for devices with MAC randomization (iPhone, Android privacy mode)
    where the user knows two devices are actually the same physical device.

    Request body:
    {
        "source_ip": "192.168.1.100",  // Device to copy settings from
        "inherit_template": true,       // Copy template assignment
        "inherit_behavior": true,       // Copy learned behavior profile
        "deactivate_source": false      // Mark source as inactive after transfer
    }
    """
    try:
        data = request.get_json()
        source_ip = data.get('source_ip')

        if not source_ip:
            return jsonify({'success': False, 'error': 'source_ip is required'}), 400

        # Get both devices
        target_device = db.get_device_by_ip(ip_address)
        source_device = db.get_device_by_ip(source_ip)

        if not target_device:
            return jsonify({'success': False, 'error': f'Target device {ip_address} not found'}), 404
        if not source_device:
            return jsonify({'success': False, 'error': f'Source device {source_ip} not found'}), 404

        success = db.inherit_device_settings(
            target_device_id=target_device['id'],
            source_device_id=source_device['id'],
            inherit_template=data.get('inherit_template', True),
            inherit_behavior=data.get('inherit_behavior', True),
            deactivate_source=data.get('deactivate_source', False)
        )

        if success:
            return jsonify({
                'success': True,
                'message': f'Settings inherited from {source_ip} to {ip_address}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to inherit settings'}), 500

    except Exception as e:
        logger.error(f"Error inheriting settings for {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>', methods=['DELETE'])
@login_required
def api_delete_device(ip_address):
    """Delete a device from the database"""
    try:
        success = db.delete_device_by_ip(ip_address)
        if success:
            return jsonify({'success': True, 'message': 'Device deleted'})
        else:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting device {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>/touch', methods=['POST'])
@login_required
def api_touch_device(ip_address):
    """
    Update a device's last_seen timestamp to NOW.
    Use this to manually refresh activity for devices like Access Points
    that don't generate much traffic themselves.
    """
    try:
        success = db.touch_device(ip_address=ip_address)
        if success:
            return jsonify({
                'success': True,
                'message': f'Device {ip_address} last_seen updated',
                'ip_address': ip_address
            })
        else:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
    except Exception as e:
        logger.error(f"Error touching device {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/touch', methods=['POST'])
@login_required
def api_touch_devices_bulk():
    """
    Update last_seen for multiple devices at once.

    Request body:
        ip_addresses: List of IP addresses to touch

    Use this to refresh activity for multiple devices like Access Points.
    """
    try:
        data = request.get_json()
        ip_addresses = data.get('ip_addresses', [])

        if not ip_addresses:
            return jsonify({'success': False, 'error': 'ip_addresses list required'}), 400

        updated = db.touch_devices_bulk(ip_addresses)
        return jsonify({
            'success': True,
            'message': f'Updated {updated} devices',
            'updated_count': updated,
            'requested_count': len(ip_addresses)
        })
    except Exception as e:
        logger.error(f"Error bulk touching devices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/data-retention/cleanup', methods=['POST'])
@login_required
def api_data_retention_cleanup():
    """
    Manually trigger data retention cleanup.

    Uses retention periods from config.yaml (single source of truth).
    Warns if settings are below NIS2 compliance requirements.
    """
    try:
        # Get retention config from database manager (reads from config.yaml)
        retention = db.get_retention_config()
        alerts_days = retention['alerts_days']
        metrics_days = retention['metrics_days']

        conn = db._get_connection()
        cursor = conn.cursor()

        deleted = {}

        # Use config values for cleanup
        cursor.execute(f"SELECT COUNT(*) FROM alerts WHERE timestamp < NOW() - INTERVAL '{alerts_days} days'")
        old_alerts = cursor.fetchone()[0]

        cursor.execute(f"SELECT COUNT(*) FROM traffic_metrics WHERE timestamp < NOW() - INTERVAL '{metrics_days} days'")
        old_metrics = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM top_talkers WHERE timestamp < NOW() - INTERVAL '30 days'")
        old_talkers = cursor.fetchone()[0]

        # Manual cleanup using config retention periods
        if old_alerts > 0:
            cursor.execute(f"DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '{alerts_days} days'")
            deleted['alerts'] = cursor.rowcount
        else:
            deleted['alerts'] = 0

        if old_metrics > 0:
            cursor.execute(f"DELETE FROM traffic_metrics WHERE timestamp < NOW() - INTERVAL '{metrics_days} days'")
            deleted['traffic_metrics'] = cursor.rowcount
        else:
            deleted['traffic_metrics'] = 0

        if old_talkers > 0:
            cursor.execute("DELETE FROM top_talkers WHERE timestamp < NOW() - INTERVAL '30 days'")
            deleted['top_talkers'] = cursor.rowcount
        else:
            deleted['top_talkers'] = 0

        conn.commit()
        db._return_connection(conn)

        # Cleanup old PCAP files (recursive through all subdirectories)
        import os
        import time as _time
        pcap_deleted = 0
        pcap_root = '/var/log/netmonitor/pcap'
        pcap_cutoff = _time.time() - (metrics_days * 86400)
        if os.path.exists(pcap_root):
            try:
                for dirpath, _dirnames, filenames in os.walk(pcap_root):
                    for fname in filenames:
                        if not fname.endswith('.pcap'):
                            continue
                        fpath = os.path.join(dirpath, fname)
                        if os.path.getmtime(fpath) < pcap_cutoff:
                            os.remove(fpath)
                            pcap_deleted += 1
            except Exception as e:
                logger.warning(f"Error cleaning PCAPs in {pcap_root}: {e}")
        deleted['pcap_files'] = pcap_deleted

        # Invalidate PCAP stats cache after cleanup
        global pcap_stats_cache_time
        pcap_stats_cache_time = None

        total_deleted = sum(deleted.values())
        logger.info(f"Manual data retention cleanup: {total_deleted} records/files deleted (incl. {pcap_deleted} PCAPs)")

        return jsonify({
            'success': True,
            'message': f'Cleanup complete: {total_deleted} record(s)/file(s) deleted',
            'data': {
                'deleted': deleted,
                'total': total_deleted
            }
        })

    except Exception as e:
        logger.error(f"Error in data retention cleanup: {e}")
        if 'conn' in locals():
            conn.rollback()
            db._return_connection(conn)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/data-retention/config', methods=['GET'])
@login_required
def api_data_retention_config():
    """
    Get current data retention configuration and NIS2 compliance status.
    Used by frontend to show warnings if retention is below NIS2 requirements.
    """
    try:
        retention = db.get_retention_config()
        return jsonify({
            'success': True,
            'data': retention
        })
    except Exception as e:
        logger.error(f"Error getting retention config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/cleanup-duplicates', methods=['POST'])
@login_required
def api_cleanup_duplicate_devices():
    """
    Manually trigger cleanup of duplicate device entries with same MAC address.
    Keeps most recently seen device active, marks older duplicates as inactive.

    This runs automatically every 30 minutes, but can be triggered manually here.
    """
    try:
        deactivated = db.cleanup_duplicate_mac_devices()

        return jsonify({
            'success': True,
            'message': f'Cleanup complete: {deactivated} duplicate device(s) deactivated',
            'deactivated_count': deactivated
        })
    except Exception as e:
        logger.error(f"Error cleaning up duplicate devices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/duplicates', methods=['GET'])
@login_required
def api_get_duplicate_devices():
    """
    Get detailed information about duplicate device entries (same MAC, different IPs).
    Returns groups of devices with the same MAC address.
    """
    try:
        # Get all active devices
        devices = db.get_devices(include_inactive=False)

        # Group by MAC address
        mac_groups = {}
        for device in devices:
            mac = device.get('mac_address')
            if mac:  # Only consider devices with MAC addresses
                if mac not in mac_groups:
                    mac_groups[mac] = []
                mac_groups[mac].append(device)

        # Find duplicates (MAC with multiple IPs)
        duplicates = []
        for mac, devices_list in mac_groups.items():
            if len(devices_list) > 1:
                # Sort by last_seen descending (most recent first)
                devices_list.sort(key=lambda d: d.get('last_seen', ''), reverse=True)

                # Determine if this looks like a DHCP issue
                ips = [d.get('ip_address', '').split('/')[0] for d in devices_list]
                is_dhcp_range = any('10.100.0.' in ip and 26 <= int(ip.split('.')[-1]) <= 59
                                   for ip in ips if ip and '.' in ip and ip.split('.')[-1].isdigit())

                duplicates.append({
                    'mac_address': mac,
                    'vendor': devices_list[0].get('vendor', 'Unknown'),
                    'hostname': devices_list[0].get('hostname', '-'),
                    'device_count': len(devices_list),
                    'devices': [{
                        'ip_address': d.get('ip_address'),
                        'hostname': d.get('hostname'),
                        'last_seen': d.get('last_seen'),
                        'template_name': d.get('template_name'),
                        'is_most_recent': i == 0
                    } for i, d in enumerate(devices_list)],
                    'is_dhcp_issue': is_dhcp_range,
                    'recommendation': _get_duplicate_recommendation(devices_list, is_dhcp_range)
                })

        return jsonify({
            'success': True,
            'duplicate_count': len(duplicates),
            'total_duplicate_devices': sum(d['device_count'] for d in duplicates),
            'duplicates': duplicates
        })
    except Exception as e:
        logger.error(f"Error getting duplicate devices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def _get_duplicate_recommendation(devices_list, is_dhcp_issue):
    """Generate actionable recommendations for duplicate MAC addresses."""
    most_recent_ip = devices_list[0].get('ip_address', '').split('/')[0]

    if is_dhcp_issue:
        return {
            'severity': 'high',
            'type': 'dhcp_conflict',
            'title': 'DHCP Configuration Issue Detected',
            'description': f'Device is receiving IPs from dynamic range despite likely having a fixed reservation.',
            'actions': [
                'Check DHCP server: verify MAC-based reservation is active',
                'Check for rogue DHCP servers on the network',
                'Configure static IP directly on the device (bypass DHCP)',
                f'Use "Cleanup Duplicates" button to keep only {most_recent_ip}',
                'Monitor device - if it keeps getting new IPs, DHCP server has an issue'
            ]
        }
    else:
        return {
            'severity': 'medium',
            'type': 'ip_change',
            'title': 'Device IP Address Changed',
            'description': f'Device has changed IP addresses, old entries still visible.',
            'actions': [
                f'Most recent IP: {most_recent_ip} - this is likely correct',
                'Use "Cleanup Duplicates" to remove old entries automatically',
                'Or manually delete individual old IPs if you know which is correct',
                'If device frequently changes IPs: assign fixed DHCP reservation'
            ]
        }


@app.route('/api/devices/<path:ip_address>/traffic-stats')
@login_required
def api_get_device_traffic_stats(ip_address):
    """
    Get traffic statistics for a device.
    Requires active network monitoring to collect stats.
    """
    try:
        # Try to get stats from active device discovery instance
        # This requires the netmonitor to be running
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        # Return stored learned behavior if available
        learned_behavior = device.get('learned_behavior', {})

        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'device': {
                'hostname': device.get('hostname'),
                'mac_address': device.get('mac_address'),
                'vendor': device.get('vendor'),
                'template_name': device.get('template_name')
            },
            'learned_behavior': learned_behavior,
            'note': 'Real-time stats require active monitoring. Use MCP API for live data.'
        })
    except Exception as e:
        logger.error(f"Error getting traffic stats for {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>/classification-hints')
@login_required
def api_get_device_classification_hints(ip_address):
    """
    Get classification hints for a device based on learned behavior.
    """
    try:
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        learned_behavior = device.get('learned_behavior', {})

        # Generate hints from learned behavior
        hints = {
            'suggested_templates': [],
            'vendor': device.get('vendor'),
            'hostname_pattern': None,
            'behavior_summary': {}
        }

        hostname = device.get('hostname', '')
        if hostname:
            # Analyze hostname for patterns
            hostname_lower = hostname.lower()
            if any(x in hostname_lower for x in ['cam', 'ipc', 'nvr', 'dvr']):
                hints['hostname_pattern'] = 'ip_camera'
                hints['suggested_templates'].append({'name': 'IP Camera', 'reason': 'Hostname pattern'})
            elif any(x in hostname_lower for x in ['nas', 'storage', 'qnap', 'synology']):
                hints['hostname_pattern'] = 'nas'
                hints['suggested_templates'].append({'name': 'NAS/File Server', 'reason': 'Hostname pattern'})
            elif any(x in hostname_lower for x in ['printer', 'hp', 'epson', 'canon', 'brother']):
                hints['hostname_pattern'] = 'printer'
                hints['suggested_templates'].append({'name': 'Network Printer', 'reason': 'Hostname pattern'})
            elif any(x in hostname_lower for x in ['tv', 'roku', 'firetv', 'chromecast', 'appletv']):
                hints['hostname_pattern'] = 'smart_tv'
                hints['suggested_templates'].append({'name': 'Smart TV', 'reason': 'Hostname pattern'})

        # Analyze ports from learned behavior
        if learned_behavior:
            server_ports = learned_behavior.get('server_ports', [])
            for port_info in server_ports:
                port = port_info.get('port')
                if port == 80 or port == 443:
                    hints['suggested_templates'].append({'name': 'Web Server', 'reason': f'Serving on port {port}'})
                elif port == 22:
                    hints['suggested_templates'].append({'name': 'Linux Server', 'reason': 'SSH service'})
                elif port in (445, 139):
                    hints['suggested_templates'].append({'name': 'NAS/File Server', 'reason': 'SMB service'})
                elif port == 554:
                    hints['suggested_templates'].append({'name': 'IP Camera', 'reason': 'RTSP service'})

            hints['behavior_summary'] = {
                'protocols': learned_behavior.get('protocols', []),
                'typical_ports': [p['port'] for p in learned_behavior.get('typical_ports', [])][:10],
                'traffic_pattern': learned_behavior.get('traffic_pattern'),
                'destinations_count': len(learned_behavior.get('typical_destinations', []))
            }

        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'hints': hints
        })

    except Exception as e:
        logger.error(f"Error getting classification hints for {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>/save-learned-behavior', methods=['POST'])
@login_required
def api_save_device_learned_behavior(ip_address):
    """
    Save learned behavior to the database.
    This captures the current learned behavior profile from active monitoring.
    """
    try:
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        # Get current learned behavior from the device record
        learned_behavior = device.get('learned_behavior', {})

        if not learned_behavior:
            return jsonify({
                'success': False,
                'error': 'No learned behavior available. Device needs active monitoring to collect data.'
            }), 400

        # The learned behavior is already stored in the database via device_discovery
        # This endpoint confirms it's saved and returns the current state
        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'message': 'Learned behavior is stored in database',
            'learned_behavior': learned_behavior
        })

    except Exception as e:
        logger.error(f"Error saving learned behavior for {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/update-vendors', methods=['POST'])
@login_required
def api_update_device_vendors():
    """
    Update vendor information for all devices that have a MAC address but no vendor.
    Uses the OUI database to look up vendor names from MAC addresses.
    """
    try:
        # Get device discovery instance
        from device_discovery import DeviceDiscovery
        device_discovery = DeviceDiscovery(db_manager=db)

        # Update missing vendors
        updated_count = device_discovery.update_missing_vendors()

        return jsonify({
            'success': True,
            'updated_count': updated_count,
            'message': f'Updated vendor information for {updated_count} devices'
        })

    except Exception as e:
        logger.error(f"Error updating device vendors: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<path:ip_address>/learning-status')
@login_required
def api_get_device_learning_status(ip_address):
    """
    Get the learning status for a device.
    Shows how much traffic has been analyzed and readiness for template generation.
    """
    try:
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({
                'success': True,
                'ip_address': ip_address,
                'status': 'not_found',
                'message': 'Device not found'
            })

        learned_behavior = device.get('learned_behavior', {})

        # Determine status
        if not learned_behavior:
            status = 'not_started'
            message = 'No traffic analyzed yet'
            ready_for_template = False
            packet_count = 0
            unique_ports = 0
        else:
            # Get packet count from traffic_summary (the actual structure)
            traffic_summary = learned_behavior.get('traffic_summary', {})
            packet_count = traffic_summary.get('total_packets', 0)

            # Get unique ports from ports structure
            ports_data = learned_behavior.get('ports', {})
            outbound_ports = ports_data.get('outbound_destination_ports', [])
            inbound_ports = ports_data.get('inbound_source_ports', [])
            unique_ports = len(set(outbound_ports + inbound_ports))

            unique_destinations = traffic_summary.get('unique_outbound_destinations', 0)

            if packet_count < 100:
                status = 'learning'
                message = f'Analyzing traffic ({packet_count} packets)'
                ready_for_template = False
            elif unique_ports < 2:
                status = 'learning'
                message = 'Need more diverse port activity'
                ready_for_template = False
            else:
                status = 'ready'
                message = 'Sufficient data for template generation'
                ready_for_template = True

        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'status': status,
            'message': message,
            'ready_for_template': ready_for_template,
            'statistics': {
                'packet_count': packet_count,
                'unique_ports': unique_ports,
                'unique_destinations': learned_behavior.get('traffic_summary', {}).get('unique_outbound_destinations', 0) if learned_behavior else 0,
                'protocols': learned_behavior.get('ports', {}).get('protocols', []) if learned_behavior else []
            }
        })

    except Exception as e:
        logger.error(f"Error getting learning status for {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates/from-device', methods=['POST'])
@login_required
def api_create_template_from_device():
    """
    Create a new device template based on the learned behavior of a specific device.
    """
    try:
        data = request.get_json()

        ip_address = data.get('ip_address')
        template_name = data.get('template_name')
        category = data.get('category', 'other')
        description = data.get('description')
        merge_with_template_id = data.get('merge_with_template_id')  # Optional: merge with existing template

        if not ip_address or not template_name:
            return jsonify({
                'success': False,
                'error': 'ip_address and template_name are required'
            }), 400

        # Get device and its learned behavior
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        learned_behavior = device.get('learned_behavior', {})
        if not learned_behavior:
            return jsonify({
                'success': False,
                'error': 'No learned behavior available for this device'
            }), 400

        # Check if enough data - get packet count from traffic_summary structure
        traffic_summary = learned_behavior.get('traffic_summary', {})
        packet_count = traffic_summary.get('total_packets', 0)
        if packet_count < 50:
            return jsonify({
                'success': False,
                'error': f'Insufficient data ({packet_count} packets). Need at least 50 packets for template generation.'
            }), 400

        # Create the template
        if not description:
            description = f"Auto-generated from device {ip_address}"
            if device.get('hostname'):
                description += f" ({device['hostname']})"

        # Check if an active template with this name already exists
        existing_templates = db.get_device_templates(include_inactive=False)
        if any(t.get('name', '').lower() == template_name.lower() for t in existing_templates):
            return jsonify({
                'success': False,
                'error': f'Template with name "{template_name}" already exists'
            }), 400

        # Create template (will reactivate if an inactive one with same name exists)
        template_id = db.create_device_template(
            name=template_name,
            description=description,
            category=category,
            created_by=current_user.username if current_user.is_authenticated else 'auto'
        )

        if not template_id:
            return jsonify({'success': False, 'error': 'Failed to create template (database error)'}), 500

        behaviors_added = 0

        # If merging with existing template, copy its behaviors first
        if merge_with_template_id:
            existing_template = db.get_device_template_by_id(merge_with_template_id)
            if existing_template:
                existing_behaviors = existing_template.get('behaviors', [])
                logger.info(f"Merging with template {merge_with_template_id}: copying {len(existing_behaviors)} existing behaviors")

                # Copy all behaviors from existing template
                for behavior in existing_behaviors:
                    db.add_template_behavior(
                        template_id=template_id,
                        behavior_type=behavior['behavior_type'],
                        parameters=behavior.get('parameters', {}),
                        action=behavior.get('action', 'allow'),
                        description=f"From template '{existing_template['name']}': {behavior.get('description', '')}"
                    )
                    behaviors_added += 1

                logger.info(f"Copied {behaviors_added} behaviors from existing template")

        # Get ports data from the correct structure
        ports_data = learned_behavior.get('ports', {})

        # Add allowed outbound ports behavior
        outbound_ports = ports_data.get('outbound_destination_ports', [])
        if outbound_ports:
            ports = outbound_ports[:20]  # Limit to 20 ports
            if ports:
                db.add_template_behavior(
                    template_id=template_id,
                    behavior_type='allowed_ports',
                    parameters={'ports': ports, 'direction': 'outbound'},
                    action='allow',
                    description=f"Learned outbound ports: {', '.join(map(str, ports[:5]))}..."
                )
                behaviors_added += 1

        # Add server ports behavior (inbound)
        inbound_ports = ports_data.get('inbound_source_ports', [])
        if inbound_ports:
            ports = inbound_ports[:10]  # Limit to 10 ports
            if ports:
                db.add_template_behavior(
                    template_id=template_id,
                    behavior_type='allowed_ports',
                    parameters={'ports': ports, 'direction': 'inbound'},
                    action='allow',
                    description=f"Learned server ports: {', '.join(map(str, ports[:5]))}..."
                )
                behaviors_added += 1

        # Add protocols behavior
        protocols = ports_data.get('protocols', [])
        if protocols:
            # Convert to strings for description (protocols may be integers)
            protocol_strs = [str(p) for p in protocols]
            db.add_template_behavior(
                template_id=template_id,
                behavior_type='allowed_protocols',
                parameters={'protocols': protocols},
                action='allow',
                description=f"Learned protocols: {', '.join(protocol_strs)}"
            )
            behaviors_added += 1

        # Add traffic pattern behavior based on characteristics
        characteristics = learned_behavior.get('characteristics', {})
        traffic_pattern = None
        params = {}

        if characteristics.get('is_high_bandwidth'):
            traffic_pattern = 'streaming'
            params = {'high_bandwidth': True, 'streaming': True}
        elif characteristics.get('is_server'):
            traffic_pattern = 'server'
            params = {'high_connection_rate': True}
        elif characteristics.get('is_low_frequency'):
            traffic_pattern = 'periodic'
            params = {'periodic': True, 'low_frequency': True}

        if traffic_pattern and params:
            db.add_template_behavior(
                template_id=template_id,
                behavior_type='traffic_pattern',
                parameters=params,
                action='allow',
                description=f"Learned traffic pattern: {traffic_pattern}"
            )
            behaviors_added += 1

        # Optionally assign the template to the source device
        if data.get('assign_to_device', True):
            device_id = device.get('id')
            if device_id:
                db.assign_device_template(
                    device_id=device_id,
                    template_id=template_id,
                    confidence=0.8,
                    method='learned'
                )

        return jsonify({
            'success': True,
            'template_id': template_id,
            'template_name': template_name,
            'behaviors_added': behaviors_added,
            'message': f'Template "{template_name}" created with {behaviors_added} behavior rules'
        })

    except Exception as e:
        logger.error(f"Error creating template from device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Internal API for MCP Server ====================
# These endpoints allow localhost access without authentication
# for the MCP HTTP API server to call

@app.route('/api/internal/devices/<path:ip_address>/template', methods=['PUT'])
@local_or_login_required
def api_internal_assign_device_template(ip_address):
    """
    Internal API: Assign a template to a device
    Allows localhost access for MCP server
    """
    try:
        data = request.get_json()
        template_id = data.get('template_id')
        confidence = data.get('confidence', 1.0)
        method = data.get('method', 'mcp')

        if template_id is None:
            return jsonify({'success': False, 'error': 'template_id is required'}), 400

        # Get device by IP
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        success = db.assign_device_template(
            device_id=device['id'],
            template_id=template_id if template_id != 0 else None,
            confidence=confidence,
            method=method
        )

        if success:
            return jsonify({
                'success': True,
                'message': f'Template {template_id} assigned to device {ip_address}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to assign template'}), 500

    except Exception as e:
        logger.error(f"Error assigning template to {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/device-templates/from-device', methods=['POST'])
@local_or_login_required
def api_internal_create_template_from_device():
    """
    Internal API: Create a template from a device's learned behavior
    Allows localhost access for MCP server
    """
    try:
        data = request.get_json()

        ip_address = data.get('ip_address')
        template_name = data.get('template_name')
        category = data.get('category', 'other')
        description = data.get('description')

        if not ip_address or not template_name:
            return jsonify({
                'success': False,
                'error': 'ip_address and template_name are required'
            }), 400

        # Get device and its learned behavior
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        learned_behavior = device.get('learned_behavior', {})
        if not learned_behavior:
            return jsonify({
                'success': False,
                'error': 'No learned behavior available for this device'
            }), 400

        # Check if enough data - look in traffic_summary for packet count
        traffic_summary = learned_behavior.get('traffic_summary', {})
        packet_count = traffic_summary.get('total_packets', 0)
        if packet_count < 50:
            return jsonify({
                'success': False,
                'error': f'Insufficient data ({packet_count} packets). Need at least 50 packets.'
            }), 400

        # Create the template
        if not description:
            description = f"Auto-generated from device {ip_address}"
            if device.get('hostname'):
                description += f" ({device['hostname']})"

        # Check if an active template with this name already exists
        existing_templates = db.get_device_templates(include_inactive=False)
        if any(t.get('name', '').lower() == template_name.lower() for t in existing_templates):
            return jsonify({
                'success': False,
                'error': f'Template with name "{template_name}" already exists'
            }), 400

        # Create template (will reactivate if an inactive one with same name exists)
        template_id = db.create_device_template(
            name=template_name,
            description=description,
            category=category,
            created_by='mcp'
        )

        if not template_id:
            return jsonify({'success': False, 'error': 'Failed to create template'}), 500

        # Add behaviors based on learned data
        behaviors_added = 0
        ports_data = learned_behavior.get('ports', {})

        # Add outbound port behaviors
        dst_ports = ports_data.get('outbound_destination_ports', [])
        if dst_ports:
            db.add_template_behavior(
                template_id=template_id,
                behavior_type='allowed_ports',
                parameters={'ports': dst_ports[:20], 'direction': 'outbound'},
                action='allow',
                description=f"Learned outbound destination ports"
            )
            behaviors_added += 1

        # Add inbound port behaviors (server ports)
        src_ports = ports_data.get('inbound_source_ports', [])
        if src_ports:
            db.add_template_behavior(
                template_id=template_id,
                behavior_type='allowed_ports',
                parameters={'ports': src_ports[:20], 'direction': 'inbound'},
                action='allow',
                description=f"Learned inbound server ports"
            )
            behaviors_added += 1

        # Add protocol behaviors (convert protocol numbers to names)
        protocol_numbers = ports_data.get('protocols', [])
        if protocol_numbers:
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol_names = [protocol_map.get(p, str(p)) for p in protocol_numbers]
            db.add_template_behavior(
                template_id=template_id,
                behavior_type='allowed_protocols',
                parameters={'protocols': protocol_names},
                action='allow',
                description=f"Learned protocols: {', '.join(protocol_names)}"
            )
            behaviors_added += 1

        # Add any suggested behaviors from the learning system
        suggested = learned_behavior.get('suggested_behaviors', [])
        for behavior in suggested[:5]:  # Limit to 5 suggested behaviors
            db.add_template_behavior(
                template_id=template_id,
                behavior_type=behavior.get('behavior_type', 'custom'),
                parameters=behavior.get('parameters', {}),
                action=behavior.get('action', 'allow'),
                description=behavior.get('description', 'Suggested behavior')
            )
            behaviors_added += 1

        # Optionally assign the template to the source device
        if data.get('assign_to_device', True):
            db.assign_device_template(
                device_id=device['id'],
                template_id=template_id,
                confidence=0.8,
                method='learned'
            )

        return jsonify({
            'success': True,
            'template_id': template_id,
            'template_name': template_name,
            'behaviors_added': behaviors_added,
            'message': f'Template "{template_name}" created with {behaviors_added} behavior rules'
        })

    except Exception as e:
        logger.error(f"Error creating template from device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/devices/<path:ip_address>/save-learned-behavior', methods=['POST'])
@local_or_login_required
def api_internal_save_device_learned_behavior(ip_address):
    """
    Internal API: Save learned behavior to the database.
    Allows localhost access for MCP server.
    """
    try:
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        # Get current learned behavior from the device record
        learned_behavior = device.get('learned_behavior', {})

        if not learned_behavior:
            return jsonify({
                'success': False,
                'error': 'No learned behavior available. Device needs active monitoring to collect data.'
            }), 400

        # The learned behavior is already stored in the database via device_discovery
        # This endpoint confirms it's saved and returns the current state
        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'message': 'Learned behavior is stored in database',
            'learned_behavior': learned_behavior
        })

    except Exception as e:
        logger.error(f"Error saving learned behavior for {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/service-providers', methods=['POST'])
@local_or_login_required
def api_internal_create_service_provider():
    """
    Internal API: Create a service provider
    Allows localhost access for MCP server
    """
    try:
        data = request.get_json()

        name = data.get('name')
        category = data.get('category')
        ip_ranges = data.get('ip_ranges', [])
        domains = data.get('domains', [])
        description = data.get('description', '')

        if not name or not category:
            return jsonify({
                'success': False,
                'error': 'name and category are required'
            }), 400

        provider_id = db.create_service_provider(
            name=name,
            category=category,
            ip_ranges=ip_ranges,
            domains=domains,
            description=description,
            created_by='mcp'
        )

        if provider_id:
            return jsonify({
                'success': True,
                'provider_id': provider_id,
                'message': f'Service provider "{name}" created'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to create provider'}), 500

    except Exception as e:
        logger.error(f"Error creating service provider: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== TLS Analysis Internal API ====================

@app.route('/api/internal/tls-metadata')
@local_or_login_required
def api_internal_tls_metadata():
    """
    Internal API: Get TLS metadata from detector
    Allows localhost access for MCP server
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        ip_filter = request.args.get('ip_filter')
        sni_filter = request.args.get('sni_filter')

        # Get TLS metadata from detector if available
        metadata = []
        if hasattr(app, 'monitor') and app.monitor and hasattr(app.monitor, 'detector'):
            detector = app.monitor.detector
            if hasattr(detector, 'get_tls_metadata'):
                metadata = detector.get_tls_metadata(limit=limit)

                # Apply filters
                if ip_filter:
                    metadata = [m for m in metadata if ip_filter in m.get('src_ip', '') or ip_filter in m.get('dst_ip', '')]
                if sni_filter:
                    metadata = [m for m in metadata if sni_filter.lower() in (m.get('sni') or '').lower()]

        return jsonify({
            'success': True,
            'metadata': metadata,
            'count': len(metadata)
        })

    except Exception as e:
        logger.error(f"Error getting TLS metadata: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/tls-stats')
@local_or_login_required
def api_internal_tls_stats():
    """
    Internal API: Get TLS analyzer statistics
    Allows localhost access for MCP server
    """
    try:
        stats = {}
        if hasattr(app, 'monitor') and app.monitor and hasattr(app.monitor, 'detector'):
            detector = app.monitor.detector
            if hasattr(detector, 'get_tls_stats'):
                stats = detector.get_tls_stats()

        return jsonify({
            'success': True,
            'stats': stats
        })

    except Exception as e:
        logger.error(f"Error getting TLS stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/ja3-check/<ja3_hash>')
@local_or_login_required
def api_internal_ja3_check(ja3_hash):
    """
    Internal API: Check if JA3 fingerprint is malicious
    Allows localhost access for MCP server
    """
    try:
        is_malicious = False
        malware_family = None

        if hasattr(app, 'monitor') and app.monitor and hasattr(app.monitor, 'detector'):
            detector = app.monitor.detector
            if hasattr(detector, 'tls_analyzer') and detector.tls_analyzer:
                is_malicious, malware_family = detector.tls_analyzer.check_ja3(ja3_hash)

        return jsonify({
            'success': True,
            'ja3_hash': ja3_hash,
            'is_malicious': is_malicious,
            'malware_family': malware_family
        })

    except Exception as e:
        logger.error(f"Error checking JA3: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/ja3-blacklist', methods=['POST'])
@local_or_login_required
def api_internal_ja3_blacklist():
    """
    Internal API: Add JA3 fingerprint to blacklist
    Allows localhost access for MCP server
    """
    try:
        data = request.get_json()
        ja3_hash = data.get('ja3_hash')
        malware_family = data.get('malware_family')

        if not ja3_hash or not malware_family:
            return jsonify({'success': False, 'error': 'ja3_hash and malware_family required'}), 400

        if hasattr(app, 'monitor') and app.monitor and hasattr(app.monitor, 'detector'):
            detector = app.monitor.detector
            if hasattr(detector, 'tls_analyzer') and detector.tls_analyzer:
                detector.tls_analyzer.add_ja3_blacklist(ja3_hash, malware_family)
                return jsonify({
                    'success': True,
                    'ja3_hash': ja3_hash,
                    'malware_family': malware_family
                })

        return jsonify({'success': False, 'error': 'TLS analyzer not available'}), 503

    except Exception as e:
        logger.error(f"Error adding JA3 to blacklist: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== PCAP Export Internal API ====================

@app.route('/api/internal/pcap-captures')
@local_or_login_required
def api_internal_pcap_captures():
    """
    Internal API: List PCAP captures
    Allows localhost access for MCP server
    """
    try:
        captures = []
        if hasattr(app, 'pcap_exporter') and app.pcap_exporter:
            captures = app.pcap_exporter.list_captures()

        return jsonify({
            'success': True,
            'captures': captures,
            'count': len(captures)
        })

    except Exception as e:
        logger.error(f"Error listing PCAP captures: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/pcap-stats')
@local_or_login_required
def api_internal_pcap_stats():
    """
    Internal API: Get PCAP exporter statistics
    Allows localhost access for MCP server
    """
    try:
        stats = {}
        if hasattr(app, 'pcap_exporter') and app.pcap_exporter:
            stats = app.pcap_exporter.get_stats()

        return jsonify({
            'success': True,
            'stats': stats
        })

    except Exception as e:
        logger.error(f"Error getting PCAP stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/pcap-export-flow', methods=['POST'])
@local_or_login_required
def api_internal_pcap_export_flow():
    """
    Internal API: Export flow to PCAP
    Allows localhost access for MCP server
    """
    try:
        data = request.get_json()
        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip')
        dst_port = data.get('dst_port')

        if not src_ip or not dst_ip:
            return jsonify({'success': False, 'error': 'src_ip and dst_ip required'}), 400

        if hasattr(app, 'pcap_exporter') and app.pcap_exporter:
            filepath = app.pcap_exporter.export_flow(src_ip, dst_ip, dst_port=dst_port)
            if filepath:
                return jsonify({
                    'success': True,
                    'filepath': filepath
                })
            else:
                return jsonify({
                    'success': True,
                    'filepath': None,
                    'message': f'No packets found for flow {src_ip} -> {dst_ip}'
                }), 404

        return jsonify({'success': False, 'error': 'PCAP exporter not available'}), 503

    except Exception as e:
        logger.error(f"Error exporting flow PCAP: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/packet-buffer-summary')
@local_or_login_required
def api_internal_packet_buffer_summary():
    """
    Internal API: Get packet buffer summary
    Allows localhost access for MCP server
    """
    try:
        summary = {}
        if hasattr(app, 'pcap_exporter') and app.pcap_exporter:
            summary = app.pcap_exporter.get_buffer_summary()

        return jsonify({
            'success': True,
            'summary': summary
        })

    except Exception as e:
        logger.error(f"Error getting packet buffer summary: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Sensor PCAP API (NIS2 Compliance) ====================

@app.route('/api/pcap/sensors')
@login_required
def api_get_sensor_pcap_list():
    """
    Get list of PCAP files received from sensors (NIS2 forensic evidence).
    Supports pagination for better performance with large file counts.

    Query params:
        limit: Max files to return (default: 100)
        offset: Number of files to skip (default: 0)
    """
    try:
        pcap_dir = Path('/var/log/netmonitor/pcap/sensors')
        if not pcap_dir.exists():
            return jsonify({
                'success': True,
                'captures': [],
                'count': 0,
                'total': 0
            })

        # Get pagination parameters
        limit = request.args.get('limit', default=100, type=int)
        offset = request.args.get('offset', default=0, type=int)
        limit = min(limit, 500)  # Cap at 500 to prevent excessive memory use

        # Quick optimization: collect files with mtime first, sort by that
        # This avoids full stat() calls when we only need the most recent files
        file_list = []
        for pcap_file in pcap_dir.glob('*.pcap'):
            stat = pcap_file.stat()
            file_list.append((pcap_file, stat.st_ctime, stat))

        # Sort by creation time (newest first) using the cached stat
        file_list.sort(key=lambda x: x[1], reverse=True)

        total = len(file_list)

        # Apply pagination
        paginated_files = file_list[offset:offset + limit]

        captures = []
        for pcap_file, _, stat in paginated_files:
            # Parse filename: sensor_alerttype_srcip_timestamp.pcap
            parts = pcap_file.stem.split('_')
            sensor_id = parts[0] if len(parts) > 0 else 'unknown'

            captures.append({
                'filename': pcap_file.name,
                'sensor_id': sensor_id,
                'size_bytes': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

        return jsonify({
            'success': True,
            'captures': captures,
            'count': len(captures),
            'total': total,
            'offset': offset,
            'limit': limit
        })

    except Exception as e:
        logger.error(f"Error listing sensor PCAP files: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pcap/sensors/<filename>')
@login_required
def api_download_sensor_pcap(filename):
    """
    Download a specific sensor PCAP file for analysis.
    """
    try:
        pcap_dir = Path('/var/log/netmonitor/pcap/sensors')
        pcap_path = pcap_dir / filename

        # Security: prevent path traversal
        if not pcap_path.resolve().is_relative_to(pcap_dir.resolve()):
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400

        if not pcap_path.exists():
            return jsonify({'success': False, 'error': 'File not found'}), 404

        return send_from_directory(
            pcap_dir,
            filename,
            as_attachment=True,
            mimetype='application/vnd.tcpdump.pcap'
        )

    except Exception as e:
        logger.error(f"Error downloading sensor PCAP: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pcap/sensors/<filename>', methods=['DELETE'])
@login_required
def api_delete_sensor_pcap(filename):
    """
    Delete a sensor PCAP file (admin only).
    """
    try:
        pcap_dir = Path('/var/log/netmonitor/pcap/sensors')
        pcap_path = pcap_dir / filename

        # Security: prevent path traversal
        if not pcap_path.resolve().is_relative_to(pcap_dir.resolve()):
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400

        if not pcap_path.exists():
            return jsonify({'success': False, 'error': 'File not found'}), 404

        pcap_path.unlink()
        logger.info(f"Deleted sensor PCAP: {filename}")

        return jsonify({
            'success': True,
            'message': f'Deleted {filename}'
        })

    except Exception as e:
        logger.error(f"Error deleting sensor PCAP: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/pcap')
@login_required
def api_get_alert_pcap(alert_id):
    """
    Get PCAP file associated with an alert (if available).
    Checks both local SOC captures and sensor uploads.
    """
    try:
        # Get alert from database
        alert = db.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'success': False, 'error': 'Alert not found'}), 404

        # Check if alert has PCAP reference in metadata
        metadata = alert.get('metadata', {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}

        pcap_file = metadata.get('pcap_file')
        if not pcap_file:
            return jsonify({
                'success': True,
                'has_pcap': False,
                'message': 'No PCAP available for this alert'
            })

        # Determine PCAP location based on source
        pcap_source = metadata.get('pcap_source', 'local')
        if pcap_source == 'sensor':
            pcap_dir = Path('/var/log/netmonitor/pcap/sensors')
        else:
            pcap_dir = Path('/var/log/netmonitor/pcap')

        pcap_path = pcap_dir / pcap_file

        if not pcap_path.exists():
            return jsonify({
                'success': True,
                'has_pcap': False,
                'message': f'PCAP file {pcap_file} no longer available (may have been cleaned up)'
            })

        return send_from_directory(
            pcap_dir,
            pcap_file,
            as_attachment=True,
            mimetype='application/vnd.tcpdump.pcap'
        )

    except Exception as e:
        logger.error(f"Error getting alert PCAP: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/pcap-captures/<filename>', methods=['DELETE'])
@local_or_login_required
def api_internal_delete_pcap_capture(filename):
    """
    Internal API: Delete a PCAP capture
    Allows localhost access for MCP server
    """
    try:
        if hasattr(app, 'pcap_exporter') and app.pcap_exporter:
            success = app.pcap_exporter.delete_capture(filename)
            if success:
                return jsonify({
                    'success': True,
                    'message': f'Deleted {filename}'
                })
            else:
                return jsonify({'success': False, 'error': 'File not found'}), 404

        return jsonify({'success': False, 'error': 'PCAP exporter not available'}), 503

    except Exception as e:
        logger.error(f"Error deleting PCAP capture: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Device Templates API ====================

@app.route('/api/device-templates')
@login_required
def api_get_device_templates():
    """Get all device templates"""
    try:
        category = request.args.get('category')
        include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'

        templates = db.get_device_templates(
            category=category,
            include_inactive=include_inactive
        )

        return jsonify({
            'success': True,
            'templates': templates,
            'total': len(templates)
        })
    except Exception as e:
        logger.error(f"Error getting device templates: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates/<int:template_id>')
@login_required
def api_get_device_template(template_id):
    """Get a specific device template with its behaviors"""
    try:
        template = db.get_device_template_by_id(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        return jsonify({
            'success': True,
            'template': template
        })
    except Exception as e:
        logger.error(f"Error getting template {template_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates', methods=['POST'])
@login_required
def api_create_device_template():
    """Create a new device template"""
    try:
        data = request.get_json()

        name = data.get('name')
        if not name:
            return jsonify({'success': False, 'error': 'name is required'}), 400

        template_id = db.create_device_template(
            name=name,
            description=data.get('description'),
            icon=data.get('icon', 'device'),
            category=data.get('category', 'other'),
            created_by=current_user.username if current_user.is_authenticated else 'api'
        )

        if template_id:
            # Add behaviors if provided
            behaviors = data.get('behaviors', [])
            for behavior in behaviors:
                db.add_template_behavior(
                    template_id=template_id,
                    behavior_type=behavior.get('behavior_type'),
                    parameters=behavior.get('parameters', {}),
                    action=behavior.get('action', 'allow'),
                    description=behavior.get('description')
                )

            return jsonify({
                'success': True,
                'template_id': template_id,
                'message': 'Template created successfully'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to create template'}), 500

    except Exception as e:
        logger.error(f"Error creating device template: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates/<int:template_id>/clone', methods=['POST'])
@login_required
def api_clone_device_template(template_id):
    """Clone an existing device template (including built-in templates)"""
    try:
        # Get the source template
        source = db.get_device_template_by_id(template_id)
        if not source:
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        data = request.get_json() or {}

        # Create new template with optional custom name
        new_name = data.get('name', f"{source['name']} (Copy)")
        new_description = data.get('description', source.get('description', ''))

        new_template_id = db.create_device_template(
            name=new_name,
            description=new_description,
            icon=source.get('icon', 'device'),
            category=source.get('category', 'other'),
            created_by=current_user.username if current_user.is_authenticated else 'api'
        )

        if new_template_id:
            # Copy all behaviors from source template
            source_behaviors = db.get_template_behaviors(template_id)
            for behavior in source_behaviors:
                db.add_template_behavior(
                    template_id=new_template_id,
                    behavior_type=behavior.get('behavior_type'),
                    parameters=behavior.get('parameters', {}),
                    action=behavior.get('action', 'allow'),
                    description=behavior.get('description')
                )

            return jsonify({
                'success': True,
                'template_id': new_template_id,
                'message': f'Template cloned successfully as "{new_name}"'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to clone template'}), 500

    except Exception as e:
        logger.error(f"Error cloning device template: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates/<int:template_id>', methods=['PUT'])
@login_required
def api_update_device_template(template_id):
    """Update an existing device template"""
    try:
        data = request.get_json()

        # Check if template exists and is not builtin
        template = db.get_device_template_by_id(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        if template.get('is_builtin'):
            return jsonify({'success': False, 'error': 'Cannot modify builtin templates'}), 403

        success = db.update_device_template(
            template_id=template_id,
            name=data.get('name'),
            description=data.get('description'),
            icon=data.get('icon'),
            category=data.get('category'),
            is_active=data.get('is_active')
        )

        if success:
            return jsonify({'success': True, 'message': 'Template updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to update template'}), 500

    except Exception as e:
        logger.error(f"Error updating template {template_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates/<int:template_id>', methods=['DELETE'])
@login_required
def api_delete_device_template(template_id):
    """Delete a device template"""
    try:
        template = db.get_device_template_by_id(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        if template.get('is_builtin'):
            return jsonify({'success': False, 'error': 'Cannot delete builtin templates'}), 403

        success = db.delete_device_template(template_id)
        if success:
            return jsonify({'success': True, 'message': 'Template deleted'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete template'}), 500

    except Exception as e:
        logger.error(f"Error deleting template {template_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates/<int:template_id>/behaviors', methods=['POST'])
@login_required
def api_add_template_behavior(template_id):
    """Add a behavior rule to a template"""
    try:
        data = request.get_json()

        template = db.get_device_template_by_id(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        behavior_type = data.get('behavior_type')
        if not behavior_type:
            return jsonify({'success': False, 'error': 'behavior_type is required'}), 400

        behavior_id = db.add_template_behavior(
            template_id=template_id,
            behavior_type=behavior_type,
            parameters=data.get('parameters', {}),
            action=data.get('action', 'allow'),
            description=data.get('description')
        )

        if behavior_id:
            return jsonify({
                'success': True,
                'behavior_id': behavior_id,
                'message': 'Behavior added successfully'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to add behavior'}), 500

    except Exception as e:
        logger.error(f"Error adding behavior to template {template_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device-templates/behaviors/<int:behavior_id>', methods=['DELETE'])
@login_required
def api_delete_template_behavior(behavior_id):
    """Delete a behavior rule from a template"""
    try:
        success = db.delete_template_behavior(behavior_id)
        if success:
            return jsonify({'success': True, 'message': 'Behavior deleted'})
        else:
            return jsonify({'success': False, 'error': 'Behavior not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting behavior {behavior_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Service Providers API ====================

@app.route('/api/service-providers')
@login_required
def api_get_service_providers():
    """Get all service providers"""
    try:
        category = request.args.get('category')
        include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'

        providers = db.get_service_providers(
            category=category,
            include_inactive=include_inactive
        )

        return jsonify({
            'success': True,
            'providers': providers,
            'total': len(providers)
        })
    except Exception as e:
        logger.error(f"Error getting service providers: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/service-providers/<int:provider_id>')
@login_required
def api_get_service_provider(provider_id):
    """Get a specific service provider"""
    try:
        provider = db.get_service_provider_by_id(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404

        return jsonify({
            'success': True,
            'provider': provider
        })
    except Exception as e:
        logger.error(f"Error getting provider {provider_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/service-providers', methods=['POST'])
@login_required
def api_create_service_provider():
    """Create a new service provider"""
    try:
        data = request.get_json()

        name = data.get('name')
        category = data.get('category')

        if not name or not category:
            return jsonify({'success': False, 'error': 'name and category are required'}), 400

        provider_id = db.create_service_provider(
            name=name,
            category=category,
            description=data.get('description'),
            ip_ranges=data.get('ip_ranges', []),
            domains=data.get('domains', []),
            created_by=current_user.username if current_user.is_authenticated else 'api'
        )

        if provider_id:
            return jsonify({
                'success': True,
                'provider_id': provider_id,
                'message': 'Provider created successfully'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to create provider'}), 500

    except Exception as e:
        logger.error(f"Error creating service provider: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/service-providers/<int:provider_id>', methods=['PUT'])
@login_required
def api_update_service_provider(provider_id):
    """Update a service provider"""
    try:
        data = request.get_json()

        provider = db.get_service_provider_by_id(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404

        if provider.get('is_builtin'):
            return jsonify({'success': False, 'error': 'Cannot modify builtin providers'}), 403

        success = db.update_service_provider(
            provider_id=provider_id,
            name=data.get('name'),
            category=data.get('category'),
            description=data.get('description'),
            ip_ranges=data.get('ip_ranges'),
            domains=data.get('domains'),
            is_active=data.get('is_active')
        )

        if success:
            return jsonify({'success': True, 'message': 'Provider updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to update provider'}), 500

    except Exception as e:
        logger.error(f"Error updating provider {provider_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/service-providers/<int:provider_id>', methods=['DELETE'])
@login_required
def api_delete_service_provider(provider_id):
    """Delete a service provider"""
    try:
        provider = db.get_service_provider_by_id(provider_id)
        if not provider:
            return jsonify({'success': False, 'error': 'Provider not found'}), 404

        if provider.get('is_builtin'):
            return jsonify({'success': False, 'error': 'Cannot delete builtin providers'}), 403

        success = db.delete_service_provider(provider_id)
        if success:
            return jsonify({'success': True, 'message': 'Provider deleted'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete provider'}), 500

    except Exception as e:
        logger.error(f"Error deleting provider {provider_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/service-providers/check-ip')
@login_required
def api_check_ip_in_providers():
    """Check if an IP belongs to any service provider"""
    try:
        ip_address = request.args.get('ip')
        if not ip_address:
            return jsonify({'success': False, 'error': 'ip parameter is required'}), 400

        result = db.check_ip_in_service_providers(ip_address)

        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'is_known_provider': result is not None,
            'provider': result
        })
    except Exception as e:
        logger.error(f"Error checking IP {request.args.get('ip')}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Alert Suppression API ====================

@app.route('/api/suppression/stats')
@login_required
def api_get_suppression_stats():
    """Get alert suppression statistics"""
    try:
        # Try to get live stats from behavior matcher if available
        # For now, return database-derived stats
        from behavior_matcher import BehaviorMatcher

        # Count devices with templates (potential suppressions)
        devices = db.get_devices()
        devices_with_templates = len([d for d in devices if d.get('template_id')])

        # Get recent suppressed alerts from logs (simplified)
        stats = {
            'devices_monitored': len(devices),
            'devices_with_templates': devices_with_templates,
            'templates_active': len(db.get_device_templates()),
            'service_providers': len(db.get_service_providers()),
            'note': 'Real-time suppression stats available via MCP API during active monitoring'
        }

        return jsonify({
            'success': True,
            'stats': stats
        })

    except ImportError:
        return jsonify({
            'success': True,
            'stats': {
                'note': 'BehaviorMatcher not available',
                'devices_monitored': len(db.get_devices()),
                'templates_active': len(db.get_device_templates())
            }
        })
    except Exception as e:
        logger.error(f"Error getting suppression stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/suppression/test', methods=['POST'])
@login_required
def api_test_alert_suppression():
    """
    Test if a hypothetical alert would be suppressed.
    Useful for testing template configurations.
    """
    try:
        data = request.get_json()

        source_ip = data.get('source_ip')
        threat_type = data.get('threat_type')
        severity = data.get('severity', 'MEDIUM')

        if not source_ip or not threat_type:
            return jsonify({
                'success': False,
                'error': 'source_ip and threat_type are required'
            }), 400

        # Check if device has a template
        device = db.get_device_by_ip(source_ip)

        if not device:
            return jsonify({
                'success': True,
                'would_suppress': False,
                'reason': 'Device not found in database'
            })

        if not device.get('template_id'):
            return jsonify({
                'success': True,
                'would_suppress': False,
                'reason': 'Device has no template assigned'
            })

        # Get template and test suppression
        from behavior_matcher import BehaviorMatcher
        matcher = BehaviorMatcher(db_manager=db)

        test_threat = {
            'source_ip': source_ip,
            'destination_ip': data.get('destination_ip'),
            'type': threat_type,
            'severity': severity,
            'metadata': data.get('metadata', {})
        }

        would_suppress, reason = matcher.should_suppress_alert(test_threat)

        return jsonify({
            'success': True,
            'would_suppress': would_suppress,
            'reason': reason,
            'device': {
                'ip': source_ip,
                'template': device.get('template_name'),
                'template_id': device.get('template_id')
            }
        })

    except ImportError:
        return jsonify({
            'success': False,
            'error': 'BehaviorMatcher module not available'
        }), 500
    except Exception as e:
        logger.error(f"Error testing alert suppression: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Device Classification Stats API ====================

@app.route('/api/device-classification/stats')
@login_required
def api_get_device_classification_stats():
    """Get overall device classification statistics"""
    try:
        devices = db.get_devices()
        templates = db.get_device_templates()
        providers = db.get_service_providers()

        # Calculate statistics
        total_devices = len(devices)
        classified_devices = len([d for d in devices if d.get('template_id')])
        manual_classifications = len([d for d in devices if d.get('classification_method') == 'manual'])
        auto_classifications = len([d for d in devices if d.get('classification_method') in ('auto', 'learned')])

        # Devices by template (handle None values)
        by_template = {}
        for device in devices:
            template_name = device.get('template_name') or 'Unclassified'
            by_template[template_name] = by_template.get(template_name, 0) + 1

        # Devices by vendor (handle None values)
        by_vendor = {}
        for device in devices:
            vendor = device.get('vendor') or 'Unknown'
            by_vendor[vendor] = by_vendor.get(vendor, 0) + 1

        # Templates by category (handle None values)
        templates_by_category = {}
        for template in templates:
            cat = template.get('category') or 'other'
            templates_by_category[cat] = templates_by_category.get(cat, 0) + 1

        # Service providers by category (handle None values)
        providers_by_category = {}
        for provider in providers:
            cat = provider.get('category') or 'other'
            providers_by_category[cat] = providers_by_category.get(cat, 0) + 1

        return jsonify({
            'success': True,
            'stats': {
                'devices': {
                    'total': total_devices,
                    'classified': classified_devices,
                    'unclassified': total_devices - classified_devices,
                    'classification_rate': round(classified_devices / total_devices * 100, 1) if total_devices > 0 else 0,
                    'manual_classifications': manual_classifications,
                    'auto_classifications': auto_classifications,
                    'by_template': by_template,
                    'by_vendor': dict(sorted(by_vendor.items(), key=lambda x: x[1], reverse=True)[:10])
                },
                'templates': {
                    'total': len(templates),
                    'builtin': len([t for t in templates if t.get('is_builtin')]),
                    'custom': len([t for t in templates if not t.get('is_builtin')]),
                    'by_category': templates_by_category
                },
                'service_providers': {
                    'total': len(providers),
                    'builtin': len([p for p in providers if p.get('is_builtin')]),
                    'custom': len([p for p in providers if not p.get('is_builtin')]),
                    'by_category': providers_by_category
                }
            }
        })

    except Exception as e:
        error_trace = traceback.format_exc()
        logger.error(f"Error getting classification stats: {e}\n{error_trace}")
        return jsonify({'success': False, 'error': str(e), 'trace': error_trace}), 500


# ==================== ML Classification API ====================

# Global ML classifier manager (initialized lazily)
_ml_classifier_manager = None


def get_ml_classifier():
    """Get or create ML classifier manager."""
    global _ml_classifier_manager
    if _ml_classifier_manager is None:
        try:
            from ml_classifier import MLClassifierManager, SKLEARN_AVAILABLE
            if SKLEARN_AVAILABLE:
                # Pass config for ML settings
                ml_config = config if config else {}
                _ml_classifier_manager = MLClassifierManager(db_manager=db, config=ml_config)
                logger.info("ML Classifier Manager initialized")

                # Auto-start background training if enabled in config
                auto_train = ml_config.get('ml', {}).get('auto_train', True)
                if auto_train:
                    _ml_classifier_manager.start_background_training()
                    logger.info("ML background training auto-started")
            else:
                logger.warning("scikit-learn not available, ML classification disabled")
        except ImportError as e:
            logger.warning(f"ML Classifier not available: {e}")
    return _ml_classifier_manager


@app.route('/api/ml/status')
@login_required
def api_ml_status():
    """Get ML classifier status and statistics."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({
            'success': True,
            'available': False,
            'message': 'ML classification not available (scikit-learn not installed)'
        })

    return jsonify({
        'success': True,
        'available': True,
        'status': ml.get_status()
    })


@app.route('/api/ml/train', methods=['POST'])
@login_required
def api_ml_train():
    """Train ML classification models."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({
            'success': False,
            'error': 'ML classification not available'
        }), 400

    try:
        result = ml.train_models()
        return jsonify({
            'success': result.get('success', False),
            'result': result
        })
    except Exception as e:
        error_trace = traceback.format_exc()
        logger.error(f"Error training ML models: {e}\n{error_trace}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml/classify/<path:ip_address>')
@login_required
def api_ml_classify_device(ip_address):
    """Classify a single device using ML."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({
            'success': False,
            'error': 'ML classification not available'
        }), 400

    try:
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        result = ml.classify_device(device)
        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'result': result
        })
    except Exception as e:
        error_trace = traceback.format_exc()
        logger.error(f"Error classifying device {ip_address}: {e}\n{error_trace}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Global state for background ML classification
_ml_classification_task = {
    'running': False,
    'result': None,
    'error': None,
    'started_at': None
}

def _run_ml_classification_background(ml, update_db):
    """Run ML classification in background thread."""
    global _ml_classification_task
    try:
        _ml_classification_task['running'] = True
        _ml_classification_task['error'] = None
        _ml_classification_task['started_at'] = datetime.now().isoformat()

        result = ml.classifier.classify_all_devices(update_db=update_db)

        _ml_classification_task['result'] = result
        _ml_classification_task['running'] = False
        logger.info(f"Background ML classification complete: {result.get('classified', 0)} classified")

    except Exception as e:
        logger.error(f"Background ML classification error: {e}")
        _ml_classification_task['error'] = str(e)
        _ml_classification_task['running'] = False


@app.route('/api/ml/classify-all', methods=['POST'])
@login_required
def api_ml_classify_all():
    """Classify all devices using ML (runs in background)."""
    global _ml_classification_task

    ml = get_ml_classifier()
    if not ml:
        return jsonify({
            'success': False,
            'error': 'ML classification not available'
        }), 400

    # Check if already running
    if _ml_classification_task['running']:
        return jsonify({
            'success': True,
            'status': 'already_running',
            'message': 'ML classification is already running',
            'started_at': _ml_classification_task['started_at']
        })

    try:
        data = request.get_json(silent=True) or {}
        update_db = data.get('update_db', False)

        # Start classification in background thread
        import threading
        thread = threading.Thread(
            target=_run_ml_classification_background,
            args=(ml, update_db),
            daemon=True
        )
        thread.start()

        return jsonify({
            'success': True,
            'status': 'started',
            'message': 'ML classification started in background'
        })

    except Exception as e:
        error_trace = traceback.format_exc()
        logger.error(f"Error starting ML classification: {e}\n{error_trace}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml/classify-all/status')
@login_required
def api_ml_classify_all_status():
    """Get status of background ML classification."""
    global _ml_classification_task

    if _ml_classification_task['running']:
        return jsonify({
            'success': True,
            'status': 'running',
            'started_at': _ml_classification_task['started_at']
        })
    elif _ml_classification_task['error']:
        return jsonify({
            'success': False,
            'status': 'error',
            'error': _ml_classification_task['error']
        })
    elif _ml_classification_task['result']:
        return jsonify({
            'success': True,
            'status': 'completed',
            'result': _ml_classification_task['result']
        })
    else:
        return jsonify({
            'success': True,
            'status': 'idle',
            'message': 'No classification running'
        })


@app.route('/api/ml/start-background-training', methods=['POST'])
@login_required
def api_ml_start_background_training():
    """Start background ML training thread."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({
            'success': False,
            'error': 'ML classification not available'
        }), 400

    try:
        ml.start_background_training()
        return jsonify({
            'success': True,
            'message': 'Background training started'
        })
    except Exception as e:
        logger.error(f"Error starting background training: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Internal ML endpoints (localhost access for MCP/CLI)
@app.route('/api/internal/ml/status')
@local_or_login_required
def api_internal_ml_status():
    """Internal API: Get ML status (localhost access)."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({
            'success': True,
            'available': False,
            'message': 'ML classification not available (scikit-learn not installed)'
        })
    return jsonify({
        'success': True,
        'available': True,
        'status': ml.get_status()
    })


@app.route('/api/internal/ml/train', methods=['POST'])
@local_or_login_required
def api_internal_ml_train():
    """Internal API: Train ML models (localhost access)."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({'success': False, 'error': 'ML classification not available'}), 400
    try:
        result = ml.train_models()
        return jsonify({'success': result.get('success', False), 'result': result})
    except Exception as e:
        logger.error(f"Error training ML models: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/ml/classify/<path:ip_address>')
@local_or_login_required
def api_internal_ml_classify_device(ip_address):
    """Internal API: Classify a device (localhost access)."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({'success': False, 'error': 'ML classification not available'}), 400
    try:
        device = db.get_device_by_ip(ip_address)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        result = ml.classify_device(device)
        return jsonify({'success': True, 'ip_address': ip_address, 'result': result})
    except Exception as e:
        logger.error(f"Error classifying device {ip_address}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/ml/classify-all', methods=['POST'])
@local_or_login_required
def api_internal_ml_classify_all():
    """Internal API: Classify all devices (localhost access)."""
    ml = get_ml_classifier()
    if not ml:
        return jsonify({'success': False, 'error': 'ML classification not available'}), 400
    try:
        data = request.get_json(silent=True) or {}
        update_db = data.get('update_db', False)
        result = ml.classifier.classify_all_devices(update_db=update_db)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        logger.error(f"Error classifying all devices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'status': 'connected', 'timestamp': datetime.now().isoformat()})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('request_update')
def handle_request_update():
    """Handle client request for data update"""
    try:
        data = db.get_dashboard_data()
        emit('dashboard_update', data)
    except Exception as e:
        logger.error(f"Error sending update: {e}")
        emit('error', {'message': str(e)})


# ==================== Server Control ====================

class DashboardServer:
    """Dashboard server wrapper"""

    def __init__(self, config_file='config.yaml', host='0.0.0.0', port=8080):
        """Initialize dashboard server"""
        self.config_file = config_file
        self.host = host
        self.port = port
        self.thread = None
        self.running = False

        # Initialize
        init_dashboard(config_file)

    def start(self):
        """Start dashboard server in background thread"""
        if self.running:
            logger.warning("Dashboard server already running")
            return

        self.running = True

        def run_server():
            logger.info(f"Starting dashboard server on {self.host}:{self.port}")
            # Use eventlet's wsgi server instead of Flask's development server
            socketio.run(
                app,
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                log_output=False  # Disable werkzeug logs, we have our own
            )

        self.thread = threading.Thread(target=run_server, daemon=True)
        self.thread.start()

        # Give server time to start
        eventlet.sleep(0.5)

        logger.info(f"Dashboard server started: http://{self.host}:{self.port}")

    def stop(self):
        """Stop dashboard server"""
        self.running = False
        logger.info("Dashboard server stopped")

    def broadcast_alert(self, alert):
        """Broadcast new alert to all connected clients"""
        try:
            # Note: broadcast=True removed - socketio.emit() broadcasts by default in v5.x+
            socketio.emit('new_alert', alert)
        except Exception as e:
            logger.error(f"Error broadcasting alert: {e}")

    def broadcast_metrics(self, metrics):
        """Broadcast metrics update to all connected clients"""
        try:
            # Note: broadcast=True removed - socketio.emit() broadcasts by default in v5.x+
            socketio.emit('metrics_update', metrics)
        except Exception as e:
            logger.error(f"Error broadcasting metrics: {e}")


def main():
    """Standalone dashboard server"""
    import argparse

    parser = argparse.ArgumentParser(description='Network Monitor Web Dashboard')
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to bind to')

    args = parser.parse_args()

    # Initialize
    init_dashboard(args.config)

    # Start server
    print(f"Starting Network Monitor Dashboard on http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop")

    try:
        socketio.run(app, host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\nStopping dashboard server...")


if __name__ == '__main__':
    main()
