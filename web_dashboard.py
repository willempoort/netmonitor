#!/usr/bin/env python3
"""
Web Dashboard Server
Real-time security monitoring dashboard
"""

import os
import sys
import logging
import threading
from pathlib import Path
from datetime import datetime

# Import eventlet first and monkey patch
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, jsonify, request, session, g, redirect, url_for
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
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 60 minutes (increased from 30)
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
        db = DatabaseManager(
            host=pg_config.get('host', 'localhost'),
            port=pg_config.get('port', 5432),
            database=pg_config.get('database', 'netmonitor'),
            user=pg_config.get('user', 'netmonitor'),
            password=pg_config.get('password', 'netmonitor'),
            min_connections=pg_config.get('min_connections', 2),
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

            # No valid authentication
            logger.warning(f"Unauthorized API access attempt from {request.remote_addr}")
            return jsonify({
                'success': False,
                'error': 'Authentication required (sensor token or web login)'
            }), 401

        return decorated_function
    return decorator


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
            login_user(user, remember=True)  # Remember user to keep session alive
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
            login_user(user, remember=True)  # Remember user to keep session alive
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

@app.route('/api/status')
def api_status():
    """API status endpoint (public)"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

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
        from geoip_helper import get_country_for_ips

        # Collect all unique IPs
        all_ips = set()
        for alert in details.get('alerts', []):
            if alert.get('source_ip'):
                all_ips.add(alert['source_ip'])
            if alert.get('destination_ip'):
                all_ips.add(alert['destination_ip'])

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

@app.route('/api/sensors/<sensor_id>/alerts', methods=['POST'])
def api_submit_sensor_alerts(sensor_id):
    """Submit alerts from remote sensor (batch)"""
    try:
        data = request.get_json()

        # Expect array of alerts
        alerts = data.get('alerts', [])
        if not isinstance(alerts, list):
            return jsonify({'success': False, 'error': 'alerts must be an array'}), 400

        # Update heartbeat
        db.update_sensor_heartbeat(sensor_id)

        # Insert all alerts
        success_count = 0
        for alert in alerts:
            # Parse timestamp if provided
            timestamp = None
            if 'timestamp' in alert:
                try:
                    timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                except:
                    pass

            success = db.insert_alert_from_sensor(
                sensor_id=sensor_id,
                severity=alert.get('severity', 'INFO'),
                threat_type=alert.get('threat_type', 'UNKNOWN'),
                source_ip=alert.get('source_ip'),
                destination_ip=alert.get('destination_ip'),
                description=alert.get('description', ''),
                metadata=alert.get('metadata'),
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
                        'timestamp': alert.get('timestamp', datetime.now().isoformat())
                    })
                except:
                    pass  # Don't fail if broadcast fails

        return jsonify({
            'success': True,
            'received': len(alerts),
            'inserted': success_count
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
    """Add whitelist entry"""
    try:
        data = request.get_json()
        ip_cidr = data.get('ip_cidr')
        description = data.get('description', '')
        scope = data.get('scope', 'global')
        sensor_id = data.get('sensor_id')
        created_by = data.get('created_by', 'dashboard')

        if not ip_cidr:
            return jsonify({'success': False, 'error': 'ip_cidr required'}), 400

        entry_id = db.add_whitelist_entry(
            ip_cidr=ip_cidr,
            description=description,
            scope=scope,
            sensor_id=sensor_id,
            created_by=created_by
        )

        if entry_id:
            return jsonify({
                'success': True,
                'entry_id': entry_id,
                'message': f'Whitelist entry added: {ip_cidr}'
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
    """Check if IP is whitelisted"""
    try:
        sensor_id = request.args.get('sensor_id')
        is_whitelisted = db.check_ip_whitelisted(ip_address, sensor_id=sensor_id)
        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'is_whitelisted': is_whitelisted
        })
    except Exception as e:
        logger.error(f"Error checking whitelist: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== Configuration Management Endpoints ====================

@app.route('/api/config', methods=['GET'])
@require_sensor_token_or_login()
def api_get_config():
    """Get configuration for a sensor (merged defaults + global + sensor-specific)"""
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

        return jsonify({'success': True, 'config': config})
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/parameters', methods=['GET'])
@login_required
def api_get_config_parameters():
    """Get all configuration parameters with metadata"""
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
