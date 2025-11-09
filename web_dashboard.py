#!/usr/bin/env python3
"""
Web Dashboard Server
Real-time security monitoring dashboard
"""

import sys
import logging
import threading
from pathlib import Path
from datetime import datetime

# Import eventlet first and monkey patch
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Add current dir to path
sys.path.insert(0, str(Path(__file__).parent))

from config_loader import load_config
from database import DatabaseManager


# Initialize Flask app
app = Flask(__name__,
           template_folder='web/templates',
           static_folder='web/static')
app.config['SECRET_KEY'] = 'netmonitor-secret-key-change-in-production'
CORS(app)

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


def init_dashboard(config_file='config.yaml'):
    """Initialize dashboard components"""
    global db, config, logger

    # Load config
    config = load_config(config_file)

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('NetMonitor.WebDashboard')

    # Initialize database
    db_path = config.get('dashboard', {}).get('database_path', '/var/lib/netmonitor/netmonitor.db')
    db = DatabaseManager(db_path=db_path)

    logger.info("Web Dashboard geïnitialiseerd")


# ==================== REST API Endpoints ====================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    """API status endpoint"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/dashboard')
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
            socketio.emit('new_alert', alert, broadcast=True)
        except Exception as e:
            logger.error(f"Error broadcasting alert: {e}")

    def broadcast_metrics(self, metrics):
        """Broadcast metrics update to all connected clients"""
        try:
            socketio.emit('metrics_update', metrics, broadcast=True)
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
