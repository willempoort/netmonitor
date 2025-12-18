#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
WSGI Entry Point for NetMonitor Dashboard
For use with Gunicorn or other WSGI servers
"""

import os
import sys
import logging
from pathlib import Path

# Ensure we're in the correct directory
app_dir = Path(__file__).parent.absolute()
os.chdir(app_dir)
sys.path.insert(0, str(app_dir))

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import the Flask app and SocketIO instance from web_dashboard
# Note: app and socketio are created at module level in web_dashboard.py
# init_dashboard() only initializes database and authentication, it does NOT return anything
from web_dashboard import app, socketio, init_dashboard

# Initialize the dashboard components (database, auth managers, etc.)
init_dashboard(config_file='config.yaml')

# For gunicorn with eventlet workers and Flask-SocketIO v5.x+:
# Expose the Flask app object (NOT the socketio instance)
# The SocketIO instance has already wrapped the app at initialization in web_dashboard.py
# So the Flask app is already SocketIO-enabled and handles WebSocket connections
application = app

if __name__ == "__main__":
    # This allows running the file directly for testing
    # In production, gunicorn will import 'application' instead
    print("Starting NetMonitor Dashboard in development mode...")
    print("For production, use: gunicorn -c gunicorn_config.py wsgi:application")
    socketio.run(app, host='0.0.0.0', port=8000, debug=False)
