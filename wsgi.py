#!/usr/bin/env python3
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

# Import the Flask app from web_dashboard
from web_dashboard import init_dashboard

# Initialize the dashboard and get the Flask app
# The init_dashboard function creates and returns the Flask app instance
app = init_dashboard(config_file='config.yaml')

# For gunicorn, we need to expose the Flask app object
application = app

if __name__ == "__main__":
    # This allows running the file directly for testing
    # In production, gunicorn will import 'application' instead
    print("Starting NetMonitor Dashboard in development mode...")
    print("For production, use: gunicorn -c gunicorn_config.py wsgi:application")
    app.run(host='0.0.0.0', port=8000, debug=False)
