"""
Gunicorn Configuration for NetMonitor Dashboard
Production-ready WSGI server configuration with SocketIO support
"""

import multiprocessing
import os

# Server socket
bind = "127.0.0.1:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "eventlet"  # Required for SocketIO support
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = "/var/log/netmonitor/gunicorn_access.log"
errorlog = "/var/log/netmonitor/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "netmonitor-dashboard"

# Server mechanics
daemon = False
pidfile = "/var/run/netmonitor/gunicorn.pid"
umask = 0o022
user = None  # Run as current user (usually root for packet capture)
group = None
tmp_upload_dir = None

# SSL (optional - nginx handles this in our setup)
# keyfile = None
# certfile = None

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting NetMonitor Dashboard with Gunicorn")

def on_reload(server):
    """Called to recycle workers during a reload."""
    server.log.info("Reloading NetMonitor Dashboard")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info(f"NetMonitor Dashboard ready on {bind}")
    server.log.info(f"Workers: {workers} (eventlet mode for SocketIO)")

def on_exit(server):
    """Called just before exiting."""
    server.log.info("Shutting down NetMonitor Dashboard")

# Environment variables (optional)
raw_env = [
    # "DASHBOARD_PORT=8000",
    # "DASHBOARD_HOST=0.0.0.0",
]
