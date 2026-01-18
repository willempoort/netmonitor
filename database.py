# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Database Module - PostgreSQL + TimescaleDB
Optimized for time-series security data with hypertables and continuous aggregates
"""

import psycopg2
from psycopg2 import pool, errors
from psycopg2.extras import RealDictCursor
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import threading


class DatabaseManager:
    """Manages PostgreSQL + TimescaleDB for alerts and metrics"""

    def __init__(self, host='localhost', port=5432, database='netmonitor',
                 user='netmonitor', password='netmonitor',
                 min_connections=2, max_connections=10):
        """Initialize database manager with connection pooling"""
        self.logger = logging.getLogger('NetMonitor.Database')

        # Connection pool for thread-safe database access
        try:
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                min_connections,
                max_connections,
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )
            self.logger.info(f"Connection pool created: {host}:{port}/{database}")
        except Exception as e:
            self.logger.error(f"Failed to create connection pool: {e}")
            raise

        # Check schema version - skip heavy init if already up to date
        SCHEMA_VERSION = 16  # Increment this when schema changes

        if self._check_schema_version(SCHEMA_VERSION):
            self.logger.info(f"Database schema is up to date (v{SCHEMA_VERSION})")
        else:
            # Initialize database schema
            self._init_database()

            # Initialize MCP API schema (for token authentication)
            self._init_mcp_schema()

            # Create hypertables and continuous aggregates
            self._setup_timescaledb()

            # Initialize builtin data (templates, service providers)
            self._init_builtin_data()

            # Update schema version
            self._set_schema_version(SCHEMA_VERSION)
            self.logger.info(f"Database schema updated to v{SCHEMA_VERSION}")

    def _check_schema_version(self, required_version: int) -> bool:
        """Check if database schema is at the required version"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Check if schema_version table exists and has correct version
            cursor.execute("""
                SELECT version FROM schema_version
                WHERE component = 'netmonitor'
                LIMIT 1
            """)
            row = cursor.fetchone()
            conn.commit()  # Release any locks from the SELECT
            if row and row[0] >= required_version:
                return True
            return False
        except Exception as e:
            # Table doesn't exist or other error - need to run init
            try:
                conn.rollback()  # Clean up transaction state
            except Exception:
                pass
            return False
        finally:
            self._return_connection(conn)

    def _set_schema_version(self, version: int):
        """Set the current schema version"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO schema_version (component, version, updated_at)
                VALUES ('netmonitor', %s, NOW())
                ON CONFLICT (component) DO UPDATE SET version = %s, updated_at = NOW()
            """, (version, version))
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.warning(f"Could not set schema version: {e}")
        finally:
            self._return_connection(conn)

    def _get_connection(self):
        """Get connection from pool"""
        return self.connection_pool.getconn()

    def _return_connection(self, conn):
        """Return connection to pool"""
        self.connection_pool.putconn(conn)

    def _init_database(self):
        """Initialize database schema"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Schema version tracking table (must be first)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS schema_version (
                    component VARCHAR(50) PRIMARY KEY,
                    version INTEGER NOT NULL DEFAULT 1,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
            ''')

            # Enable TimescaleDB extension (optional - will continue without it if not available)
            try:
                cursor.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
                self.logger.info("TimescaleDB extension enabled")
                self.timescaledb_enabled = True
            except Exception as e:
                self.logger.warning(f"TimescaleDB not available, continuing without it: {e}")
                self.timescaledb_enabled = False
                conn.rollback()  # Rollback the failed transaction
                cursor = conn.cursor()  # Get new cursor after rollback

            # Alerts table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    severity TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    source_ip INET,
                    destination_ip INET,
                    description TEXT,
                    metadata JSONB,
                    acknowledged BOOLEAN DEFAULT FALSE
                );
            ''')

            # Traffic metrics table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_metrics (
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    total_packets BIGINT DEFAULT 0,
                    total_bytes BIGINT DEFAULT 0,
                    inbound_packets BIGINT DEFAULT 0,
                    inbound_bytes BIGINT DEFAULT 0,
                    outbound_packets BIGINT DEFAULT 0,
                    outbound_bytes BIGINT DEFAULT 0
                );
            ''')

            # Top talkers table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS top_talkers (
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    ip_address INET NOT NULL,
                    hostname TEXT,
                    packet_count BIGINT DEFAULT 0,
                    byte_count BIGINT DEFAULT 0,
                    direction TEXT
                );
            ''')

            # System stats table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_stats (
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    cpu_percent REAL,
                    memory_percent REAL,
                    packets_per_second REAL,
                    alerts_per_minute INTEGER,
                    threat_feed_iocs INTEGER
                );
            ''')

            # Remote sensors table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sensors (
                    id SERIAL PRIMARY KEY,
                    sensor_id TEXT UNIQUE NOT NULL,
                    hostname TEXT NOT NULL,
                    location TEXT,
                    ip_address INET,
                    version TEXT,
                    status TEXT DEFAULT 'offline',
                    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen TIMESTAMPTZ,
                    config JSONB
                );
            ''')

            # Sensor metrics table (will become hypertable)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sensor_metrics (
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    sensor_id TEXT NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    uptime_seconds BIGINT,
                    packets_captured BIGINT,
                    alerts_sent BIGINT,
                    network_interface TEXT,
                    FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE
                );
            ''')

            # Sensor commands table for remote control
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sensor_commands (
                    id SERIAL PRIMARY KEY,
                    sensor_id TEXT NOT NULL,
                    command_type TEXT NOT NULL,
                    parameters JSONB,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    executed_at TIMESTAMPTZ,
                    result JSONB,
                    FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE
                );
            ''')

            # Index for faster command polling
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sensor_commands_sensor_status
                ON sensor_commands(sensor_id, status, created_at);
            ''')

            # IP Whitelist table for centralized whitelist management
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_whitelists (
                    id SERIAL PRIMARY KEY,
                    ip_cidr CIDR NOT NULL,
                    description TEXT,
                    scope TEXT DEFAULT 'global',
                    sensor_id TEXT,
                    direction TEXT DEFAULT 'both',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_by TEXT,
                    FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE,
                    CONSTRAINT valid_scope CHECK (scope IN ('global', 'sensor')),
                    CONSTRAINT valid_direction CHECK (direction IN ('inbound', 'outbound', 'both'))
                );
            ''')

            # Add direction column if not exists (for existing installations)
            cursor.execute('''
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                                   WHERE table_name = 'ip_whitelists' AND column_name = 'direction') THEN
                        ALTER TABLE ip_whitelists ADD COLUMN direction TEXT DEFAULT 'both';
                        ALTER TABLE ip_whitelists ADD CONSTRAINT valid_direction
                            CHECK (direction IN ('inbound', 'outbound', 'both'));
                    END IF;
                END $$;
            ''')

            # Index for faster whitelist lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_ip_whitelists_scope
                ON ip_whitelists(scope, sensor_id);
            ''')

            # Sensor configuration table for centralized config management
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sensor_configs (
                    id SERIAL PRIMARY KEY,
                    sensor_id TEXT,
                    parameter_path TEXT NOT NULL,
                    parameter_value JSONB NOT NULL,
                    parameter_type TEXT NOT NULL,
                    scope TEXT DEFAULT 'global',
                    description TEXT,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_by TEXT,
                    FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE,
                    CONSTRAINT valid_config_scope CHECK (scope IN ('global', 'sensor')),
                    CONSTRAINT unique_sensor_param UNIQUE (sensor_id, parameter_path)
                );
            ''')

            # Index for faster config lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sensor_configs_lookup
                ON sensor_configs(sensor_id, parameter_path);
            ''')

            # Sensor authentication tokens table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sensor_tokens (
                    id SERIAL PRIMARY KEY,
                    sensor_id TEXT NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    token_name TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_used TIMESTAMPTZ,
                    expires_at TIMESTAMPTZ,
                    is_active BOOLEAN DEFAULT TRUE,
                    permissions JSONB DEFAULT '{"alerts": true, "metrics": true, "commands": false}'::jsonb,
                    FOREIGN KEY (sensor_id) REFERENCES sensors(sensor_id) ON DELETE CASCADE
                );
            ''')

            # Index for fast token lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sensor_tokens_hash
                ON sensor_tokens(token_hash) WHERE is_active = TRUE;
            ''')

            # Index for sensor token management
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sensor_tokens_sensor
                ON sensor_tokens(sensor_id, is_active);
            ''')

            # Web users table with 2FA support
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    role VARCHAR(20) DEFAULT 'operator',
                    totp_secret VARCHAR(32),
                    totp_enabled BOOLEAN DEFAULT FALSE,
                    backup_codes TEXT[],
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    last_login TIMESTAMPTZ,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMPTZ,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_by VARCHAR(50),
                    CONSTRAINT valid_role CHECK (role IN ('admin', 'operator', 'viewer'))
                );
            ''')

            # Web user audit log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_user_audit (
                    id BIGSERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES web_users(id),
                    username VARCHAR(50),
                    event_type VARCHAR(50) NOT NULL,
                    ip_address INET,
                    user_agent TEXT,
                    details JSONB,
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                );
            ''')

            # Web sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_sessions (
                    id VARCHAR(255) PRIMARY KEY,
                    user_id INTEGER REFERENCES web_users(id),
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    last_activity TIMESTAMPTZ DEFAULT NOW(),
                    ip_address INET,
                    user_agent TEXT,
                    expires_at TIMESTAMPTZ
                );
            ''')

            # ==================== Device Classification Tables ====================

            # Device templates - predefined and user-defined device types
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_templates (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) UNIQUE NOT NULL,
                    description TEXT,
                    icon VARCHAR(50) DEFAULT 'device',
                    category VARCHAR(50) DEFAULT 'other',
                    is_builtin BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW(),
                    created_by VARCHAR(50)
                );
            ''')

            # Template behaviors - allowed/expected behaviors per template
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS template_behaviors (
                    id SERIAL PRIMARY KEY,
                    template_id INTEGER NOT NULL REFERENCES device_templates(id) ON DELETE CASCADE,
                    behavior_type VARCHAR(50) NOT NULL,
                    parameters JSONB NOT NULL DEFAULT '{}',
                    action VARCHAR(20) DEFAULT 'allow',
                    description TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT valid_behavior_type CHECK (behavior_type IN (
                        'allowed_ports', 'allowed_protocols', 'allowed_sources',
                        'expected_destinations', 'traffic_pattern', 'connection_behavior',
                        'dns_behavior', 'time_restrictions', 'bandwidth_limit'
                    )),
                    CONSTRAINT valid_action CHECK (action IN ('allow', 'alert', 'suppress'))
                );
            ''')

            # Index for faster behavior lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_template_behaviors_template
                ON template_behaviors(template_id, behavior_type);
            ''')

            # Discovered/registered network devices
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id SERIAL PRIMARY KEY,
                    ip_address INET NOT NULL,
                    mac_address MACADDR,
                    hostname VARCHAR(255),
                    vendor VARCHAR(100),
                    template_id INTEGER REFERENCES device_templates(id) ON DELETE SET NULL,
                    sensor_id TEXT REFERENCES sensors(sensor_id) ON DELETE CASCADE,
                    learned_behavior JSONB DEFAULT '{}',
                    classification_confidence REAL DEFAULT 0.0,
                    classification_method VARCHAR(50),
                    first_seen TIMESTAMPTZ DEFAULT NOW(),
                    last_seen TIMESTAMPTZ DEFAULT NOW(),
                    is_active BOOLEAN DEFAULT TRUE,
                    notes TEXT,
                    created_by VARCHAR(50),
                    CONSTRAINT unique_device_per_sensor UNIQUE (ip_address, sensor_id)
                );
            ''')

            # Indexes for device lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_devices_template ON devices(template_id);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_devices_sensor ON devices(sensor_id);
            ''')

            # Service providers - streaming services, CDN providers, etc.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_providers (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    ip_ranges JSONB DEFAULT '[]',
                    domains JSONB DEFAULT '[]',
                    description TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    is_builtin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW(),
                    created_by VARCHAR(50),
                    CONSTRAINT valid_category CHECK (category IN (
                        'streaming', 'cdn', 'cloud', 'social', 'gaming', 'other'
                    )),
                    CONSTRAINT unique_provider_name UNIQUE (name, category)
                );
            ''')

            # Index for faster provider lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_service_providers_category
                ON service_providers(category, is_active);
            ''')

            # ==================== Threat Intelligence Feeds ====================

            # Threat feeds - external threat intelligence for enhanced detection
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    id SERIAL PRIMARY KEY,
                    feed_type VARCHAR(50) NOT NULL,
                    indicator VARCHAR(255) NOT NULL,
                    indicator_type VARCHAR(50),
                    source VARCHAR(100),
                    confidence_score REAL DEFAULT 1.0,
                    first_seen TIMESTAMPTZ DEFAULT NOW(),
                    last_updated TIMESTAMPTZ DEFAULT NOW(),
                    expires_at TIMESTAMPTZ,
                    metadata JSONB DEFAULT '{}',
                    is_active BOOLEAN DEFAULT TRUE,
                    CONSTRAINT valid_feed_type CHECK (feed_type IN (
                        'phishing', 'tor_exit', 'cryptomining', 'vpn_exit', 'malware_c2',
                        'botnet_c2', 'known_attacker', 'malicious_domain', 'suspicious_ip',
                        'ransomware_ioc', 'exploit_kit', 'other'
                    )),
                    CONSTRAINT valid_indicator_type CHECK (indicator_type IN (
                        'ip', 'domain', 'url', 'hash', 'cidr', 'asn', 'other'
                    )),
                    CONSTRAINT unique_feed_indicator UNIQUE (feed_type, indicator)
                );
            ''')

            # Indexes for faster threat feed lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_threat_feeds_type_active
                ON threat_feeds(feed_type, is_active, last_updated DESC);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_threat_feeds_indicator
                ON threat_feeds(indicator, feed_type) WHERE is_active = TRUE;
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_threat_feeds_expires
                ON threat_feeds(expires_at) WHERE expires_at IS NOT NULL AND is_active = TRUE;
            ''')

            # Indexes for web authentication
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_web_users_username
                ON web_users(username) WHERE is_active = TRUE;
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_web_users_email
                ON web_users(email) WHERE is_active = TRUE;
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_web_user_audit_user
                ON web_user_audit(user_id, timestamp DESC);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_web_user_audit_event
                ON web_user_audit(event_type, timestamp DESC);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_web_sessions_user
                ON web_sessions(user_id, last_activity DESC);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_web_sessions_expires
                ON web_sessions(expires_at);
            ''')

            conn.commit()
            self.logger.info("Database schema created")

            # Migration: Add hostname column if it doesn't exist (for existing databases)
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'top_talkers' AND column_name = 'hostname'
                    ) THEN
                        ALTER TABLE top_talkers ADD COLUMN hostname TEXT;
                    END IF;
                END $$;
            """)

            # Migration: Add sensor_id column to alerts table
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'alerts' AND column_name = 'sensor_id'
                    ) THEN
                        ALTER TABLE alerts ADD COLUMN sensor_id TEXT DEFAULT 'central';
                    END IF;
                END $$;
            """)

            # Migration: Add bandwidth_mbps column to sensor_metrics table
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'sensor_metrics' AND column_name = 'bandwidth_mbps'
                    ) THEN
                        ALTER TABLE sensor_metrics ADD COLUMN bandwidth_mbps REAL;
                    END IF;
                END $$;
            """)

            # Migration: Add vendor column to devices table
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'devices' AND column_name = 'vendor'
                    ) THEN
                        ALTER TABLE devices ADD COLUMN vendor VARCHAR(100);
                    END IF;
                END $$;
            """)

            # Migration: Update valid_behavior_type constraint to include allowed_sources
            # This is needed for templates with source IP whitelisting
            cursor.execute("""
                DO $$
                BEGIN
                    -- Check if constraint exists but doesn't include 'allowed_sources'
                    IF EXISTS (
                        SELECT 1 FROM information_schema.check_constraints
                        WHERE constraint_name = 'valid_behavior_type'
                        AND check_clause NOT LIKE '%allowed_sources%'
                    ) THEN
                        ALTER TABLE template_behaviors DROP CONSTRAINT valid_behavior_type;
                        ALTER TABLE template_behaviors ADD CONSTRAINT valid_behavior_type CHECK (
                            behavior_type IN (
                                'allowed_ports', 'allowed_protocols', 'allowed_sources',
                                'expected_destinations', 'traffic_pattern', 'connection_behavior',
                                'dns_behavior', 'time_restrictions', 'bandwidth_limit'
                            )
                        );
                    END IF;
                END $$;
            """)

            # Migration v16: Add sensor_id column to traffic_metrics for distributed collection
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'traffic_metrics' AND column_name = 'sensor_id'
                    ) THEN
                        ALTER TABLE traffic_metrics ADD COLUMN sensor_id TEXT DEFAULT 'central';
                        CREATE INDEX IF NOT EXISTS idx_traffic_metrics_sensor_id ON traffic_metrics(sensor_id);
                    END IF;
                END $$;
            """)

            # Migration v16: Add sensor_id column to top_talkers for distributed collection
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'top_talkers' AND column_name = 'sensor_id'
                    ) THEN
                        ALTER TABLE top_talkers ADD COLUMN sensor_id TEXT DEFAULT 'central';
                        CREATE INDEX IF NOT EXISTS idx_top_talkers_sensor_id ON top_talkers(sensor_id);
                    END IF;
                END $$;
            """)

            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating schema: {e}")
            raise
        finally:
            self._return_connection(conn)

    def _init_mcp_schema(self):
        """Initialize MCP API token tables for HTTP-based API authentication"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # MCP API Tokens table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mcp_api_tokens (
                    id SERIAL PRIMARY KEY,
                    token VARCHAR(64) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    scope VARCHAR(50) NOT NULL DEFAULT 'read_only',
                    enabled BOOLEAN NOT NULL DEFAULT true,
                    rate_limit_per_minute INTEGER DEFAULT 60,
                    rate_limit_per_hour INTEGER DEFAULT 1000,
                    rate_limit_per_day INTEGER DEFAULT 10000,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    created_by VARCHAR(255),
                    last_used_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    request_count BIGINT DEFAULT 0,
                    last_ip_address INET,
                    CONSTRAINT mcp_valid_scope CHECK (scope IN ('read_only', 'read_write', 'admin'))
                );
            ''')

            # MCP Token Usage table (audit log)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mcp_api_token_usage (
                    id BIGSERIAL PRIMARY KEY,
                    token_id INTEGER REFERENCES mcp_api_tokens(id) ON DELETE CASCADE,
                    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
                    endpoint VARCHAR(255) NOT NULL,
                    method VARCHAR(10) NOT NULL,
                    ip_address INET,
                    user_agent TEXT,
                    status_code INTEGER,
                    response_time_ms INTEGER,
                    error_message TEXT
                );
            ''')

            # Indexes for performance
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_mcp_tokens_token
                ON mcp_api_tokens(token);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_mcp_tokens_enabled
                ON mcp_api_tokens(enabled) WHERE enabled = true;
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_mcp_usage_token_id
                ON mcp_api_token_usage(token_id);
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_mcp_usage_timestamp
                ON mcp_api_token_usage(timestamp);
            ''')

            conn.commit()
            self.logger.info("MCP API schema created")

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating MCP schema: {e}")
            raise
        finally:
            self._return_connection(conn)

    def _setup_timescaledb(self):
        """Setup TimescaleDB hypertables and continuous aggregates"""
        # Skip if TimescaleDB is not available
        if not hasattr(self, 'timescaledb_enabled') or not self.timescaledb_enabled:
            self.logger.info("Skipping TimescaleDB setup (not available)")
            return

        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Create hypertables (partitioned by time)
            # Skip if already exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'alerts'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('alerts', 'timestamp',
                        chunk_time_interval => INTERVAL '1 day',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: alerts")

            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'traffic_metrics'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('traffic_metrics', 'timestamp',
                        chunk_time_interval => INTERVAL '1 day',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: traffic_metrics")

            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'top_talkers'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('top_talkers', 'timestamp',
                        chunk_time_interval => INTERVAL '1 hour',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: top_talkers")

            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'system_stats'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('system_stats', 'timestamp',
                        chunk_time_interval => INTERVAL '1 day',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: system_stats")

            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables
                    WHERE hypertable_name = 'sensor_metrics'
                );
            """)
            if not cursor.fetchone()[0]:
                cursor.execute("""
                    SELECT create_hypertable('sensor_metrics', 'timestamp',
                        chunk_time_interval => INTERVAL '1 day',
                        if_not_exists => TRUE
                    );
                """)
                self.logger.info("Created hypertable: sensor_metrics")

            # Create indices for fast queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts (threat_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sensor_id ON alerts (sensor_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensor_metrics_sensor_id ON sensor_metrics (sensor_id, timestamp DESC);")

            # Create continuous aggregate for alert statistics (pre-computed every hour)
            cursor.execute("""
                CREATE MATERIALIZED VIEW IF NOT EXISTS alert_stats_hourly
                WITH (timescaledb.continuous) AS
                SELECT
                    time_bucket('1 hour', timestamp) AS bucket,
                    severity,
                    threat_type,
                    COUNT(*) as count
                FROM alerts
                GROUP BY bucket, severity, threat_type
                WITH NO DATA;
            """)

            # Add refresh policy (auto-refresh every hour)
            cursor.execute("""
                SELECT add_continuous_aggregate_policy('alert_stats_hourly',
                    start_offset => INTERVAL '3 hours',
                    end_offset => INTERVAL '1 hour',
                    schedule_interval => INTERVAL '1 hour',
                    if_not_exists => TRUE
                );
            """)

            # Create retention policy (delete data older than 90 days)
            cursor.execute("""
                SELECT add_retention_policy('alerts', INTERVAL '90 days', if_not_exists => TRUE);
            """)
            cursor.execute("""
                SELECT add_retention_policy('traffic_metrics', INTERVAL '90 days', if_not_exists => TRUE);
            """)

            # Enable compression for old data (compress data older than 7 days)
            cursor.execute("""
                ALTER TABLE alerts SET (
                    timescaledb.compress,
                    timescaledb.compress_segmentby = 'severity,threat_type'
                );
            """)
            cursor.execute("""
                SELECT add_compression_policy('alerts', INTERVAL '7 days', if_not_exists => TRUE);
            """)

            conn.commit()
            self.logger.info("TimescaleDB features configured (hypertables, aggregates, compression)")

        except Exception as e:
            conn.rollback()
            self.logger.warning(f"TimescaleDB setup warning (may already exist): {e}")
        finally:
            self._return_connection(conn)

    # ==================== Threat Feed Management ====================

    def add_threat_feed_indicator(self, feed_type: str, indicator: str,
                                   indicator_type: str, source: str = None,
                                   confidence_score: float = 1.0,
                                   expires_at: datetime = None,
                                   metadata: Dict = None) -> Optional[int]:
        """Add or update a threat feed indicator

        Args:
            feed_type: Type of threat (phishing, tor_exit, cryptomining, etc.)
            indicator: The indicator value (IP, domain, URL, hash)
            indicator_type: Type of indicator (ip, domain, url, hash, cidr, asn)
            source: Source of the indicator (e.g., 'PhishTank', 'Tor Project')
            confidence_score: Confidence score (0.0 to 1.0)
            expires_at: Optional expiration timestamp
            metadata: Additional metadata as dict

        Returns:
            indicator ID if successful, None otherwise
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Upsert: update if exists, insert if not
            cursor.execute('''
                INSERT INTO threat_feeds
                (feed_type, indicator, indicator_type, source, confidence_score, expires_at, metadata, last_updated)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (feed_type, indicator)
                DO UPDATE SET
                    indicator_type = EXCLUDED.indicator_type,
                    source = EXCLUDED.source,
                    confidence_score = EXCLUDED.confidence_score,
                    expires_at = EXCLUDED.expires_at,
                    metadata = EXCLUDED.metadata,
                    last_updated = NOW(),
                    is_active = TRUE
                RETURNING id
            ''', (feed_type, indicator, indicator_type, source, confidence_score,
                  expires_at, json.dumps(metadata or {})))

            indicator_id = cursor.fetchone()[0]
            conn.commit()
            return indicator_id

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding threat feed indicator: {e}")
            return None
        finally:
            self._return_connection(conn)

    def get_threat_feed_indicators(self, feed_type: str = None,
                                   indicator_type: str = None,
                                   is_active: bool = True,
                                   limit: int = 10000) -> List[Dict]:
        """Get threat feed indicators

        Args:
            feed_type: Optional filter by feed type
            indicator_type: Optional filter by indicator type
            is_active: Only return active indicators (default True)
            limit: Maximum number of results

        Returns:
            List of threat indicators
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            query = '''
                SELECT id, feed_type, indicator, indicator_type, source,
                       confidence_score, first_seen, last_updated, expires_at,
                       metadata, is_active
                FROM threat_feeds
                WHERE 1=1
            '''
            params = []

            if feed_type:
                query += ' AND feed_type = %s'
                params.append(feed_type)

            if indicator_type:
                query += ' AND indicator_type = %s'
                params.append(indicator_type)

            if is_active is not None:
                query += ' AND is_active = %s'
                params.append(is_active)

            # Only return non-expired indicators
            query += ' AND (expires_at IS NULL OR expires_at > NOW())'

            query += ' ORDER BY last_updated DESC LIMIT %s'
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting threat feed indicators: {e}")
            return []
        finally:
            self._return_connection(conn)

    def check_threat_indicator(self, indicator: str, feed_types: List[str] = None) -> Optional[Dict]:
        """Check if an indicator matches a threat feed entry

        Args:
            indicator: The indicator to check (IP, domain, etc.)
            feed_types: Optional list of feed types to check

        Returns:
            Dict with match details if found, None otherwise
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            query = '''
                SELECT id, feed_type, indicator, indicator_type, source,
                       confidence_score, metadata
                FROM threat_feeds
                WHERE indicator = %s
                  AND is_active = TRUE
                  AND (expires_at IS NULL OR expires_at > NOW())
            '''
            params = [indicator]

            if feed_types:
                placeholders = ','.join(['%s'] * len(feed_types))
                query += f' AND feed_type IN ({placeholders})'
                params.extend(feed_types)

            query += ' ORDER BY confidence_score DESC LIMIT 1'

            cursor.execute(query, params)
            result = cursor.fetchone()

            return dict(result) if result else None

        except Exception as e:
            self.logger.error(f"Error checking threat indicator {indicator}: {e}")
            return None
        finally:
            self._return_connection(conn)

    def check_ip_in_threat_feeds(self, ip_address: str, feed_types: List[str] = None) -> Optional[Dict]:
        """Check if an IP address matches threat feeds (exact match or CIDR range)

        Args:
            ip_address: IP address to check
            feed_types: Optional list of feed types to check

        Returns:
            Dict with match details if found, None otherwise
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Check for exact match or CIDR range match
            query = '''
                SELECT id, feed_type, indicator, indicator_type, source,
                       confidence_score, metadata
                FROM threat_feeds
                WHERE is_active = TRUE
                  AND (expires_at IS NULL OR expires_at > NOW())
                  AND indicator_type IN ('ip', 'cidr')
                  AND (
                    indicator = %s
                    OR (indicator_type = 'cidr' AND inet %s <<= cidr(indicator))
                  )
            '''
            params = [ip_address, ip_address]

            if feed_types:
                placeholders = ','.join(['%s'] * len(feed_types))
                query += f' AND feed_type IN ({placeholders})'
                params.extend(feed_types)

            query += ' ORDER BY confidence_score DESC LIMIT 1'

            cursor.execute(query, params)
            result = cursor.fetchone()

            return dict(result) if result else None

        except Exception as e:
            self.logger.error(f"Error checking IP in threat feeds {ip_address}: {e}")
            return None
        finally:
            self._return_connection(conn)

    def cleanup_expired_threat_feeds(self) -> int:
        """Remove expired threat feed indicators

        Returns:
            Number of indicators removed
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Mark expired indicators as inactive instead of deleting
            cursor.execute('''
                UPDATE threat_feeds
                SET is_active = FALSE
                WHERE expires_at IS NOT NULL
                  AND expires_at < NOW()
                  AND is_active = TRUE
                RETURNING id
            ''')

            count = cursor.rowcount
            conn.commit()

            if count > 0:
                self.logger.info(f"Marked {count} expired threat feed indicators as inactive")

            return count

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error cleaning up expired threat feeds: {e}")
            return 0
        finally:
            self._return_connection(conn)

    def bulk_import_threat_feed(self, feed_type: str, indicators: List[Dict],
                               source: str = None) -> int:
        """Bulk import threat indicators

        Args:
            feed_type: Type of threat feed
            indicators: List of dicts with 'indicator', 'indicator_type', and optional fields
            source: Source name for all indicators

        Returns:
            Number of indicators imported
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            count = 0

            for item in indicators:
                indicator = item.get('indicator')
                indicator_type = item.get('indicator_type', 'ip')
                confidence = item.get('confidence_score', 1.0)
                expires_at = item.get('expires_at')
                metadata = item.get('metadata', {})

                if not indicator:
                    continue

                cursor.execute('''
                    INSERT INTO threat_feeds
                    (feed_type, indicator, indicator_type, source, confidence_score, expires_at, metadata, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (feed_type, indicator)
                    DO UPDATE SET
                        last_updated = NOW(),
                        is_active = TRUE
                ''', (feed_type, indicator, indicator_type, source, confidence,
                      expires_at, json.dumps(metadata)))

                count += 1

            conn.commit()
            self.logger.info(f"Bulk imported {count} threat indicators for feed type: {feed_type}")
            return count

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error bulk importing threat feed: {e}")
            return 0
        finally:
            self._return_connection(conn)

    # ==================== Builtin Data Initialization ====================

    def _init_builtin_data(self):
        """Initialize builtin device templates and service providers"""
        try:
            templates_count = self.init_builtin_templates()
            providers_count = self.init_builtin_service_providers()

            if templates_count > 0 or providers_count > 0:
                self.logger.info(f"Builtin data initialized: {templates_count} templates, {providers_count} service providers")
        except Exception as e:
            self.logger.warning(f"Could not initialize builtin data: {e}")

    def add_alert(self, alert: Dict) -> int:
        """Add alert to database"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Convert metadata dict to JSON
            metadata_json = json.dumps(alert.get('metadata', {})) if alert.get('metadata') else None

            # Get sensor_id from alert (defaults to 'central' in DB if not provided)
            sensor_id = alert.get('sensor_id')

            # Convert empty strings to None for inet type (PostgreSQL rejects empty strings)
            source_ip = alert.get('source_ip') or None
            destination_ip = alert.get('destination_ip') or None

            cursor.execute('''
                INSERT INTO alerts (severity, threat_type, source_ip, destination_ip, description, metadata, sensor_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                alert.get('severity', 'INFO'),
                alert.get('type', 'UNKNOWN'),
                source_ip,
                destination_ip,
                alert.get('description', ''),
                metadata_json,
                sensor_id
            ))

            alert_id = cursor.fetchone()[0]
            conn.commit()
            return alert_id

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding alert: {e}")
            return -1
        finally:
            self._return_connection(conn)

    def get_recent_alerts(self, limit: int = 100, hours: int = 24) -> List[Dict]:
        """Get recent alerts"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            cursor.execute('''
                SELECT
                    id,
                    timestamp,
                    severity,
                    threat_type,
                    source_ip::text as source_ip,
                    destination_ip::text as destination_ip,
                    description,
                    metadata,
                    acknowledged
                FROM alerts
                WHERE timestamp > %s
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (cutoff_time, limit))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_alert_statistics(self, hours: int = 24) -> Dict:
        """Get alert statistics using continuous aggregates for speed"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Total alerts
            cursor.execute('SELECT COUNT(*) as total FROM alerts WHERE timestamp > %s', (cutoff_time,))
            total = cursor.fetchone()['total']

            # By severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE timestamp > %s
                GROUP BY severity
            ''', (cutoff_time,))
            by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

            # By type
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM alerts
                WHERE timestamp > %s
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 10
            ''', (cutoff_time,))
            by_type = {row['threat_type']: row['count'] for row in cursor.fetchall()}

            # Top source IPs
            cursor.execute('''
                SELECT source_ip::text as source_ip, COUNT(*) as count
                FROM alerts
                WHERE timestamp > %s AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (cutoff_time,))
            top_sources = [{'ip': row['source_ip'], 'count': row['count']} for row in cursor.fetchall()]

            return {
                'total': total,
                'by_severity': by_severity,
                'by_type': by_type,
                'top_sources': top_sources
            }

        except Exception as e:
            self.logger.error(f"Error getting alert statistics: {e}")
            return {'total': 0, 'by_severity': {}, 'by_type': {}, 'top_sources': []}
        finally:
            self._return_connection(conn)

    def add_traffic_metrics(self, metrics: Dict, sensor_id: str = 'central'):
        """Add traffic metrics with sensor identification"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO traffic_metrics
                (sensor_id, total_packets, total_bytes, inbound_packets, inbound_bytes, outbound_packets, outbound_bytes)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                sensor_id,
                metrics.get('total_packets', 0),
                metrics.get('total_bytes', 0),
                metrics.get('inbound_packets', 0),
                metrics.get('inbound_bytes', 0),
                metrics.get('outbound_packets', 0),
                metrics.get('outbound_bytes', 0)
            ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding traffic metrics: {e}")
        finally:
            self._return_connection(conn)

    def get_traffic_history(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get traffic history with bandwidth in Mbps and peak tracking"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Use time_bucket for efficient aggregation
            # Calculate average bandwidth (Mbps) over 5-minute buckets
            # Formula: (total_bytes * 8 / 1000000) / 300 seconds = Mbps
            # Also track MAX to show peak bandwidth within each bucket
            # Note: Use total_bytes as fallback when inbound_bytes is 0 (mirror port scenarios)
            # Peak calculation uses sensor-specific sample intervals:
            #   - soc-server: 10 seconds (metrics_collector saves every 10s)
            #   - sensors: 30 seconds (sensor_client sends every 30s by default)
            cursor.execute('''
                SELECT
                    time_bucket('5 minutes', timestamp) AS timestamp,
                    SUM(total_packets) as total_packets,
                    SUM(total_bytes) as total_bytes,
                    SUM(inbound_packets) as inbound_packets,
                    SUM(inbound_bytes) as inbound_bytes,
                    SUM(outbound_packets) as outbound_packets,
                    SUM(outbound_bytes) as outbound_bytes,
                    -- Average bandwidth in Mbps over 5-minute window (300 seconds)
                    -- Use total_bytes if inbound is 0 (mirror port sees only one direction)
                    ROUND((GREATEST(SUM(inbound_bytes), SUM(total_bytes) - SUM(outbound_bytes)) * 8.0 / 1000000.0 / 300.0)::numeric, 2) as inbound_mbps,
                    ROUND((SUM(outbound_bytes) * 8.0 / 1000000.0 / 300.0)::numeric, 2) as outbound_mbps,
                    -- Peak bandwidth: calculate Mbps per sample using sensor-specific interval
                    ROUND(MAX(
                        GREATEST(
                            CASE
                                WHEN sensor_id = 'soc-server' THEN inbound_bytes * 8.0 / 1000000.0 / 10.0
                                ELSE inbound_bytes * 8.0 / 1000000.0 / 30.0
                            END,
                            CASE
                                WHEN sensor_id = 'soc-server' THEN (total_bytes - outbound_bytes) * 8.0 / 1000000.0 / 10.0
                                ELSE (total_bytes - outbound_bytes) * 8.0 / 1000000.0 / 30.0
                            END
                        )
                    )::numeric, 2) as inbound_mbps_peak,
                    ROUND(MAX(
                        CASE
                            WHEN sensor_id = 'soc-server' THEN outbound_bytes * 8.0 / 1000000.0 / 10.0
                            ELSE outbound_bytes * 8.0 / 1000000.0 / 30.0
                        END
                    )::numeric, 2) as outbound_mbps_peak
                FROM traffic_metrics
                WHERE timestamp > %s
                GROUP BY time_bucket('5 minutes', timestamp)
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (cutoff_time, limit))

            results = [dict(row) for row in cursor.fetchall()]
            results.reverse()  # Chronological order
            return results

        except Exception as e:
            self.logger.error(f"Error getting traffic history: {e}")
            return []
        finally:
            self._return_connection(conn)

    def update_top_talkers(self, talkers: List[Dict], sensor_id: str = 'central'):
        """Batch insert top talkers with sensor identification"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Use executemany for batch insert
            values = [
                (
                    sensor_id,
                    talker['ip'],
                    talker.get('hostname'),  # Include hostname
                    talker.get('packets', 0),
                    talker.get('bytes', 0),
                    talker.get('direction', 'unknown')
                )
                for talker in talkers
            ]

            cursor.executemany('''
                INSERT INTO top_talkers (sensor_id, ip_address, hostname, packet_count, byte_count, direction)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', values)

            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating top talkers: {e}")
        finally:
            self._return_connection(conn)

    def get_top_talkers(self, limit: int = 10, minutes: int = 5) -> List[Dict]:
        """Get top talkers with bandwidth in Mbps (default: last 5 minutes, configurable for historical analysis)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Use PostgreSQL NOW() instead of Python datetime to avoid timezone issues
            # Calculate bandwidth in Mbps from total bytes over time period
            # Formula: (bytes * 8 / 1000000) / (minutes * 60) = Mbps
            cursor.execute('''
                SELECT
                    ip_address::text as ip,
                    MAX(hostname) as hostname,
                    SUM(packet_count) as packets,
                    SUM(byte_count) as bytes,
                    ROUND((SUM(byte_count) * 8.0 / 1000000.0 / %s / 60.0)::numeric, 2) as mbps,
                    direction
                FROM top_talkers
                WHERE timestamp > NOW() - INTERVAL '%s minutes'
                GROUP BY ip_address, direction
                ORDER BY bytes DESC
                LIMIT %s
            ''', (minutes, minutes, limit))

            results = cursor.fetchall()
            self.logger.debug(f"get_top_talkers returned {len(results)} results for last {minutes} minutes")
            return [dict(row) for row in results]

        except Exception as e:
            self.logger.error(f"Error getting top talkers: {e}", exc_info=True)
            return []
        finally:
            self._return_connection(conn)

    def add_system_stats(self, stats: Dict):
        """Add system statistics"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO system_stats (cpu_percent, memory_percent, packets_per_second, alerts_per_minute, threat_feed_iocs)
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                stats.get('cpu_percent', 0),
                stats.get('memory_percent', 0),
                stats.get('packets_per_second', 0),
                stats.get('alerts_per_minute', 0),
                stats.get('threat_feed_iocs', 0)
            ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding system stats: {e}")
        finally:
            self._return_connection(conn)

    def get_latest_system_stats(self) -> Dict:
        """Get latest system statistics for gauges"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cursor.execute('''
                SELECT * FROM system_stats
                ORDER BY timestamp DESC
                LIMIT 1
            ''')

            row = cursor.fetchone()
            if row:
                return {
                    'traffic': {
                        'packets_per_second': row.get('packets_per_second', 0),
                        'alerts_per_minute': row.get('alerts_per_minute', 0)
                    },
                    'system': {
                        'cpu_percent': row.get('cpu_percent', 0),
                        'memory_percent': row.get('memory_percent', 0)
                    }
                }
            else:
                return {
                    'traffic': {'packets_per_second': 0, 'alerts_per_minute': 0},
                    'system': {'cpu_percent': 0, 'memory_percent': 0}
                }

        except Exception as e:
            self.logger.error(f"Error getting latest system stats: {e}")
            return {
                'traffic': {'packets_per_second': 0, 'alerts_per_minute': 0},
                'system': {'cpu_percent': 0, 'memory_percent': 0}
            }
        finally:
            self._return_connection(conn)

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark alert as acknowledged"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            cursor.execute('UPDATE alerts SET acknowledged = TRUE WHERE id = %s', (alert_id,))

            conn.commit()
            return cursor.rowcount > 0

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error acknowledging alert: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_threat_type_details(self, threat_type: str, hours: int = 24, limit: int = 100) -> Dict:
        """Get detailed information for a specific threat type"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Get all alerts for this threat type
            cursor.execute('''
                SELECT
                    id,
                    timestamp,
                    severity,
                    threat_type,
                    source_ip::text as source_ip,
                    destination_ip::text as destination_ip,
                    description,
                    metadata,
                    acknowledged
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (threat_type, cutoff_time, limit))

            alerts = [dict(row) for row in cursor.fetchall()]

            # Collect unique IPs for hostname resolution
            unique_ips = set()
            for alert in alerts:
                if alert['source_ip']:
                    unique_ips.add(alert['source_ip'])
                if alert['destination_ip']:
                    unique_ips.add(alert['destination_ip'])

            # Try to get hostnames from top_talkers table
            ip_hostnames = {}
            if unique_ips:
                placeholders = ','.join(['%s'] * len(unique_ips))
                cursor.execute(f'''
                    SELECT DISTINCT ON (ip_address)
                        ip_address::text as ip,
                        hostname
                    FROM top_talkers
                    WHERE ip_address IN ({placeholders})
                    AND hostname IS NOT NULL
                    ORDER BY ip_address, timestamp DESC
                ''', tuple(unique_ips))

                for row in cursor.fetchall():
                    if row['hostname'] and row['hostname'] != row['ip']:
                        ip_hostnames[row['ip']] = row['hostname']

            # Parse metadata for additional details
            for alert in alerts:
                if alert['source_ip']:
                    alert['source_hostname'] = ip_hostnames.get(alert['source_ip'])
                if alert['destination_ip']:
                    alert['destination_hostname'] = ip_hostnames.get(alert['destination_ip'])

                # Parse metadata JSON if present
                if alert['metadata']:
                    import json
                    try:
                        alert['metadata_parsed'] = json.loads(alert['metadata'])
                    except:
                        alert['metadata_parsed'] = {}

            # Get statistics for this threat type
            cursor.execute('''
                SELECT
                    COUNT(*) as total_count,
                    COUNT(DISTINCT source_ip) as unique_sources,
                    COUNT(DISTINCT destination_ip) as unique_targets,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s
            ''', (threat_type, cutoff_time))

            stats = dict(cursor.fetchone())

            # Get top source IPs for this threat type
            cursor.execute('''
                SELECT
                    source_ip::text as ip,
                    COUNT(*) as count
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (threat_type, cutoff_time))

            top_sources = [dict(row) for row in cursor.fetchall()]

            # Add hostnames to top sources
            for source in top_sources:
                source['hostname'] = ip_hostnames.get(source['ip'])

            # Get top destination IPs for this threat type
            cursor.execute('''
                SELECT
                    destination_ip::text as ip,
                    COUNT(*) as count
                FROM alerts
                WHERE threat_type = %s AND timestamp > %s AND destination_ip IS NOT NULL
                GROUP BY destination_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (threat_type, cutoff_time))

            top_targets = [dict(row) for row in cursor.fetchall()]

            # Add hostnames to top targets
            for target in top_targets:
                target['hostname'] = ip_hostnames.get(target['ip'])

            return {
                'threat_type': threat_type,
                'alerts': alerts,
                'statistics': stats,
                'top_sources': top_sources,
                'top_targets': top_targets
            }

        except Exception as e:
            self.logger.error(f"Error getting threat type details: {e}")
            return {
                'threat_type': threat_type,
                'alerts': [],
                'statistics': {},
                'top_sources': [],
                'top_targets': []
            }
        finally:
            self._return_connection(conn)

    def get_dashboard_data(self) -> Dict:
        """Get all data for dashboard in one call - optimized for performance"""
        return {
            'recent_alerts': self.get_recent_alerts(limit=20, hours=24),
            'alert_stats': self.get_alert_statistics(hours=24),
            'traffic_history': self.get_traffic_history(hours=24, limit=100),
            'top_talkers': self.get_top_talkers(limit=10),
            'current_metrics': self.get_latest_system_stats()
        }

    # ==================== Sensor Management Methods ====================

    def register_sensor(self, sensor_id: str, hostname: str, location: str = None,
                       ip_address: str = None, version: str = None, config: Dict = None) -> bool:
        """Register a new remote sensor or update existing one"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Upsert sensor
            cursor.execute('''
                INSERT INTO sensors (sensor_id, hostname, location, ip_address, version, status, last_seen, config)
                VALUES (%s, %s, %s, %s, %s, 'online', NOW(), %s)
                ON CONFLICT (sensor_id)
                DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    location = EXCLUDED.location,
                    ip_address = EXCLUDED.ip_address,
                    version = EXCLUDED.version,
                    status = 'online',
                    last_seen = NOW(),
                    config = EXCLUDED.config
            ''', (sensor_id, hostname, location, ip_address, version, json.dumps(config) if config else None))

            conn.commit()
            self.logger.info(f"Sensor registered: {sensor_id} ({hostname})")
            return True

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error registering sensor: {e}")
            return False
        finally:
            self._return_connection(conn)

    def deregister_sensor(self, sensor_id: str) -> bool:
        """Remove a sensor from the database (for self-monitor disable)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Delete sensor and all related data
            cursor.execute('DELETE FROM sensor_metrics WHERE sensor_id = %s', (sensor_id,))
            cursor.execute('DELETE FROM sensors WHERE sensor_id = %s', (sensor_id,))

            conn.commit()
            self.logger.info(f"Sensor deregistered: {sensor_id}")
            return True

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deregistering sensor: {e}")
            return False
        finally:
            self._return_connection(conn)

    def update_sensor_heartbeat(self, sensor_id: str) -> bool:
        """Update sensor last_seen timestamp"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sensors
                SET last_seen = NOW(), status = 'online'
                WHERE sensor_id = %s
            ''', (sensor_id,))
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating sensor heartbeat: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_sensors(self) -> List[Dict]:
        """Get all registered sensors with their latest metrics"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            cursor.execute('''
                SELECT
                    s.sensor_id,
                    s.hostname,
                    COALESCE(
                        (SELECT parameter_value#>>'{}'
                         FROM sensor_configs
                         WHERE sensor_id = s.sensor_id
                         AND parameter_path = 'sensor.location'
                         LIMIT 1),
                        s.location
                    ) as location,
                    s.ip_address::text as ip_address,
                    s.version,
                    s.status,
                    s.config,
                    s.registered_at,
                    s.last_seen,
                    CASE
                        WHEN s.last_seen > NOW() - INTERVAL '2 minutes' THEN 'online'
                        WHEN s.last_seen > NOW() - INTERVAL '10 minutes' THEN 'warning'
                        ELSE 'offline'
                    END as computed_status,
                    sm.cpu_percent,
                    sm.memory_percent,
                    sm.disk_percent,
                    sm.uptime_seconds,
                    sm.packets_captured,
                    sm.alerts_sent,
                    sm.network_interface,
                    sm.bandwidth_mbps
                FROM sensors s
                LEFT JOIN LATERAL (
                    SELECT *
                    FROM sensor_metrics
                    WHERE sensor_id = s.sensor_id
                    ORDER BY timestamp DESC
                    LIMIT 1
                ) sm ON true
                ORDER BY
                    CASE
                        WHEN s.sensor_id LIKE '%soc-server%' THEN 0
                        ELSE 1
                    END,
                    s.hostname
            ''')

            sensors = [dict(row) for row in cursor.fetchall()]

            # Get alert counts for each sensor
            for sensor in sensors:
                cursor.execute('''
                    SELECT COUNT(*) as count
                    FROM alerts
                    WHERE sensor_id = %s AND timestamp > NOW() - INTERVAL '24 hours'
                ''', (sensor['sensor_id'],))
                sensor['alerts_24h'] = cursor.fetchone()['count']

            return sensors

        except Exception as e:
            self.logger.error(f"Error getting sensors: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_sensor_by_id(self, sensor_id: str) -> Optional[Dict]:
        """Get specific sensor details"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT
                    s.sensor_id,
                    s.hostname,
                    COALESCE(
                        (SELECT parameter_value#>>'{}'
                         FROM sensor_configs
                         WHERE sensor_id = s.sensor_id
                         AND parameter_path = 'sensor.location'
                         LIMIT 1),
                        s.location
                    ) as location,
                    s.ip_address::text as ip_address,
                    s.version,
                    s.status,
                    s.registered_at,
                    s.last_seen,
                    s.config
                FROM sensors s
                WHERE s.sensor_id = %s
            ''', (sensor_id,))

            result = cursor.fetchone()
            return dict(result) if result else None

        except Exception as e:
            self.logger.error(f"Error getting sensor: {e}")
            return None
        finally:
            self._return_connection(conn)

    def save_sensor_metrics(self, sensor_id: str, cpu_percent: float = None,
                          memory_percent: float = None, disk_percent: float = None,
                          uptime_seconds: int = None, packets_captured: int = None,
                          alerts_sent: int = None, network_interface: str = None,
                          bandwidth_mbps: float = None) -> bool:
        """
        Save sensor performance metrics and update last_seen timestamp.

        This function serves as an implicit heartbeat for sensors that save metrics regularly.
        Both remote sensors (sensor_client.py) and SOC server self-monitoring (netmonitor.py)
        use this to maintain their 'online' status.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Insert metrics into sensor_metrics table
            cursor.execute('''
                INSERT INTO sensor_metrics
                (sensor_id, cpu_percent, memory_percent, disk_percent, uptime_seconds,
                 packets_captured, alerts_sent, network_interface, bandwidth_mbps)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (sensor_id, cpu_percent, memory_percent, disk_percent, uptime_seconds,
                  packets_captured, alerts_sent, network_interface, bandwidth_mbps))

            # Update last_seen timestamp (implicit heartbeat)
            # This keeps the sensor status as 'online' in the dashboard
            cursor.execute('''
                UPDATE sensors
                SET last_seen = NOW(), status = 'online'
                WHERE sensor_id = %s
            ''', (sensor_id,))

            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error saving sensor metrics: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_sensor_metrics(self, sensor_id: str, hours: int = 24) -> List[Dict]:
        """Get sensor metrics history"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cutoff = datetime.now() - timedelta(hours=hours)

            cursor.execute('''
                SELECT
                    timestamp,
                    cpu_percent,
                    memory_percent,
                    disk_percent,
                    uptime_seconds,
                    packets_captured,
                    alerts_sent,
                    bandwidth_mbps,
                    network_interface
                FROM sensor_metrics
                WHERE sensor_id = %s AND timestamp > %s
                ORDER BY timestamp DESC
            ''', (sensor_id, cutoff))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting sensor metrics: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_aggregated_metrics(self) -> Dict:
        """
        Get aggregated metrics from all sensors for dashboard
        Used when SOC server is in management-only mode (self_monitor.enabled=false)
        """
        from decimal import Decimal

        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Get latest metrics from all sensors (last 2 minutes)
            cursor.execute('''
                SELECT
                    sensor_id,
                    packets_captured,
                    alerts_sent,
                    bandwidth_mbps,
                    timestamp
                FROM sensor_metrics
                WHERE timestamp > NOW() - INTERVAL '2 minutes'
                ORDER BY timestamp DESC
            ''')

            recent_metrics = cursor.fetchall()

            # Calculate packets/sec from deltas
            # Group by sensor_id and get last 2 records for each
            sensor_packets = {}
            sensor_bandwidth = {}
            sensor_latest_timestamp = {}

            for metric in recent_metrics:
                sid = metric['sensor_id']

                # Initialize structures for new sensors
                if sid not in sensor_packets:
                    sensor_packets[sid] = []
                    sensor_bandwidth[sid] = 0
                    sensor_latest_timestamp[sid] = metric['timestamp']

                # Always use the MOST RECENT bandwidth (results are ordered DESC)
                # Update bandwidth if this record is newer than previously seen
                if metric['timestamp'] >= sensor_latest_timestamp[sid]:
                    bw = metric['bandwidth_mbps']
                    sensor_bandwidth[sid] = float(bw) if isinstance(bw, Decimal) else (bw or 0)
                    sensor_latest_timestamp[sid] = metric['timestamp']

                # Convert packets_captured to int
                packets = metric['packets_captured']
                packets = int(packets) if isinstance(packets, Decimal) else (packets or 0)

                sensor_packets[sid].append({
                    'packets': packets,
                    'timestamp': metric['timestamp']
                })

            # Calculate total packets/sec
            total_packets_per_sec = 0
            total_bandwidth = sum(sensor_bandwidth.values())

            for sid, metrics_list in sensor_packets.items():
                if len(metrics_list) >= 2:
                    # Sort by timestamp
                    sorted_metrics = sorted(metrics_list, key=lambda x: x['timestamp'])
                    latest = sorted_metrics[-1]
                    previous = sorted_metrics[-2]

                    # Calculate delta
                    packet_delta = latest['packets'] - previous['packets']
                    time_delta = (latest['timestamp'] - previous['timestamp']).total_seconds()

                    if time_delta > 0:
                        packets_per_sec = packet_delta / time_delta
                        total_packets_per_sec += packets_per_sec

            # Get alerts in last minute
            cursor.execute('''
                SELECT COUNT(*) as count
                FROM alerts
                WHERE timestamp > NOW() - INTERVAL '1 minute'
            ''')
            alerts_result = cursor.fetchone()['count']
            alerts_last_minute = int(alerts_result) if isinstance(alerts_result, Decimal) else alerts_result

            # Get total packets from all sensors (last 5 minutes for smoother display)
            cursor.execute('''
                SELECT COALESCE(SUM(packets_captured), 0) as total_packets
                FROM (
                    SELECT DISTINCT ON (sensor_id) packets_captured
                    FROM sensor_metrics
                    WHERE timestamp > NOW() - INTERVAL '5 minutes'
                    ORDER BY sensor_id, timestamp DESC
                ) latest_per_sensor
            ''')
            total_packets_result = cursor.fetchone()['total_packets']
            total_packets = int(total_packets_result) if isinstance(total_packets_result, Decimal) else total_packets_result

            return {
                'packets_per_sec': round(float(total_packets_per_sec), 1),
                'alerts_per_min': int(alerts_last_minute),
                'total_packets': int(total_packets),
                'bandwidth_mbps': round(float(total_bandwidth), 2),
                'sensor_count': len(sensor_packets)
            }

        except Exception as e:
            self.logger.error(f"Error getting aggregated metrics: {e}")
            return {
                'packets_per_sec': 0,
                'alerts_per_min': 0,
                'total_packets': 0,
                'bandwidth_mbps': 0,
                'sensor_count': 0
            }
        finally:
            self._return_connection(conn)

    def insert_alert_from_sensor(self, sensor_id: str, severity: str, threat_type: str,
                                 source_ip: str = None, destination_ip: str = None,
                                 description: str = None, metadata: Dict = None,
                                 timestamp: datetime = None) -> bool:
        """Insert alert from remote sensor"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            ts = timestamp if timestamp else datetime.now()

            cursor.execute('''
                INSERT INTO alerts
                (timestamp, severity, threat_type, source_ip, destination_ip, description, metadata, sensor_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (ts, severity, threat_type, source_ip, destination_ip, description,
                  json.dumps(metadata) if metadata else None, sensor_id))

            conn.commit()
            return True

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error inserting alert from sensor: {e}")
            return False
        finally:
            self._return_connection(conn)

    # ==================== Sensor Command Methods ====================

    def create_sensor_command(self, sensor_id: str, command_type: str,
                            parameters: Dict = None) -> Optional[int]:
        """Create a new command for a sensor"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sensor_commands (sensor_id, command_type, parameters, status)
                VALUES (%s, %s, %s, 'pending')
                RETURNING id
            ''', (sensor_id, command_type, json.dumps(parameters) if parameters else None))

            command_id = cursor.fetchone()[0]
            conn.commit()
            self.logger.info(f"Command created: {command_type} for sensor {sensor_id}")
            return command_id

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating sensor command: {e}")
            return None
        finally:
            self._return_connection(conn)

    def get_pending_commands(self, sensor_id: str) -> List[Dict]:
        """Get all pending commands for a sensor"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT id, command_type, parameters, created_at
                FROM sensor_commands
                WHERE sensor_id = %s AND status = 'pending'
                ORDER BY created_at ASC
            ''', (sensor_id,))

            commands = [dict(row) for row in cursor.fetchall()]

            # Parse JSON parameters
            for cmd in commands:
                if cmd.get('parameters'):
                    cmd['parameters'] = json.loads(cmd['parameters']) if isinstance(cmd['parameters'], str) else cmd['parameters']

            return commands

        except Exception as e:
            self.logger.error(f"Error getting pending commands: {e}")
            return []
        finally:
            self._return_connection(conn)

    def update_command_status(self, command_id: int, status: str,
                            result: Dict = None) -> bool:
        """Update command execution status"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sensor_commands
                SET status = %s, executed_at = NOW(), result = %s
                WHERE id = %s
            ''', (status, json.dumps(result) if result else None, command_id))

            conn.commit()
            return True

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating command status: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_sensor_command_history(self, sensor_id: str, limit: int = 50) -> List[Dict]:
        """Get command history for a sensor"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT id, command_type, parameters, status, created_at, executed_at, result
                FROM sensor_commands
                WHERE sensor_id = %s
                ORDER BY created_at DESC
                LIMIT %s
            ''', (sensor_id, limit))

            commands = [dict(row) for row in cursor.fetchall()]

            # Parse JSON fields
            for cmd in commands:
                if cmd.get('parameters'):
                    cmd['parameters'] = json.loads(cmd['parameters']) if isinstance(cmd['parameters'], str) else cmd['parameters']
                if cmd.get('result'):
                    cmd['result'] = json.loads(cmd['result']) if isinstance(cmd['result'], str) else cmd['result']

            return commands

        except Exception as e:
            self.logger.error(f"Error getting command history: {e}")
            return []
        finally:
            self._return_connection(conn)

    # ==================== Whitelist Management Methods ====================

    def add_whitelist_entry(self, ip_cidr: str, description: str = None,
                          scope: str = 'global', sensor_id: str = None,
                          direction: str = 'both',
                          created_by: str = 'system') -> Optional[int]:
        """Add IP/CIDR to whitelist

        Args:
            ip_cidr: IP address or CIDR range to whitelist
            description: Human-readable description
            scope: 'global' or 'sensor'
            sensor_id: Required if scope is 'sensor'
            direction: 'inbound', 'outbound', or 'both' (default)
            created_by: User/system that created the entry
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Validate scope
            if scope == 'sensor' and not sensor_id:
                self.logger.error("sensor_id required for sensor-scoped whitelist")
                return None

            # Validate direction
            if direction not in ('inbound', 'outbound', 'both'):
                self.logger.error(f"Invalid direction: {direction}. Must be 'inbound', 'outbound', or 'both'")
                return None

            cursor.execute('''
                INSERT INTO ip_whitelists (ip_cidr, description, scope, sensor_id, direction, created_by)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (ip_cidr, description, scope, sensor_id, direction, created_by))

            entry_id = cursor.fetchone()[0]
            conn.commit()
            self.logger.info(f"Whitelist entry added: {ip_cidr} ({scope}, {direction})")
            return entry_id

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding whitelist entry: {e}")
            return None
        finally:
            self._return_connection(conn)

    def get_whitelist(self, scope: str = None, sensor_id: str = None) -> List[Dict]:
        """Get whitelist entries"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            query = 'SELECT * FROM ip_whitelists WHERE 1=1'
            params = []

            if scope:
                query += ' AND scope = %s'
                params.append(scope)

            if sensor_id:
                query += ' AND (sensor_id = %s OR scope = \'global\')'
                params.append(sensor_id)

            query += ' ORDER BY created_at DESC'

            cursor.execute(query, params)
            entries = [dict(row) for row in cursor.fetchall()]

            # Convert CIDR to string
            for entry in entries:
                if entry.get('ip_cidr'):
                    entry['ip_cidr'] = str(entry['ip_cidr'])

            return entries

        except Exception as e:
            self.logger.error(f"Error getting whitelist: {e}")
            return []
        finally:
            self._return_connection(conn)

    def delete_whitelist_entry(self, entry_id: int) -> bool:
        """Delete whitelist entry"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM ip_whitelists WHERE id = %s', (entry_id,))
            conn.commit()
            self.logger.info(f"Whitelist entry {entry_id} deleted")
            return True
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deleting whitelist entry: {e}")
            return False
        finally:
            self._return_connection(conn)

    def check_ip_whitelisted(self, ip_address: str, sensor_id: str = None,
                              direction: str = None) -> bool:
        """Check if IP is whitelisted (for sensor or globally)

        Args:
            ip_address: IP address to check
            sensor_id: Optional sensor ID for sensor-specific rules
            direction: 'source', 'destination', or None (checks 'both' only)
                       Also accepts legacy 'inbound'/'outbound' for backwards compatibility

        Returns:
            True if IP matches a whitelist entry for the given direction
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Build direction filter
            # Support both new terminology (source/destination) and legacy (inbound/outbound)
            # source = outbound (when IP is the source of traffic)
            # destination = inbound (when IP is the destination of traffic)
            if direction == 'source':
                # Match 'source' or legacy 'outbound' or 'both'
                direction_filter = "AND (direction IN ('source', 'outbound', 'both'))"
                direction_param = None
            elif direction == 'destination':
                # Match 'destination' or legacy 'inbound' or 'both'
                direction_filter = "AND (direction IN ('destination', 'inbound', 'both'))"
                direction_param = None
            elif direction in ('inbound', 'outbound'):
                # Legacy support
                direction_filter = "AND (direction = %s OR direction = 'both')"
                direction_param = direction
            else:
                direction_filter = "AND direction = 'both'"
                direction_param = None

            # Check both global and sensor-specific whitelists
            # Use >>= operator: "does CIDR contain or equal IP?"
            if sensor_id:
                if direction_param:
                    cursor.execute(f'''
                        SELECT COUNT(*) FROM ip_whitelists
                        WHERE ip_cidr >>= inet %s
                          AND (scope = 'global' OR (scope = 'sensor' AND sensor_id = %s))
                          {direction_filter}
                    ''', (ip_address, sensor_id, direction_param))
                else:
                    cursor.execute(f'''
                        SELECT COUNT(*) FROM ip_whitelists
                        WHERE ip_cidr >>= inet %s
                          AND (scope = 'global' OR (scope = 'sensor' AND sensor_id = %s))
                          {direction_filter}
                    ''', (ip_address, sensor_id))
            else:
                if direction_param:
                    cursor.execute(f'''
                        SELECT COUNT(*) FROM ip_whitelists
                        WHERE ip_cidr >>= inet %s AND scope = 'global'
                          {direction_filter}
                    ''', (ip_address, direction_param))
                else:
                    cursor.execute(f'''
                        SELECT COUNT(*) FROM ip_whitelists
                        WHERE ip_cidr >>= inet %s AND scope = 'global'
                          {direction_filter}
                    ''', (ip_address,))

            count = cursor.fetchone()[0]
            return count > 0

        except Exception as e:
            self.logger.error(f"Error checking whitelist for {ip_address}: {e}")
            return False
        finally:
            self._return_connection(conn)

    # ==================== Configuration Management ====================

    def set_config_parameter(self, parameter_path: str, value: Any,
                            sensor_id: str = None, scope: str = 'global',
                            description: str = None, updated_by: str = None) -> bool:
        """Set a configuration parameter (global or per-sensor)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Determine parameter type
            param_type = type(value).__name__

            # Convert value to JSON-serializable format
            import json
            json_value = json.dumps(value)

            cursor.execute('''
                INSERT INTO sensor_configs
                (sensor_id, parameter_path, parameter_value, parameter_type, scope, description, updated_by)
                VALUES (%s, %s, %s::jsonb, %s, %s, %s, %s)
                ON CONFLICT (sensor_id, parameter_path)
                DO UPDATE SET
                    parameter_value = EXCLUDED.parameter_value,
                    parameter_type = EXCLUDED.parameter_type,
                    updated_at = NOW(),
                    updated_by = EXCLUDED.updated_by
            ''', (sensor_id, parameter_path, json_value, param_type, scope, description, updated_by))

            conn.commit()
            return True

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error setting config parameter: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_sensor_config(self, sensor_id: str = None, parameter_path: str = None) -> Dict:
        """Get configuration for a sensor (merges global + sensor-specific)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            if parameter_path:
                # Get specific parameter (sensor-specific overrides global)
                if sensor_id:
                    cursor.execute('''
                        SELECT parameter_path, parameter_value, parameter_type, scope
                        FROM sensor_configs
                        WHERE parameter_path = %s
                          AND (sensor_id IS NULL OR sensor_id = %s)
                        ORDER BY CASE WHEN sensor_id IS NULL THEN 1 ELSE 0 END
                        LIMIT 1
                    ''', (parameter_path, sensor_id))
                else:
                    cursor.execute('''
                        SELECT parameter_path, parameter_value, parameter_type, scope
                        FROM sensor_configs
                        WHERE parameter_path = %s AND sensor_id IS NULL
                    ''', (parameter_path,))
            else:
                # Get all parameters
                if sensor_id:
                    # Get global + sensor-specific (sensor-specific overrides)
                    cursor.execute('''
                        WITH ranked_configs AS (
                            SELECT
                                parameter_path,
                                parameter_value,
                                parameter_type,
                                scope,
                                ROW_NUMBER() OVER (
                                    PARTITION BY parameter_path
                                    ORDER BY CASE WHEN sensor_id IS NULL THEN 1 ELSE 0 END
                                ) as rn
                            FROM sensor_configs
                            WHERE sensor_id IS NULL OR sensor_id = %s
                        )
                        SELECT parameter_path, parameter_value, parameter_type, scope
                        FROM ranked_configs
                        WHERE rn = 1
                    ''', (sensor_id,))
                else:
                    cursor.execute('''
                        SELECT parameter_path, parameter_value, parameter_type, scope
                        FROM sensor_configs
                        WHERE sensor_id IS NULL
                    ''')

            rows = cursor.fetchall()

            # Build config dict from parameter paths
            config = {}
            for row in rows:
                path_parts = row['parameter_path'].split('.')
                current = config

                # Navigate/create nested structure
                for part in path_parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]

                # Set the value (JSONB is already parsed by psycopg2 - no need to parse again)
                value = row['parameter_value']
                current[path_parts[-1]] = value

            return config

        except Exception as e:
            self.logger.error(f"Error getting sensor config: {e}")
            return {}
        finally:
            self._return_connection(conn)

    def get_all_config_parameters(self, sensor_id: str = None) -> List[Dict]:
        """Get all configuration parameters with metadata"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            if sensor_id:
                cursor.execute('''
                    SELECT
                        id, sensor_id, parameter_path, parameter_value,
                        parameter_type, scope, description, updated_at, updated_by
                    FROM sensor_configs
                    WHERE sensor_id IS NULL OR sensor_id = %s
                    ORDER BY parameter_path, sensor_id NULLS FIRST
                ''', (sensor_id,))
            else:
                cursor.execute('''
                    SELECT
                        id, sensor_id, parameter_path, parameter_value,
                        parameter_type, scope, description, updated_at, updated_by
                    FROM sensor_configs
                    WHERE sensor_id IS NULL
                    ORDER BY parameter_path
                ''')

            import json
            results = []
            for row in cursor.fetchall():
                row_dict = dict(row)
                # JSONB is already parsed by psycopg2 - no need to json.loads()
                # Just keep the value as-is (it's already a Python object: dict, list, bool, etc.)
                results.append(row_dict)

            return results

        except Exception as e:
            self.logger.error(f"Error getting config parameters: {e}")
            return []
        finally:
            self._return_connection(conn)

    def delete_config_parameter(self, parameter_path: str, sensor_id: str = None) -> bool:
        """Delete a configuration parameter"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            if sensor_id:
                cursor.execute('''
                    DELETE FROM sensor_configs
                    WHERE parameter_path = %s AND sensor_id = %s
                ''', (parameter_path, sensor_id))
            else:
                cursor.execute('''
                    DELETE FROM sensor_configs
                    WHERE parameter_path = %s AND sensor_id IS NULL
                ''', (parameter_path,))

            conn.commit()
            return True

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deleting config parameter: {e}")
            return False
        finally:
            self._return_connection(conn)

    # ==================== Device Template Management ====================

    def create_device_template(self, name: str, description: str = None,
                               icon: str = 'device', category: str = 'other',
                               is_builtin: bool = False, created_by: str = None,
                               return_existing: bool = False) -> Optional[int]:
        """Create a new device template

        Args:
            return_existing: If True, return existing template ID when name conflicts.
                           If False, return None when name conflicts (default).

        Note: If an inactive template with the same name exists, it will be
              reactivated and updated with the new properties.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # First check if an inactive template with this name exists
            cursor.execute('''
                SELECT id, is_active FROM device_templates
                WHERE LOWER(name) = LOWER(%s)
            ''', (name,))
            existing = cursor.fetchone()

            if existing:
                template_id, is_active = existing
                if not is_active:
                    # Reactivate the inactive template and update its properties
                    cursor.execute('''
                        UPDATE device_templates
                        SET is_active = TRUE,
                            description = %s,
                            icon = %s,
                            category = %s,
                            created_by = %s,
                            updated_at = NOW()
                        WHERE id = %s
                    ''', (description, icon, category, created_by, template_id))
                    conn.commit()
                    self.logger.info(f"Device template reactivated: {name} (ID: {template_id})")
                    return template_id
                else:
                    # Active template already exists
                    if return_existing:
                        self.logger.debug(f"Device template already exists: {name} (ID: {template_id})")
                        return template_id
                    else:
                        self.logger.debug(f"Device template already exists, skipping: {name}")
                        return None

            # No existing template, create new one
            cursor.execute('''
                INSERT INTO device_templates (name, description, icon, category, is_builtin, created_by)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (name, description, icon, category, is_builtin, created_by))
            result = cursor.fetchone()
            conn.commit()
            if result:
                template_id = result[0]
                self.logger.info(f"Device template created: {name} (ID: {template_id})")
                return template_id
            return None
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating device template: {e}")
            return None
        finally:
            self._return_connection(conn)

    def get_device_templates(self, include_inactive: bool = False,
                            category: str = None) -> List[Dict]:
        """Get all device templates with device counts"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            # Use subquery for device count to avoid GROUP BY issues
            query = '''
                SELECT t.*,
                       COALESCE((SELECT COUNT(*) FROM devices d WHERE d.template_id = t.id), 0) as device_count
                FROM device_templates t
                WHERE 1=1
            '''
            params = []

            if not include_inactive:
                query += ' AND t.is_active = TRUE'

            if category:
                query += ' AND t.category = %s'
                params.append(category)

            query += ' ORDER BY t.is_builtin DESC, t.name ASC'
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting device templates: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_device_template_by_id(self, template_id: int) -> Optional[Dict]:
        """Get a specific device template with its behaviors"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Get template
            cursor.execute('SELECT * FROM device_templates WHERE id = %s', (template_id,))
            template = cursor.fetchone()
            if not template:
                return None

            template = dict(template)

            # Get behaviors
            cursor.execute('''
                SELECT * FROM template_behaviors
                WHERE template_id = %s
                ORDER BY behavior_type
            ''', (template_id,))
            template['behaviors'] = [dict(row) for row in cursor.fetchall()]

            return template
        except Exception as e:
            self.logger.error(f"Error getting device template: {e}")
            return None
        finally:
            self._return_connection(conn)

    def update_device_template(self, template_id: int, **kwargs) -> bool:
        """Update a device template"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Build update query dynamically
            allowed_fields = ['name', 'description', 'icon', 'category', 'is_active']
            updates = []
            params = []

            for field in allowed_fields:
                if field in kwargs:
                    updates.append(f"{field} = %s")
                    params.append(kwargs[field])

            if not updates:
                return False

            updates.append("updated_at = NOW()")
            params.append(template_id)

            cursor.execute(f'''
                UPDATE device_templates
                SET {', '.join(updates)}
                WHERE id = %s
            ''', params)

            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating device template: {e}")
            return False
        finally:
            self._return_connection(conn)

    def delete_device_template(self, template_id: int) -> bool:
        """Delete a device template (soft delete by setting is_active=False)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Check if builtin (can't delete builtin templates)
            cursor.execute('SELECT is_builtin FROM device_templates WHERE id = %s', (template_id,))
            result = cursor.fetchone()
            if result and result[0]:
                self.logger.warning(f"Cannot delete builtin template {template_id}")
                return False

            cursor.execute('''
                UPDATE device_templates
                SET is_active = FALSE, updated_at = NOW()
                WHERE id = %s
            ''', (template_id,))

            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deleting device template: {e}")
            return False
        finally:
            self._return_connection(conn)

    # ==================== Template Behavior Management ====================

    def add_template_behavior(self, template_id: int, behavior_type: str,
                             parameters: Dict, action: str = 'allow',
                             description: str = None) -> Optional[int]:
        """Add a behavior rule to a template"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO template_behaviors
                (template_id, behavior_type, parameters, action, description)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            ''', (template_id, behavior_type, json.dumps(parameters), action, description))
            behavior_id = cursor.fetchone()[0]
            conn.commit()
            return behavior_id
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error adding template behavior: {e}")
            return None
        finally:
            self._return_connection(conn)

    def get_template_behaviors(self, template_id: int) -> List[Dict]:
        """Get all behaviors for a template"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT * FROM template_behaviors
                WHERE template_id = %s
                ORDER BY behavior_type
            ''', (template_id,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting template behaviors: {e}")
            return []
        finally:
            self._return_connection(conn)

    def update_template_behavior(self, behavior_id: int, parameters: Dict = None,
                                action: str = None, description: str = None) -> bool:
        """Update a template behavior"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            updates = []
            params = []

            if parameters is not None:
                updates.append("parameters = %s")
                params.append(json.dumps(parameters))
            if action is not None:
                updates.append("action = %s")
                params.append(action)
            if description is not None:
                updates.append("description = %s")
                params.append(description)

            if not updates:
                return False

            params.append(behavior_id)
            cursor.execute(f'''
                UPDATE template_behaviors
                SET {', '.join(updates)}
                WHERE id = %s
            ''', params)

            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating template behavior: {e}")
            return False
        finally:
            self._return_connection(conn)

    def delete_template_behavior(self, behavior_id: int) -> bool:
        """Delete a template behavior"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM template_behaviors WHERE id = %s', (behavior_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deleting template behavior: {e}")
            return False
        finally:
            self._return_connection(conn)

    # ==================== Device Management ====================

    def register_device(self, ip_address: str, sensor_id: str = None,
                       mac_address: str = None, hostname: str = None,
                       vendor: str = None, template_id: int = None,
                       created_by: str = None) -> Optional[int]:
        """
        Register a new device or update if exists.

        Uses MAC address as primary identifier when available (important for DHCP
        environments where IP addresses change). Falls back to IP-based matching
        when MAC is not available.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # First check: Do we have a device with this MAC address? (DHCP-friendly)
            # This allows IP changes without creating duplicate device entries
            if mac_address:
                cursor.execute('''
                    SELECT id, ip_address::text as ip_address FROM devices
                    WHERE mac_address = %s AND sensor_id = %s
                ''', (mac_address, sensor_id))
                existing = cursor.fetchone()

                if existing:
                    device_id, old_ip_raw = existing
                    # Normalize IP (strip /32 CIDR suffix from PostgreSQL INET type)
                    old_ip = old_ip_raw.split('/')[0] if old_ip_raw and '/' in old_ip_raw else old_ip_raw

                    # Only update if IP actually changed
                    if old_ip != ip_address:
                        try:
                            cursor.execute('''
                                UPDATE devices SET
                                    ip_address = %s,
                                    hostname = COALESCE(%s, hostname),
                                    vendor = COALESCE(%s, vendor),
                                    last_seen = NOW(),
                                    is_active = TRUE
                                WHERE id = %s
                                RETURNING id
                            ''', (ip_address, hostname, vendor, device_id))
                            device_id = cursor.fetchone()[0]
                            conn.commit()
                            self.logger.info(f"Device IP updated: {old_ip} -> {ip_address} (MAC: {mac_address})")
                        except errors.UniqueViolation:
                            # New IP already exists for another device - just update last_seen
                            conn.rollback()
                            cursor.execute('''
                                UPDATE devices SET
                                    hostname = COALESCE(%s, hostname),
                                    vendor = COALESCE(%s, vendor),
                                    last_seen = NOW(),
                                    is_active = TRUE
                                WHERE id = %s
                                RETURNING id
                            ''', (hostname, vendor, device_id))
                            device_id = cursor.fetchone()[0]
                            conn.commit()
                    else:
                        # Just update last_seen, hostname, vendor
                        cursor.execute('''
                            UPDATE devices SET
                                hostname = COALESCE(%s, hostname),
                                vendor = COALESCE(%s, vendor),
                                last_seen = NOW(),
                                is_active = TRUE
                            WHERE id = %s
                            RETURNING id
                        ''', (hostname, vendor, device_id))
                        device_id = cursor.fetchone()[0]
                        conn.commit()

                    return device_id

            # No MAC or MAC not found - use IP-based matching with UPSERT
            cursor.execute('''
                INSERT INTO devices
                (ip_address, sensor_id, mac_address, hostname, vendor, template_id, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT ON CONSTRAINT unique_device_per_sensor
                DO UPDATE SET
                    mac_address = COALESCE(EXCLUDED.mac_address, devices.mac_address),
                    hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                    vendor = COALESCE(EXCLUDED.vendor, devices.vendor),
                    last_seen = NOW(),
                    is_active = TRUE
                RETURNING id
            ''', (ip_address, sensor_id, mac_address, hostname, vendor, template_id, created_by))
            device_id = cursor.fetchone()[0]
            conn.commit()
            return device_id
        except errors.UniqueViolation:
            # Race condition or constraint violation - try simple UPDATE
            conn.rollback()
            try:
                cursor.execute('''
                    UPDATE devices SET
                        mac_address = COALESCE(%s, mac_address),
                        hostname = COALESCE(%s, hostname),
                        vendor = COALESCE(%s, vendor),
                        last_seen = NOW(),
                        is_active = TRUE
                    WHERE ip_address = %s AND sensor_id = %s
                    RETURNING id
                ''', (mac_address, hostname, vendor, ip_address, sensor_id))
                result = cursor.fetchone()
                if result:
                    conn.commit()
                    return result[0]
            except Exception:
                conn.rollback()
            return None
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error registering device: {e}")
            return None
        finally:
            self._return_connection(conn)

    def get_devices(self, sensor_id: str = None, template_id: int = None,
                   include_inactive: bool = False) -> List[Dict]:
        """Get all devices with optional filters"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            query = '''
                SELECT d.*,
                       d.ip_address::text as ip_address,
                       d.mac_address::text as mac_address,
                       t.name as template_name,
                       t.icon as template_icon,
                       t.category as template_category
                FROM devices d
                LEFT JOIN device_templates t ON d.template_id = t.id
                WHERE 1=1
            '''
            params = []

            if not include_inactive:
                query += ' AND d.is_active = TRUE'

            if sensor_id:
                query += ' AND d.sensor_id = %s'
                params.append(sensor_id)

            if template_id:
                query += ' AND d.template_id = %s'
                params.append(template_id)

            query += ' ORDER BY d.last_seen DESC'
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting devices: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_device_by_ip(self, ip_address: str, sensor_id: str = None) -> Optional[Dict]:
        """Get a specific device by IP address"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            query = '''
                SELECT d.*,
                       d.ip_address::text as ip_address,
                       d.mac_address::text as mac_address,
                       t.name as template_name,
                       t.icon as template_icon
                FROM devices d
                LEFT JOIN device_templates t ON d.template_id = t.id
                WHERE d.ip_address = %s
            '''
            params = [ip_address]

            if sensor_id:
                query += ' AND d.sensor_id = %s'
                params.append(sensor_id)

            cursor.execute(query, params)
            result = cursor.fetchone()
            return dict(result) if result else None
        except Exception as e:
            self.logger.error(f"Error getting device by IP: {e}")
            return None
        finally:
            self._return_connection(conn)

    def update_device_vendor(self, device_id: int, vendor: str) -> bool:
        """Update the vendor for a device"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE devices
                SET vendor = %s
                WHERE id = %s
            ''', (vendor, device_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating device vendor: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_devices_without_vendor(self) -> List[Dict]:
        """Get all devices that have a MAC address but no/unknown vendor"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''
                SELECT id, ip_address::text as ip_address, mac_address::text as mac_address
                FROM devices
                WHERE mac_address IS NOT NULL
                  AND (vendor IS NULL OR vendor = '' OR vendor = 'Unknown')
            ''')
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting devices without vendor: {e}")
            return []
        finally:
            self._return_connection(conn)

    def assign_device_template(self, device_id: int, template_id: int,
                              confidence: float = 1.0,
                              method: str = 'manual') -> bool:
        """Assign a template to a device"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE devices
                SET template_id = %s,
                    classification_confidence = %s,
                    classification_method = %s,
                    last_seen = NOW()
                WHERE id = %s
            ''', (template_id, confidence, method, device_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error assigning device template: {e}")
            return False
        finally:
            self._return_connection(conn)

    def update_device_learned_behavior(self, device_id: int,
                                       learned_behavior: Dict) -> bool:
        """Update the learned behavior profile of a device"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE devices
                SET learned_behavior = %s,
                    last_seen = NOW()
                WHERE id = %s
            ''', (json.dumps(learned_behavior), device_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating device learned behavior: {e}")
            return False
        finally:
            self._return_connection(conn)

    def update_device_classification(self, device_id: int,
                                     classification_method: str,
                                     classification_confidence: float) -> bool:
        """
        Update only the classification fields of a device (not the template).
        Used by ML classifier to store classification results.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE devices
                SET classification_method = %s,
                    classification_confidence = %s,
                    last_seen = NOW()
                WHERE id = %s
            ''', (classification_method, classification_confidence, device_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating device classification: {e}")
            return False
        finally:
            self._return_connection(conn)

    def touch_device(self, device_id: int = None, ip_address: str = None) -> bool:
        """
        Update a device's last_seen timestamp to NOW().
        Use this to manually refresh activity for devices that don't generate much traffic.

        Args:
            device_id: Device ID (preferred)
            ip_address: IP address (alternative, updates all matching devices)

        Returns:
            True if at least one device was updated
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            if device_id:
                cursor.execute('''
                    UPDATE devices
                    SET last_seen = NOW(), is_active = TRUE
                    WHERE id = %s
                ''', (device_id,))
            elif ip_address:
                # Normalize IP address
                clean_ip = ip_address.split('/')[0] if '/' in ip_address else ip_address
                cursor.execute('''
                    UPDATE devices
                    SET last_seen = NOW(), is_active = TRUE
                    WHERE ip_address = %s::inet
                ''', (clean_ip,))
            else:
                return False

            conn.commit()
            updated = cursor.rowcount > 0
            if updated:
                self.logger.info(f"Touched device: id={device_id}, ip={ip_address}")
            return updated
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error touching device: {e}")
            return False
        finally:
            self._return_connection(conn)

    def touch_devices_bulk(self, ip_addresses: list) -> int:
        """
        Update last_seen for multiple devices at once.

        Args:
            ip_addresses: List of IP addresses to touch

        Returns:
            Number of devices updated
        """
        if not ip_addresses:
            return 0

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Clean IP addresses
            clean_ips = [ip.split('/')[0] if '/' in ip else ip for ip in ip_addresses]

            cursor.execute('''
                UPDATE devices
                SET last_seen = NOW(), is_active = TRUE
                WHERE ip_address = ANY(%s::inet[])
            ''', (clean_ips,))

            conn.commit()
            updated = cursor.rowcount
            self.logger.info(f"Bulk touched {updated} devices")
            return updated
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error bulk touching devices: {e}")
            return 0
        finally:
            self._return_connection(conn)

    def delete_device(self, device_id: int) -> bool:
        """Delete a device by ID (soft delete)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE devices
                SET is_active = FALSE
                WHERE id = %s
            ''', (device_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deleting device: {e}")
            return False
        finally:
            self._return_connection(conn)

    def delete_device_by_ip(self, ip_address: str) -> bool:
        """Delete a device by IP address (soft delete)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Normalize IP address - remove /32 suffix if present
            ip_clean = ip_address.replace('/32', '')

            # Use host() function to compare just the IP without CIDR mask
            cursor.execute('''
                UPDATE devices
                SET is_active = FALSE
                WHERE (host(ip_address) = %s OR ip_address::text = %s OR ip_address::text = %s)
                  AND is_active = TRUE
            ''', (ip_clean, ip_clean, f"{ip_clean}/32"))
            conn.commit()
            deleted = cursor.rowcount > 0
            if deleted:
                self.logger.info(f"Deleted device: {ip_address}")
            else:
                self.logger.warning(f"Device not found for deletion: {ip_address}")
            return deleted
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deleting device by IP {ip_address}: {e}")
            return False
        finally:
            self._return_connection(conn)

    # ==================== Service Provider Management ====================

    def create_service_provider(self, name: str, category: str,
                               ip_ranges: List[str] = None,
                               domains: List[str] = None,
                               description: str = None,
                               is_builtin: bool = False,
                               created_by: str = None) -> Optional[int]:
        """Create a new service provider"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO service_providers
                (name, category, ip_ranges, domains, description, is_builtin, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (name, category,
                  json.dumps(ip_ranges or []),
                  json.dumps(domains or []),
                  description, is_builtin, created_by))
            provider_id = cursor.fetchone()[0]
            conn.commit()
            self.logger.info(f"Service provider created: {name} (ID: {provider_id})")
            return provider_id
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating service provider: {e}")
            return None
        finally:
            self._return_connection(conn)

    def get_service_providers(self, category: str = None,
                             include_inactive: bool = False) -> List[Dict]:
        """Get all service providers"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            query = 'SELECT * FROM service_providers WHERE 1=1'
            params = []

            if not include_inactive:
                query += ' AND is_active = TRUE'

            if category:
                query += ' AND category = %s'
                params.append(category)

            query += ' ORDER BY category, name'
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting service providers: {e}")
            return []
        finally:
            self._return_connection(conn)

    def get_service_provider_by_id(self, provider_id: int) -> Optional[Dict]:
        """Get a specific service provider"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('SELECT * FROM service_providers WHERE id = %s', (provider_id,))
            result = cursor.fetchone()
            return dict(result) if result else None
        except Exception as e:
            self.logger.error(f"Error getting service provider: {e}")
            return None
        finally:
            self._return_connection(conn)

    def update_service_provider(self, provider_id: int, **kwargs) -> bool:
        """Update a service provider"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            allowed_fields = ['name', 'category', 'ip_ranges', 'domains',
                            'description', 'is_active']
            updates = []
            params = []

            for field in allowed_fields:
                if field in kwargs:
                    if field in ['ip_ranges', 'domains']:
                        updates.append(f"{field} = %s")
                        params.append(json.dumps(kwargs[field]))
                    else:
                        updates.append(f"{field} = %s")
                        params.append(kwargs[field])

            if not updates:
                return False

            updates.append("updated_at = NOW()")
            params.append(provider_id)

            cursor.execute(f'''
                UPDATE service_providers
                SET {', '.join(updates)}
                WHERE id = %s
            ''', params)

            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error updating service provider: {e}")
            return False
        finally:
            self._return_connection(conn)

    def delete_service_provider(self, provider_id: int) -> bool:
        """Delete a service provider (soft delete)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Check if builtin
            cursor.execute('SELECT is_builtin FROM service_providers WHERE id = %s', (provider_id,))
            result = cursor.fetchone()
            if result and result[0]:
                self.logger.warning(f"Cannot delete builtin service provider {provider_id}")
                return False

            cursor.execute('''
                UPDATE service_providers
                SET is_active = FALSE, updated_at = NOW()
                WHERE id = %s
            ''', (provider_id,))

            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error deleting service provider: {e}")
            return False
        finally:
            self._return_connection(conn)

    def get_all_service_provider_ip_ranges(self, category: str = None) -> List[str]:
        """Get all IP ranges from active service providers (for detector filtering)"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            query = '''
                SELECT ip_ranges FROM service_providers
                WHERE is_active = TRUE
            '''
            params = []

            if category:
                query += ' AND category = %s'
                params.append(category)

            cursor.execute(query, params)

            all_ranges = []
            for row in cursor.fetchall():
                ranges = row[0]
                if ranges:
                    # JSONB is already parsed
                    if isinstance(ranges, list):
                        all_ranges.extend(ranges)
                    elif isinstance(ranges, str):
                        all_ranges.extend(json.loads(ranges))

            return all_ranges
        except Exception as e:
            self.logger.error(f"Error getting service provider IP ranges: {e}")
            return []
        finally:
            self._return_connection(conn)

    def check_ip_in_service_providers(self, ip_address: str,
                                      category: str = None) -> Optional[Dict]:
        """Check if an IP belongs to any service provider"""
        import ipaddress

        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return None

        providers = self.get_service_providers(category=category)

        for provider in providers:
            ip_ranges = provider.get('ip_ranges', [])
            if isinstance(ip_ranges, str):
                ip_ranges = json.loads(ip_ranges)

            for ip_range in ip_ranges:
                try:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ip in network:
                        return {
                            'provider_id': provider['id'],
                            'provider_name': provider['name'],
                            'category': provider['category'],
                            'matched_range': ip_range
                        }
                except ValueError:
                    continue

        return None

    # ==================== Builtin Data Initialization ====================

    def init_builtin_templates(self) -> int:
        """Initialize builtin device templates"""
        builtin_templates = [
            {
                'name': 'IP Camera',
                'description': 'Network surveillance camera (RTSP, ONVIF)',
                'icon': 'camera',
                'category': 'iot',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 554, 8080, 8554]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'RTSP']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'max_outbound_mbps': 10, 'continuous': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Smart Speaker',
                'description': 'Voice assistant device (Alexa, Google Home, HomePod)',
                'icon': 'speaker',
                'category': 'iot',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 8443]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'mDNS', 'SSDP']}, 'action': 'allow'},
                    {'type': 'dns_behavior', 'params': {'allow_cloud_dns': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Smart TV',
                'description': 'Internet-connected television',
                'icon': 'tv',
                'category': 'iot',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 8080, 8443]}, 'action': 'allow'},
                    {'type': 'expected_destinations', 'params': {'categories': ['streaming', 'cdn']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'max_outbound_mbps': 50, 'streaming': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Web Server',
                'description': 'HTTP/HTTPS web server',
                'icon': 'server',
                'category': 'server',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'high_connection_rate': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'File Server (NAS)',
                'description': 'Network Attached Storage device',
                'icon': 'storage',
                'category': 'server',
                'behaviors': [
                    # Outbound behaviors
                    {'type': 'traffic_pattern', 'params': {'high_bandwidth': True, 'internal_only': True}, 'action': 'allow'},
                    # Inbound behaviors - NAS receives many connections for file access
                    {'type': 'allowed_ports', 'params': {'ports': [21, 22, 80, 139, 443, 445, 548, 873, 2049, 3260], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_sources', 'params': {'internal': True}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'high_connection_rate': True, 'accepts_connections': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Database Server',
                'description': 'Database server (MySQL, PostgreSQL, MongoDB)',
                'icon': 'database',
                'category': 'server',
                'behaviors': [
                    # Inbound behaviors - database servers receive connections from apps
                    {'type': 'allowed_ports', 'params': {'ports': [1433, 1521, 3306, 5432, 27017], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_sources', 'params': {'internal': True}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'high_connection_rate': True, 'accepts_connections': True}, 'action': 'allow'},
                    {'type': 'expected_destinations', 'params': {'internal_only': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Printer',
                'description': 'Network printer or multifunction device',
                'icon': 'printer',
                'category': 'iot',
                'behaviors': [
                    # Inbound behaviors - printers receive print jobs
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 515, 631, 9100], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_sources', 'params': {'internal': True}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'mDNS', 'SNMP']}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Workstation',
                'description': 'Desktop computer or laptop',
                'icon': 'computer',
                'category': 'endpoint',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443], 'direction': 'outbound'}, 'action': 'allow'},
                    {'type': 'dns_behavior', 'params': {'normal_queries': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Mobile Device',
                'description': 'Smartphone or tablet',
                'icon': 'phone',
                'category': 'endpoint',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443]}, 'action': 'allow'},
                    {'type': 'expected_destinations', 'params': {'categories': ['streaming', 'cdn', 'cloud']}, 'action': 'allow'},
                ]
            },
            {
                'name': 'IoT Sensor',
                'description': 'Generic IoT sensor or actuator',
                'icon': 'sensors',
                'category': 'iot',
                'behaviors': [
                    {'type': 'connection_behavior', 'params': {'low_frequency': True, 'periodic': True}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'low_bandwidth': True}, 'action': 'allow'},
                ]
            },
            # Network Infrastructure
            {
                'name': 'Access Point',
                'description': 'WiFi access point or wireless controller',
                'icon': 'router',
                'category': 'infrastructure',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [22, 80, 443, 8080, 8443]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'ICMP', 'RADIUS']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'high_bandwidth': True, 'continuous': True}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'high_connection_rate': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Network Switch',
                'description': 'Managed network switch',
                'icon': 'hub',
                'category': 'infrastructure',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [22, 23, 80, 161, 443, 830]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'ICMP', 'SNMP', 'LLDP', 'STP']}, 'action': 'allow'},
                    {'type': 'expected_destinations', 'params': {'internal_only': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'UniFi Controller',
                'description': 'Ubiquiti UniFi Network Controller - create a COPY with your allowed external source IPs',
                'icon': 'cloud',
                'category': 'server',
                'behaviors': [
                    # UniFi Controller inbound ports
                    {'type': 'allowed_ports', 'params': {'ports': [8443, 8080, 8880, 8843, 6789, 27117], 'direction': 'inbound'}, 'action': 'allow'},
                    # STUN port for remote APs
                    {'type': 'allowed_ports', 'params': {'ports': [3478], 'protocols': ['UDP'], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP']}, 'action': 'allow'},
                    # Example: Add your external AP IPs here (create custom template)
                    # {'type': 'allowed_sources', 'params': {'subnets': ['203.0.113.0/24']}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'high_connection_rate': True, 'accepts_connections': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'UniFi Controller Client',
                'description': 'External UniFi device connecting to internal controller (customize allowed_ips with your controller IP)',
                'icon': 'wifi',
                'category': 'infrastructure',
                'behaviors': [
                    # UniFi ports: 8443 (controller UI/API), 8080 (device inform), 3478 (STUN), 6789 (speed test)
                    {'type': 'allowed_ports', 'params': {'ports': [8443, 8080, 3478, 6789, 10001], 'direction': 'outbound'}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP']}, 'action': 'allow'},
                    # IMPORTANT: Replace with your actual UniFi controller IP(s)
                    {'type': 'expected_destinations', 'params': {'allowed_ips': ['192.168.1.1']}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'periodic': True, 'low_frequency': True}, 'action': 'allow'},
                ]
            },
            # Server types
            {
                'name': 'DNS Server',
                'description': 'Domain Name System server',
                'icon': 'dns',
                'category': 'server',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [53, 853, 5353], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'DNS']}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'high_connection_rate': True}, 'action': 'allow'},
                    {'type': 'expected_destinations', 'params': {'internal_only': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'DHCP Server',
                'description': 'Dynamic Host Configuration Protocol server',
                'icon': 'settings_ethernet',
                'category': 'server',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [67, 68, 546, 547]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['UDP', 'DHCP']}, 'action': 'allow'},
                    {'type': 'expected_destinations', 'params': {'internal_only': True}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'low_bandwidth': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'PBX Server',
                'description': 'VoIP/SIP telephone exchange (Asterisk, FreePBX, 3CX)',
                'icon': 'phone_in_talk',
                'category': 'server',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 5060, 5061, 5080, 5443, 8089, 10000, 20000]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'SIP', 'RTP', 'SRTP']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'continuous': True, 'voice_traffic': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Remote Desktop Server',
                'description': 'Remote desktop/terminal server (RDP, VNC, SSH)',
                'icon': 'desktop_windows',
                'category': 'server',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [22, 3389, 5900, 5901, 5902], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'RDP']}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'long_sessions': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Windows/Samba Server',
                'description': 'Windows file sharing or Samba server (SMB/CIFS)',
                'icon': 'folder_shared',
                'category': 'server',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [135, 137, 138, 139, 445, 3268, 3269], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'SMB', 'NetBIOS']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'high_bandwidth': True, 'internal_only': True}, 'action': 'allow'},
                    {'type': 'expected_destinations', 'params': {'internal_only': True}, 'action': 'allow'},
                ]
            },
            # Domotica / Home Automation
            {
                'name': 'Smart Plug',
                'description': 'WiFi-controlled power outlet (Tuya, Shelly, TP-Link Kasa)',
                'icon': 'power',
                'category': 'iot',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 6668, 8883]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'MQTT']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'low_bandwidth': True, 'periodic': True}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'low_frequency': True, 'periodic': True, 'small_packets': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Smart Light',
                'description': 'WiFi/Zigbee smart bulb or light controller (Philips Hue, LIFX, Yeelight)',
                'icon': 'lightbulb',
                'category': 'iot',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 8080, 8443, 56700]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'mDNS', 'SSDP']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'low_bandwidth': True, 'bursty': True}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'low_frequency': True, 'event_driven': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Smart Thermostat',
                'description': 'WiFi thermostat (Nest, Ecobee, Tado, Honeywell)',
                'icon': 'thermostat',
                'category': 'iot',
                'behaviors': [
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 8883]}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'MQTT']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'low_bandwidth': True, 'periodic': True}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'periodic': True, 'cloud_connected': True}, 'action': 'allow'},
                    {'type': 'dns_behavior', 'params': {'allow_cloud_dns': True}, 'action': 'allow'},
                ]
            },
            {
                'name': 'Home Automation Hub',
                'description': 'Smart home controller (Home Assistant, Hubitat, SmartThings)',
                'icon': 'home',
                'category': 'iot',
                'behaviors': [
                    # Outbound behaviors (traffic FROM this device)
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 1883, 8080, 8123, 8883], 'direction': 'outbound'}, 'action': 'allow'},
                    {'type': 'allowed_protocols', 'params': {'protocols': ['TCP', 'UDP', 'MQTT', 'mDNS', 'SSDP', 'CoAP']}, 'action': 'allow'},
                    {'type': 'traffic_pattern', 'params': {'moderate_bandwidth': True, 'continuous': True}, 'action': 'allow'},
                    # Inbound behaviors (traffic TO this device) - new!
                    {'type': 'allowed_ports', 'params': {'ports': [80, 443, 8080, 8123, 8443, 21063], 'direction': 'inbound'}, 'action': 'allow'},
                    {'type': 'allowed_sources', 'params': {'internal': True}, 'action': 'allow'},
                    {'type': 'connection_behavior', 'params': {'high_connection_rate': True, 'accepts_connections': True, 'api_server': True}, 'action': 'allow'},
                ]
            },
        ]

        count = 0
        for template_data in builtin_templates:
            # Check if already exists
            existing = self.get_device_templates()
            if any(t['name'] == template_data['name'] for t in existing):
                continue

            template_id = self.create_device_template(
                name=template_data['name'],
                description=template_data['description'],
                icon=template_data['icon'],
                category=template_data['category'],
                is_builtin=True,
                created_by='system'
            )

            if template_id:
                for behavior in template_data.get('behaviors', []):
                    self.add_template_behavior(
                        template_id=template_id,
                        behavior_type=behavior['type'],
                        parameters=behavior['params'],
                        action=behavior['action']
                    )
                count += 1

        self.logger.info(f"Initialized {count} builtin device templates")
        return count

    def init_builtin_service_providers(self) -> int:
        """Initialize builtin service providers from config defaults"""
        builtin_providers = [
            {
                'name': 'Netflix',
                'category': 'streaming',
                'description': 'Netflix streaming service',
                'ip_ranges': [
                    '23.246.0.0/18', '37.77.184.0/21', '45.57.0.0/17',
                    '64.120.128.0/17', '66.197.128.0/17', '108.175.32.0/20',
                    '185.2.220.0/22', '185.9.188.0/22', '192.173.64.0/18',
                    '198.38.96.0/19', '198.45.48.0/20', '208.75.76.0/22',
                    '2620:10c:7000::/44'
                ]
            },
            {
                'name': 'Google/YouTube',
                'category': 'streaming',
                'description': 'Google services including YouTube',
                'ip_ranges': [
                    '142.250.0.0/15', '172.217.0.0/16', '173.194.0.0/16',
                    '216.58.192.0/19', '2001:4860::/32'
                ]
            },
            {
                'name': 'Amazon CloudFront',
                'category': 'cdn',
                'description': 'Amazon CloudFront CDN (Prime Video)',
                'ip_ranges': [
                    '13.32.0.0/15', '13.224.0.0/14', '13.249.0.0/16',
                    '18.64.0.0/14', '2600:9000::/28'
                ]
            },
            {
                'name': 'Cloudflare',
                'category': 'cdn',
                'description': 'Cloudflare CDN and security services',
                'ip_ranges': [
                    '104.16.0.0/13', '172.64.0.0/13', '162.158.0.0/15',
                    '2606:4700::/32'
                ]
            },
            {
                'name': 'Akamai',
                'category': 'cdn',
                'description': 'Akamai CDN services',
                'ip_ranges': [
                    '23.32.0.0/11', '23.192.0.0/11', '95.100.0.0/15',
                    '2.16.0.0/13', '184.24.0.0/13', '2600:1400::/24'
                ]
            },
        ]

        count = 0
        for provider_data in builtin_providers:
            # Check if already exists
            existing = self.get_service_providers()
            if any(p['name'] == provider_data['name'] for p in existing):
                continue

            provider_id = self.create_service_provider(
                name=provider_data['name'],
                category=provider_data['category'],
                description=provider_data['description'],
                ip_ranges=provider_data['ip_ranges'],
                is_builtin=True,
                created_by='system'
            )

            if provider_id:
                count += 1

        self.logger.info(f"Initialized {count} builtin service providers")
        return count

    def close(self):
        """Close all connections in the pool"""
        if hasattr(self, 'connection_pool'):
            self.connection_pool.closeall()
            self.logger.info("Database connection pool closed")
