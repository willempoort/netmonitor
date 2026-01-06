#!/usr/bin/env python3
"""
Simple database status checker for NetMonitor
Shows what's configured and what's actually working
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config_loader import load_config

print("=" * 70)
print("NetMonitor Database Status Check")
print("=" * 70)
print()

# Load config
try:
    config = load_config('config.yaml')
    print("✓ config.yaml loaded successfully")
except Exception as e:
    print(f"✗ Failed to load config.yaml: {e}")
    sys.exit(1)

# Check database configuration
db_config = config.get('database', {})
db_type = db_config.get('type', None)

# Database is enabled if type is set (postgresql or sqlite)
db_enabled = db_type in ('postgresql', 'sqlite')

print(f"\n📋 Database Configuration:")
print(f"   Type: {db_type or 'Not configured'}")
print(f"   Enabled: {db_enabled}")

if not db_enabled:
    print()
    print("⚠️  Database is NOT CONFIGURED in config.yaml")
    print("   NetMonitor is running in standalone mode without database.")
    print()
    print("   This means:")
    print("   - No configuration management")
    print("   - No sensor_configs table")
    print("   - No threat detection parameters in database")
    print()
    print("   To enable database:")
    print("   1. Edit config.yaml")
    print("   2. Set database.type: postgresql")
    print("   3. Configure database connection settings")
    print("   4. Restart NetMonitor")
    sys.exit(0)

# Get connection settings based on database type
if db_type == 'postgresql':
    pg_config = db_config.get('postgresql', {})
    print(f"   Host: {pg_config.get('host', 'localhost')}")
    print(f"   Port: {pg_config.get('port', 5432)}")
    print(f"   Database: {pg_config.get('database', 'netmonitor')}")
    print(f"   User: {pg_config.get('user', 'netmonitor')}")
elif db_type == 'sqlite':
    sqlite_config = db_config.get('sqlite', {})
    print(f"   Path: {sqlite_config.get('path', '/var/lib/netmonitor/netmonitor.db')}")

# Try to connect
print(f"\n🔌 Testing database connection...")

try:
    from database import DatabaseManager

    # Initialize DatabaseManager with correct config structure
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
    else:
        # SQLite fallback
        sqlite_config = db_config.get('sqlite', {})
        db = DatabaseManager(db_path=sqlite_config.get('path', '/var/lib/netmonitor/netmonitor.db'))
    print("✓ Database connection successful!")

    # Check schema
    conn = db._get_connection()
    cursor = conn.cursor()

    # Check netmonitor_meta
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = 'netmonitor_meta'
        )
    """)
    has_meta = cursor.fetchone()[0]

    if has_meta:
        cursor.execute("SELECT schema_version, last_updated FROM netmonitor_meta LIMIT 1")
        row = cursor.fetchone()
        if row:
            version, updated = row
            print(f"✓ Schema version: {version}")
            print(f"  Last updated: {updated}")
    else:
        print("⚠️  netmonitor_meta table missing - creating now...")

        # Check if old schema_version table exists (pre-v13 databases)
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'schema_version'
            )
        """)
        has_old_schema = cursor.fetchone()[0]

        # Auto-create netmonitor_meta table for upgrades from old versions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS netmonitor_meta (
                id SERIAL PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                last_updated TIMESTAMPTZ DEFAULT NOW()
            );

            INSERT INTO netmonitor_meta (schema_version)
            VALUES (13)
            ON CONFLICT DO NOTHING;
        """)
        conn.commit()

        print("✓ netmonitor_meta table created with schema_version=13")
        if has_old_schema:
            print("  (Migrated from old schema_version table)")
        else:
            print("  (Upgrade from pre-versioning database detected)")

    # Check sensor_configs
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = 'sensor_configs'
        )
    """)
    has_configs = cursor.fetchone()[0]

    if has_configs:
        cursor.execute("SELECT COUNT(*) FROM sensor_configs")
        count = cursor.fetchone()[0]
        print(f"✓ sensor_configs table exists ({count} parameters)")

        # Check for old advanced_threats.* parameters that need migration
        cursor.execute("SELECT COUNT(*) FROM sensor_configs WHERE parameter_path LIKE 'advanced_threats.%'")
        old_count = cursor.fetchone()[0]

        if old_count > 0:
            print(f"\n⚠️  Found {old_count} old 'advanced_threats.*' parameters")
            print("   Auto-migrating to 'threat.*' prefix...")

            # Delete old advanced_threats.* parameters (replaced by threat.* in database)
            cursor.execute("DELETE FROM sensor_configs WHERE parameter_path LIKE 'advanced_threats.%'")
            deleted = cursor.rowcount

            # Remove duplicate threat.* entries (keep most recent)
            cursor.execute("""
                DELETE FROM sensor_configs
                WHERE id IN (
                    SELECT id
                    FROM (
                        SELECT id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY sensor_id, parameter_path
                                   ORDER BY updated_at DESC
                               ) as rn
                        FROM sensor_configs
                        WHERE parameter_path LIKE 'threat.%'
                    ) t
                    WHERE rn > 1
                )
            """)
            duplicates = cursor.rowcount

            conn.commit()

            print(f"   ✓ Deleted {deleted} old parameters")
            if duplicates > 0:
                print(f"   ✓ Removed {duplicates} duplicate entries")
            print("   ✓ Migration complete")
    else:
        print("✗ sensor_configs table does not exist")

    # List all tables
    cursor.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        ORDER BY table_name
    """)
    tables = [row[0] for row in cursor.fetchall()]

    print(f"\n📊 Database has {len(tables)} tables:")
    for table in tables:
        print(f"   - {table}")

    db._return_connection(conn)
    db.close()

    print()
    if not has_meta:
        print("⚡ Action Required:")
        print("   The database exists but is not initialized.")
        print("   Simply start NetMonitor to auto-create all tables:")
        print()
        print("   python netmonitor.py")
        print()
        print("   Or if running as service:")
        print("   sudo systemctl start netmonitor")

except Exception as e:
    print(f"✗ Database connection failed: {e}")
    print()
    print("Possible causes:")
    print("  - PostgreSQL is not running")
    print("  - Wrong connection settings in config.yaml")
    print("  - Database 'netmonitor' does not exist")
    print("  - User lacks permissions")

print()
print("=" * 70)
