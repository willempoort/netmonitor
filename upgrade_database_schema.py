#!/usr/bin/env python3
"""
Database Schema Upgrade Tool
Checks current schema version and upgrades if needed
"""

import sys
import os

# Add current dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import DatabaseManager
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main():
    print("=" * 70)
    print("NetMonitor Database Schema Upgrade Tool")
    print("=" * 70)
    print()

    # Load config
    from config_loader import load_config
    config = load_config('config.yaml')

    db_config = config.get('database', {})
    db_type = db_config.get('type', None)

    if db_type not in ('postgresql', 'sqlite'):
        print("❌ Database is not configured in config.yaml")
        print(f"   Current type: {db_type or 'Not set'}")
        print()
        print("   Set database.type to 'postgresql' or 'sqlite'")
        return 1

    # Initialize database manager (will auto-upgrade schema)
    print("🔍 Connecting to database...")
    try:
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
            # SQLite
            sqlite_config = db_config.get('sqlite', {})
            db = DatabaseManager(db_path=sqlite_config.get('path', '/var/lib/netmonitor/netmonitor.db'))
        print("✓ Connected successfully")
        print()

        # Check schema version
        conn = db._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT schema_version, last_updated FROM netmonitor_meta LIMIT 1")
        row = cursor.fetchone()

        if row:
            version, last_updated = row
            print(f"📊 Current Schema Version: {version}")
            print(f"📅 Last Updated: {last_updated}")
        else:
            print("❌ No schema version found")

        print()

        # Check if sensor_configs table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'sensor_configs'
            )
        """)

        sensor_configs_exists = cursor.fetchone()[0]

        if sensor_configs_exists:
            print("✓ sensor_configs table EXISTS")

            # Count parameters
            cursor.execute("SELECT COUNT(*), COUNT(DISTINCT parameter_path) FROM sensor_configs")
            total, unique = cursor.fetchone()
            print(f"  - {total} total entries")
            print(f"  - {unique} unique parameters")

            # Check for threat.* parameters
            cursor.execute("SELECT COUNT(*) FROM sensor_configs WHERE parameter_path LIKE 'threat.%'")
            threat_count = cursor.fetchone()[0]
            print(f"  - {threat_count} threat detection parameters")

            # Check for old advanced_threats.* parameters
            cursor.execute("SELECT COUNT(*) FROM sensor_configs WHERE parameter_path LIKE 'advanced_threats.%'")
            old_count = cursor.fetchone()[0]

            if old_count > 0:
                print()
                print(f"⚠️  Found {old_count} old 'advanced_threats.*' parameters")
                print("   These should be migrated to 'threat.*' prefix")
                print()

                response = input("   Run migration now? (y/n): ")
                if response.lower() == 'y':
                    cursor.execute("""
                        UPDATE sensor_configs
                        SET parameter_path = 'threat.' || substring(parameter_path from 19)
                        WHERE parameter_path LIKE 'advanced_threats.%'
                        RETURNING parameter_path
                    """)
                    migrated = cursor.fetchall()
                    conn.commit()
                    print(f"   ✓ Migrated {len(migrated)} parameters to 'threat.*' prefix")

                    for (path,) in migrated:
                        print(f"     - {path}")
        else:
            print("❌ sensor_configs table DOES NOT EXIST")
            print()
            print("The database schema needs to be upgraded.")
            print("The DatabaseManager should have automatically created the table.")
            print()
            print("Possible issues:")
            print("  1. Database user lacks CREATE TABLE permissions")
            print("  2. Schema upgrade failed during initialization")
            print("  3. Database connection issues")
            print()
            print("Try restarting NetMonitor to trigger schema upgrade:")
            print("  sudo systemctl restart netmonitor")

        db._return_connection(conn)
        db.close()

        print()
        print("=" * 70)
        return 0

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
