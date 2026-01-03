#!/usr/bin/env python3
"""
Direct migration script to add suppress_alert_types to CHECK constraint
Run this before update_unifi_template.py
"""

import sys
import os
import psycopg2
import yaml

def migrate_constraint():
    """Update the valid_behavior_type CHECK constraint"""

    # Load config
    config_file = 'config.yaml'
    if not os.path.exists(config_file):
        print(f"❌ Config file niet gevonden: {config_file}")
        print("   Run dit script vanuit de /opt/netmonitor directory")
        return False

    with open(config_file, 'r') as f:
        full_config = yaml.safe_load(f)

    if 'database' not in full_config:
        print("❌ Database config niet gevonden in config.yaml")
        return False

    db_config = full_config['database']

    # Flatten postgresql config if present
    if db_config.get('type') == 'postgresql' and 'postgresql' in db_config:
        pg_config = db_config['postgresql']
        config = {
            'host': pg_config.get('host', 'localhost'),
            'port': pg_config.get('port', 5432),
            'database': pg_config.get('database', 'netmonitor'),
            'user': pg_config.get('user', 'netmonitor'),
            'password': pg_config.get('password', ''),
        }
    else:
        config = db_config

    print(f"📊 Connecting to database: {config.get('host', 'localhost')}:{config.get('port', 5432)}")

    try:
        # Connect directly with psycopg2
        conn = psycopg2.connect(
            host=config.get('host', 'localhost'),
            port=config.get('port', 5432),
            database=config.get('database', 'netmonitor'),
            user=config.get('user', 'netmonitor'),
            password=config.get('password', 'netmonitor')
        )

        cursor = conn.cursor()

        # Check current constraint
        print("🔍 Checking current constraint...")
        cursor.execute("""
            SELECT pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conname = 'valid_behavior_type'
            AND conrelid = 'template_behaviors'::regclass
        """)

        result = cursor.fetchone()
        if result:
            current_def = result[0]
            print(f"   Current: {current_def[:100]}...")

            if 'suppress_alert_types' in current_def:
                print("✅ Constraint bevat al 'suppress_alert_types'!")
                conn.close()
                return True

        # Update constraint
        print("⚙️  Updating constraint...")
        cursor.execute("""
            ALTER TABLE template_behaviors DROP CONSTRAINT IF EXISTS valid_behavior_type;
        """)

        cursor.execute("""
            ALTER TABLE template_behaviors ADD CONSTRAINT valid_behavior_type CHECK (
                behavior_type IN (
                    'allowed_ports', 'allowed_protocols', 'allowed_sources',
                    'expected_destinations', 'traffic_pattern', 'connection_behavior',
                    'dns_behavior', 'time_restrictions', 'bandwidth_limit', 'suppress_alert_types'
                )
            );
        """)

        conn.commit()

        # Verify
        cursor.execute("""
            SELECT pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conname = 'valid_behavior_type'
            AND conrelid = 'template_behaviors'::regclass
        """)

        result = cursor.fetchone()
        if result and 'suppress_alert_types' in result[0]:
            print("✅ Constraint succesvol bijgewerkt!")
            print(f"   Nieuwe definitie: {result[0][:150]}...")
            conn.close()
            return True
        else:
            print("❌ Verificatie mislukt")
            conn.close()
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("Database Constraint Migration (v2.8)")
    print("=" * 60)
    print()

    success = migrate_constraint()

    if success:
        print()
        print("🎯 Nu kun je update_unifi_template.py runnen!")

    sys.exit(0 if success else 1)
