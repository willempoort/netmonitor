#!/usr/bin/env python3
"""
Update UniFi Controller template met suppress_alert_types behavior
Voor v2.8 release
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import DatabaseManager
import yaml

def update_unifi_template():
    """Update UniFi Controller template met nieuwe suppress_alert_types behavior"""

    # Load config
    config_file = 'config.yaml'
    if not os.path.exists(config_file):
        print(f"❌ Config file niet gevonden: {config_file}")
        print("   Run dit script vanuit de /opt/netmonitor directory")
        return False

    with open(config_file, 'r') as f:
        full_config = yaml.safe_load(f)

    # Extract database config - DatabaseManager expects it at root level
    if 'database' not in full_config:
        print("❌ Database config niet gevonden in config.yaml")
        return False

    db_config = full_config['database']

    # DatabaseManager expects flattened config, but config.yaml has nested structure
    # Flatten postgresql config if present
    if db_config.get('type') == 'postgresql' and 'postgresql' in db_config:
        pg_config = db_config['postgresql']
        config = {
            'type': 'postgresql',
            'host': pg_config.get('host', 'localhost'),
            'port': pg_config.get('port', 5432),
            'database': pg_config.get('database', 'netmonitor'),
            'user': pg_config.get('user', 'netmonitor'),
            'password': pg_config.get('password', ''),
            'min_connections': pg_config.get('min_connections', 2),
            'max_connections': pg_config.get('max_connections', 10)
        }
    else:
        config = db_config

    print(f"📊 Connecting to database: {config.get('host', 'localhost')}:{config.get('port', 5432)}")

    # DatabaseManager expects individual parameters, not a dict
    db = DatabaseManager(
        host=config.get('host', 'localhost'),
        port=config.get('port', 5432),
        database=config.get('database', 'netmonitor'),
        user=config.get('user', 'netmonitor'),
        password=config.get('password', 'netmonitor'),
        min_connections=config.get('min_connections', 2),
        max_connections=config.get('max_connections', 10)
    )

    try:
        # Find UniFi Controller template
        templates = db.get_device_templates()
        unifi_template = None

        for template in templates:
            if template['name'] == 'UniFi Controller':
                unifi_template = template
                break

        if not unifi_template:
            print("❌ UniFi Controller template niet gevonden!")
            print("   Templates worden aangemaakt bij eerste server start.")
            return False

        template_id = unifi_template['id']
        print(f"✓ UniFi Controller template gevonden (ID: {template_id})")

        # Check if suppress_alert_types already exists
        details = db.get_device_template_by_id(template_id)
        behaviors = details.get('behaviors', [])

        has_suppress = any(
            b.get('behavior_type') == 'suppress_alert_types'
            for b in behaviors
        )

        if has_suppress:
            print("✓ suppress_alert_types behavior bestaat al!")
            return True

        # Add suppress_alert_types behavior
        print("⚙️  Voeg suppress_alert_types behavior toe...")

        cursor = db.conn.cursor()
        cursor.execute('''
            INSERT INTO template_behaviors (template_id, behavior_type, parameters, action, description)
            VALUES (%s, %s, %s, %s, %s)
        ''', (
            template_id,
            'suppress_alert_types',
            '{"alert_types": ["HTTP_SENSITIVE_DATA", "HTTP_HIGH_ENTROPY_PAYLOAD"]}',
            'allow',
            'UniFi management traffic bevat configuratie data die lijkt op sensitive data'
        ))
        db.conn.commit()

        print("✅ suppress_alert_types behavior toegevoegd!")
        print()
        print("📋 UniFi Controller template nu actief met:")

        # Show all behaviors
        details = db.get_device_template_by_id(template_id)
        behaviors = details.get('behaviors', [])

        for i, behavior in enumerate(behaviors, 1):
            print(f"   {i}. {behavior.get('behavior_type')}: {behavior.get('description', 'N/A')}")

        print()
        print("🎯 Assign dit template aan je UniFi controller:")
        print("   Dashboard → Settings → Devices → [UniFi Controller IP] → Template: 'UniFi Controller'")

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()

if __name__ == '__main__':
    print("=" * 60)
    print("UniFi Controller Template Updater (v2.8)")
    print("=" * 60)
    print()

    success = update_unifi_template()

    sys.exit(0 if success else 1)
