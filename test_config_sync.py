#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Test script om SOC server config sync te diagnosticeren
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from database import DatabaseManager
from config_loader import load_config

def main():
    print("=" * 60)
    print("SOC Server Config Sync Diagnostics")
    print("=" * 60)
    print()

    # Load config.yaml
    print("[1] Loading config.yaml...")
    try:
        config = load_config("config.yaml")
        print("    ✓ config.yaml loaded successfully")

        # Check self_monitor settings
        self_monitor = config.get('self_monitor', {})
        enabled = self_monitor.get('enabled', False)
        sensor_id = self_monitor.get('sensor_id', 'soc-server')

        print(f"    - self_monitor.enabled: {enabled}")
        print(f"    - self_monitor.sensor_id: {sensor_id}")
        print()
    except Exception as e:
        print(f"    ✗ Failed to load config.yaml: {e}")
        return

    if not enabled:
        print("⚠️  Self-monitoring is DISABLED")
        print("   Set self_monitor.enabled: true in config.yaml")
        return

    # Test database connection
    print("[2] Testing database connection...")
    try:
        db_config = config.get('database', {})
        db_type = db_config.get('type', 'postgresql')

        if db_type != 'postgresql':
            print(f"    ✗ Unsupported database type: {db_type}")
            return

        pg_config = db_config.get('postgresql', {})
        db = DatabaseManager(
            host=pg_config.get('host', 'localhost'),
            port=pg_config.get('port', 5432),
            database=pg_config.get('database', 'netmonitor'),
            user=pg_config.get('user', 'netmonitor'),
            password=pg_config.get('password', 'netmonitor')
        )
        print("    ✓ Database connection successful")
        print(f"    - Connected to: {pg_config.get('host')}:{pg_config.get('port')}")
        print(f"    - Database: {pg_config.get('database')}")
        print()
    except Exception as e:
        print(f"    ✗ Database connection failed: {e}")
        print()
        print("⚠️  Cannot sync config without database connection")
        return

    # Test config loading from database
    print("[3] Loading config from database...")
    try:
        db_config_data = db.get_sensor_config(sensor_id=sensor_id)

        if not db_config_data:
            print(f"    ⚠️  No config found in database for sensor '{sensor_id}'")
            print("    Using config.yaml defaults only")
            print()
            print("To add config to database:")
            print("1. Go to Dashboard → Configuration Management")
            print("2. Edit detection thresholds")
            print("3. Save changes")
        else:
            print(f"    ✓ Config found in database for sensor '{sensor_id}'")

            if 'thresholds' in db_config_data:
                threshold_count = len(db_config_data['thresholds'])
                print(f"    - Threshold categories: {threshold_count}")

                categories = list(db_config_data['thresholds'].keys())
                print(f"    - Categories: {', '.join(categories[:5])}")
                if len(categories) > 5:
                    print(f"                  ... and {len(categories) - 5} more")
                print()

                # Show example of one threshold
                first_cat = categories[0]
                first_thresh = db_config_data['thresholds'][first_cat]
                print(f"    Example ({first_cat}):")
                for key, value in list(first_thresh.items())[:3]:
                    print(f"      - {key}: {value}")
            else:
                print("    - No threshold configuration in database")
            print()
    except Exception as e:
        print(f"    ✗ Failed to load config from database: {e}")
        import traceback
        traceback.print_exc()
        return

    # Summary
    print("=" * 60)
    print("Summary:")
    print("=" * 60)

    if db_config_data and 'thresholds' in db_config_data:
        print("✓ SOC server WILL use database configuration")
        print("✓ Config sync will work automatically")
        print()
        print("When you start the SOC server:")
        print("- Initial config loaded from config.yaml")
        print("- Database config merged (database takes precedence)")
        print("- Config syncs automatically every 5 minutes")
        print()
        print("Check logs for:")
        print('  "SOC server self-monitoring enabled as sensor: soc-server"')
        print('  "✓ Config updated from database: X parameter(s) changed"')
    else:
        print("⚠️  SOC server will use config.yaml ONLY")
        print("   No database config found for sensor 'soc-server'")
        print()
        print("To enable database config sync:")
        print("1. Start SOC server (will register itself)")
        print("2. Go to Dashboard → Configuration")
        print("3. Edit and save configuration")
        print("4. Config will sync automatically")

if __name__ == '__main__':
    main()
