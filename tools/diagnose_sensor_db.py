#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Diagnose Sensor Database Issues
Shows what sensors are actually in the database
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config_loader import load_config
from database import DatabaseManager
import json


def diagnose_sensors(config_file='config.yaml'):
    """Check what sensors are in the database"""

    # Load config
    config = load_config(config_file)

    # Connect to database
    db_config = config.get('database', {}).get('postgresql', {})
    db = DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor')
    )

    print("=" * 70)
    print("SENSOR DATABASE DIAGNOSTIC")
    print("=" * 70)
    print()

    # Get all sensors
    try:
        sensors = db.get_sensors()

        if not sensors:
            print("❌ NO SENSORS FOUND IN DATABASE!")
            print()
            print("This means:")
            print("  1. The SOC server sensor was never registered")
            print("  2. Or the registration failed silently")
            print()
            print("Run: python3 tools/register_soc_sensor.py")
            return False

        print(f"✅ Found {len(sensors)} sensor(s) in database:")
        print()

        for i, sensor in enumerate(sensors, 1):
            print(f"[{i}] Sensor ID: {sensor.get('sensor_id')}")
            print(f"    Hostname: {sensor.get('hostname')}")
            print(f"    Location: {sensor.get('location')}")
            print(f"    Status: {sensor.get('status')}")
            print(f"    IP: {sensor.get('ip_address')}")
            print(f"    Last seen: {sensor.get('last_seen')}")

            # Check config
            config_data = sensor.get('config')
            if config_data:
                if isinstance(config_data, str):
                    try:
                        config_data = json.loads(config_data)
                    except:
                        print(f"    Config: [Invalid JSON string]")
                        config_data = None

                if config_data:
                    print(f"    Config keys: {list(config_data.keys())}")
                    if 'available_interfaces' in config_data:
                        ifaces = config_data['available_interfaces']
                        print(f"    Available interfaces: {len(ifaces)} interface(s)")
                        for iface in ifaces:
                            if isinstance(iface, dict):
                                print(f"      - {iface.get('name')} (status: {iface.get('status')})")
                            else:
                                print(f"      - {iface}")
                    else:
                        print(f"    ⚠️  No available_interfaces in config!")

                    if 'interface' in config_data:
                        print(f"    Current interface: {config_data['interface']}")
                    else:
                        print(f"    ⚠️  No interface setting in config!")
            else:
                print(f"    ⚠️  No config data!")

            print()

        # Check if soc-server exists
        print("-" * 70)
        print("Checking for 'soc-server' specifically...")
        print()

        soc_sensor = db.get_sensor_by_id('soc-server')
        if soc_sensor:
            print("✅ 'soc-server' sensor found!")
            print(f"   Hostname: {soc_sensor.get('hostname')}")
            print(f"   Config type: {type(soc_sensor.get('config'))}")
            if soc_sensor.get('config'):
                config_data = soc_sensor['config']
                if isinstance(config_data, str):
                    print(f"   ⚠️  Config is a STRING, not a dict!")
                    print(f"   Config value: {config_data[:100]}...")
                else:
                    print(f"   ✅ Config is a dict")
                    print(f"   Config keys: {list(config_data.keys())}")
        else:
            print("❌ 'soc-server' sensor NOT found!")
            print()
            print("Available sensor IDs:")
            for sensor in sensors:
                print(f"  - {sensor.get('sensor_id')}")
            print()
            print("Solution: Run registration script:")
            print("  python3 tools/register_soc_sensor.py")

        return True

    except Exception as e:
        print(f"❌ Error querying database: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        db.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Diagnose Sensor Database')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    args = parser.parse_args()

    success = diagnose_sensors(args.config)
    sys.exit(0 if success else 1)
