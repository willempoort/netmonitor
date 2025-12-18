#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Script om live de detector config te inspecteren terwijl het draait
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config_loader import load_config
from database import DatabaseManager

def main():
    print("=" * 70)
    print("LIVE CONFIG INSPECTOR")
    print("=" * 70)
    print()

    # Load config
    config = load_config("config.yaml")
    sensor_id = config.get('self_monitor', {}).get('sensor_id', 'soc-server')

    # Connect to database
    db_config = config.get('database', {}).get('postgresql', {})
    db = DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor')
    )

    print("Monitoring config values every 5 seconds...")
    print("Press Ctrl+C to stop")
    print()
    print(f"Watching: thresholds.packet_size.min_suspicious_size")
    print()

    try:
        while True:
            # Get current database value
            db_full_config = db.get_sensor_config(sensor_id=sensor_id)
            db_value = None
            if db_full_config:
                db_value = db_full_config.get('thresholds', {}).get('packet_size', {}).get('min_suspicious_size')

            # Get config.yaml value
            yaml_value = config.get('thresholds', {}).get('packet_size', {}).get('min_suspicious_size')

            # Simulate merge (what detector sees)
            merged_value = yaml_value
            if db_value is not None:
                merged_value = db_value

            timestamp = time.strftime('%H:%M:%S')

            print(f"[{timestamp}]  config.yaml: {yaml_value:>10}  |  database: {str(db_value):>10}  |  detector sees: {merged_value:>10}")

            time.sleep(5)

    except KeyboardInterrupt:
        print()
        print("Stopped monitoring")
        print()
        print("=" * 70)
        print("INSTRUCTIONS TO FIX:")
        print("=" * 70)
        print()
        print("If 'database' column shows 'None':")
        print("  1. Go to Dashboard → Configuration")
        print("  2. Find: thresholds.packet_size.min_suspicious_size")
        print("  3. Set value (e.g., 50000 for 50KB)")
        print("  4. Click Save")
        print()
        print("The detector will pick up the change within 5 minutes")
        print("(or restart netmonitor for immediate effect)")

if __name__ == '__main__':
    main()
