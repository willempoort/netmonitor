#!/usr/bin/env python3
"""
Debug script to check exact database config values
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from database import DatabaseManager
from config_loader import load_config

def main():
    print("=" * 70)
    print("DATABASE CONFIG DEBUG")
    print("=" * 70)
    print()

    # Load config.yaml
    config = load_config("config.yaml")
    db_config = config.get('database', {}).get('postgresql', {})

    # Connect to database
    db = DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor')
    )

    # Get database config for soc-server
    sensor_id = 'soc-server'
    print(f"[1] Getting config from database for sensor_id='{sensor_id}'...")
    print()

    db_config_data = db.get_sensor_config(sensor_id=sensor_id)

    if not db_config_data:
        print("⚠️  NO CONFIG IN DATABASE")
        return

    print("✓ Config found in database")
    print()

    # Print complete config structure
    print("[2] Complete database config structure:")
    print()
    print(json.dumps(db_config_data, indent=2))
    print()

    # Check packet_size specifically
    print("=" * 70)
    print("[3] packet_size threshold analysis:")
    print("=" * 70)
    print()

    if 'thresholds' in db_config_data and 'packet_size' in db_config_data['thresholds']:
        packet_size_config = db_config_data['thresholds']['packet_size']

        print("Database has packet_size config:")
        for key, value in packet_size_config.items():
            print(f"  - {key}: {value}")
        print()

        # Check if critical parameter is present
        if 'min_suspicious_size' in packet_size_config:
            print(f"✓ min_suspicious_size IS in database: {packet_size_config['min_suspicious_size']}")
        else:
            print("⚠️  min_suspicious_size NOT in database")
            print("   This parameter is used for UNUSUAL_PACKET_SIZE detection")
            print("   Detector will use config.yaml value instead")
        print()

        if 'max_normal_size' in packet_size_config:
            print(f"✓ max_normal_size IS in database: {packet_size_config['max_normal_size']}")
        else:
            print("⚠️  max_normal_size NOT in database")
        print()

        if 'enabled' in packet_size_config:
            print(f"✓ enabled IS in database: {packet_size_config['enabled']}")
        else:
            print("⚠️  enabled NOT in database")
    else:
        print("⚠️  NO packet_size config in database thresholds")

    print()
    print("=" * 70)
    print("[4] config.yaml packet_size (for comparison):")
    print("=" * 70)
    print()

    yaml_packet_size = config.get('thresholds', {}).get('packet_size', {})
    for key, value in yaml_packet_size.items():
        print(f"  - {key}: {value}")
    print()

    print("=" * 70)
    print("[5] What will happen when configs are merged:")
    print("=" * 70)
    print()

    # Simulate merge
    merged = yaml_packet_size.copy()
    if 'thresholds' in db_config_data and 'packet_size' in db_config_data['thresholds']:
        merged.update(db_config_data['thresholds']['packet_size'])

    print("Final merged packet_size config:")
    for key, value in merged.items():
        source = "database" if (key in db_config_data.get('thresholds', {}).get('packet_size', {})) else "config.yaml"
        print(f"  - {key}: {value} (from {source})")
    print()

    # Check detector usage
    print("=" * 70)
    print("[6] Detector usage:")
    print("=" * 70)
    print()
    print("The detector uses: threshold = self.config['thresholds']['packet_size']['min_suspicious_size']")
    print(f"Current value after merge would be: {merged.get('min_suspicious_size', 'MISSING!')}")
    print()

    if 'min_suspicious_size' not in db_config_data.get('thresholds', {}).get('packet_size', {}):
        print("⚠️  PROBLEM IDENTIFIED:")
        print("   The database does NOT have 'min_suspicious_size' parameter")
        print("   Only 'max_normal_size' was set in dashboard")
        print()
        print("   To fix: Go to dashboard → Configuration → packet_size")
        print("          Set BOTH parameters:")
        print("          - min_suspicious_size: <desired value>")
        print("          - max_normal_size: <desired value>")

if __name__ == '__main__':
    main()
