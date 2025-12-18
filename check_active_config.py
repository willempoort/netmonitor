#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Check welke config de detector DAADWERKELIJK gebruikt
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config_loader import load_config
from database import DatabaseManager

def main():
    print("=" * 70)
    print("ACTIVE DETECTOR CONFIG CHECK")
    print("=" * 70)
    print()

    # Load config zoals netmonitor.py doet
    config = load_config("config.yaml")

    print("[1] Config.yaml packet_size threshold:")
    print()
    yaml_packet = config.get('thresholds', {}).get('packet_size', {})
    print(f"  min_suspicious_size: {yaml_packet.get('min_suspicious_size', 'MISSING')}")
    print(f"  max_normal_size: {yaml_packet.get('max_normal_size', 'MISSING')}")
    print(f"  enabled: {yaml_packet.get('enabled', 'MISSING')}")
    print()

    # Check if self-monitoring enabled
    self_monitor = config.get('self_monitor', {})
    if not self_monitor.get('enabled'):
        print("⚠️  Self-monitoring DISABLED - using only config.yaml")
        return

    sensor_id = self_monitor.get('sensor_id', 'soc-server')

    # Connect to database
    db_config = config.get('database', {}).get('postgresql', {})
    db = DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor')
    )

    print("[2] Database config for soc-server:")
    print()

    db_full_config = db.get_sensor_config(sensor_id=sensor_id)

    if not db_full_config:
        print("  ⚠️  NO config in database")
        print()
        print("RESULT: Detector uses ONLY config.yaml values")
        return

    db_packet = db_full_config.get('thresholds', {}).get('packet_size', {})

    if db_packet:
        print("  ✓ Database has packet_size config:")
        print(f"    min_suspicious_size: {db_packet.get('min_suspicious_size', 'NOT SET')}")
        print(f"    max_normal_size: {db_packet.get('max_normal_size', 'NOT SET')}")
        print(f"    enabled: {db_packet.get('enabled', 'NOT SET')}")
    else:
        print("  ⚠️  Database has NO packet_size config")

    print()
    print("[3] Merged config (wat detector DAADWERKELIJK gebruikt):")
    print()

    # Simulate merge zoals netmonitor._deep_merge_config doet
    merged = yaml_packet.copy()
    if db_packet:
        merged.update(db_packet)

    min_size = merged.get('min_suspicious_size', 'MISSING!')
    max_size = merged.get('max_normal_size', 'MISSING!')
    enabled = merged.get('enabled', 'MISSING!')

    print(f"  min_suspicious_size: {min_size} bytes")
    print(f"  max_normal_size: {max_size} bytes")
    print(f"  enabled: {enabled}")
    print()

    print("=" * 70)
    print("ANALYSIS:")
    print("=" * 70)
    print()

    if 'min_suspicious_size' not in db_packet:
        print("⚠️  PROBLEM FOUND!")
        print()
        print("Database does NOT have 'min_suspicious_size' parameter.")
        print("Detector uses this parameter for UNUSUAL_PACKET_SIZE detection.")
        print()
        print(f"Current value used: {min_size} bytes (from config.yaml)")
        print()
        print("Packets larger than this generate alerts:")
        print("  - 5422 bytes → ALERT")
        print("  - 6190 bytes → ALERT")
        print("  - 10182 bytes → ALERT")
        print()
        print("SOLUTION:")
        print("=========")
        print()
        print("Go to Dashboard → Configuration Management → Thresholds")
        print("Find: packet_size")
        print("Set BOTH parameters:")
        print("  - min_suspicious_size: <desired value in bytes>")
        print("  - max_normal_size: <desired value in bytes>")
        print()
        print("Example values:")
        print("  - min_suspicious_size: 50000  (50KB - alleen zeer grote packets)")
        print("  - max_normal_size: 65535      (max voor single packet)")
        print()
        print("Or set via Dashboard → Sensors → soc-server → Settings")

    else:
        print("✓ Configuration is complete")
        print()
        print(f"Alerts will be generated for packets > {min_size} bytes")

if __name__ == '__main__':
    main()
