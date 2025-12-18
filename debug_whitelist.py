#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Debug script to check whitelist configuration
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from database import DatabaseManager
from config_loader import load_config

def main():
    print("=" * 70)
    print("WHITELIST DEBUG")
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

    sensor_id = 'soc-server'

    print("[1] Checking config.yaml whitelist:")
    print()
    config_whitelist = config.get('whitelist', [])
    if config_whitelist:
        print(f"✓ config.yaml has {len(config_whitelist)} whitelist entries:")
        for ip in config_whitelist:
            print(f"  - {ip}")
    else:
        print("⚠️  config.yaml has NO whitelist entries")
    print()

    print("=" * 70)
    print("[2] Checking database whitelist (GLOBAL):")
    print()

    # Get global whitelist from database (scope='global')
    try:
        global_entries = db.get_whitelist(scope='global')

        if global_entries:
            print(f"✓ Database has {len(global_entries)} GLOBAL whitelist entries:")
            for entry in global_entries:
                ip = entry.get('ip_cidr', 'N/A')
                desc = entry.get('description', 'No description')
                entry_id = entry.get('id', 'N/A')
                print(f"  - {ip:20s} | {desc:40s} | ID: {entry_id}")
        else:
            print("⚠️  Database has NO global whitelist entries")

    except Exception as e:
        print(f"✗ Error querying global whitelist: {e}")
        global_entries = []

    print()
    print("=" * 70)
    print(f"[3] Checking database whitelist (SENSOR-SPECIFIC for '{sensor_id}'):")
    print()

    # Get sensor-specific whitelist from database
    try:
        # Get all whitelist entries for this sensor (includes global + sensor-specific)
        all_entries = db.get_whitelist(sensor_id=sensor_id)

        # Filter to only sensor-specific (not global)
        sensor_entries = [e for e in all_entries if e.get('scope') == 'sensor']

        if sensor_entries:
            print(f"✓ Database has {len(sensor_entries)} sensor-specific whitelist entries:")
            for entry in sensor_entries:
                ip = entry.get('ip_cidr', 'N/A')
                desc = entry.get('description', 'No description')
                entry_id = entry.get('id', 'N/A')
                print(f"  - {ip:20s} | {desc:40s} | ID: {entry_id}")
        else:
            print(f"⚠️  Database has NO sensor-specific whitelist entries for '{sensor_id}'")

    except Exception as e:
        print(f"✗ Error querying sensor whitelist: {e}")
        sensor_entries = []

    print()
    print("=" * 70)
    print("[4] Testing whitelist check function:")
    print()

    # Test some IPs
    test_ips = []

    # Add IPs from config
    if config_whitelist:
        # Extract first IP (without CIDR if present)
        first_ip = config_whitelist[0].split('/')[0]
        test_ips.append(first_ip)

    # Add IPs from database
    if global_entries:
        first_global_ip = global_entries[0].get('ip_cidr', '').split('/')[0]
        if first_global_ip:
            test_ips.append(first_global_ip)

    if sensor_entries:
        first_sensor_ip = sensor_entries[0].get('ip_cidr', '').split('/')[0]
        if first_sensor_ip:
            test_ips.append(first_sensor_ip)

    # Add a non-whitelisted IP
    test_ips.append("8.8.8.8")

    # Remove duplicates
    test_ips = list(dict.fromkeys(test_ips))

    for test_ip in test_ips:
        try:
            is_whitelisted = db.check_ip_whitelisted(test_ip, sensor_id=sensor_id)
            status = "✓ WHITELISTED" if is_whitelisted else "✗ NOT whitelisted"
            print(f"  {test_ip:20s} → {status}")
        except Exception as e:
            print(f"  {test_ip:20s} → ERROR: {e}")

    print()
    print("=" * 70)
    print("[5] Summary:")
    print("=" * 70)
    print()

    total_whitelist = len(config_whitelist)
    if global_entries:
        total_whitelist += len(global_entries)
    if sensor_entries:
        total_whitelist += len(sensor_entries)

    print(f"Total whitelist sources:")
    print(f"  - config.yaml: {len(config_whitelist)} entries")
    print(f"  - Database global: {len(global_entries) if global_entries else 0} entries")
    print(f"  - Database sensor-specific: {len(sensor_entries) if sensor_entries else 0} entries")
    print(f"  - TOTAL: {total_whitelist} entries")
    print()

    if total_whitelist == 0:
        print("⚠️  WARNING: NO WHITELIST ENTRIES FOUND!")
        print("   Add whitelist entries via:")
        print("   - Dashboard → Whitelist Management")
        print("   - Or edit config.yaml whitelist section")
    else:
        print("✓ Whitelist is configured")
        print()
        print("If you're still getting alerts for whitelisted IPs:")
        print("1. Verify the EXACT IP (use test above)")
        print("2. Check if IP is in CIDR range")
        print("3. Restart netmonitor: sudo systemctl restart netmonitor")
        print("4. Enable debug logging in config.yaml: logging.level = DEBUG")
        print("5. Check logs: journalctl -u netmonitor -f | grep -i whitelist")

if __name__ == '__main__':
    main()
