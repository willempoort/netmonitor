#!/usr/bin/env python3
"""
NetMonitor - Whitelist Sensor IPs
Voegt alle bekende sensor IPs toe aan de database whitelist
"""

import sys
from database import DatabaseManager
from config_loader import load_config

def whitelist_sensors():
    """Voeg alle sensor IPs toe aan whitelist"""

    # Load config
    config = load_config('config.yaml')

    # Connect to database
    print("Connecting to database...")
    db_config = config['database']['postgresql']
    db = DatabaseManager(
        host=db_config['host'],
        port=db_config['port'],
        database=db_config['database'],
        user=db_config['user'],
        password=db_config['password']
    )

    # Get all sensors from database
    print("Fetching sensor list...")
    sensors = db.get_sensors()

    if not sensors:
        print("No sensors found in database")
        return

    print(f"Found {len(sensors)} sensor(s)")

    # Add each sensor IP to whitelist
    success_count = 0
    for sensor in sensors:
        sensor_id = sensor.get('sensor_id')
        ip_address = sensor.get('ip_address')

        if not ip_address:
            print(f"  ⚠ Sensor {sensor_id} heeft geen IP adres, skip...")
            continue

        # Check if already whitelisted
        if db.check_ip_whitelisted(ip_address):
            print(f"  ✓ {ip_address} ({sensor_id}) - already whitelisted")
            continue

        # Add to whitelist
        try:
            db.add_ip_to_whitelist(
                ip_cidr=f"{ip_address}/32",  # Single IP as /32
                scope='global',
                description=f'Sensor: {sensor_id}',
                added_by='system'
            )
            print(f"  ✓ {ip_address} ({sensor_id}) - toegevoegd aan whitelist")
            success_count += 1
        except Exception as e:
            print(f"  ✗ Error whitelisting {ip_address}: {e}", file=sys.stderr)

    print(f"\n✓ {success_count} sensor IP(s) toegevoegd aan whitelist")
    print("\nNote: Restart sensors om config sync te triggeren:")
    print("  sudo systemctl restart netmonitor")

if __name__ == '__main__':
    whitelist_sensors()
