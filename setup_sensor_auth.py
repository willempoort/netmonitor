#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Setup Script voor Sensor Authentication
Genereert tokens voor remote sensors
"""

import sys
from pathlib import Path

# Add current dir to path
sys.path.insert(0, str(Path(__file__).parent))

from database import DatabaseManager
from sensor_auth import SensorAuthManager
from config_loader import load_config


def main():
    print("=" * 60)
    print("NetMonitor - Sensor Token Setup")
    print("=" * 60)
    print()

    # Load config
    config = load_config('config.yaml')

    # Connect to database
    print("[1/3] Connecting to database...")
    db_config = config.get('database', {}).get('postgresql', {})
    db = DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor')
    )
    print("✓ Database connected")
    print()

    # Initialize auth manager
    print("[2/3] Initializing authentication manager...")
    auth = SensorAuthManager(db)
    print("✓ Auth manager ready")
    print()

    # Interactive token generation
    print("[3/3] Generate sensor token")
    print("-" * 60)

    sensor_id = input("Sensor ID (e.g., nano-vlan10-01): ").strip()
    if not sensor_id:
        print("❌ Sensor ID is required!")
        sys.exit(1)

    # Check if sensor exists, if not create it
    print(f"\nChecking if sensor '{sensor_id}' exists...")
    conn = db._get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT sensor_id FROM sensors WHERE sensor_id = %s", (sensor_id,))
        sensor_exists = cursor.fetchone() is not None
    finally:
        db._return_connection(conn)

    if not sensor_exists:
        print(f"⚠️  Sensor '{sensor_id}' does not exist yet.")
        print("Creating sensor first...")
        print()

        hostname = input(f"Hostname (default: {sensor_id}): ").strip() or sensor_id
        location = input("Location (optional, e.g., 'SOC-Office-VLAN10'): ").strip() or None

        # Register the sensor
        success = db.register_sensor(
            sensor_id=sensor_id,
            hostname=hostname,
            location=location
        )

        if not success:
            print("❌ Failed to create sensor!")
            sys.exit(1)

        print(f"✓ Sensor '{sensor_id}' created successfully")
        print()
    else:
        print(f"✓ Sensor '{sensor_id}' exists")
        print()

    token_name = input("Token name (optional, e.g., 'Main Token'): ").strip() or None

    expires = input("Expires in days (leave empty for no expiration): ").strip()
    expires_days = int(expires) if expires else None

    print()
    print("Permissions (press Enter to accept defaults):")
    print("  - alerts: true   (can submit alerts)")
    print("  - metrics: true  (can submit metrics)")
    print("  - commands: false (cannot execute commands)")
    print()

    allow_commands = input("Allow remote commands? (y/N): ").strip().lower() == 'y'

    permissions = {
        'alerts': True,
        'metrics': True,
        'commands': allow_commands
    }

    print()
    print("Generating token...")

    try:
        token = auth.generate_token(
            sensor_id=sensor_id,
            token_name=token_name,
            expires_days=expires_days,
            permissions=permissions
        )

        print()
        print("=" * 60)
        print("✓ TOKEN GENERATED SUCCESSFULLY!")
        print("=" * 60)
        print()
        print(f"Sensor ID:    {sensor_id}")
        print(f"Token Name:   {token_name or '(none)'}")
        print(f"Expires:      {'Never' if not expires_days else f'{expires_days} days'}")
        print(f"Permissions:  alerts={permissions['alerts']}, metrics={permissions['metrics']}, commands={permissions['commands']}")
        print()
        print("⚠️  SAVE THIS TOKEN - IT WILL NOT BE SHOWN AGAIN!")
        print()
        print("-" * 60)
        print(f"TOKEN: {token}")
        print("-" * 60)
        print()
        print("Add this to your sensor configuration:")
        print()
        print("  Environment variable:")
        print(f"    SENSOR_TOKEN={token}")
        print()
        print("  Or in sensor service file:")
        print(f'    Environment="SENSOR_TOKEN={token}"')
        print()
        print("  Or as command line argument:")
        print(f'    --token "{token}"')
        print()

    except Exception as e:
        print(f"❌ Error generating token: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
