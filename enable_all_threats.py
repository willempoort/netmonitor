#!/usr/bin/env python3
"""
Enable All Threat Detections
Quick script to enable all 60 threat detections at once for testing
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config_loader import load_config
from database import DatabaseManager

print("=" * 70)
print("Enable All NetMonitor Threat Detections")
print("=" * 70)
print()

# Load config
try:
    config = load_config('config.yaml')
    print("✓ config.yaml loaded")
except Exception as e:
    print(f"✗ Failed to load config.yaml: {e}")
    sys.exit(1)

# Connect to database
db_config = config.get('database', {})
db_type = db_config.get('type', None)

if db_type != 'postgresql':
    print("✗ This script requires PostgreSQL database")
    sys.exit(1)

pg_config = db_config.get('postgresql', {})

try:
    db = DatabaseManager(
        host=pg_config.get('host', 'localhost'),
        port=pg_config.get('port', 5432),
        database=pg_config.get('database', 'netmonitor'),
        user=pg_config.get('user', 'netmonitor'),
        password=pg_config.get('password', 'netmonitor'),
        min_connections=1,
        max_connections=2
    )
    print("✓ Connected to database")
except Exception as e:
    print(f"✗ Database connection failed: {e}")
    sys.exit(1)

# Get all threat.*.enabled parameters
conn = db._get_connection()
cursor = conn.cursor()

cursor.execute("""
    SELECT parameter_path, parameter_value
    FROM sensor_configs
    WHERE parameter_path LIKE 'threat.%.enabled'
      AND scope = 'global'
    ORDER BY parameter_path
""")

params = cursor.fetchall()
print(f"\n📋 Found {len(params)} threat detection parameters")
print()

# Count enabled vs disabled
enabled_count = sum(1 for _, val in params if val == 'true')
disabled_count = len(params) - enabled_count

print(f"   Currently enabled: {enabled_count}")
print(f"   Currently disabled: {disabled_count}")
print()

if disabled_count == 0:
    print("✓ All threat detections are already enabled!")
    db._return_connection(conn)
    db.close()
    sys.exit(0)

# Ask for confirmation
print("⚡ This will enable ALL threat detections:")
print()
for path, _ in params:
    threat_name = path.replace('threat.', '').replace('.enabled', '')
    print(f"   - {threat_name}")

print()
response = input("Enable all? (yes/no): ").strip().lower()

if response not in ('yes', 'y'):
    print("Aborted.")
    db._return_connection(conn)
    db.close()
    sys.exit(0)

# Enable all
print()
print("Enabling all threat detections...")

updated = 0
for path, current_value in params:
    if current_value != 'true':
        cursor.execute("""
            UPDATE sensor_configs
            SET parameter_value = 'true',
                updated_at = NOW(),
                updated_by = 'enable_all_threats'
            WHERE parameter_path = %s
              AND scope = 'global'
        """, (path,))
        updated += cursor.rowcount

conn.commit()
db._return_connection(conn)
db.close()

print(f"✓ Enabled {updated} threat detections")
print()
print("Sensors will auto-sync within 5 minutes.")
print("Or restart sensors for immediate effect:")
print("   sudo systemctl restart netmonitor-sensor")
print()
print("=" * 70)
