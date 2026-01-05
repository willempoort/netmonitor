#!/usr/bin/env python3
"""
Fix corrupted template behavior parameters where JSON was double-encoded.

This fixes cases where {"low_bandwidth":true} became {"{\"low_bandwidth\":true}":true}
"""

import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import DatabaseManager
from config_loader import load_config

def fix_corrupted_behaviors():
    """Find and fix corrupted behavior parameters"""
    config = load_config()
    db = DatabaseManager(config)

    conn = db._get_connection()
    try:
        cursor = conn.cursor()

        # Get all template behaviors
        cursor.execute('SELECT id, behavior_type, parameters FROM template_behaviors')
        rows = cursor.fetchall()

        fixed_count = 0

        for row in rows:
            behavior_id = row[0]
            behavior_type = row[1]
            params_raw = row[2]

            # Parse parameters if string
            if isinstance(params_raw, str):
                try:
                    params = json.loads(params_raw)
                except:
                    continue
            else:
                params = params_raw

            if not isinstance(params, dict):
                continue

            # Check for corrupted keys (keys that look like JSON strings)
            corrupted_keys = [k for k in params.keys() if k.startswith('{') and k.endswith('}')]

            if corrupted_keys:
                print(f"\n🔍 Found corrupted behavior ID {behavior_id} ({behavior_type}):")
                print(f"   Current: {json.dumps(params)}")

                # Try to fix it
                fixed_params = {}

                for key in corrupted_keys:
                    # Try to parse the key as JSON
                    try:
                        parsed = json.loads(key)
                        if isinstance(parsed, dict):
                            # Merge the parsed dict into fixed_params
                            fixed_params.update(parsed)
                            print(f"   ✓ Parsed corrupted key: {key}")
                        else:
                            # Keep as-is if not a dict
                            fixed_params[key] = params[key]
                    except json.JSONDecodeError:
                        # Not valid JSON, keep as-is
                        fixed_params[key] = params[key]

                # Keep non-corrupted keys
                for key, value in params.items():
                    if key not in corrupted_keys:
                        fixed_params[key] = value

                print(f"   Fixed:   {json.dumps(fixed_params)}")

                # Update in database
                cursor.execute(
                    'UPDATE template_behaviors SET parameters = %s WHERE id = %s',
                    (json.dumps(fixed_params), behavior_id)
                )
                fixed_count += 1

        if fixed_count > 0:
            conn.commit()
            print(f"\n✅ Fixed {fixed_count} corrupted behavior(s)")
        else:
            print("\n✅ No corrupted behaviors found")

        return fixed_count

    except Exception as e:
        conn.rollback()
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 0
    finally:
        db._return_connection(conn)

if __name__ == '__main__':
    print("=" * 60)
    print("Template Behavior Corruption Fix")
    print("=" * 60)

    fixed = fix_corrupted_behaviors()

    if fixed > 0:
        print("\n📝 Please refresh the web UI to see the fixed behaviors")

    sys.exit(0 if fixed >= 0 else 1)
