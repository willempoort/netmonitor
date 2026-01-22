#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Load/Reload Builtin Templates and Service Providers
This ensures default data is available even if database was kept during install
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config_loader import load_config
from database import DatabaseManager


def load_builtin_data(config_file='config.yaml'):
    """Load builtin device templates and service providers"""

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

    print("Checking builtin data...")
    print()

    try:
        # Check existing templates
        print("Checking device templates...")
        existing_templates = db.get_device_templates()
        print(f"  Found {len(existing_templates)} existing templates")

        # Load templates (will skip if they exist)
        templates_count = db.init_builtin_templates()
        if templates_count > 0:
            print(f"  ✓ Loaded {templates_count} new device templates")
        else:
            print(f"  ✓ All builtin templates already exist (no new templates loaded)")

        # Check existing providers
        print()
        print("Checking service providers...")
        # Count existing providers
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM service_providers")
        existing_providers_count = cursor.fetchone()[0]
        conn.commit()
        db._return_connection(conn)
        print(f"  Found {existing_providers_count} existing service providers")

        # Load service providers (will skip if they exist)
        providers_count = db.init_builtin_service_providers()
        if providers_count > 0:
            print(f"  ✓ Loaded {providers_count} new service providers")
        else:
            print(f"  ✓ All builtin service providers already exist (no new providers loaded)")

        print()
        total_existing = len(existing_templates) + existing_providers_count
        total_new = templates_count + providers_count

        if total_new > 0:
            print(f"✓ Loaded {total_new} new builtin items ({templates_count} templates, {providers_count} providers)")
        else:
            print(f"✓ All builtin data already exists in database ({len(existing_templates)} templates, {existing_providers_count} providers)")
            print("  No action needed - templates and providers are already available in Web UI")

        return True

    except Exception as e:
        print(f"✗ Error loading builtin data: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        db.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Load Builtin Templates and Service Providers')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    args = parser.parse_args()

    success = load_builtin_data(args.config)
    sys.exit(0 if success else 1)
