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

    print("Loading builtin data...")
    print()

    try:
        # Load templates
        print("Loading device templates...")
        templates_count = db.init_builtin_templates()
        print(f"  ✓ Loaded {templates_count} device templates")

        # Load service providers
        print("Loading service providers...")
        providers_count = db.init_builtin_service_providers()
        print(f"  ✓ Loaded {providers_count} service providers")

        print()
        print(f"✓ Total builtin data loaded: {templates_count} templates, {providers_count} service providers")
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
