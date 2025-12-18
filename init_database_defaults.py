#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
NetMonitor - Database Default Configuration Initializer
Loads default threshold values from config.yaml into the database
"""

import sys
from database import DatabaseManager
from config_loader import load_config

def flatten_config(config_dict, parent_key='', sep='.'):
    """
    Flatten nested config dict into parameter_path format.
    Example: {'thresholds': {'packet_size': {'min_suspicious_size': 1400}}}
    Becomes: {'thresholds.packet_size.min_suspicious_size': 1400}
    """
    items = []
    for key, value in config_dict.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(flatten_config(value, new_key, sep=sep).items())
        else:
            items.append((new_key, value))
    return dict(items)

def load_defaults():
    """Load default config parameters into database"""

    # Load config.yaml
    print("Loading config.yaml...")
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

    # Extract thresholds from config
    thresholds = config.get('thresholds', {})

    if not thresholds:
        print("No thresholds found in config.yaml")
        return

    print(f"Found {len(thresholds)} threshold categories in config.yaml")

    # Flatten nested config to parameter_path format
    flat_config = flatten_config({'thresholds': thresholds})

    # Save each parameter to database
    print("Saving default thresholds to database (global scope)...")

    success_count = 0
    error_count = 0

    for param_path, value in flat_config.items():
        try:
            # Save parameter as global config
            result = db.set_config_parameter(
                parameter_path=param_path,
                value=value,
                sensor_id=None,  # None = global config
                scope='global',
                description=f'Default value from config.yaml',
                updated_by='system'
            )

            if result:
                success_count += 1
            else:
                error_count += 1
                print(f"  ✗ Failed to save: {param_path}", file=sys.stderr)

        except Exception as e:
            error_count += 1
            print(f"  ✗ Error saving {param_path}: {e}", file=sys.stderr)

    # Summary
    print(f"\n✓ Saved {success_count} parameters to database")

    if error_count > 0:
        print(f"✗ {error_count} parameters failed to save", file=sys.stderr)
        sys.exit(1)

    # Show categories
    categories = set()
    for param_path in flat_config.keys():
        parts = param_path.split('.')
        if len(parts) >= 2:
            categories.add(parts[1])  # thresholds.CATEGORY.param -> CATEGORY

    print(f"✓ Loaded {len(categories)} threshold categories:")
    for category in sorted(categories):
        print(f"  - {category}")

if __name__ == '__main__':
    load_defaults()
